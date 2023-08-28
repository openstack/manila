#!/bin/bash

# Plugin file for enabling manila services
# ----------------------------------------

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set -o xtrace

# Entry Points
# ------------

function _clean_share_group {
    local vg=$1
    local vg_prefix=$2
    # Clean out existing shares
    for lv in `sudo lvs --noheadings -o lv_name $vg`; do
        # vg_prefix prefixes the LVs we want
        if [[ "${lv#$vg_prefix}" != "$lv" ]]; then
            sudo umount -f $MANILA_MNT_DIR/$lv
            sudo lvremove -f $vg/$lv
            sudo rm -rf $MANILA_MNT_DIR/$lv
        fi
    done
}

function _clean_manila_lvm_backing_file {
    local vg=$1

    # if there is no logical volume left, it's safe to attempt a cleanup
    # of the backing file
    if [ -z "`sudo lvs --noheadings -o lv_name $vg`" ]; then
        # if the backing physical device is a loop device, it was probably setup by devstack
        VG_DEV=$(sudo losetup -j $DATA_DIR/${vg}-backing-file | awk -F':' '/backing-file/ { print $1
}')
        if [[ -n "$VG_DEV" ]]; then
            sudo losetup -d $VG_DEV
            rm -f $DATA_DIR/${vg}-backing-file
        fi
    fi
}

function _clean_zfsonlinux_data {
    for filename in "$MANILA_ZFSONLINUX_BACKEND_FILES_CONTAINER_DIR"/*; do
        if [[ $(sudo zpool list | grep $filename) ]]; then
            echo "Destroying zpool named $filename"
            sudo zpool destroy -f $filename
            file="$MANILA_ZFSONLINUX_BACKEND_FILES_CONTAINER_DIR$filename"
            echo "Destroying file named $file"
            rm -f $file
        fi
    done
}

# cleanup_manila - Remove residual data files, anything left over from previous
# runs that a clean run would need to clean up
function cleanup_manila {
    # All stuff, that are created by share drivers will be cleaned up by other services.
    _clean_share_group $SHARE_GROUP $SHARE_NAME_PREFIX
    _clean_manila_lvm_backing_file $SHARE_GROUP
    _clean_zfsonlinux_data

    if [ $(trueorfalse False MANILA_USE_UWSGI) == True ]; then
        remove_uwsgi_config "$MANILA_UWSGI_CONF" "$MANILA_WSGI"
    fi
}

# _config_manila_apache_wsgi() - Configure manila-api wsgi application.
function _config_manila_apache_wsgi {
    local manila_api_apache_conf
    local venv_path=""
    manila_api_apache_conf=$(apache_site_config_for manila-api)

    sudo cp $MANILA_DIR/devstack/apache-manila.template $manila_api_apache_conf
    sudo sed -e "
        s|%APACHE_NAME%|$APACHE_NAME|g;
        s|%MANILA_BIN_DIR%|$MANILA_BIN_DIR|g;
        s|%PORT%|$REAL_MANILA_SERVICE_PORT|g;
        s|%APIWORKERS%|$API_WORKERS|g;
        s|%USER%|$STACK_USER|g;
    " -i $manila_api_apache_conf
}

# configure_backends - Configures backends enabled by MANILA_ENABLED_BACKENDS
function configure_backends {
    # Configure MANILA_ENABLED_BACKENDS backends
    for group_name in $(echo $MANILA_ENABLED_BACKENDS | sed "s/,/ /g"); do
        iniset $MANILA_CONF $group_name share_driver $SHARE_DRIVER
        iniset $MANILA_CONF $group_name share_backend_name ${group_name^^}
        iniset $MANILA_CONF $group_name path_to_public_key $MANILA_PATH_TO_PUBLIC_KEY
        iniset $MANILA_CONF $group_name path_to_private_key $MANILA_PATH_TO_PRIVATE_KEY
        iniset $MANILA_CONF $group_name service_image_name $MANILA_SERVICE_IMAGE_NAME
        iniset $MANILA_CONF $group_name service_instance_user $MANILA_SERVICE_INSTANCE_USER
        iniset $MANILA_CONF $group_name driver_handles_share_servers True

        if [ "$SHARE_DRIVER" == $MANILA_CONTAINER_DRIVER ]; then
            iniset $MANILA_CONF $group_name network_api_class $MANILA_NETWORK_API_CLASS
            iniset $MANILA_CONF $group_name neutron_host_id $(hostname)
            iniset $MANILA_CONF $group_name neutron_vnic_type $MANILA_NEUTRON_VNIC_TYPE
        fi

        if [ $(trueorfalse False MANILA_USE_SERVICE_INSTANCE_PASSWORD) == True ]; then
            iniset $MANILA_CONF $group_name service_instance_password $MANILA_SERVICE_INSTANCE_PASSWORD
        fi

        if [ "$SHARE_DRIVER" == "manila.share.drivers.generic.GenericShareDriver" ]; then
            iniset $MANILA_CONF $group_name ssh_conn_timeout $MANILA_SSH_TIMEOUT
        fi
    done
}

# set_config_opts - this allows to set any config opt to any config group,
# parsing env vars by prefix special 'MANILA_OPTGROUP_'.
function set_config_opts {
    # expects only one param - name of config group(s) as list separated by commas
    GROUP_NAMES=$1
    if [[ -n "$GROUP_NAMES" ]]; then
        for be in ${GROUP_NAMES//,/ }; do
            # get backend_specific opt values
            prefix=MANILA_OPTGROUP_$be\_
            ( set -o posix ; set ) | grep ^$prefix | while read -r line ; do
                # parse it to opt names and values
                opt=${line#$prefix}
                opt_name=${opt%%=*}
                opt_value=${opt##*=}
                iniset $MANILA_CONF $be $opt_name $opt_value
            done
        done
    fi
}

# set_cinder_quotas - Sets Cinder quotas, that is useful for generic driver,
# which uses Cinder volumes and snapshots.
function set_cinder_quotas {
    # Update Cinder configuration to make sure default quotas are enough
    # for Manila using Generic driver with parallel testing.
    if is_service_enabled cinder; then
        if [[ ! "$CINDER_CONF" ]]; then
            CINDER_CONF=/etc/cinder/cinder.conf
        fi
        iniset $CINDER_CONF DEFAULT quota_volumes 50
        iniset $CINDER_CONF DEFAULT quota_snapshots 50
        iniset $CINDER_CONF DEFAULT quota_gigabytes 1000
    fi
}

function set_backend_availability_zones {
    ENABLED_BACKENDS=$1
    echo_summary "Setting up backend_availability_zone option \
        for any enabled backends that do not use the Generic driver and have \
        not been set previously. Availability zones for the Generic driver \
        must coincide with those created for Nova and Cinder."
    local zonenum
    generic_driver='manila.share.drivers.generic.GenericShareDriver'
    for BE in ${ENABLED_BACKENDS//,/ }; do
        share_driver=$(iniget $MANILA_CONF $BE share_driver)
        az=$(iniget $MANILA_CONF $BE backend_availability_zone)
        if [[ -z $az && $share_driver != $generic_driver ]]; then
            zone="manila-zone-$((zonenum++))"
            iniset $MANILA_CONF $BE backend_availability_zone $zone
        fi
    done
}

# configure_manila - Set config files, create data dirs, etc
function configure_manila {
    if [[ ! -d $MANILA_CONF_DIR ]]; then
        sudo mkdir -p $MANILA_CONF_DIR
    fi
    sudo chown $STACK_USER $MANILA_CONF_DIR

    # Set the paths of certain binaries
    MANILA_ROOTWRAP=$(get_rootwrap_location manila)

    # If Manila ships the new rootwrap filters files, deploy them
    # (owned by root) and add a parameter to $MANILA_ROOTWRAP
    ROOTWRAP_MANILA_SUDOER_CMD="$MANILA_ROOTWRAP"
    if [[ -d $MANILA_DIR/etc/manila/rootwrap.d ]]; then
        # Wipe any existing rootwrap.d files first
        if [[ -d $MANILA_CONF_DIR/rootwrap.d ]]; then
            sudo rm -rf $MANILA_CONF_DIR/rootwrap.d
        fi
        # Deploy filters to /etc/manila/rootwrap.d
        sudo mkdir -m 755 $MANILA_CONF_DIR/rootwrap.d
        sudo cp $MANILA_DIR/etc/manila/rootwrap.d/*.filters $MANILA_CONF_DIR/rootwrap.d
        sudo chown -R root:root $MANILA_CONF_DIR/rootwrap.d
        sudo chmod 644 $MANILA_CONF_DIR/rootwrap.d/*
        # Set up rootwrap.conf, pointing to /etc/manila/rootwrap.d
        sudo cp $MANILA_DIR/etc/manila/rootwrap.conf $MANILA_CONF_DIR/
        sudo sed -e "s:^filters_path=.*$:filters_path=$MANILA_CONF_DIR/rootwrap.d:" -i $MANILA_CONF_DIR/rootwrap.conf
        sudo chown root:root $MANILA_CONF_DIR/rootwrap.conf
        sudo chmod 0644 $MANILA_CONF_DIR/rootwrap.conf
        # Specify rootwrap.conf as first parameter to manila-rootwrap
        MANILA_ROOTWRAP="$MANILA_ROOTWRAP $MANILA_CONF_DIR/rootwrap.conf"
        ROOTWRAP_MANILA_SUDOER_CMD="$MANILA_ROOTWRAP *"
    fi

    TEMPFILE=`mktemp`
    echo "$USER ALL=(root) NOPASSWD: $ROOTWRAP_MANILA_SUDOER_CMD" >$TEMPFILE
    chmod 0440 $TEMPFILE
    sudo chown root:root $TEMPFILE
    sudo mv $TEMPFILE /etc/sudoers.d/manila-rootwrap

    cp $MANILA_DIR/etc/manila/api-paste.ini $MANILA_API_PASTE_INI

    # Remove old conf file if exists
    rm -f $MANILA_CONF

    configure_keystone_authtoken_middleware $MANILA_CONF manila

    iniset $MANILA_CONF DEFAULT auth_strategy keystone
    iniset $MANILA_CONF DEFAULT debug True
    iniset $MANILA_CONF DEFAULT scheduler_driver $MANILA_SCHEDULER_DRIVER
    iniset $MANILA_CONF DEFAULT share_name_template ${SHARE_NAME_PREFIX}%s
    iniset $MANILA_CONF DATABASE connection `database_connection_url manila`
    iniset $MANILA_CONF DATABASE max_pool_size 40
    iniset $MANILA_CONF DEFAULT api_paste_config $MANILA_API_PASTE_INI
    iniset $MANILA_CONF DEFAULT rootwrap_config $MANILA_CONF_DIR/rootwrap.conf
    iniset $MANILA_CONF DEFAULT osapi_share_extension manila.api.contrib.standard_extensions
    iniset $MANILA_CONF DEFAULT state_path $MANILA_STATE_PATH

    # Note: Sample share types will still be created if the below is False

    if [ $(trueorfalse False MANILA_CONFIGURE_DEFAULT_TYPES) == True ]; then
        iniset $MANILA_CONF DEFAULT default_share_type $MANILA_DEFAULT_SHARE_TYPE
        iniset $MANILA_CONF DEFAULT default_share_group_type $MANILA_DEFAULT_SHARE_GROUP_TYPE
    fi

    if ! [[ -z $MANILA_SHARE_MIGRATION_PERIOD_TASK_INTERVAL ]]; then
        iniset $MANILA_CONF DEFAULT migration_driver_continue_update_interval $MANILA_SHARE_MIGRATION_PERIOD_TASK_INTERVAL
    fi

    if ! [[ -z $MANILA_SERVER_MIGRATION_PERIOD_TASK_INTERVAL ]]; then
        iniset $MANILA_CONF DEFAULT server_migration_driver_continue_update_interval $MANILA_SERVER_MIGRATION_PERIOD_TASK_INTERVAL
    fi

    if ! [[ -z $MANILA_CREATE_BACKUP_CONTINUE_TASK_INTERVAL ]]; then
        iniset $MANILA_CONF DEFAULT driver_backup_continue_update_interval $MANILA_CREATE_BACKUP_CONTINUE_TASK_INTERVAL
    fi

    if ! [[ -z $MANILA_RESTORE_BACKUP_CONTINUE_TASK_INTERVAL ]]; then
        iniset $MANILA_CONF DEFAULT driver_restore_continue_update_interval $MANILA_RESTORE_BACKUP_CONTINUE_TASK_INTERVAL
    fi

    if ! [[ -z $MANILA_DATA_COPY_CHECK_HASH ]]; then
        iniset $MANILA_CONF DEFAULT check_hash $MANILA_DATA_COPY_CHECK_HASH
    fi

    iniset $MANILA_CONF DEFAULT enabled_share_protocols $MANILA_ENABLED_SHARE_PROTOCOLS

    iniset $MANILA_CONF oslo_concurrency lock_path $MANILA_LOCK_PATH

    iniset $MANILA_CONF DEFAULT wsgi_keep_alive False

    iniset $MANILA_CONF DEFAULT lvm_share_volume_group $SHARE_GROUP

    # Set the replica_state_update_interval
    iniset $MANILA_CONF DEFAULT replica_state_update_interval $MANILA_REPLICA_STATE_UPDATE_INTERVAL
    # Set the use_scheduler_creating_share_from_snapshot
    iniset $MANILA_CONF DEFAULT use_scheduler_creating_share_from_snapshot $MANILA_USE_SCHEDULER_CREATING_SHARE_FROM_SNAPSHOT

    if is_service_enabled neutron; then
        configure_keystone_authtoken_middleware $MANILA_CONF neutron neutron
    fi
    if is_service_enabled nova; then
        configure_keystone_authtoken_middleware $MANILA_CONF nova nova
    fi
    if is_service_enabled cinder; then
        configure_keystone_authtoken_middleware $MANILA_CONF cinder cinder
    fi
    if is_service_enabled glance; then
        configure_keystone_authtoken_middleware $MANILA_CONF glance glance
    fi
    if [ ! $MANILA_ENABLED_BACKENDS ]; then
        # MANILA_ENABLED_BACKENDS is a required option
        echo -"No configured backends, please set a value to MANILA_ENABLED_BACKENDS"
        exit 1
    fi

    configure_backends
    iniset $MANILA_CONF DEFAULT enabled_share_backends $MANILA_ENABLED_BACKENDS

    if [ ! -f $MANILA_PATH_TO_PRIVATE_KEY ]; then
        ssh-keygen -N "" -t $MANILA_KEY_FORMAT -f $MANILA_PATH_TO_PRIVATE_KEY;
    fi

    iniset $MANILA_CONF DEFAULT manila_service_keypair_name $MANILA_SERVICE_KEYPAIR_NAME

    REAL_MANILA_SERVICE_PORT=$MANILA_SERVICE_PORT
    if is_service_enabled tls-proxy; then
        # Set the protocol to 'https', update the endpoint base and set the default port
        MANILA_SERVICE_PROTOCOL="https"
        MANILA_ENDPOINT_BASE="${MANILA_ENDPOINT_BASE/http:/https:}"
        REAL_MANILA_SERVICE_PORT=$MANILA_SERVICE_PORT_INT
        # Set the service port for a proxy to take the original
        iniset $MANILA_CONF DEFAULT osapi_share_listen_port $REAL_MANILA_SERVICE_PORT
        iniset $MANILA_CONF oslo_middleware enable_proxy_headers_parsing True
    fi

    iniset_rpc_backend manila $MANILA_CONF DEFAULT

    setup_logging $MANILA_CONF

    MANILA_CONFIGURE_GROUPS=${MANILA_CONFIGURE_GROUPS:-"$MANILA_ENABLED_BACKENDS"}
    set_config_opts $MANILA_CONFIGURE_GROUPS
    set_config_opts DEFAULT
    set_backend_availability_zones $MANILA_ENABLED_BACKENDS

    if [ $(trueorfalse False MANILA_USE_UWSGI) == True ]; then
        write_uwsgi_config "$MANILA_UWSGI_CONF" "$MANILA_WSGI" "/share"
    fi

    if [ $(trueorfalse False MANILA_USE_MOD_WSGI) == True ]; then
        _config_manila_apache_wsgi
    fi

    if [[ "$MANILA_ENFORCE_SCOPE" == True ]] ; then
        iniset $MANILA_CONF oslo_policy enforce_scope true
        iniset $MANILA_CONF oslo_policy enforce_new_defaults true
        OS_CLOUD="devstack-admin"
    fi
}


function create_manila_service_keypair {
    if is_service_enabled nova; then
        local keypair_exists=$( openstack --os-cloud devstack-admin keypair list | grep " $MANILA_SERVICE_KEYPAIR_NAME " )
        if [[ -z $keypair_exists ]]; then
            openstack --os-cloud devstack-admin keypair create $MANILA_SERVICE_KEYPAIR_NAME --public-key $MANILA_PATH_TO_PUBLIC_KEY
        fi
    fi
}


function is_driver_enabled {
    driver_name=$1
    for BE in ${MANILA_ENABLED_BACKENDS//,/ }; do
        share_driver=$(iniget $MANILA_CONF $BE share_driver)
        if [ "$share_driver" == "$driver_name" ]; then
            return 0
        fi
    done
    return 1
}


# create_service_share_servers - creates service Nova VMs, one per generic
# driver, and only if it is configured to mode without handling of share servers.
function create_service_share_servers {
    created_admin_network=false
    for BE in ${MANILA_ENABLED_BACKENDS//,/ }; do
        driver_handles_share_servers=$(iniget $MANILA_CONF $BE driver_handles_share_servers)
        share_driver=$(iniget $MANILA_CONF $BE share_driver)
        generic_driver='manila.share.drivers.generic.GenericShareDriver'
        if [[ $share_driver == $generic_driver ]]; then
            if [[ $(trueorfalse False driver_handles_share_servers) == False ]]; then
                vm_name='manila_service_share_server_'$BE
                local vm_exists=$( openstack --os-cloud devstack-admin server list --all-projects | grep " $vm_name " )
                if [[ -z $vm_exists ]]; then
                    private_net_id=$(openstack --os-cloud devstack-admin network show $PRIVATE_NETWORK_NAME -f value -c id)
                    vm_id=$(openstack --os-cloud devstack-admin server create $vm_name \
                        --flavor $MANILA_SERVICE_VM_FLAVOR_NAME \
                        --image $MANILA_SERVICE_IMAGE_NAME \
                        --nic net-id=$private_net_id \
                        --security-group $MANILA_SERVICE_SECGROUP \
                        --key-name $MANILA_SERVICE_KEYPAIR_NAME \
                        | grep ' id ' | get_field 2)
                else
                    vm_id=$(openstack --os-cloud devstack-admin server show $vm_name -f value -c id)
                fi

                floating_ip=$(openstack --os-cloud devstack-admin floating ip create $PUBLIC_NETWORK_NAME --subnet $PUBLIC_SUBNET_NAME | grep 'floating_ip_address' | get_field 2)
                openstack --os-cloud devstack-admin server add floating ip $vm_id $floating_ip

                iniset $MANILA_CONF $BE service_instance_name_or_id $vm_id
                iniset $MANILA_CONF $BE service_net_name_or_ip $floating_ip
                iniset $MANILA_CONF $BE tenant_net_name_or_ip $PRIVATE_NETWORK_NAME
            else
                if is_service_enabled neutron; then
                    if ! [[ -z $MANILA_ADMIN_NET_RANGE ]]; then
                        if [ $created_admin_network == false ]; then
                            project_id=$(openstack --os-cloud devstack-admin project show $SERVICE_PROJECT_NAME -c id -f value)
                            local admin_net_id=$( openstack --os-cloud devstack-admin network show admin_net -f value -c id )
                            if [[ -z $admin_net_id ]]; then
                                openstack --os-cloud devstack-admin network create admin_net --project $project_id
                                admin_net_id=$(openstack --os-cloud devstack-admin network show admin_net -f value -c id)
                            fi

                            local admin_subnet_id=$( openstack --os-cloud devstack-admin subnet show admin_subnet -f value -c id )
                            if [[ -z $admin_subnet_id ]]; then
                                openstack --os-cloud devstack-admin subnet create admin_subnet --project $project_id --ip-version 4 --network $admin_net_id --gateway None --subnet-range $MANILA_ADMIN_NET_RANGE
                                admin_subnet_id=$(openstack --os-cloud devstack-admin subnet show admin_subnet -f value -c id)
                            fi
                            created_admin_network=true
                        fi
                        iniset $MANILA_CONF $BE admin_network_id $admin_net_id
                        iniset $MANILA_CONF $BE admin_subnet_id $admin_subnet_id
                    fi
                fi
            fi
        fi
    done
    configure_data_service_generic_driver
}

function configure_data_service_generic_driver {
    enabled_backends=(${MANILA_ENABLED_BACKENDS//,/ })
    share_driver=$(iniget $MANILA_CONF ${enabled_backends[0]} share_driver)
    generic_driver='manila.share.drivers.generic.GenericShareDriver'
    if [[ $share_driver == $generic_driver ]]; then
        driver_handles_share_servers=$(iniget $MANILA_CONF ${enabled_backends[0]} driver_handles_share_servers)
        if [[ $(trueorfalse False driver_handles_share_servers) == False ]]; then
            iniset $MANILA_CONF DEFAULT data_node_access_ips $PUBLIC_NETWORK_GATEWAY
        else
            if ! [[ -z $MANILA_DATA_NODE_IP ]]; then
                iniset $MANILA_CONF DEFAULT data_node_access_ips $MANILA_DATA_NODE_IP
            fi
        fi
    fi
}
# create_manila_service_flavor - creates flavor, that will be used by backends
# with configured generic driver to boot Nova VMs with.
function create_manila_service_flavor {
    if is_service_enabled nova; then
        local flavor_exists=$( openstack --os-cloud devstack-admin flavor list | grep " $MANILA_SERVICE_VM_FLAVOR_NAME " )
        if [[ -z $flavor_exists ]]; then
            # Create flavor for Manila's service VM
            openstack --os-cloud devstack-admin --os-cloud devstack-admin flavor create \
                $MANILA_SERVICE_VM_FLAVOR_NAME \
                --id $MANILA_SERVICE_VM_FLAVOR_REF \
                --ram $MANILA_SERVICE_VM_FLAVOR_RAM \
                --disk $MANILA_SERVICE_VM_FLAVOR_DISK \
                --vcpus $MANILA_SERVICE_VM_FLAVOR_VCPUS
        fi
    fi
}

# create_manila_service_image - creates image, that will be used by backends
# with configured generic driver to boot Nova VMs from.
function create_manila_service_image {
    if is_service_enabled nova g-api; then
        TOKEN=$(openstack --os-cloud devstack-admin token issue -c id -f value)
        local image_exists=$( openstack --os-cloud devstack-admin image list | grep " $MANILA_SERVICE_IMAGE_NAME " )
        if [[ -z $image_exists ]]; then
            # Download Manila's image
            upload_image $MANILA_SERVICE_IMAGE_URL $TOKEN
        fi
    fi
}

# create_manila_service_secgroup - creates security group that is used by
# Nova VMs when generic driver is configured.
function create_manila_service_secgroup {
    # Create a secgroup
    if ! openstack --os-cloud devstack-admin security group list | grep -q $MANILA_SERVICE_SECGROUP; then
        openstack --os-cloud devstack-admin security group create $MANILA_SERVICE_SECGROUP --description "$MANILA_SERVICE_SECGROUP description"
        if ! timeout 30 sh -c "while ! openstack --os-cloud devstack-admin security group list | grep -q $MANILA_SERVICE_SECGROUP; do sleep 1; done"; then
            echo "Security group not created"
            exit 1
        fi
    fi

    # Configure Security Group Rules
    if ! openstack --os-cloud devstack-admin security group rule list $MANILA_SERVICE_SECGROUP | grep -q icmp; then
        openstack --os-cloud devstack-admin security group rule create $MANILA_SERVICE_SECGROUP --protocol icmp
    fi
    if ! openstack --os-cloud devstack-admin security group rule list $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 22 "; then
        openstack --os-cloud devstack-admin security group rule create $MANILA_SERVICE_SECGROUP --protocol tcp --dst-port 22
    fi
    if ! openstack --os-cloud devstack-admin security group rule list $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 2049 "; then
        openstack --os-cloud devstack-admin security group rule create $MANILA_SERVICE_SECGROUP --protocol tcp --dst-port 2049
    fi
    if ! openstack --os-cloud devstack-admin security group rule list $MANILA_SERVICE_SECGROUP | grep -q " udp .* 2049 "; then
        openstack --os-cloud devstack-admin security group rule create $MANILA_SERVICE_SECGROUP --protocol udp --dst-port 2049
    fi
    if ! openstack --os-cloud devstack-admin security group rule list $MANILA_SERVICE_SECGROUP | grep -q " udp .* 445 "; then
        openstack --os-cloud devstack-admin security group rule create $MANILA_SERVICE_SECGROUP --protocol udp --dst-port 445
    fi
    if ! openstack --os-cloud devstack-admin security group rule list $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 445 "; then
        openstack --os-cloud devstack-admin security group rule create $MANILA_SERVICE_SECGROUP --protocol tcp --dst-port 445
    fi
    if ! openstack --os-cloud devstack-admin security group rule list $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 139 "; then
        openstack --os-cloud devstack-admin security group rule create $MANILA_SERVICE_SECGROUP --protocol tcp --dst-port 137:139
    fi
    if ! openstack --os-cloud devstack-admin security group rule list $MANILA_SERVICE_SECGROUP | grep -q " udp .* 139 "; then
        openstack --os-cloud devstack-admin security group rule create $MANILA_SERVICE_SECGROUP --protocol udp --dst-port 137:139
    fi

    # List secgroup rules
    openstack --os-cloud devstack-admin security group rule list $MANILA_SERVICE_SECGROUP
}

# create_manila_accounts - Set up common required manila accounts
function create_manila_accounts {

    create_service_user "manila"

    get_or_create_service "manila" "share" "Manila Shared Filesystem Service"
    get_or_create_endpoint "share" "$REGION_NAME" \
        "$MANILA_ENDPOINT_BASE/v1/\$(project_id)s"

    # Set up Manila v2 service and endpoint - as of microversion 2.60,
    # project_id is no longer necessary in the v2 endpoint
    get_or_create_service "manilav2" "sharev2" "Manila Shared Filesystem Service V2"
    get_or_create_endpoint "sharev2" "$REGION_NAME" \
        "$MANILA_ENDPOINT_BASE/v2"

    # Set up Manila legacy v2 service and endpoint - as of microversion 2.60,
    # project_id is no longer necessary in the v2 endpoint
    get_or_create_service "manilav2_legacy" "sharev2_legacy" "Manila Shared
    Filesystem Service V2 (Legacy 2.0)"
    get_or_create_endpoint "sharev2_legacy" "$REGION_NAME" \
        "$MANILA_ENDPOINT_BASE/v2/\$(project_id)s"

    # Set up an endpoint for "shared-file-system" - this is necessary to
    # standardize a naming for the v2 API and for the openstacksdk.
    # See: https://specs.openstack.org/openstack/service-types-authority/
    get_or_create_service "shared-file-system" "shared-file-system" "Manila
    Shared Filesystem Service v2 API (alias of the sharev2 service)"
    get_or_create_endpoint "shared-file-system" "$REGION_NAME" \
        "$MANILA_ENDPOINT_BASE/v2"

}

# create_default_share_group_type - create share group type that will be set as default.
function create_default_share_group_type {

    local type_exists=$( openstack --os-cloud $OS_CLOUD share group type list | grep " $MANILA_DEFAULT_SHARE_GROUP_TYPE " )
    if [[ -z $type_exists ]]; then
        openstack --os-cloud $OS_CLOUD share group type create $MANILA_DEFAULT_SHARE_GROUP_TYPE $MANILA_DEFAULT_SHARE_TYPE
    fi
    if [[ $MANILA_DEFAULT_SHARE_GROUP_TYPE_SPECS ]]; then
        openstack --os-cloud $OS_CLOUD share group type set $MANILA_DEFAULT_SHARE_GROUP_TYPE --group-specs $MANILA_DEFAULT_SHARE_GROUP_TYPE_SPECS
    fi

}

# create_default_share_type - create share type that will be set as default
# if $MANILA_CONFIGURE_DEFAULT_TYPES is set to True, if set to False, the share
# type identified by $MANILA_DEFAULT_SHARE_TYPE is still created, but not
# configured as default.
function create_default_share_type {
    enabled_backends=(${MANILA_ENABLED_BACKENDS//,/ })
    driver_handles_share_servers=$(iniget $MANILA_CONF ${enabled_backends[0]} driver_handles_share_servers)

    local type_exists=$( openstack --os-cloud $OS_CLOUD share type list | grep " $MANILA_DEFAULT_SHARE_TYPE " )
    if [[ -z $type_exists ]]; then
        local command_args="$MANILA_DEFAULT_SHARE_TYPE $driver_handles_share_servers"
        if [[ $MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS ]]; then
            command_args="$command_args --extra-specs $MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS"
        fi
        openstack --os-cloud $OS_CLOUD share type create $command_args
    fi

}

# create_custom_share_types - create share types suitable for both possible
# driver modes with names "dhss_true" and "dhss_false".
function create_custom_share_types {
    local command_args="dhss_true True"
    if [[ $MANILA_DHSS_TRUE_SHARE_TYPE_EXTRA_SPECS ]]; then
        command_args="$command_args --extra-specs $MANILA_DHSS_TRUE_SHARE_TYPE_EXTRA_SPECS"
    fi
    openstack --os-cloud $OS_CLOUD share type create $command_args

    command_args="dhss_false False"
    if [[ $MANILA_DHSS_FALSE_SHARE_TYPE_EXTRA_SPECS ]]; then
        command_args="$command_args --extra-specs $MANILA_DHSS_FALSE_SHARE_TYPE_EXTRA_SPECS"
    fi
    openstack --os-cloud $OS_CLOUD share type create $command_args
}

# configure_backing_file - Set up backing file for LVM
function configure_backing_file {
    sudo vgscan
    if ! sudo vgs $SHARE_GROUP; then
        if [ "$CONFIGURE_BACKING_FILE" = "True" ]; then
            SHARE_BACKING_FILE=${SHARE_BACKING_FILE:-$DATA_DIR/${SHARE_GROUP}-backing-file}
            # Only create if the file doesn't already exists
            [[ -f $SHARE_BACKING_FILE ]] || truncate -s $SHARE_BACKING_FILE_SIZE $SHARE_BACKING_FILE
            DEV=`sudo losetup -f --show $SHARE_BACKING_FILE`
        else
            DEV=$SHARE_BACKING_FILE
        fi
        # Only create if the loopback device doesn't contain $SHARE_GROUP
        if ! sudo vgs $SHARE_GROUP; then sudo vgcreate $SHARE_GROUP $DEV; fi
    fi

    mkdir -p $MANILA_STATE_PATH/shares
    mkdir -p /tmp/shares
}

# init_manila - Initializes database and creates manila dir if absent
function init_manila {

    if is_service_enabled $DATABASE_BACKENDS; then
        # (re)create manila database
        recreate_database manila

        $MANILA_BIN_DIR/manila-manage db sync

        if [[ $(trueorfalse False MANILA_USE_DOWNGRADE_MIGRATIONS) == True ]]; then
            # Use both - upgrade and downgrade migrations to verify that
            # downgrade migrations do not break structure of Manila database.
            $MANILA_BIN_DIR/manila-manage db downgrade
            $MANILA_BIN_DIR/manila-manage db sync
        fi

        # Display version as debug-action (see bug/1473400)
        $MANILA_BIN_DIR/manila-manage db version
    fi

    if [ "$SHARE_DRIVER" == "manila.share.drivers.lvm.LVMShareDriver" ]; then
        if is_service_enabled m-shr; then
            # Configure a default volume group called '`lvm-shares`' for the share
            # service if it does not yet exist.  If you don't wish to use a file backed
            # volume group, create your own volume group called ``stack-volumes`` before
            # invoking ``stack.sh``.
            #
            # By default, the backing file is 8G in size, and is stored in ``/opt/stack/data``.

            configure_backing_file
        fi
    elif [ "$SHARE_DRIVER" == $MANILA_CONTAINER_DRIVER ]; then
        if is_service_enabled m-shr; then
            SHARE_GROUP=$MANILA_CONTAINER_VOLUME_GROUP_NAME
            configure_backing_file
        fi

    elif [ "$SHARE_DRIVER" == "manila.share.drivers.zfsonlinux.driver.ZFSonLinuxShareDriver" ]; then
        if is_service_enabled m-shr; then
            mkdir -p $MANILA_ZFSONLINUX_BACKEND_FILES_CONTAINER_DIR
            file_counter=0
            MANILA_ZFSONLINUX_SERVICE_IP=${MANILA_ZFSONLINUX_SERVICE_IP:-"127.0.0.1"}
            for BE in ${MANILA_ENABLED_BACKENDS//,/ }; do
                if [[ $file_counter == 0 ]]; then
                    # NOTE(vponomaryov): create two pools for first ZFS backend
                    # to cover different use cases that are supported by driver:
                    # - Support of more than one zpool for share backend.
                    # - Support of nested datasets.
                    local first_file="$MANILA_ZFSONLINUX_BACKEND_FILES_CONTAINER_DIR"/alpha
                    local second_file="$MANILA_ZFSONLINUX_BACKEND_FILES_CONTAINER_DIR"/betta
                    truncate -s $MANILA_ZFSONLINUX_ZPOOL_SIZE $first_file
                    truncate -s $MANILA_ZFSONLINUX_ZPOOL_SIZE $second_file
                    sudo zpool create alpha $first_file
                    sudo zpool create betta $second_file
                    # Create subdir (nested dataset) for second pool
                    sudo zfs create betta/subdir
                    iniset $MANILA_CONF $BE zfs_zpool_list alpha,betta/subdir
                elif [[ $file_counter == 1 ]]; then
                    local file="$MANILA_ZFSONLINUX_BACKEND_FILES_CONTAINER_DIR"/gamma
                    truncate -s $MANILA_ZFSONLINUX_ZPOOL_SIZE $file
                    sudo zpool create gamma $file
                    iniset $MANILA_CONF $BE zfs_zpool_list gamma
                else
                    local filename=file"$file_counter"
                    local file="$MANILA_ZFSONLINUX_BACKEND_FILES_CONTAINER_DIR"/"$filename"
                    truncate -s $MANILA_ZFSONLINUX_ZPOOL_SIZE $file
                    sudo zpool create $filename $file
                    iniset $MANILA_CONF $BE zfs_zpool_list $filename
                fi
                iniset $MANILA_CONF $BE zfs_share_export_ip $MANILA_ZFSONLINUX_SHARE_EXPORT_IP
                iniset $MANILA_CONF $BE zfs_service_ip $MANILA_ZFSONLINUX_SERVICE_IP
                iniset $MANILA_CONF $BE zfs_dataset_creation_options $MANILA_ZFSONLINUX_DATASET_CREATION_OPTIONS
                iniset $MANILA_CONF $BE zfs_use_ssh $MANILA_ZFSONLINUX_USE_SSH
                iniset $MANILA_CONF $BE zfs_ssh_username $MANILA_ZFSONLINUX_SSH_USERNAME
                iniset $MANILA_CONF $BE replication_domain $MANILA_ZFSONLINUX_REPLICATION_DOMAIN
                iniset $MANILA_CONF $BE driver_handles_share_servers False
                let "file_counter=file_counter+1"
            done
            # Install the server's SSH key in our known_hosts file
            eval STACK_HOME=~$STACK_USER
            ssh-keyscan ${MANILA_ZFSONLINUX_SERVICE_IP} >> $STACK_HOME/.ssh/known_hosts
            # If the server is this machine, setup trust for ourselves (otherwise you're on your own)
            if [ "$MANILA_ZFSONLINUX_SERVICE_IP" = "127.0.0.1" ] || [ "$MANILA_ZFSONLINUX_SERVICE_IP" = "localhost" ] ; then
                # Trust our own SSH keys
                eval SSH_USER_HOME=~$MANILA_ZFSONLINUX_SSH_USERNAME
                cat $STACK_HOME/.ssh/*.pub >> $SSH_USER_HOME/.ssh/authorized_keys
                # Give ssh user sudo access
                echo "$MANILA_ZFSONLINUX_SSH_USERNAME ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers > /dev/null
                iniset $MANILA_CONF DEFAULT data_node_access_ips $MANILA_ZFSONLINUX_SERVICE_IP
            fi
        fi
    fi
}

# check_nfs_kernel_service_state_ubuntu- Make sure nfsd is running
function check_nfs_kernel_service_state_ubuntu {
    # (aovchinnikov): Workaround for nfs-utils bug 1052264
    if [[ $(sudo service nfs-kernel-server status &> /dev/null || echo 'fail') == 'fail' ]]; then
        echo "Apparently nfsd is not running. Trying to fix that."
        sudo mkdir -p "/media/nfsdonubuntuhelper"
        # (aovchinnikov): shell wrapping is needed for cases when a file to be written
        # is owned by root.
        sudo sh -c "echo '/media/nfsdonubuntuhelper 127.0.0.1(ro)' >> /etc/exports"
        sudo service nfs-kernel-server start
    fi
    if [[ $(sudo service nfs-kernel-server status &> /dev/null || echo 'fail') == 'fail' ]]; then
        echo "Failed to start nfsd. Exiting."
        exit 1
    fi
}

function _install_nfs_and_samba {
    if is_ubuntu; then
        install_package nfs-kernel-server nfs-common samba
        check_nfs_kernel_service_state_ubuntu
    elif is_fedora; then
        install_package nfs-utils samba
        sudo systemctl enable smb.service
        sudo systemctl start smb.service
        sudo systemctl enable nfs-server.service
        sudo systemctl start nfs-server.service
    elif is_suse; then
        install_package nfs-kernel-server nfs-utils samba
    else
        echo "This distro is not supported. Skipping step of NFS and Samba installation."
    fi
}

# install_manilaclient - Collect source and prepare
#   In order to install from git, add LIBS_FROM_GIT="python-manilaclient"
#   to local.conf
function install_manilaclient {
    if use_library_from_git "python-manilaclient"; then
        git_clone $MANILACLIENT_REPO $MANILACLIENT_DIR $MANILACLIENT_BRANCH
        setup_develop $MANILACLIENT_DIR
    else
        pip_install python-manilaclient
    fi
}

# install_manila - Collect source and prepare
function install_manila {
    setup_develop $MANILA_DIR

    if is_service_enabled m-shr; then

        if [[ ! $(systemctl is-active nfs-ganesha.service) == 'active' ]] ; then
            if [ "$SHARE_DRIVER" != "manila.share.drivers.cephfs.driver.CephFSDriver" ] ; then
                _install_nfs_and_samba
            fi
        fi

        if [ "$SHARE_DRIVER" == "manila.share.drivers.zfsonlinux.driver.ZFSonLinuxShareDriver" ]; then
            if [[ $(sudo zfs list &> /dev/null && sudo zpool list &> /dev/null || echo 'absent') == 'absent' ]]; then
                # ZFS not found, try to install it
                if is_ubuntu; then
                    if [[ $(lsb_release -s -d) == *"14.04"* ]]; then
                        # Trusty
                        sudo apt-get install -y software-properties-common
                        sudo apt-add-repository --yes ppa:zfs-native/stable

                        # Workaround for bug #1609696
                        sudo apt-mark hold grub*

                        sudo apt-get -y -q update && sudo apt-get -y -q upgrade

                        # Workaround for bug #1609696
                        sudo apt-mark unhold grub*

                        sudo apt-get install -y linux-headers-generic
                        sudo apt-get install -y build-essential
                        sudo apt-get install -y ubuntu-zfs

                    elif [[ $(echo $(lsb_release -rs) '>=' 16.04 | bc -l) == 1 ]]; then
                        # Xenial and beyond
                        sudo apt-get install -y zfsutils-linux
                    else
                        echo "Only 'Trusty', 'Xenial' and newer releases of Ubuntu are supported."
                        exit 1
                    fi
                else
                    echo "Manila Devstack plugin supports installation "\
                        "of ZFS packages only for 'Ubuntu' distros. "\
                        "Please, install it first by other means or add its support "\
                        "for your distro."
                    exit 1
                fi
                sudo modprobe zfs
                sudo modprobe zpool
            fi
            check_nfs_kernel_service_state_ubuntu
        elif [ "$SHARE_DRIVER" == $MANILA_CONTAINER_DRIVER ]; then
            if is_ubuntu; then
                echo "Installing docker...."
                install_docker_ubuntu
                echo "Importing docker image"
                import_docker_service_image_ubuntu
            elif is_fedora; then
                echo "Installing docker...."
                install_docker_fedora
                echo "Importing docker image"
                # TODO(tbarron): See if using a fedora container image
                # is faster/smaller because of fewer extra dependencies.
                import_docker_service_image_ubuntu
            else
                echo "Manila Devstack plugin does not support Container Driver on"\
                     " distros other than Ubuntu or Fedora."
                exit 1
            fi
        fi
    fi

}

#configure_samba - Configure node as Samba server
function configure_samba {
    if [ "$SHARE_DRIVER" == "manila.share.drivers.lvm.LVMShareDriver" ]; then
        # TODO(vponomaryov): add here condition for ZFSonLinux driver too
        # when it starts to support SAMBA
        samba_daemon_name=smbd
        if is_service_enabled m-shr; then
            if is_fedora; then
                samba_daemon_name=smb
            fi
            sudo service $samba_daemon_name restart || echo "Couldn't restart '$samba_daemon_name' service"
        fi

        if [[ -e /usr/share/samba/smb.conf ]]; then
            sudo cp /usr/share/samba/smb.conf $SMB_CONF
        fi
        sudo chown $STACK_USER -R /etc/samba
        iniset $SMB_CONF global include registry
        iniset $SMB_CONF global security user
        if [ ! -d "$SMB_PRIVATE_DIR" ]; then
            sudo mkdir $SMB_PRIVATE_DIR
            sudo touch $SMB_PRIVATE_DIR/secrets.tdb
        fi

        for backend_name in ${MANILA_ENABLED_BACKENDS//,/ }; do
            iniset $MANILA_CONF $backend_name driver_handles_share_servers False
            iniset $MANILA_CONF $backend_name lvm_share_export_ips $MANILA_LVM_SHARE_EXPORT_IPS
        done
        iniset $MANILA_CONF DEFAULT data_node_access_ips $HOST_IP
    fi
}

# start_manila_api - starts manila API services and checks its availability
function start_manila_api {

    # NOTE(vkmc) If both options are set to true we are using uwsgi
    # as the preferred way to deploy manila. See
    # https://governance.openstack.org/tc/goals/pike/deploy-api-in-wsgi.html#uwsgi-vs-mod-wsgi
    # for more details
    if [ $(trueorfalse False MANILA_USE_UWSGI) == True ] && [ $(trueorfalse False MANILA_USE_MOD_WSGI) == True ]; then
        MSG="Both MANILA_USE_UWSGI and MANILA_USE_MOD_WSGI are set to True.
            Using UWSGI as the preferred option
            Set MANILA_USE_UWSGI to False to deploy manila api with MOD_WSGI"
        warn $LINENO $MSG
    fi

    if [ $(trueorfalse False MANILA_USE_UWSGI) == True ]; then
        echo "Deploying with UWSGI"
        run_process m-api "$(which uwsgi) --ini $MANILA_UWSGI_CONF --procname-prefix manila-api"
    elif [ $(trueorfalse False MANILA_USE_MOD_WSGI) == True ]; then
        echo "Deploying with MOD_WSGI"
        install_apache_wsgi
        enable_apache_site manila-api
        restart_apache_server
        tail_log m-api /var/log/$APACHE_NAME/manila_api.log
    else
        echo "Deploying with built-in server"
        run_process m-api "$MANILA_BIN_DIR/manila-api --config-file $MANILA_CONF"
    fi

    echo "Waiting for Manila API to start..."
    # This is a health check against the manila-api service we just started.
    # We use the port ($REAL_MANILA_SERVICE_PORT) here because we want to hit
    # the bare service endpoint, even if the tls tunnel should be enabled.
    # We're making sure that the internal port is checked using unencryted
    # traffic at this point.

    local MANILA_HEALTH_CHECK_URL=$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$REAL_MANILA_SERVICE_PORT

    if [ $(trueorfalse False MANILA_USE_UWSGI) == True ]; then
        MANILA_HEALTH_CHECK_URL=$MANILA_ENDPOINT_BASE
    fi

    if ! wait_for_service $SERVICE_TIMEOUT $MANILA_HEALTH_CHECK_URL; then
        die $LINENO "Manila API did not start"
    fi

    # Start proxies if enabled
    #
    # If tls-proxy is enabled and MANILA_USE_UWSGI is set to True, a generic
    # http-services-tls-proxy will be set up to handle tls-termination to
    # manila as well as all the other https services, we don't need to
    # create our own.
    if [ $(trueorfalse False MANILA_USE_UWSGI) == False ] && is_service_enabled tls-proxy; then
        start_tls_proxy manila '*' $MANILA_SERVICE_PORT $MANILA_SERVICE_HOST $MANILA_SERVICE_PORT_INT
    fi
}

# start_rest_of_manila - starts non-api manila services
function start_rest_of_manila {
    run_process m-shr "$MANILA_BIN_DIR/manila-share --config-file $MANILA_CONF"
    run_process m-sch "$MANILA_BIN_DIR/manila-scheduler --config-file $MANILA_CONF"
    run_process m-dat "$MANILA_BIN_DIR/manila-data --config-file $MANILA_CONF"
}

# start_manila - start all manila services. This function is kept for compatibility
# reasons with old approach.
function start_manila {
    start_manila_api
    start_rest_of_manila
}

# stop_manila - Stop running processes
function stop_manila {
    # Disable manila api service
    if [ $(trueorfalse False MANILA_USE_MOD_WSGI) == True ]; then
        disable_apache_site manila-api
        restart_apache_server
    else
        stop_process m-api
    fi

    # Kill all other manila processes
    for serv in m-sch m-shr m-dat; do
        stop_process $serv
    done
}

# update_tempest - Function used for updating Tempest config if Tempest service enabled
function update_tempest {
    if is_service_enabled tempest; then

        if [[ "$(trueorfalse False MANILA_SETUP_IPV6)" == "True" ]]; then
            # The public network was created by us, so set it explicitly in
            # tempest.conf
            public_net_id=$(openstack --os-cloud devstack-admin network list --name $PUBLIC_NETWORK_NAME -f value -c ID )
            iniset $TEMPEST_CONFIG network public_network_id $public_net_id
        fi

        TEMPEST_CONFIG=${TEMPEST_CONFIG:-$TEMPEST_DIR/etc/tempest.conf}

        if [ $(trueorfalse False MANILA_USE_SERVICE_INSTANCE_PASSWORD) == True ]; then
            iniset $TEMPEST_CONFIG share image_password $MANILA_SERVICE_INSTANCE_PASSWORD
        fi
        iniset $TEMPEST_CONFIG share image_with_share_tools $MANILA_SERVICE_IMAGE_NAME
        iniset $TEMPEST_CONFIG enforce_scope manila "$MANILA_ENFORCE_SCOPE"

        # If testing a stable branch, we need to ensure we're testing with supported
        # API micro-versions; so set the versions from code if we're not testing the
        # master branch. If we're testing master, we'll allow manila-tempest-plugin
        # (which is branchless) tell us what versions it wants to test.
        if [[ "$TARGET_BRANCH" != "master" ]]; then
            # Grab the supported API micro-versions from the code
            _DEFAULT_MIN_VERSION=$(openstack --os-cloud devstack versions show --service sharev2 -c 'Min Microversion' --status CURRENT -f value)
            _DEFAULT_MAX_VERSION=$(openstack --os-cloud devstack versions show --service sharev2 -c 'Max Microversion' --status CURRENT -f value)
            # Override the *_api_microversion tempest options if present
            MANILA_TEMPEST_MIN_API_MICROVERSION=${MANILA_TEMPEST_MIN_API_MICROVERSION:-$_DEFAULT_MIN_VERSION}
            MANILA_TEMPEST_MAX_API_MICROVERSION=${MANILA_TEMPEST_MAX_API_MICROVERSION:-$_DEFAULT_MAX_VERSION}
            # Set these options in tempest.conf
            iniset $TEMPEST_CONFIG share min_api_microversion $MANILA_TEMPEST_MIN_API_MICROVERSION
            iniset $TEMPEST_CONFIG share max_api_microversion $MANILA_TEMPEST_MAX_API_MICROVERSION
        fi
    fi
}

function install_docker_ubuntu {
    sudo apt-get update
    install_package apparmor
    install_package docker.io
}

function install_docker_fedora {
    install_package docker
    sudo systemctl enable docker
    sudo systemctl start docker
}

function download_image {
    local image_url=$1

    local image image_fname

    image_fname=`basename "$image_url"`
    if [[ $image_url != file* ]]; then
        # Downloads the image (uec ami+akistyle), then extracts it.
        if [[ ! -f $FILES/$image_fname || "$(stat -c "%s" $FILES/$image_fname)" = "0" ]]; then
            wget --progress=dot:giga -c $image_url -O $FILES/$image_fname
            if [[ $? -ne 0 ]]; then
                echo "Not found: $image_url"
                return
            fi
        fi
        image="$FILES/${image_fname}"
    else
        # File based URL (RFC 1738): ``file://host/path``
        # Remote files are not considered here.
        # unix: ``file:///home/user/path/file``
        # windows: ``file:///C:/Documents%20and%20Settings/user/path/file``
        image=$(echo $image_url | sed "s/^file:\/\///g")
        if [[ ! -f $image || "$(stat -c "%s" $image)" == "0" ]]; then
            echo "Not found: $image_url"
            return
        fi
    fi
}

function import_docker_service_image_ubuntu {
    GZIPPED_IMG_NAME=`basename "$MANILA_DOCKER_IMAGE_URL"`
    IMG_NAME_LOAD=${GZIPPED_IMG_NAME%.*}
    LOCAL_IMG_NAME=${IMG_NAME_LOAD%.*}
    if [[ "$(sudo docker images -q $LOCAL_IMG_NAME)" == "" ]]; then
        download_image $MANILA_DOCKER_IMAGE_URL
        # Import image in Docker
        gzip -d $FILES/$GZIPPED_IMG_NAME
        sudo docker load --input $FILES/$IMG_NAME_LOAD
    fi
}

function remove_docker_service_image {
    sudo docker rmi $MANILA_DOCKER_IMAGE_ALIAS
}


function install_libraries {
    if [ $(trueorfalse True RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS) == True ]; then
        if is_ubuntu; then
            install_package nfs-common
        else
            install_package nfs-utils
        fi
    fi
}

function allow_host_ports_for_share_mounting {

    if [[ $MANILA_ENABLED_SHARE_PROTOCOLS =~ NFS ]]; then
        # 111 and 2049 are for rpcbind and NFS
        # Other ports are for NFSv3 statd, mountd and lockd daemons
        MANILA_TCP_PORTS=(2049 111 32803 892 875 662)
        MANILA_UDP_PORTS=(111 32769 892 875 662)
    fi
    if [[ $MANILA_ENABLED_SHARE_PROTOCOLS =~ CEPHFS ]]; then
        # clients need access to the ceph daemons
        MANILA_TCP_PORTS=(${MANILA_TCP_PORTS[*]} 6789 6800:7300)
    fi

    if [[ -v MANILA_TCP_PORTS || -v MANILA_UDP_PORTS ]]; then
        for ipcmd in iptables ip6tables; do
            sudo $ipcmd -N manila-storage
            sudo $ipcmd -I INPUT 1 -j manila-storage
            for port in ${MANILA_TCP_PORTS[*]}; do
                sudo $ipcmd -A manila-storage -m tcp -p tcp --dport $port -j ACCEPT
            done
            for port in ${MANILA_UDP_PORTS[*]}; do
                sudo $ipcmd -A manila-storage -m udp -p udp --dport $port -j ACCEPT
            done
        done
    fi
}

function setup_ipv6 {

    # This will fail with multiple default routes and is not needed in CI
    # but may be useful when developing with devstack locally
    if [ $(trueorfalse False MANILA_RESTORE_IPV6_DEFAULT_ROUTE) == True ]; then
        # save IPv6 default route to add back later after enabling forwarding
        local default_route=$(ip -6 route | grep default | cut -d ' ' -f1,2,3,4,5)
    fi

    # make sure those system values are set
    sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0
    sudo sysctl -w net.ipv6.conf.all.accept_ra=2
    sudo sysctl -w net.ipv6.conf.all.forwarding=1

    # Disable in-band as our communication is only internal
    sudo ovs-vsctl set Bridge $PUBLIC_BRIDGE other_config:disable-in-band=true

    # Create address scopes and subnet pools
    openstack --os-cloud devstack-admin address scope create --share --ip-version 4 scope-v4
    openstack --os-cloud devstack-admin address scope create --share --ip-version 6 scope-v6
    openstack --os-cloud devstack-admin subnet pool create $SUBNETPOOL_NAME_V4 --default-prefix-length $SUBNETPOOL_SIZE_V4 --pool-prefix $SUBNETPOOL_PREFIX_V4 --address-scope scope-v4 --default --share
    openstack --os-cloud devstack-admin subnet pool create $SUBNETPOOL_NAME_V6 --default-prefix-length $SUBNETPOOL_SIZE_V6 --pool-prefix $SUBNETPOOL_PREFIX_V6 --address-scope scope-v6 --default --share

    # Create example private network and router
    openstack --os-cloud devstack-admin router create $Q_ROUTER_NAME
    openstack --os-cloud devstack-admin network create $PRIVATE_NETWORK_NAME
    openstack --os-cloud devstack-admin subnet create --ip-version 6 --use-default-subnet-pool --ipv6-address-mode $IPV6_ADDRESS_MODE --ipv6-ra-mode $IPV6_RA_MODE --network $PRIVATE_NETWORK_NAME $IPV6_PRIVATE_SUBNET_NAME
    openstack --os-cloud devstack-admin subnet create --ip-version 4 --use-default-subnet-pool --network $PRIVATE_NETWORK_NAME $PRIVATE_SUBNET_NAME
    openstack --os-cloud devstack-admin router add subnet $Q_ROUTER_NAME $IPV6_PRIVATE_SUBNET_NAME
    openstack --os-cloud devstack-admin router add subnet $Q_ROUTER_NAME $PRIVATE_SUBNET_NAME

    # Create public network
    openstack --os-cloud devstack-admin network create $PUBLIC_NETWORK_NAME --external --default --provider-network-type flat --provider-physical-network $PUBLIC_PHYSICAL_NETWORK
    local public_gateway_ipv6=$(openstack --os-cloud devstack-admin subnet create $IPV6_PUBLIC_SUBNET_NAME --ip-version 6 --network $PUBLIC_NETWORK_NAME --subnet-pool $SUBNETPOOL_NAME_V6 --no-dhcp -c gateway_ip -f value)
    local public_gateway_ipv4=$(openstack --os-cloud devstack-admin subnet create $PUBLIC_SUBNET_NAME --ip-version 4 --network $PUBLIC_NETWORK_NAME --subnet-range $FLOATING_RANGE --no-dhcp -c gateway_ip -f value)

    # Set router to use public network
    openstack --os-cloud devstack-admin router set --external-gateway $PUBLIC_NETWORK_NAME $Q_ROUTER_NAME

    # Configure interfaces due to NEUTRON_CREATE_INITIAL_NETWORKS=False
    local ipv4_cidr_len=${FLOATING_RANGE#*/}
    sudo ip -6 addr add "$public_gateway_ipv6"/$SUBNETPOOL_SIZE_V6 dev $PUBLIC_BRIDGE
    sudo ip addr add "$public_gateway_ipv4"/"$ipv4_cidr_len" dev $PUBLIC_BRIDGE

    # Enabling interface is needed due to NEUTRON_CREATE_INITIAL_NETWORKS=False
    sudo ip link set $PUBLIC_BRIDGE up

    if [ "$SHARE_DRIVER" == "manila.share.drivers.lvm.LVMShareDriver" ]; then
        for backend_name in ${MANILA_ENABLED_BACKENDS//,/ }; do
            iniset $MANILA_CONF $backend_name lvm_share_export_ips $public_gateway_ipv4,$public_gateway_ipv6
        done
        iniset $MANILA_CONF DEFAULT data_node_access_ips $public_gateway_ipv4
    fi

    if [ "$SHARE_DRIVER" == "manila.share.drivers.cephfs.driver.CephFSDriver" ]; then
        for backend_name in ${MANILA_ENABLED_BACKENDS//,/ }; do
            iniset $MANILA_CONF $backend_name cephfs_ganesha_export_ips $public_gateway_ipv4,$public_gateway_ipv6
        done
        iniset $MANILA_CONF DEFAULT data_node_access_ips $public_gateway_ipv4
    fi

    # install Quagga for setting up the host routes dynamically
    install_package quagga

    # set Quagga daemons
    (
    echo "zebra=yes"
    echo "bgpd=yes"
    echo "ospfd=no"
    echo "ospf6d=no"
    echo "ripd=no"
    echo "ripngd=no"
    echo "isisd=no"
    echo "babeld=no"
    ) | sudo tee /etc/quagga/daemons > /dev/null

    # set Quagga zebra.conf
    (
    echo "hostname dsvm"
    echo "password openstack"
    echo "log file /var/log/quagga/zebra.log"
    ) | sudo tee /etc/quagga/zebra.conf > /dev/null

    # set Quagga vtysh.conf
    (
    echo "service integrated-vtysh-config"
    echo "username quagga nopassword"
    ) | sudo tee /etc/quagga/vtysh.conf > /dev/null

    # set Quagga bgpd.conf
    (
    echo "log file /var/log/quagga/bgpd.log"
    echo "bgp multiple-instance"
    echo "router bgp 200"
    echo " bgp router-id 1.2.3.4"
    echo " neighbor $public_gateway_ipv6 remote-as 100"
    echo " neighbor $public_gateway_ipv6 passive"
    echo " address-family ipv6"
    echo "  neighbor $public_gateway_ipv6 activate"
    echo "line vty"
    echo "debug bgp events"
    echo "debug bgp filters"
    echo "debug bgp fsm"
    echo "debug bgp keepalives"
    echo "debug bgp updates"
    ) | sudo tee /etc/quagga/bgpd.conf > /dev/null

    # Quagga logging
    sudo mkdir -p /var/log/quagga
    sudo touch /var/log/quagga/zebra.log
    sudo touch /var/log/quagga/bgpd.log
    sudo chown -R quagga:quagga /var/log/quagga


    GetOSVersion
    QUAGGA_SERVICES="zebra bgpd"
    if [[ is_ubuntu && "$os_CODENAME" == "xenial" ]]; then
        # In Ubuntu Xenial, the services bgpd and zebra are under
        # one systemd unit: quagga
        QUAGGA_SERVICES="quagga"
    elif is_fedora; then
        # Disable SELinux rule that conflicts with Zebra
        sudo setsebool -P zebra_write_config 1
    fi
    sudo systemctl enable $QUAGGA_SERVICES
    sudo systemctl restart $QUAGGA_SERVICES

    # log the systemd status
    sudo systemctl status $QUAGGA_SERVICES

    # This will fail with mutltiple default routes and is not needed in CI
    # but may be useful when developing with devstack locally
    if [ $(trueorfalse False MANILA_RESTORE_IPV6_DEFAULT_ROUTE) == True ]; then
        # add default IPv6 route back
        if ! [[ -z $default_route ]]; then
            # "replace" should ignore "RTNETLINK answers: File exists"
            # error if the route wasn't flushed by the bgp setup we did earlier.
            sudo ip -6 route replace $default_route
        fi
    fi

}

function setup_bgp_for_ipv6 {
    public_gateway_ipv6=$(openstack --os-cloud devstack-admin subnet show ipv6-public-subnet -c gateway_ip -f value)
    openstack --os-cloud devstack-admin bgp speaker create --ip-version 6 --local-as 100 bgpspeaker
    openstack --os-cloud devstack-admin bgp speaker add network bgpspeaker $PUBLIC_NETWORK_NAME
    openstack --os-cloud devstack-admin bgp peer create --peer-ip $public_gateway_ipv6 --remote-as 200 bgppeer
    openstack --os-cloud devstack-admin bgp speaker add peer bgpspeaker bgppeer
}

# Main dispatcher
if [[ "$1" == "stack" && "$2" == "install" ]]; then
    echo_summary "Installing Manila Client"
    install_manilaclient
    echo_summary "Installing Manila"
    install_manila
    set_cinder_quotas
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    echo_summary "Configuring Manila"
    configure_manila
    echo_summary "Initializing Manila"
    init_manila
    echo_summary "Installing extra libraries"
    install_libraries
    echo_summary "Creating Manila entities for auth service"
    create_manila_accounts

    # Cinder config update
    if is_service_enabled cinder && [[ -n "$CINDER_OVERSUBSCRIPTION_RATIO" ]]; then
        CINDER_CONF=${CINDER_CONF:-/etc/cinder/cinder.conf}
        CINDER_ENABLED_BACKENDS=$(iniget $CINDER_CONF DEFAULT enabled_backends)
        for BN in ${CINDER_ENABLED_BACKENDS//,/ }; do
            iniset $CINDER_CONF $BN lvm_max_over_subscription_ratio $CINDER_OVERSUBSCRIPTION_RATIO
        done
        iniset $CINDER_CONF DEFAULT max_over_subscription_ratio $CINDER_OVERSUBSCRIPTION_RATIO
    fi
elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    if is_service_enabled nova; then
        echo_summary "Creating Manila service flavor"
        create_manila_service_flavor

        echo_summary "Creating Manila service security group"
        create_manila_service_secgroup
    fi

    # Skip image downloads when disabled.
    # This way vendor Manila driver CI tests can skip
    # this potentially long and unnecessary download.
    if [ "$MANILA_SERVICE_IMAGE_ENABLED" = "True" ]; then
        echo_summary "Creating Manila service image"
        create_manila_service_image
    else
        echo_summary "Skipping download of Manila service image"
    fi

    if is_service_enabled nova; then
        echo_summary "Creating Manila service keypair"
        create_manila_service_keypair
    fi

    echo_summary "Configure Samba server"
    configure_samba

    echo_summary "Configuring IPv6"
    if [ $(trueorfalse False MANILA_SETUP_IPV6) == True ]; then
        setup_ipv6
    fi

    echo_summary "Starting Manila API"
    start_manila_api

    # Workaround for bug #1660304
    if [ "$SHARE_DRIVER" != "manila.share.drivers.generic.GenericShareDriver" ]; then
        echo_summary "Starting rest of Manila services - scheduler, share and data"
        start_rest_of_manila
    fi

    echo_summary "Creating Manila default share type"
    create_default_share_type

    echo_summary "Creating Manila default share group type"
    create_default_share_group_type

    echo_summary "Creating Manila custom share types"
    create_custom_share_types

    echo_summary "Manila UI is no longer enabled by default. \
        Add enable_plugin manila-ui https://opendev.org/openstack/manila-ui \
        to your local.conf file to enable Manila UI"

elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
    ###########################################################################
    # NOTE(vponomaryov): Workaround for bug #1660304
    # We are able to create Nova VMs now only when last Nova step is performed
    # which is registration of cell0. It is registered as last action in
    # "post-extra" section.
    if is_service_enabled nova; then
        echo_summary "Creating Manila service VMs for generic driver \
            backends for which handlng of share servers is disabled."
        create_service_share_servers
    fi

    if [ "$SHARE_DRIVER" == "manila.share.drivers.generic.GenericShareDriver" ]; then
        echo_summary "Starting rest of Manila services - scheduler, share and data"
        start_rest_of_manila
    fi
    ###########################################################################

    echo_summary "Update Tempest config"
    update_tempest


    if [[ "$(trueorfalse False MANILA_ALLOW_NAS_SERVER_PORTS_ON_HOST)" == "True" ]]; then
        echo_summary "Allowing IPv4 and IPv6 access to NAS ports on the host"
        allow_host_ports_for_share_mounting
    fi

    if [[ "$(trueorfalse False MANILA_SETUP_IPV6)" == "True" ]]; then
        # Now that all plugins are loaded, setup BGP
        echo_summary "Setting up BGP speaker to advertise routes to project networks"
        setup_bgp_for_ipv6
    fi

fi

if [[ "$1" == "unstack" ]]; then
    stop_manila
    cleanup_manila
fi

if [[ "$1" == "clean" ]]; then
    stop_manila
    cleanup_manila
    sudo rm -rf /etc/manila
fi

# Restore xtrace
$XTRACE
