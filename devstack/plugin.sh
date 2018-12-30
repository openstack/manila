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
        s|%PORT%|$MANILA_SERVICE_PORT|g;
        s|%APIWORKERS%|$API_WORKERS|g;
        s|%USER%|$STACK_USER|g;
    " -i $manila_api_apache_conf
}

# configure_default_backends - configures default Manila backends with generic driver.
function configure_default_backends {
    # Configure two default backends with generic drivers onboard
    for group_name in $MANILA_BACKEND1_CONFIG_GROUP_NAME $MANILA_BACKEND2_CONFIG_GROUP_NAME; do
        iniset $MANILA_CONF $group_name share_driver $SHARE_DRIVER
        if [ "$MANILA_BACKEND1_CONFIG_GROUP_NAME" == "$group_name" ]; then
            iniset $MANILA_CONF $group_name share_backend_name $MANILA_SHARE_BACKEND1_NAME
        else
            iniset $MANILA_CONF $group_name share_backend_name $MANILA_SHARE_BACKEND2_NAME
        fi
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

# configure_manila - Set config files, create data dirs, etc
function configure_manila {
    if [[ ! -d $MANILA_CONF_DIR ]]; then
        sudo mkdir -p $MANILA_CONF_DIR
    fi
    sudo chown $STACK_USER $MANILA_CONF_DIR

    if [[ -f $MANILA_DIR/etc/manila/policy.json ]]; then
        cp -p $MANILA_DIR/etc/manila/policy.json $MANILA_CONF_DIR
    fi

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

    configure_auth_token_middleware $MANILA_CONF manila  $MANILA_AUTH_CACHE_DIR

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

    if ! [[ -z $MANILA_DATA_COPY_CHECK_HASH ]]; then
        iniset $MANILA_CONF DEFAULT check_hash $MANILA_DATA_COPY_CHECK_HASH
    fi

    iniset $MANILA_CONF DEFAULT enabled_share_protocols $MANILA_ENABLED_SHARE_PROTOCOLS

    iniset $MANILA_CONF oslo_concurrency lock_path $MANILA_LOCK_PATH

    iniset $MANILA_CONF DEFAULT wsgi_keep_alive False

    iniset $MANILA_CONF DEFAULT lvm_share_volume_group $SHARE_GROUP

    # Set the replica_state_update_interval
    iniset $MANILA_CONF DEFAULT replica_state_update_interval $MANILA_REPLICA_STATE_UPDATE_INTERVAL

    if is_service_enabled neutron; then
        configure_auth_token_middleware $MANILA_CONF neutron $MANILA_AUTH_CACHE_DIR neutron
    fi
    if is_service_enabled nova; then
        configure_auth_token_middleware $MANILA_CONF nova $MANILA_AUTH_CACHE_DIR nova
    fi
    if is_service_enabled cinder; then
        configure_auth_token_middleware $MANILA_CONF cinder $MANILA_AUTH_CACHE_DIR cinder
    fi

    # Note: set up config group does not mean that this backend will be enabled.
    # To enable it, specify its name explicitly using "enabled_share_backends" opt.
    configure_default_backends
    default_backends=$MANILA_BACKEND1_CONFIG_GROUP_NAME
    if [ "$MANILA_MULTI_BACKEND" = "True" ]; then
        default_backends+=,$MANILA_BACKEND2_CONFIG_GROUP_NAME
    fi
    if [ ! $MANILA_ENABLED_BACKENDS ]; then
        # If $MANILA_ENABLED_BACKENDS is not set, use configured backends by default
        export MANILA_ENABLED_BACKENDS=$default_backends
    fi
    iniset $MANILA_CONF DEFAULT enabled_share_backends $MANILA_ENABLED_BACKENDS

    if [ ! -f $MANILA_PATH_TO_PRIVATE_KEY ]; then
        ssh-keygen -N "" -t rsa -f $MANILA_PATH_TO_PRIVATE_KEY;
    fi

    iniset $MANILA_CONF DEFAULT manila_service_keypair_name $MANILA_SERVICE_KEYPAIR_NAME

    if is_service_enabled tls-proxy; then
        # Set the service port for a proxy to take the original
        iniset $MANILA_CONF DEFAULT osapi_share_listen_port $MANILA_SERVICE_PORT_INT
    fi

    iniset_rpc_backend manila $MANILA_CONF DEFAULT

    setup_logging $MANILA_CONF

    MANILA_CONFIGURE_GROUPS=${MANILA_CONFIGURE_GROUPS:-"$MANILA_ENABLED_BACKENDS"}
    set_config_opts $MANILA_CONFIGURE_GROUPS
    set_config_opts DEFAULT

    if [ $(trueorfalse False MANILA_USE_MOD_WSGI) == True ]; then
        _config_manila_apache_wsgi
    fi
}


function create_manila_service_keypair {
    if is_service_enabled nova; then
        local keypair_exists=$( openstack keypair list | grep " $MANILA_SERVICE_KEYPAIR_NAME " )
        if [[ -z $keypair_exists ]]; then
            openstack keypair create $MANILA_SERVICE_KEYPAIR_NAME --public-key $MANILA_PATH_TO_PUBLIC_KEY
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
                local vm_exists=$( openstack server list --all-projects | grep " $vm_name " )
                if [[ -z $vm_exists ]]; then
                    private_net_id=$(openstack network show $PRIVATE_NETWORK_NAME -f value -c id)
                    vm_id=$(openstack server create $vm_name \
                        --flavor $MANILA_SERVICE_VM_FLAVOR_NAME \
                        --image $MANILA_SERVICE_IMAGE_NAME \
                        --nic net-id=$private_net_id \
                        --security-group $MANILA_SERVICE_SECGROUP \
                        --key-name $MANILA_SERVICE_KEYPAIR_NAME \
                        | grep ' id ' | get_field 2)
                else
                    vm_id=$(openstack server show $vm_name -f value -c id)
                fi

                floating_ip=$(openstack floating ip create $PUBLIC_NETWORK_NAME --subnet $PUBLIC_SUBNET_NAME | grep 'floating_ip_address' | get_field 2)
                openstack server add floating ip $vm_id $floating_ip

                iniset $MANILA_CONF $BE service_instance_name_or_id $vm_id
                iniset $MANILA_CONF $BE service_net_name_or_ip $floating_ip
                iniset $MANILA_CONF $BE tenant_net_name_or_ip $PRIVATE_NETWORK_NAME
            else
                if is_service_enabled neutron; then
                    if ! [[ -z $MANILA_ADMIN_NET_RANGE ]]; then
                        if [ $created_admin_network == false ]; then
                            project_id=$(openstack project show $SERVICE_PROJECT_NAME -c id -f value)
                            local admin_net_id=$( openstack network show admin_net -f value -c id )
                            if [[ -z $admin_net_id ]]; then
                                openstack network create admin_net --project $project_id
                                admin_net_id=$(openstack network show admin_net -f value -c id)
                            fi

                            local admin_subnet_id=$( openstack subnet show admin_subnet -f value -c id )
                            if [[ -z $admin_subnet_id ]]; then
                                openstack subnet create admin_subnet --project $project_id --ip-version 4 --network $admin_net_id --gateway None --subnet-range $MANILA_ADMIN_NET_RANGE
                                admin_subnet_id=$(openstack subnet show admin_subnet -f value -c id)
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
            iniset $MANILA_CONF DEFAULT data_node_access_ip $PUBLIC_NETWORK_GATEWAY
        else
            if ! [[ -z $MANILA_DATA_NODE_IP ]]; then
                iniset $MANILA_CONF DEFAULT data_node_access_ip $MANILA_DATA_NODE_IP
            fi
        fi
    fi
}
# create_manila_service_flavor - creates flavor, that will be used by backends
# with configured generic driver to boot Nova VMs with.
function create_manila_service_flavor {
    if is_service_enabled nova; then
        local flavor_exists=$( openstack flavor list | grep " $MANILA_SERVICE_VM_FLAVOR_NAME " )
        if [[ -z $flavor_exists ]]; then
            # Create flavor for Manila's service VM
            openstack flavor create \
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
    if is_service_enabled nova; then
        TOKEN=$(openstack token issue -c id -f value)
        local image_exists=$( openstack image list | grep " $MANILA_SERVICE_IMAGE_NAME " )
        if [[ -z $image_exists ]]; then
            # Download Manila's image
            if is_service_enabled g-reg; then
                upload_image $MANILA_SERVICE_IMAGE_URL $TOKEN
            fi
        fi
    fi
}

# create_manila_service_secgroup - creates security group that is used by
# Nova VMs when generic driver is configured.
function create_manila_service_secgroup {
    # Create a secgroup
    if ! openstack security group list | grep -q $MANILA_SERVICE_SECGROUP; then
        openstack security group create $MANILA_SERVICE_SECGROUP --description "$MANILA_SERVICE_SECGROUP description"
        if ! timeout 30 sh -c "while ! openstack security group list | grep -q $MANILA_SERVICE_SECGROUP; do sleep 1; done"; then
            echo "Security group not created"
            exit 1
        fi
    fi

    # Configure Security Group Rules
    if ! openstack security group rule list $MANILA_SERVICE_SECGROUP | grep -q icmp; then
        openstack security group rule create $MANILA_SERVICE_SECGROUP --protocol icmp
    fi
    if ! openstack security group rule list $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 22 "; then
        openstack security group rule create $MANILA_SERVICE_SECGROUP --protocol tcp --dst-port 22
    fi
    if ! openstack security group rule list $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 2049 "; then
        openstack security group rule create $MANILA_SERVICE_SECGROUP --protocol tcp --dst-port 2049
    fi
    if ! openstack security group rule list $MANILA_SERVICE_SECGROUP | grep -q " udp .* 2049 "; then
        openstack security group rule create $MANILA_SERVICE_SECGROUP --protocol udp --dst-port 2049
    fi
    if ! openstack security group rule list $MANILA_SERVICE_SECGROUP | grep -q " udp .* 445 "; then
        openstack security group rule create $MANILA_SERVICE_SECGROUP --protocol udp --dst-port 445
    fi
    if ! openstack security group rule list $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 445 "; then
        openstack security group rule create $MANILA_SERVICE_SECGROUP --protocol tcp --dst-port 445
    fi
    if ! openstack security group rule list $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 139 "; then
        openstack security group rule create $MANILA_SERVICE_SECGROUP --protocol tcp --dst-port 137:139
    fi
    if ! openstack security group rule list $MANILA_SERVICE_SECGROUP | grep -q " udp .* 139 "; then
        openstack security group rule create $MANILA_SERVICE_SECGROUP --protocol udp --dst-port 137:139
    fi

    # List secgroup rules
    openstack security group rule list $MANILA_SERVICE_SECGROUP
}

# create_manila_accounts - Set up common required manila accounts
function create_manila_accounts {

    create_service_user "manila"

    # Set up Manila v1 service and endpoint
    get_or_create_service "manila" "share" "Manila Shared Filesystem Service"
    get_or_create_endpoint "share" "$REGION_NAME" \
        "$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT/v1/\$(tenant_id)s" \
        "$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT/v1/\$(tenant_id)s" \
        "$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT/v1/\$(tenant_id)s"

    # Set up Manila v2 service and endpoint
    get_or_create_service "manilav2" "sharev2" "Manila Shared Filesystem Service V2"
    get_or_create_endpoint "sharev2" "$REGION_NAME" \
        "$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT/v2/\$(tenant_id)s" \
        "$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT/v2/\$(tenant_id)s" \
        "$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT/v2/\$(tenant_id)s"
}

# create_default_share_group_type - create share group type that will be set as default.
function create_default_share_group_type {
    local type_exists=$( manila share-group-type-list | grep " $MANILA_DEFAULT_SHARE_GROUP_TYPE " )
    if [[ -z $type_exists ]]; then
        manila share-group-type-create $MANILA_DEFAULT_SHARE_GROUP_TYPE $MANILA_DEFAULT_SHARE_TYPE
    fi
    if [[ $MANILA_DEFAULT_SHARE_GROUP_TYPE_SPECS ]]; then
        manila share-group-type-key $MANILA_DEFAULT_SHARE_GROUP_TYPE set $MANILA_DEFAULT_SHARE_GROUP_TYPE_SPECS
    fi
}

# create_default_share_type - create share type that will be set as default
# if $MANILA_CONFIGURE_DEFAULT_TYPES is set to True, if set to False, the share
# type identified by $MANILA_DEFAULT_SHARE_TYPE is still created, but not
# configured as default.
function create_default_share_type {
    echo "Waiting for Manila API to start..."
    if ! wait_for_service 60 $MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT; then
        die $LINENO "Manila did not start"
    fi

    enabled_backends=(${MANILA_ENABLED_BACKENDS//,/ })
    driver_handles_share_servers=$(iniget $MANILA_CONF ${enabled_backends[0]} driver_handles_share_servers)

    local type_exists=$( manila type-list | grep " $MANILA_DEFAULT_SHARE_TYPE " )
    if [[ -z $type_exists ]]; then
        local command_args="$MANILA_DEFAULT_SHARE_TYPE $driver_handles_share_servers"
        #if is_driver_enabled $MANILA_CONTAINER_DRIVER; then
        #    # TODO(aovchinnikov): Remove this condition when Container driver supports
        #    # snapshots
        #    command_args="$command_args --snapshot_support false"
        #fi
        manila type-create $command_args
    fi
    if [[ $MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS ]]; then
        manila type-key $MANILA_DEFAULT_SHARE_TYPE set $MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS
    fi
}

# create_custom_share_types - create share types suitable for both possible
# driver modes with names "dhss_true" and "dhss_false".
function create_custom_share_types {
    manila type-create dhss_true True
    if [[ $MANILA_DHSS_TRUE_SHARE_TYPE_EXTRA_SPECS ]]; then
        manila type-key dhss_true set $MANILA_DHSS_TRUE_SHARE_TYPE_EXTRA_SPECS
    fi

    manila type-create dhss_false False
    if [[ $MANILA_DHSS_FALSE_SHARE_TYPE_EXTRA_SPECS ]]; then
        manila type-key dhss_false set $MANILA_DHSS_FALSE_SHARE_TYPE_EXTRA_SPECS
    fi
}

# configure_backing_file - Set up backing file for LVM
function configure_backing_file {
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
                iniset $MANILA_CONF DEFAULT data_node_access_ip $MANILA_ZFSONLINUX_SERVICE_IP
            fi
        fi
    fi

    # Create cache dir
    sudo mkdir -p $MANILA_AUTH_CACHE_DIR
    sudo chown $STACK_USER $MANILA_AUTH_CACHE_DIR
    rm -f $MANILA_AUTH_CACHE_DIR/*
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

        if [[ ! $(systemctl is-active nfs-ganesha.service) == 'active' ]]; then
            _install_nfs_and_samba
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
                    elif [[ $(lsb_release -s -d) == *"16.04"* ]]; then
                        # Xenial
                        sudo apt-get install -y zfsutils-linux
                    else
                        echo "Only 'Trusty' and 'Xenial' releases of Ubuntu are supported."
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
        iniset $MANILA_CONF DEFAULT data_node_access_ip $HOST_IP
    fi
}

# start_manila_api - starts manila API services and checks its availability
function start_manila_api {
    if [ $(trueorfalse False MANILA_USE_MOD_WSGI) == True ]; then
        install_apache_wsgi
        enable_apache_site manila-api
        restart_apache_server
        tail_log m-api /var/log/$APACHE_NAME/manila_api.log
    else
        run_process m-api "$MANILA_BIN_DIR/manila-api --config-file $MANILA_CONF"
    fi

    echo "Waiting for Manila API to start..."
    if ! wait_for_service $SERVICE_TIMEOUT $MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT; then
        die $LINENO "Manila API did not start"
    fi

    # Start proxies if enabled
    if is_service_enabled tls-proxy; then
        start_tls_proxy '*' $MANILA_SERVICE_PORT $MANILA_SERVICE_HOST $MANILA_SERVICE_PORT_INT &
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

function install_manila_tempest_plugin {
    MANILA_TEMPEST_PLUGIN_REPO=${MANILA_TEMPEST_PLUGIN_REPO:-${GIT_BASE}/openstack/manila-tempest-plugin.git}
    MANILA_TEMPEST_PLUGIN_BRANCH=${MANILA_TEMPEST_PLUGIN_BRANCH:-master}
    MANILA_TEMPEST_PLUGIN_DIR=$DEST/manila-tempest-plugin

    git_clone $MANILA_TEMPEST_PLUGIN_REPO $MANILA_TEMPEST_PLUGIN_DIR $MANILA_TEMPEST_PLUGIN_BRANCH
    setup_develop $MANILA_TEMPEST_PLUGIN_DIR
}

# update_tempest - Function used for updating Tempest config if Tempest service enabled
function update_tempest {
    if is_service_enabled tempest; then
        TEMPEST_CONFIG=${TEMPEST_CONFIG:-$TEMPEST_DIR/etc/tempest.conf}
        ADMIN_TENANT_NAME=${ADMIN_TENANT_NAME:-"admin"}
        ADMIN_DOMAIN_NAME=${ADMIN_DOMAIN_NAME:-"Default"}
        ADMIN_PASSWORD=${ADMIN_PASSWORD:-"secretadmin"}

        if [ $(trueorfalse False MANILA_USE_SERVICE_INSTANCE_PASSWORD) == True ]; then
            iniset $TEMPEST_CONFIG share image_password $MANILA_SERVICE_INSTANCE_PASSWORD
        fi
        iniset $TEMPEST_CONFIG share image_with_share_tools $MANILA_SERVICE_IMAGE_NAME
        iniset $TEMPEST_CONFIG auth admin_username ${ADMIN_USERNAME:-"admin"}
        iniset $TEMPEST_CONFIG auth admin_password ${ADMIN_PASSWORD:-"secretadmin"}
        iniset $TEMPEST_CONFIG auth admin_tenant_name $ADMIN_TENANT_NAME
        iniset $TEMPEST_CONFIG auth admin_domain_name $ADMIN_DOMAIN_NAME
        iniset $TEMPEST_CONFIG identity username ${TEMPEST_USERNAME:-"demo"}
        iniset $TEMPEST_CONFIG identity password $ADMIN_PASSWORD
        iniset $TEMPEST_CONFIG identity tenant_name ${TEMPEST_TENANT_NAME:-"demo"}
        iniset $TEMPEST_CONFIG identity domain_name $ADMIN_DOMAIN_NAME
        iniset $TEMPEST_CONFIG identity alt_username ${ALT_USERNAME:-"alt_demo"}
        iniset $TEMPEST_CONFIG identity alt_password $ADMIN_PASSWORD
        iniset $TEMPEST_CONFIG identity alt_tenant_name ${ALT_TENANT_NAME:-"alt_demo"}
        iniset $TEMPEST_CONFIG identity alt_domain_name $ADMIN_DOMAIN_NAME
    fi
}

function install_docker_ubuntu {
    sudo apt-get update
    install_package apparmor
    install_package docker.io
}

function install_docker_fedora {
    sudo yum install -y docker
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
    if [ $(trueorfalse False MANILA_MULTI_BACKEND) == True ]; then
        if [ $(trueorfalse True RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS) == True ]; then
            if is_ubuntu; then
                install_package nfs-common
            else
                install_package nfs-utils
            fi
        fi
    fi
}

function setup_ipv6 {

    # save IPv6 default route to add back later after enabling forwarding
    local default_route=$(ip -6 route | grep default | cut -d ' ' -f1,2,3,4,5)

    # make sure those system values are set
    sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0
    sudo sysctl -w net.ipv6.conf.all.accept_ra=2
    sudo sysctl -w net.ipv6.conf.all.forwarding=1

    # Disable in-band as our communication is only internal
    sudo ovs-vsctl set Bridge $PUBLIC_BRIDGE other_config:disable-in-band=true

    # Create address scopes and subnet pools
    neutron address-scope-create --shared scope-v4 4
    neutron address-scope-create --shared scope-v6 6
    openstack subnet pool create $SUBNETPOOL_NAME_V4 --default-prefix-length $SUBNETPOOL_SIZE_V4 --pool-prefix $SUBNETPOOL_PREFIX_V4 --address-scope scope-v4 --default --share
    openstack subnet pool create $SUBNETPOOL_NAME_V6 --default-prefix-length $SUBNETPOOL_SIZE_V6 --pool-prefix $SUBNETPOOL_PREFIX_V6 --address-scope scope-v6 --default --share

    # Create example private network and router
    openstack router create $Q_ROUTER_NAME
    openstack network create $PRIVATE_NETWORK_NAME
    openstack subnet create --ip-version 6 --use-default-subnet-pool --ipv6-address-mode $IPV6_ADDRESS_MODE --ipv6-ra-mode $IPV6_RA_MODE --network $PRIVATE_NETWORK_NAME $IPV6_PRIVATE_SUBNET_NAME
    openstack subnet create --ip-version 4 --use-default-subnet-pool --network $PRIVATE_NETWORK_NAME $PRIVATE_SUBNET_NAME
    openstack router add subnet $Q_ROUTER_NAME $IPV6_PRIVATE_SUBNET_NAME
    openstack router add subnet $Q_ROUTER_NAME $PRIVATE_SUBNET_NAME

    # Create public network
    openstack network create $PUBLIC_NETWORK_NAME --external --default --provider-network-type flat --provider-physical-network $PUBLIC_PHYSICAL_NETWORK
    local public_gateway_ipv6=$(openstack subnet create $IPV6_PUBLIC_SUBNET_NAME --ip-version 6 --network $PUBLIC_NETWORK_NAME --subnet-pool $SUBNETPOOL_NAME_V6 --no-dhcp -c gateway_ip -f value)
    local public_gateway_ipv4=$(openstack subnet create $PUBLIC_SUBNET_NAME --ip-version 4 --network $PUBLIC_NETWORK_NAME --subnet-range $FLOATING_RANGE --no-dhcp -c gateway_ip -f value)

    # Set router to use public network
    openstack router set --external-gateway $PUBLIC_NETWORK_NAME $Q_ROUTER_NAME

    # Configure interfaces due to NEUTRON_CREATE_INITIAL_NETWORKS=False
    local ipv4_cidr_len=${FLOATING_RANGE#*/}
    sudo ip -6 addr add "$public_gateway_ipv6"/$SUBNETPOOL_SIZE_V6 dev $PUBLIC_BRIDGE
    sudo ip addr add $PUBLIC_NETWORK_GATEWAY/"$ipv4_cidr_len" dev $PUBLIC_BRIDGE

    # Enabling interface is needed due to NEUTRON_CREATE_INITIAL_NETWORKS=False
    sudo ip link set $PUBLIC_BRIDGE up

    if [ "$SHARE_DRIVER" == "manila.share.drivers.lvm.LVMShareDriver" ]; then
        for backend_name in ${MANILA_ENABLED_BACKENDS//,/ }; do
            iniset $MANILA_CONF $backend_name lvm_share_export_ips $public_gateway_ipv4,$public_gateway_ipv6
        done
        iniset $MANILA_CONF DEFAULT data_node_access_ip $public_gateway_ipv4
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

    # set Quagga bgpd.conf
    (
    echo "log file /var/log/quagga/bgpd.log"
    echo "bgp multiple-instance"
    echo "router bgp 200"
    echo " bgp router-id 1.2.3.4"
    echo " neighbor ::1 remote-as 100"
    echo " neighbor ::1 passive"
    echo " address-family ipv6"
    echo "  neighbor ::1 activate"
    echo "line vty"
    echo "debug bgp events"
    echo "debug bgp filters"
    echo "debug bgp fsm"
    echo "debug bgp keepalives"
    echo "debug bgp updates"
    ) | sudo tee /etc/quagga/bgpd.conf > /dev/null

    if is_ubuntu; then
        sudo systemctl enable quagga
        sudo systemctl restart quagga
    else
        # Disable SELinux rule that conflicts with Zebra
        sudo setsebool -P zebra_write_config 1
        sudo systemctl enable zebra
        sudo systemctl enable bgpd
        sudo systemctl restart zebra
        sudo systemctl restart bgpd
    fi

    # add default IPv6 route back
    if ! [[ -z $default_route ]]; then
        sudo ip -6 route add $default_route
    fi

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
        Add enable_plugin manila-ui github.com/openstack/manila-ui \
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

    echo_summary "Fetching and installing manila-tempest-plugin system-wide"
    install_manila_tempest_plugin
    echo_summary "Update Tempest config"
    update_tempest
fi

if [[ "$1" == "unstack" ]]; then
    cleanup_manila
fi

if [[ "$1" == "clean" ]]; then
    cleanup_manila
    sudo rm -rf /etc/manila
fi

# Restore xtrace
$XTRACE
