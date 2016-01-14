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

# cleanup_manila - Remove residual data files, anything left over from previous
# runs that a clean run would need to clean up
function cleanup_manila {
    # All stuff, that are created by share drivers will be cleaned up by other services.
    _clean_share_group $SHARE_GROUP $SHARE_NAME_PREFIX
    _clean_manila_lvm_backing_file $SHARE_GROUP
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

        if [ $(trueorfalse False MANILA_USE_SERVICE_INSTANCE_PASSWORD) == True ]; then
            iniset $MANILA_CONF $group_name service_instance_password $MANILA_SERVICE_INSTANCE_PASSWORD
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
    setup_develop $MANILA_DIR
    setup_develop $MANILACLIENT_DIR

    if [[ ! -d $MANILA_CONF_DIR ]]; then
        sudo mkdir -p $MANILA_CONF_DIR
    fi
    sudo chown $STACK_USER $MANILA_CONF_DIR

    cp -p $MANILA_DIR/etc/manila/policy.json $MANILA_CONF_DIR

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

    iniset $MANILA_CONF keystone_authtoken identity_uri $KEYSTONE_AUTH_URI
    iniset $MANILA_CONF keystone_authtoken admin_tenant_name $SERVICE_TENANT_NAME
    iniset $MANILA_CONF keystone_authtoken admin_user manila
    iniset $MANILA_CONF keystone_authtoken admin_password $SERVICE_PASSWORD
    iniset $MANILA_CONF keystone_authtoken signing_dir $MANILA_AUTH_CACHE_DIR

    iniset $MANILA_CONF DEFAULT auth_strategy keystone
    iniset $MANILA_CONF DEFAULT debug True
    iniset $MANILA_CONF DEFAULT verbose True
    iniset $MANILA_CONF DEFAULT scheduler_driver $MANILA_SCHEDULER_DRIVER
    iniset $MANILA_CONF DEFAULT share_name_template ${SHARE_NAME_PREFIX}%s
    iniset $MANILA_CONF DATABASE connection `database_connection_url manila`
    iniset $MANILA_CONF DATABASE max_pool_size 40
    iniset $MANILA_CONF DEFAULT api_paste_config $MANILA_API_PASTE_INI
    iniset $MANILA_CONF DEFAULT rootwrap_config $MANILA_CONF_DIR/rootwrap.conf
    iniset $MANILA_CONF DEFAULT osapi_share_extension manila.api.contrib.standard_extensions
    iniset $MANILA_CONF DEFAULT state_path $MANILA_STATE_PATH
    iniset $MANILA_CONF DEFAULT default_share_type $MANILA_DEFAULT_SHARE_TYPE

    iniset $MANILA_CONF DEFAULT nova_admin_password $SERVICE_PASSWORD
    iniset $MANILA_CONF DEFAULT cinder_admin_password $SERVICE_PASSWORD
    iniset $MANILA_CONF DEFAULT neutron_admin_password $SERVICE_PASSWORD

    iniset $MANILA_CONF DEFAULT enabled_share_protocols $MANILA_ENABLED_SHARE_PROTOCOLS

    iniset $MANILA_CONF oslo_concurrency lock_path $MANILA_LOCK_PATH

    iniset $MANILA_CONF DEFAULT wsgi_keep_alive False

    iniset $MANILA_CONF DEFAULT lvm_share_volume_group $SHARE_GROUP

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

    if [ "$SYSLOG" != "False" ]; then
        iniset $MANILA_CONF DEFAULT use_syslog True
    fi

    iniset_rpc_backend manila $MANILA_CONF DEFAULT

    if [ "$LOG_COLOR" == "True" ] && [ "$SYSLOG" == "False" ]; then
        # Add color to logging output
        iniset $MANILA_CONF DEFAULT logging_context_format_string \
            "%(asctime)s.%(msecs)d %(color)s%(levelname)s %(name)s [[01;36m%(request_id)s [00;36m%(user_id)s %(project_id)s%(color)s] [01;35m%(instance)s%(color)s%(message)s[00m"
        iniset $MANILA_CONF DEFAULT logging_default_format_string \
            "%(asctime)s.%(msecs)d %(color)s%(levelname)s %(name)s [[00;36m-%(color)s] [01;35m%(instance)s%(color)s%(message)s[00m"
        iniset $MANILA_CONF DEFAULT logging_debug_format_suffix \
            "[00;33mfrom (pid=%(process)d) %(funcName)s %(pathname)s:%(lineno)d[00m"
        iniset $MANILA_CONF DEFAULT logging_exception_prefix \
            "%(color)s%(asctime)s.%(msecs)d TRACE %(name)s [01;35m%(instance)s[00m"
    fi

    MANILA_CONFIGURE_GROUPS=${MANILA_CONFIGURE_GROUPS:-"$MANILA_ENABLED_BACKENDS"}
    set_config_opts $MANILA_CONFIGURE_GROUPS
    set_config_opts DEFAULT
}


function configure_manila_ui {
    if is_service_enabled horizon && [ "$MANILA_UI_ENABLED" = "True" ]; then
        setup_develop $MANILA_UI_DIR
        cp $MANILA_UI_DIR/manila_ui/enabled/_90_manila_*.py $HORIZON_DIR/openstack_dashboard/local/enabled
    fi
}


function create_manila_service_keypair {
    nova keypair-add $MANILA_SERVICE_KEYPAIR_NAME --pub-key $MANILA_PATH_TO_PUBLIC_KEY
}


# create_service_share_servers - creates service Nova VMs, one per generic
# driver, and only if it is configured to mode without handling of share servers.
function create_service_share_servers {
    private_net_id=$(nova net-list | grep ' private ' | get_field 1)
    for BE in ${MANILA_ENABLED_BACKENDS//,/ }; do
        driver_handles_share_servers=$(iniget $MANILA_CONF $BE driver_handles_share_servers)
        share_driver=$(iniget $MANILA_CONF $BE share_driver)
        generic_driver='manila.share.drivers.generic.GenericShareDriver'
        if [[ $(trueorfalse False driver_handles_share_servers) == False && $share_driver == $generic_driver ]]; then
            vm_name='manila_service_share_server_'$BE
            nova boot $vm_name \
                --flavor $MANILA_SERVICE_VM_FLAVOR_NAME \
                --image $MANILA_SERVICE_IMAGE_NAME \
                --nic net-id=$private_net_id \
                --security-groups $MANILA_SERVICE_SECGROUP \
                --key-name $MANILA_SERVICE_KEYPAIR_NAME

            vm_id=$(nova show $vm_name | grep ' id ' | get_field 2)

            iniset $MANILA_CONF $BE service_instance_name_or_id $vm_id
            iniset $MANILA_CONF $BE service_net_name_or_ip private
            iniset $MANILA_CONF $BE tenant_net_name_or_ip private
            iniset $MANILA_CONF $BE migration_data_copy_node_ip $PUBLIC_NETWORK_GATEWAY
        fi
    done
}

# create_manila_service_flavor - creates flavor, that will be used by backends
# with configured generic driver to boot Nova VMs with.
function create_manila_service_flavor {
    # Create flavor for Manila's service VM
    nova flavor-create \
        $MANILA_SERVICE_VM_FLAVOR_NAME \
        $MANILA_SERVICE_VM_FLAVOR_REF \
        $MANILA_SERVICE_VM_FLAVOR_RAM \
        $MANILA_SERVICE_VM_FLAVOR_DISK \
        $MANILA_SERVICE_VM_FLAVOR_VCPUS
}

# create_manila_service_image - creates image, that will be used by backends
# with configured generic driver to boot Nova VMs from.
function create_manila_service_image {
    TOKEN=$(openstack token issue -c id -f value)

    # Download Manila's image
    if is_service_enabled g-reg; then
        upload_image $MANILA_SERVICE_IMAGE_URL $TOKEN
    fi
}

# create_manila_service_secgroup - creates security group that is used by
# Nova VMs when generic driver is configured.
function create_manila_service_secgroup {
    # Create a secgroup
    if ! nova secgroup-list | grep -q $MANILA_SERVICE_SECGROUP; then
        nova secgroup-create $MANILA_SERVICE_SECGROUP "$MANILA_SERVICE_SECGROUP description"
        if ! timeout 30 sh -c "while ! nova secgroup-list | grep -q $MANILA_SERVICE_SECGROUP; do sleep 1; done"; then
            echo "Security group not created"
            exit 1
        fi
    fi

    # Configure Security Group Rules
    if ! nova secgroup-list-rules $MANILA_SERVICE_SECGROUP | grep -q icmp; then
        nova secgroup-add-rule $MANILA_SERVICE_SECGROUP icmp -1 -1 0.0.0.0/0
    fi
    if ! nova secgroup-list-rules $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 22 "; then
        nova secgroup-add-rule $MANILA_SERVICE_SECGROUP tcp 22 22 0.0.0.0/0
    fi
    if ! nova secgroup-list-rules $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 2049 "; then
        nova secgroup-add-rule $MANILA_SERVICE_SECGROUP tcp 2049 2049 0.0.0.0/0
    fi
    if ! nova secgroup-list-rules $MANILA_SERVICE_SECGROUP | grep -q " udp .* 2049 "; then
        nova secgroup-add-rule $MANILA_SERVICE_SECGROUP udp 2049 2049 0.0.0.0/0
    fi
    if ! nova secgroup-list-rules $MANILA_SERVICE_SECGROUP | grep -q " udp .* 445 "; then
        nova secgroup-add-rule $MANILA_SERVICE_SECGROUP udp 445 445 0.0.0.0/0
    fi
    if ! nova secgroup-list-rules $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 445 "; then
        nova secgroup-add-rule $MANILA_SERVICE_SECGROUP tcp 445 445 0.0.0.0/0
    fi
    if ! nova secgroup-list-rules $MANILA_SERVICE_SECGROUP | grep -q " tcp .* 139 "; then
        nova secgroup-add-rule $MANILA_SERVICE_SECGROUP tcp 137 139 0.0.0.0/0
    fi
    if ! nova secgroup-list-rules $MANILA_SERVICE_SECGROUP | grep -q " udp .* 139 "; then
        nova secgroup-add-rule $MANILA_SERVICE_SECGROUP udp 137 139 0.0.0.0/0
    fi

    # List secgroup rules
    nova secgroup-list-rules $MANILA_SERVICE_SECGROUP
}

# create_manila_accounts - Set up common required manila accounts
function create_manila_accounts {

    create_service_user "manila"

    if [[ "$KEYSTONE_CATALOG_BACKEND" = 'sql' ]]; then
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
    fi
}

# create_default_share_type - create share type that will be set as default.
function create_default_share_type {
    echo "Waiting for Manila API to start..."
    if ! wait_for_service 60 $MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT; then
        die $LINENO "Manila did not start"
    fi

    enabled_backends=(${MANILA_ENABLED_BACKENDS//,/ })
    driver_handles_share_servers=$(iniget $MANILA_CONF ${enabled_backends[0]} driver_handles_share_servers)

    manila type-create $MANILA_DEFAULT_SHARE_TYPE $driver_handles_share_servers
    if [[ $MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS ]]; then
        manila type-key $MANILA_DEFAULT_SHARE_TYPE set $MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS
    fi
}


# init_manila - Initializes database and creates manila dir if absent
function init_manila {

    if is_service_enabled $DATABASE_BACKENDS; then
        # (re)create manila database
        recreate_database manila utf8

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
        fi
    fi

    # Create cache dir
    sudo mkdir -p $MANILA_AUTH_CACHE_DIR
    sudo chown $STACK_USER $MANILA_AUTH_CACHE_DIR
    rm -f $MANILA_AUTH_CACHE_DIR/*
}

# install_manila - Collect source and prepare
function install_manila {
    git_clone $MANILACLIENT_REPO $MANILACLIENT_DIR $MANILACLIENT_BRANCH

    if [ "$SHARE_DRIVER" == "manila.share.drivers.lvm.LVMShareDriver" ]; then
        if is_service_enabled m-shr; then
            if is_ubuntu; then
                sudo apt-get install -y nfs-kernel-server nfs-common samba
            elif is_fedora; then
                sudo yum install -y nfs-utils nfs-utils-lib samba
            fi
        fi
    fi

    # install manila-ui if horizon is enabled
    if is_service_enabled horizon && [ "$MANILA_UI_ENABLED" = "True" ]; then
        git_clone $MANILA_UI_REPO $MANILA_UI_DIR $MANILA_UI_BRANCH
    fi
}

#configure_samba - Configure node as Samba server
function configure_samba {
    if [ "$SHARE_DRIVER" == "manila.share.drivers.lvm.LVMShareDriver" ]; then
        samba_daemon_name=smbd
        if is_service_enabled m-shr; then
            if is_fedora; then
                samba_daemon_name=smb
            fi
            sudo service $samba_daemon_name restart || echo "Couldn't restart '$samba_daemon_name' service"
        fi

        sudo cp /usr/share/samba/smb.conf $SMB_CONF
        sudo chown stack -R /etc/samba
        iniset $SMB_CONF global include registry
        iniset $SMB_CONF global security user
        if [ ! -d "$SMB_PRIVATE_DIR" ]; then
            sudo mkdir $SMB_PRIVATE_DIR
            sudo touch $SMB_PRIVATE_DIR/secrets.tdb
        fi

        for backend_name in ${MANILA_ENABLED_BACKENDS//,/ }; do
            iniset $MANILA_CONF $backend_name driver_handles_share_servers False
            iniset $MANILA_CONF $backend_name lvm_share_export_ip $MANILA_SERVICE_HOST
        done
    fi
}

# start_manila - Start running processes, including screen
function start_manila {
    # restart apache to reload running horizon if manila-ui is enabled
    if is_service_enabled horizon && [ "$MANILA_UI_ENABLED" = "True" ]; then
        restart_apache_server
        sleep 3 # Wait for 3 sec to ensure that apache is running
    fi

    screen_it m-api "cd $MANILA_DIR && $MANILA_BIN_DIR/manila-api --config-file $MANILA_CONF"
    screen_it m-shr "cd $MANILA_DIR && $MANILA_BIN_DIR/manila-share --config-file $MANILA_CONF"
    screen_it m-sch "cd $MANILA_DIR && $MANILA_BIN_DIR/manila-scheduler --config-file $MANILA_CONF"

    # Start proxies if enabled
    if is_service_enabled tls-proxy; then
        start_tls_proxy '*' $MANILA_SERVICE_PORT $MANILA_SERVICE_HOST $MANILA_SERVICE_PORT_INT &
    fi
}

# stop_manila - Stop running processes
function stop_manila {
    # Kill the manila screen windows
    for serv in m-api m-sch m-shr; do
        screen -S $SCREEN_NAME -p $serv -X kill
    done
}

# update_tempest - Function used for updating Tempest config if Tempest service enabled
function update_tempest {
    if is_service_enabled tempest; then
        if [ $(trueorfalse False MANILA_USE_SERVICE_INSTANCE_PASSWORD) == True ]; then
            iniset $TEMPEST_DIR/etc/tempest.conf share image_password $MANILA_SERVICE_INSTANCE_PASSWORD
        fi
    fi
}

function install_libraries {
    if [ $(trueorfalse False MANILA_MULTI_BACKEND) == True ]; then
        if [ $(trueorfalse True RUN_MANILA_MIGRATION_TESTS) == True ]; then
            if is_ubuntu; then
                install_package nfs-common
            else
                install_package nfs-utils
            fi
        fi
    fi
}

# Main dispatcher
if [[ "$1" == "stack" && "$2" == "install" ]]; then
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
    if is_service_enabled neutron; then
        iniset $Q_DHCP_CONF_FILE DEFAULT dnsmasq_local_resolv False
    fi
elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    echo_summary "Creating Manila entities for auth service"
    create_manila_accounts

    echo_summary "Creating Manila service flavor"
    create_manila_service_flavor

    echo_summary "Creating Manila service security group"
    create_manila_service_secgroup

    # Skip image downloads when disabled.
    # This way vendor Manila driver CI tests can skip
    # this potentially long and unnecessary download.
    if [ "$MANILA_SERVICE_IMAGE_ENABLED" = "True" ]; then
        echo_summary "Creating Manila service image"
        create_manila_service_image
    else
        echo_summary "Skipping download of Manila service image"
    fi

    echo_summary "Creating Manila service keypair"
    create_manila_service_keypair

    echo_summary "Creating Manila service VMs for generic driver \
        backends for which handlng of share servers is disabled."
    create_service_share_servers

    echo_summary "Configure Samba server"
    configure_samba

    echo_summary "Starting Manila"
    start_manila

    echo_summary "Creating Manila default share type"
    create_default_share_type

    echo_summary "Update Tempest config"
    update_tempest

    echo_summary "Configuring Manila UI"
    configure_manila_ui
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
