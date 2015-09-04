# Setting configuration file for Manila services
# ----------------------------------------------
# 1) It is possible to set any custom opt to any config group using following:
# $ export MANILA_OPTGROUP_foo_bar=value
# where 'foo' is name of config group and 'bar' is name of option.
#
# 2) 'MANILA_CONFIGURE_GROUPS' contains list of config group names used to create
# config groups, but 'MANILA_ENABLED_BACKENDS' is used to set config groups as
# Manila share back ends. Both can be set like following:
# $ export MANILA_ENABLED_BACKENDS=foo,bar
# where 'foo' and 'bar' are names of config groups with opts for some share
# drivers. By default they are equal. Also be attentive, if you modify both,
# make sure 'MANILA_CONFIGURE_GROUPS' contains all values from
# 'MANILA_ENABLED_BACKENDS'.
# DEFAULT group is always defined, no need to specify it within 'MANILA_CONFIGURE_GROUPS'.
#
# 3) Two default backends are used for compatibility with previous approach.
# They have same configuration except name of backend. Both use generic driver.
# They can be enabled by adding values of following env vars:
# 'MANILA_BACKEND1_CONFIG_GROUP_NAME' and 'MANILA_BACKEND2_CONFIG_GROUP_NAME'
# to the env var 'MANILA_ENABLED_BACKENDS' or will be enabled
# if 'MANILA_ENABLED_BACKENDS' is empty.

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set -o xtrace

# Defaults
# --------

MANILA_GIT_BASE=${MANILA_GIT_BASE:-https://github.com}
MANILA_REPO_ROOT=${MANILA_REPO_ROOT:-openstack}

MANILACLIENT_REPO=${MANILA_GIT_BASE}/${MANILA_REPO_ROOT}/python-manilaclient.git
MANILACLIENT_BRANCH=${MANILACLIENT_BRANCH:-master}

MANILA_UI_REPO=${MANILA_GIT_BASE}/${MANILA_REPO_ROOT}/manila-ui.git
MANILA_UI_BRANCH=${MANILA_UI_BRANCH:-$MANILACLIENT_BRANCH}
MANILA_UI_ENABLED=$(trueorfalse True MANILA_UI_ENABLED)

# set up default directories
MANILA_DIR=${MANILA_DIR:=$DEST/manila}
MANILA_LOCK_PATH=${MANILA_LOCK_PATH:=$OSLO_LOCK_PATH}
MANILA_LOCK_PATH=${MANILA_LOCK_PATH:=$MANILA_DIR/manila_locks}
MANILACLIENT_DIR=${MANILACLIENT_DIR:=$DEST/python-manilaclient}
MANILA_UI_DIR=${MANILA_UI_DIR:=$DEST/manila-ui}
MANILA_STATE_PATH=${MANILA_STATE_PATH:=$DATA_DIR/manila}
MANILA_AUTH_CACHE_DIR=${MANILA_AUTH_CACHE_DIR:-/var/cache/manila}

MANILA_CONF_DIR=${MANILA_CONF_DIR:-/etc/manila}
MANILA_CONF=$MANILA_CONF_DIR/manila.conf
MANILA_API_PASTE_INI=$MANILA_CONF_DIR/api-paste.ini

MANILA_DEFAULT_SHARE_TYPE=${MANILA_DEFAULT_SHARE_TYPE:-default}
# MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS is expected to contain extra specs key-value pairs,
# that should be assigned to default share type. Both - qualified and unqualified extra specs are supported.
# Pairs are separated by spaces, value is assigned to key using sign of equality. Examples:
# MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS='foo=bar'
# MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS='foo=bar quuz=xyzzy'
# MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS='foo=bar quuz=xyzzy fakeprefix:baz=waldo'
MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS=${MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS:-''}

# Public facing bits
MANILA_SERVICE_HOST=${MANILA_SERVICE_HOST:-$SERVICE_HOST}
MANILA_SERVICE_PORT=${MANILA_SERVICE_PORT:-8786}
MANILA_SERVICE_PORT_INT=${MANILA_SERVICE_PORT_INT:-18776}
MANILA_SERVICE_PROTOCOL=${MANILA_SERVICE_PROTOCOL:-$SERVICE_PROTOCOL}

# Support entry points installation of console scripts
if [[ -d $MANILA_DIR/bin ]]; then
    MANILA_BIN_DIR=$MANILA_DIR/bin
else
    MANILA_BIN_DIR=$(get_python_exec_prefix)
fi

# Common opts
SHARE_NAME_PREFIX=${SHARE_NAME_PREFIX:-share-}
MANILA_ENABLED_SHARE_PROTOCOLS=${ENABLED_SHARE_PROTOCOLS:-"NFS,CIFS"}
MANILA_SCHEDULER_DRIVER=${MANILA_SCHEDULER_DRIVER:-manila.scheduler.filter_scheduler.FilterScheduler}
MANILA_SERVICE_SECGROUP="manila-service"

# Following env var defines whether to apply downgrade migrations setting up DB or not.
# If it is set to False, then only 'upgrade' migrations will be applied.
# If it is set to True, then will be applied 'upgrade', 'downgrade' and 'upgrade'
# migrations again.
MANILA_USE_DOWNGRADE_MIGRATIONS=${MANILA_USE_DOWNGRADE_MIGRATIONS:-"False"}

# Common info for Generic driver(s)
SHARE_DRIVER=${SHARE_DRIVER:-manila.share.drivers.generic.GenericShareDriver}

eval USER_HOME=~
MANILA_PATH_TO_PUBLIC_KEY=${MANILA_PATH_TO_PUBLIC_KEY:-"$USER_HOME/.ssh/id_rsa.pub"}
MANILA_PATH_TO_PRIVATE_KEY=${MANILA_PATH_TO_PRIVATE_KEY:-"$USER_HOME/.ssh/id_rsa"}
MANILA_SERVICE_KEYPAIR_NAME=${MANILA_SERVICE_KEYPAIR_NAME:-"manila-service"}

MANILA_SERVICE_INSTANCE_USER=${MANILA_SERVICE_INSTANCE_USER:-"manila"}
MANILA_SERVICE_IMAGE_URL=${MANILA_SERVICE_IMAGE_URL:-"https://github.com/uglide/manila-image-elements/releases/download/0.1.0/manila-service-image.qcow2"}
MANILA_SERVICE_IMAGE_NAME=${MANILA_SERVICE_IMAGE_NAME:-"manila-service-image"}

MANILA_USE_SERVICE_INSTANCE_PASSWORD=${MANILA_USE_SERVICE_INSTANCE_PASSWORD:-"False"}
MANILA_SERVICE_INSTANCE_PASSWORD=${MANILA_SERVICE_INSTANCE_PASSWORD:-"manila"}

MANILA_SERVICE_VM_FLAVOR_REF=${MANILA_SERVICE_VM_FLAVOR_REF:-100}
MANILA_SERVICE_VM_FLAVOR_NAME=${MANILA_SERVICE_VM_FLAVOR_NAME:-"manila-service-flavor"}
MANILA_SERVICE_VM_FLAVOR_RAM=${MANILA_SERVICE_VM_FLAVOR_RAM:-128}
MANILA_SERVICE_VM_FLAVOR_DISK=${MANILA_SERVICE_VM_FLAVOR_DISK:-0}
MANILA_SERVICE_VM_FLAVOR_VCPUS=${MANILA_SERVICE_VM_FLAVOR_VCPUS:-1}

# Support for multi backend configuration (default is no support)
MANILA_MULTI_BACKEND=$(trueorfalse False MANILA_MULTI_BACKEND)
DEPRECATED_TEXT="$DEPRECATED_TEXT\n'MANILA_MULTI_BACKEND' is deprecated,
    it makes influence only when is set to True and 'MANILA_ENABLED_BACKENDS' is not set.
    Use 'MANILA_ENABLED_BACKENDS' instead if you want to use custom setting.
    Set there a list of back end names to be enabled.\n
    To configure custom back ends use (any opt in any group can be set in this way) following:
    MANILA_OPTGROUP_foo_bar=value
    where 'foo' is name of config group and 'bar' is name of option.\n"

# First share backend data, that will be used in any installation
MANILA_BACKEND1_CONFIG_GROUP_NAME=${MANILA_BACKEND1_CONFIG_GROUP_NAME:-generic1}  # deprecated
MANILA_SHARE_BACKEND1_NAME=${MANILA_SHARE_BACKEND1_NAME:-GENERIC1}  # deprecated

# Second share backend data, that will be used only with MANILA_MULTI_BACKEND=True
MANILA_BACKEND2_CONFIG_GROUP_NAME=${MANILA_BACKEND2_CONFIG_GROUP_NAME:-generic2}  # deprecated
MANILA_SHARE_BACKEND2_NAME=${MANILA_SHARE_BACKEND2_NAME:-GENERIC2}  # deprecated


# Entry Points
# ------------

# cleanup_manila - Remove residual data files, anything left over from previous
# runs that a clean run would need to clean up
function cleanup_manila {
    # This is placeholder.
    # All stuff, that are created by Generic driver will be cleaned up by other services.
    :
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

    if is_service_enabled horizon && [ "$MANILA_UI_ENABLED" = "True" ]; then
        configure_manila_ui
    fi
}


function configure_manila_ui {
    setup_develop $MANILA_UI_DIR

    cp $MANILA_UI_DIR/manila_ui/enabled/_90_manila_*.py $HORIZON_DIR/openstack_dashboard/local/enabled
}


function create_manila_service_keypair {
    openstack keypair create $MANILA_SERVICE_KEYPAIR_NAME --public-key $MANILA_PATH_TO_PUBLIC_KEY
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
        get_or_create_service "manila" "share" "Manila Shared Filesystem Service"
        get_or_create_endpoint "share" "$REGION_NAME" \
            "$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT/v1/\$(tenant_id)s" \
            "$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT/v1/\$(tenant_id)s" \
            "$MANILA_SERVICE_PROTOCOL://$MANILA_SERVICE_HOST:$MANILA_SERVICE_PORT/v1/\$(tenant_id)s"
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

    manila \
        --debug \
        --os-auth-url $KEYSTONE_AUTH_URI/v2.0 \
        --os-tenant-name ${OS_PROJECT_NAME:-$OS_TENANT_NAME} \
        --os-username $OS_USERNAME \
        --os-password $OS_PASSWORD \
        --os-region-name $OS_REGION_NAME \
        type-create $MANILA_DEFAULT_SHARE_TYPE $driver_handles_share_servers
    if [[ $MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS ]]; then
        manila \
            --debug \
            --os-auth-url $KEYSTONE_AUTH_URI/v2.0 \
            --os-tenant-name ${OS_PROJECT_NAME:-$OS_TENANT_NAME} \
            --os-username $OS_USERNAME \
            --os-password $OS_PASSWORD \
            --os-region-name $OS_REGION_NAME \
            type-key $MANILA_DEFAULT_SHARE_TYPE set $MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS
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

    # Create cache dir
    sudo mkdir -p $MANILA_AUTH_CACHE_DIR
    sudo chown $STACK_USER $MANILA_AUTH_CACHE_DIR
    rm -f $MANILA_AUTH_CACHE_DIR/*
}

# install_manila - Collect source and prepare
function install_manila {
    git_clone $MANILACLIENT_REPO $MANILACLIENT_DIR $MANILACLIENT_BRANCH

    # install manila-ui if horizon is enabled
    if is_service_enabled horizon && [ "$MANILA_UI_ENABLED" = "True" ]; then
        git_clone $MANILA_UI_REPO $MANILA_UI_DIR $MANILA_UI_BRANCH
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
elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    echo_summary "Creating Manila entities for auth service"
    create_manila_accounts

    echo_summary "Creating Manila service flavor"
    create_manila_service_flavor

    echo_summary "Creating Manila service security group"
    create_manila_service_secgroup

    echo_summary "Creating Manila service image"
    create_manila_service_image

    echo_summary "Creating Manila service keypair"
    create_manila_service_keypair

    echo_summary "Creating Manila service VMs for generic driver \
        backends for which handlng of share servers is disabled."
    create_service_share_servers

    echo_summary "Starting Manila"
    start_manila

    echo_summary "Creating Manila default share type"
    create_default_share_type

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
