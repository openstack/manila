#!/bin/bash -xe
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This script is executed inside post_test_hook function in devstack gate.
# First argument ($1) expects 'multibackend' as value for setting appropriate
# tempest conf opts, all other values will assume singlebackend installation.

SCRIPT_IS_DEPRECATED="Manila's pre_test_hook and post_test_hook scripts are
DEPRECATED. Please use alternate tools to configure devstack's local.conf
file or run tempest tests"

sudo chown -R $USER:stack $BASE/new/tempest
sudo chown -R $USER:stack $BASE/data/tempest
sudo chmod -R o+rx $BASE/new/devstack/files

# Import devstack functions 'iniset', 'iniget' and 'trueorfalse'
source $BASE/new/devstack/functions

export TEMPEST_CONFIG=${TEMPEST_CONFIG:-$BASE/new/tempest/etc/tempest.conf}

# === Handle script arguments ===

# First argument is expected to contain value equal either to 'singlebackend'
# or 'multibackend' that defines how many back-ends are used.
BACK_END_TYPE=$1

# Second argument is expected to have codename of a share driver.
DRIVER=$2

# Third argument is expected to contain either 'api' or 'scenario' values
# that define test suites to be run.
TEST_TYPE=$3

# Fourth argument is expected to be boolean-like and it should be 'true'
# when PostgreSQL DB back-end is used and 'false' when MySQL.
POSTGRES_ENABLED=$4
POSTGRES_ENABLED=$(trueorfalse True POSTGRES_ENABLED)

if [[ "$BACK_END_TYPE" == "multibackend" ]]; then
    iniset $TEMPEST_CONFIG share multi_backend True
    # Set share backends names, they are defined within pre_test_hook
    export BACKENDS_NAMES="LONDON,PARIS"
else
    export BACKENDS_NAMES="LONDON"
fi
iniset $TEMPEST_CONFIG share backend_names $BACKENDS_NAMES

# Set two retries for CI jobs
iniset $TEMPEST_CONFIG share share_creation_retry_number 2

# Suppress errors in cleanup of resources
SUPPRESS_ERRORS=${SUPPRESS_ERRORS_IN_CLEANUP:-True}
iniset $TEMPEST_CONFIG share suppress_errors_in_cleanup $SUPPRESS_ERRORS

USERNAME_FOR_USER_RULES=${USERNAME_FOR_USER_RULES:-"manila"}
PASSWORD_FOR_SAMBA_USER=${PASSWORD_FOR_SAMBA_USER:-$USERNAME_FOR_USER_RULES}

# Enable feature tests:
# Default options are as specified in tempest.
RUN_MANILA_QUOTA_TESTS=${RUN_MANILA_QUOTA_TESTS:-True}
RUN_MANILA_SHRINK_TESTS=${RUN_MANILA_SHRINK_TESTS:-True}
RUN_MANILA_SNAPSHOT_TESTS=${RUN_MANILA_SNAPSHOT_TESTS:-True}
RUN_MANILA_REVERT_TO_SNAPSHOT_TESTS=${RUN_MANILA_REVERT_TO_SNAPSHOT_TESTS:-False}
RUN_MANILA_SG_TESTS=${RUN_MANILA_SG_TESTS:-${RUN_MANILA_CG_TESTS:-True}}
RUN_MANILA_MANAGE_TESTS=${RUN_MANILA_MANAGE_TESTS:-True}
RUN_MANILA_MANAGE_SNAPSHOT_TESTS=${RUN_MANILA_MANAGE_SNAPSHOT_TESTS:-False}
RUN_MANILA_REPLICATION_TESTS=${RUN_MANILA_REPLICATION_TESTS:-False}
RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS=${RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS:-False}
RUN_MANILA_DRIVER_ASSISTED_MIGRATION_TESTS=${RUN_MANILA_DRIVER_ASSISTED_MIGRATION_TESTS:-False}
RUN_MANILA_MOUNT_SNAPSHOT_TESTS=${RUN_MANILA_MOUNT_SNAPSHOT_TESTS:-False}
RUN_MANILA_MIGRATION_WITH_PRESERVE_SNAPSHOTS_TESTS=${RUN_MANILA_MIGRATION_WITH_PRESERVE_SNAPSHOTS_TESTS:-False}
RUN_MANILA_IPV6_TESTS=${RUN_MANILA_IPV6_TESTS:-False}

MANILA_CONF=${MANILA_CONF:-/etc/manila/manila.conf}

# Capabilitities
CAPABILITY_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT=${CAPABILITY_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT:-True}
MANILA_CONFIGURE_DEFAULT_TYPES=${MANILA_CONFIGURE_DEFAULT_TYPES:-True}

if [[ -z "$MULTITENANCY_ENABLED" ]]; then
    # Define whether share drivers handle share servers or not.
    # Requires defined config option 'driver_handles_share_servers'.
    NO_SHARE_SERVER_HANDLING_MODES=0
    WITH_SHARE_SERVER_HANDLING_MODES=0

    # Convert backend names to config groups using lowercase translation
    CONFIG_GROUPS=${BACKENDS_NAMES,,}

    for CG in ${CONFIG_GROUPS//,/ }; do
        DRIVER_HANDLES_SHARE_SERVERS=$(iniget $MANILA_CONF $CG driver_handles_share_servers)
        if [[ $DRIVER_HANDLES_SHARE_SERVERS == False ]]; then
            NO_SHARE_SERVER_HANDLING_MODES=$((NO_SHARE_SERVER_HANDLING_MODES+1))
        elif [[ $DRIVER_HANDLES_SHARE_SERVERS == True ]]; then
            WITH_SHARE_SERVER_HANDLING_MODES=$((WITH_SHARE_SERVER_HANDLING_MODES+1))
        else
            echo "Config option 'driver_handles_share_servers' either is not defined or \
                    defined with improper value - '$DRIVER_HANDLES_SHARE_SERVERS'."
            exit 1
        fi
    done

    if [[ $NO_SHARE_SERVER_HANDLING_MODES -ge 1 && $WITH_SHARE_SERVER_HANDLING_MODES -ge 1 || \
            $NO_SHARE_SERVER_HANDLING_MODES -eq 0 && $WITH_SHARE_SERVER_HANDLING_MODES -eq 0 ]]; then
        echo 'Allowed only same driver modes for all backends to be run with Tempest job.'
        exit 1
    elif [[ $NO_SHARE_SERVER_HANDLING_MODES -ge 1 ]]; then
        MULTITENANCY_ENABLED='False'
    elif [[ $WITH_SHARE_SERVER_HANDLING_MODES -ge 1 ]]; then
        MULTITENANCY_ENABLED='True'
    else
        echo 'Should never get here unless an error occurred.'
        exit 1
    fi
else
    MULTITENANCY_ENABLED=$(trueorfalse True MULTITENANCY_ENABLED)
fi

# Set multitenancy configuration for Tempest
iniset $TEMPEST_CONFIG share multitenancy_enabled $MULTITENANCY_ENABLED
if [[ "$MULTITENANCY_ENABLED" == "False"  ]]; then
    # Using approach without handling of share servers we have bigger load for
    # volume creation in Cinder using Generic driver. So, reduce amount of
    # threads to avoid errors for Cinder volume creations that appear
    # because of lack of free space.
    MANILA_TEMPEST_CONCURRENCY=${MANILA_TEMPEST_CONCURRENCY:-8}
    iniset $TEMPEST_CONFIG auth create_isolated_networks False
fi

# let us control if we die or not
set +o errexit
cd $BASE/new/tempest

export MANILA_TEMPEST_CONCURRENCY=${MANILA_TEMPEST_CONCURRENCY:-6}
export MANILA_TESTS=${MANILA_TESTS:-'manila_tempest_tests.tests.api'}

# Enable quota tests
iniset $TEMPEST_CONFIG share run_quota_tests $RUN_MANILA_QUOTA_TESTS

# Enable shrink tests
iniset $TEMPEST_CONFIG share run_shrink_tests $RUN_MANILA_SHRINK_TESTS

# Enable snapshot tests
iniset $TEMPEST_CONFIG share run_snapshot_tests $RUN_MANILA_SNAPSHOT_TESTS

# Enable revert to snapshot tests
iniset $TEMPEST_CONFIG share run_revert_to_snapshot_tests $RUN_MANILA_REVERT_TO_SNAPSHOT_TESTS

# Enable share group tests
iniset $TEMPEST_CONFIG share run_share_group_tests $RUN_MANILA_SG_TESTS

# Enable manage/unmanage tests
iniset $TEMPEST_CONFIG share run_manage_unmanage_tests $RUN_MANILA_MANAGE_TESTS

# Enable manage/unmanage snapshot tests
iniset $TEMPEST_CONFIG share run_manage_unmanage_snapshot_tests $RUN_MANILA_MANAGE_SNAPSHOT_TESTS

# Enable replication tests
iniset $TEMPEST_CONFIG share run_replication_tests $RUN_MANILA_REPLICATION_TESTS

# Enable migration tests
iniset $TEMPEST_CONFIG share run_host_assisted_migration_tests $RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS
iniset $TEMPEST_CONFIG share run_driver_assisted_migration_tests $RUN_MANILA_DRIVER_ASSISTED_MIGRATION_TESTS
iniset $TEMPEST_CONFIG share run_migration_with_preserve_snapshots_tests $RUN_MANILA_MIGRATION_WITH_PRESERVE_SNAPSHOTS_TESTS

# Enable mountable snapshots tests
iniset $TEMPEST_CONFIG share run_mount_snapshot_tests $RUN_MANILA_MOUNT_SNAPSHOT_TESTS

# Create share from snapshot support
iniset $TEMPEST_CONFIG share capability_create_share_from_snapshot_support $CAPABILITY_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT

iniset $TEMPEST_CONFIG validation ip_version_for_ssh 4
iniset $TEMPEST_CONFIG validation network_for_ssh ${PRIVATE_NETWORK_NAME:-"private"}

if [ $(trueorfalse False MANILA_CONFIGURE_DEFAULT_TYPES) == True ]; then
    iniset $TEMPEST_CONFIG share default_share_type_name ${MANILA_DEFAULT_SHARE_TYPE:-default}
fi

ADMIN_DOMAIN_NAME=${ADMIN_DOMAIN_NAME:-"Default"}
export OS_PROJECT_DOMAIN_NAME=$ADMIN_DOMAIN_NAME
export OS_USER_DOMAIN_NAME=$ADMIN_DOMAIN_NAME

source $BASE/new/devstack/openrc admin admin
public_net_id=$(openstack network list --name $PUBLIC_NETWORK_NAME -f value -c ID )
iniset $TEMPEST_CONFIG network public_network_id $public_net_id

# Set config to run IPv6 tests according to env var
iniset $TEMPEST_CONFIG share run_ipv6_tests $RUN_MANILA_IPV6_TESTS

if ! [[ -z "$OVERRIDE_IP_FOR_NFS_ACCESS" ]]; then
    # Set config to use specified IP as access rule on NFS scenario tests
    # in order to workaround multiple NATs between the VMs and the storage
    # controller
    iniset $TEMPEST_CONFIG share override_ip_for_nfs_access $OVERRIDE_IP_FOR_NFS_ACCESS
fi

echo "Manila service details"
source $BASE/new/devstack/openrc admin admin
manila service-list

echo $SCRIPT_IS_DEPRECATED

echo "Running tempest manila test suites"
cd $BASE/new/tempest/
# List plugins in logs to enable debugging
sudo -H -u $USER tempest list-plugins
sudo -H -u $USER tempest run -r $MANILA_TESTS --concurrency=$MANILA_TEMPEST_CONCURRENCY
RETVAL=$?
cd -
exit $RETVAL
