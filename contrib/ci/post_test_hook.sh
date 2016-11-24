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

sudo chown -R jenkins:stack $BASE/new/tempest
sudo chown -R jenkins:stack $BASE/data/tempest
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

if [[ "$DRIVER" == "dummy" ]]; then
    export BACKENDS_NAMES="ALPHA,BETA"
elif [[ "$BACK_END_TYPE" == "multibackend" ]]; then
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
RUN_MANILA_CG_TESTS=${RUN_MANILA_CG_TESTS:-True}
RUN_MANILA_MANAGE_TESTS=${RUN_MANILA_MANAGE_TESTS:-True}
RUN_MANILA_MANAGE_SNAPSHOT_TESTS=${RUN_MANILA_MANAGE_SNAPSHOT_TESTS:-False}
RUN_MANILA_REPLICATION_TESTS=${RUN_MANILA_REPLICATION_TESTS:-False}
RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS=${RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS:-False}
RUN_MANILA_DRIVER_ASSISTED_MIGRATION_TESTS=${RUN_MANILA_DRIVER_ASSISTED_MIGRATION_TESTS:-False}

MANILA_CONF=${MANILA_CONF:-/etc/manila/manila.conf}

# Capabilitities
CAPABILITY_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT=${CAPABILITY_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT:-True}

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

if [[ "$TEST_TYPE" == "scenario" ]]; then
    echo "Set test set to scenario only"
    MANILA_TESTS='manila_tempest_tests.tests.scenario'
    iniset $TEMPEST_CONFIG auth use_dynamic_credentials True
    RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS=True
elif [[ "$DRIVER" == "generic" ]]; then
    RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS=True
    RUN_MANILA_MANAGE_SNAPSHOT_TESTS=True
    RUN_MANILA_CG_TESTS=False
    if [[ "$POSTGRES_ENABLED" == "True" ]]; then
        # Run only CIFS tests on PostgreSQL DB backend
        # to reduce amount of tests per job using 'generic' share driver.
        iniset $TEMPEST_CONFIG share enable_protocols cifs
    else
        # Run only NFS tests on MySQL DB backend to reduce amount of tests
        # per job using 'generic' share driver.
        iniset $TEMPEST_CONFIG share enable_protocols nfs
    fi
    MANILA_TESTS="(^manila_tempest_tests.tests.api)(?=.*\[.*\bbackend\b.*\])"
fi

if [[ "$DRIVER" == "lvm" ]]; then
    MANILA_TESTS="(^manila_tempest_tests.tests)(?=.*\[.*\bbackend\b.*\])"
    MANILA_TEMPEST_CONCURRENCY=8
    RUN_MANILA_CG_TESTS=False
    RUN_MANILA_MANAGE_TESTS=False
    RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS=True
    RUN_MANILA_SHRINK_TESTS=False
    RUN_MANILA_REVERT_TO_SNAPSHOT_TESTS=True
    iniset $TEMPEST_CONFIG share enable_ip_rules_for_protocols 'nfs'
    iniset $TEMPEST_CONFIG share enable_user_rules_for_protocols 'cifs'
    iniset $TEMPEST_CONFIG share image_with_share_tools 'manila-service-image-master'
    iniset $TEMPEST_CONFIG auth use_dynamic_credentials True
    iniset $TEMPEST_CONFIG share capability_snapshot_support True
    if ! grep $USERNAME_FOR_USER_RULES "/etc/passwd"; then
        sudo useradd $USERNAME_FOR_USER_RULES
    fi
    (echo $PASSWORD_FOR_SAMBA_USER; echo $PASSWORD_FOR_SAMBA_USER) | sudo smbpasswd -s -a $USERNAME_FOR_USER_RULES
    sudo smbpasswd -e $USERNAME_FOR_USER_RULES
    samba_daemon_name=smbd
    if is_fedora; then
        samba_daemon_name=smb
    fi
    sudo service $samba_daemon_name restart
elif [[ "$DRIVER" == "zfsonlinux" ]]; then
    MANILA_TESTS="(^manila_tempest_tests.tests)(?=.*\[.*\bbackend\b.*\])"
    MANILA_TEMPEST_CONCURRENCY=8
    RUN_MANILA_CG_TESTS=False
    RUN_MANILA_MANAGE_TESTS=True
    RUN_MANILA_MANAGE_SNAPSHOT_TESTS=True
    RUN_MANILA_DRIVER_ASSISTED_MIGRATION_TESTS=True
    RUN_MANILA_REPLICATION_TESTS=True
    iniset $TEMPEST_CONFIG share enable_ip_rules_for_protocols 'nfs'
    iniset $TEMPEST_CONFIG share enable_user_rules_for_protocols ''
    iniset $TEMPEST_CONFIG share enable_cert_rules_for_protocols ''
    iniset $TEMPEST_CONFIG share enable_ro_access_level_for_protocols 'nfs'
    iniset $TEMPEST_CONFIG share build_timeout 180
    iniset $TEMPEST_CONFIG share share_creation_retry_number 0
    iniset $TEMPEST_CONFIG share capability_storage_protocol 'NFS'
    iniset $TEMPEST_CONFIG share enable_protocols 'nfs'
    iniset $TEMPEST_CONFIG share suppress_errors_in_cleanup False
    iniset $TEMPEST_CONFIG share multitenancy_enabled False
    iniset $TEMPEST_CONFIG share multi_backend True
    iniset $TEMPEST_CONFIG share backend_replication_type 'readable'
    iniset $TEMPEST_CONFIG share image_with_share_tools 'manila-service-image-master'
    iniset $TEMPEST_CONFIG auth use_dynamic_credentials True
    iniset $TEMPEST_CONFIG share capability_snapshot_support True
elif [[ "$DRIVER" == "dummy" ]]; then
    MANILA_TEMPEST_CONCURRENCY=24
    RUN_MANILA_CG_TESTS=True
    RUN_MANILA_MANAGE_TESTS=False
    RUN_MANILA_DRIVER_ASSISTED_MIGRATION_TESTS=True
    RUN_MANILA_REVERT_TO_SNAPSHOT_TESTS=True
    iniset $TEMPEST_CONFIG share enable_ip_rules_for_protocols 'nfs'
    iniset $TEMPEST_CONFIG share enable_user_rules_for_protocols 'cifs'
    iniset $TEMPEST_CONFIG share enable_cert_rules_for_protocols ''
    iniset $TEMPEST_CONFIG share enable_ro_access_level_for_protocols 'nfs,cifs'
    iniset $TEMPEST_CONFIG share build_timeout 180
    iniset $TEMPEST_CONFIG share share_creation_retry_number 0
    iniset $TEMPEST_CONFIG share capability_storage_protocol 'NFS_CIFS'
    iniset $TEMPEST_CONFIG share enable_protocols 'nfs,cifs'
    iniset $TEMPEST_CONFIG share suppress_errors_in_cleanup False
    iniset $TEMPEST_CONFIG share multitenancy_enabled True
    iniset $TEMPEST_CONFIG share create_networks_when_multitenancy_enabled False
    iniset $TEMPEST_CONFIG share multi_backend True
elif [[ "$DRIVER" == "container" ]]; then
    MANILA_TESTS="(^manila_tempest_tests.tests.api)(?=.*\[.*\bbackend\b.*\])"
    MANILA_TEMPEST_CONCURRENCY=8
    RUN_MANILA_CG_TESTS=False
    RUN_MANILA_MANAGE_TESTS=False
    RUN_MANILA_QUOTA_TESTS=False
    RUN_MANILA_SHRINK_TESTS=False
    RUN_MANILA_SNAPSHOT_TESTS=False
    CAPABILITY_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT=False
    iniset $TEMPEST_CONFIG share capability_storage_protocol 'CIFS'
    iniset $TEMPEST_CONFIG share enable_protocols 'cifs'
    iniset $TEMPEST_CONFIG share enable_user_rules_for_protocols 'cifs'
    iniset $TEMPEST_CONFIG share enable_ip_rules_for_protocols ''
fi

# Enable quota tests
iniset $TEMPEST_CONFIG share run_quota_tests $RUN_MANILA_QUOTA_TESTS

# Enable shrink tests
iniset $TEMPEST_CONFIG share run_shrink_tests $RUN_MANILA_SHRINK_TESTS

# Enable snapshot tests
iniset $TEMPEST_CONFIG share run_snapshot_tests $RUN_MANILA_SNAPSHOT_TESTS

# Enable revert to snapshot tests
iniset $TEMPEST_CONFIG share run_revert_to_snapshot_tests $RUN_MANILA_REVERT_TO_SNAPSHOT_TESTS

# Enable consistency group tests
iniset $TEMPEST_CONFIG share run_consistency_group_tests $RUN_MANILA_CG_TESTS

# Enable manage/unmanage tests
iniset $TEMPEST_CONFIG share run_manage_unmanage_tests $RUN_MANILA_MANAGE_TESTS

# Enable manage/unmanage snapshot tests
iniset $TEMPEST_CONFIG share run_manage_unmanage_snapshot_tests $RUN_MANILA_MANAGE_SNAPSHOT_TESTS

# Enable replication tests
iniset $TEMPEST_CONFIG share run_replication_tests $RUN_MANILA_REPLICATION_TESTS

# Enable migration tests
iniset $TEMPEST_CONFIG share run_host_assisted_migration_tests $RUN_MANILA_HOST_ASSISTED_MIGRATION_TESTS
iniset $TEMPEST_CONFIG share run_driver_assisted_migration_tests $RUN_MANILA_DRIVER_ASSISTED_MIGRATION_TESTS

# Create share from snapshot support
iniset $TEMPEST_CONFIG share capability_create_share_from_snapshot_support $CAPABILITY_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT

# Revert share to snapshot support
CAPABILITY_REVERT_TO_SNAPSHOT_SUPPORT=${CAPABILITY_REVERT_TO_SNAPSHOT_SUPPORT:-$RUN_MANILA_REVERT_TO_SNAPSHOT_TESTS}
iniset $TEMPEST_CONFIG share capability_revert_to_snapshot_support $CAPABILITY_REVERT_TO_SNAPSHOT_SUPPORT

iniset $TEMPEST_CONFIG validation ip_version_for_ssh 4
iniset $TEMPEST_CONFIG validation network_for_ssh ${PRIVATE_NETWORK_NAME:-"private"}

# check if tempest plugin was installed correctly
echo 'import pkg_resources; print list(pkg_resources.iter_entry_points("tempest.test_plugins"))' | python

ADMIN_DOMAIN_NAME=${ADMIN_DOMAIN_NAME:-"Default"}
export OS_PROJECT_DOMAIN_NAME=$ADMIN_DOMAIN_NAME
export OS_USER_DOMAIN_NAME=$ADMIN_DOMAIN_NAME

# Also, we should wait until service VM is available
# before running Tempest tests using Generic driver in DHSS=False mode.
source $BASE/new/manila/contrib/ci/common.sh
manila_wait_for_drivers_init $MANILA_CONF

# (aovchinnikov): extra rules are needed to allow instances talk to host.
sudo iptables -N manila-nfs
sudo iptables -I INPUT 1 -j manila-nfs
TCP_PORTS=(2049 111 32803 892 875 662)
UDP_PORTS=(111 32769 892 875 662)
for port in ${TCP_PORTS[*]}; do
    sudo iptables -A manila-nfs -m tcp -p tcp --dport $port -j ACCEPT
done
for port in ${UDP_PORTS[*]}; do
    sudo iptables -A manila-nfs -m udp -p udp --dport $port -j ACCEPT
done

echo "Running tempest manila test suites"
sudo -H -u jenkins tox -eall-plugin $MANILA_TESTS -- --concurrency=$MANILA_TEMPEST_CONCURRENCY
RETVAL=$?


# If using the dummy driver, configure the second run. We can't use the
# devstack variables RUN_MANILA_* now, we'll directly iniset tempest options.
if [[ "$DRIVER" == "dummy" ]]; then
    save_tempest_results 1
    echo "First tempest run (DHSS=True) returned '$RETVAL'"
    iniset $TEMPEST_CONFIG share backend_names "GAMMA,DELTA"
    iniset $TEMPEST_CONFIG share run_manage_unmanage_tests True
    iniset $TEMPEST_CONFIG share run_manage_unmanage_snapshot_tests True
    iniset $TEMPEST_CONFIG share run_replication_tests True
    iniset $TEMPEST_CONFIG share multitenancy_enabled False
    iniset $TEMPEST_CONFIG share backend_replication_type 'readable'

    # Change driver mode for default share type to make tempest use
    # DHSS=False backends.
    source $BASE/new/devstack/openrc admin demo
    manila type-key default set driver_handles_share_servers=False

    echo "Running tempest manila test suites for DHSS=False mode"
    sudo -H -u jenkins tox -eall-plugin $MANILA_TESTS -- --concurrency=$MANILA_TEMPEST_CONCURRENCY
    RETVAL2=$?
    save_tempest_results 2

    # Exit with last code if first succeeded else exit with first error code
    if [[ "$RETVAL" == "0" ]]; then
        RETVAL=$RETVAL2
    fi

    echo "Second tempest run (DHSS=False) returned '$RETVAL2'"
fi
exit $RETVAL
