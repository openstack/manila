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

export TEMPEST_CONFIG=$BASE/new/tempest/etc/tempest.conf

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
    iniset $TEMPEST_CONFIG share run_migration_tests $(trueorfalse True RUN_MANILA_MIGRATION_TESTS)

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

# Enable consistency group tests
RUN_MANILA_CG_TESTS=${RUN_MANILA_CG_TESTS:-True}
iniset $TEMPEST_CONFIG share run_consistency_group_tests $RUN_MANILA_CG_TESTS

# Enable manage/unmanage tests
RUN_MANILA_MANAGE_TESTS=${RUN_MANILA_MANAGE_TESTS:-True}
iniset $TEMPEST_CONFIG share run_manage_unmanage_tests $RUN_MANILA_MANAGE_TESTS

if [[ -z "$MULTITENANCY_ENABLED" ]]; then
    # Define whether share drivers handle share servers or not.
    # Requires defined config option 'driver_handles_share_servers'.
    MANILA_CONF=${MANILA_CONF:-/etc/manila/manila.conf}
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
        echo 'Should never get here. If get, then error occured.'
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
    MANILA_TEMPEST_CONCURRENCY=8
fi

# let us control if we die or not
set +o errexit
cd $BASE/new/tempest

export MANILA_TEMPEST_CONCURRENCY=${MANILA_TEMPEST_CONCURRENCY:-12}
export MANILA_TESTS=${MANILA_TESTS:-'manila_tempest_tests.tests.api'}

if [[ "$TEST_TYPE" == "scenario" ]]; then
    echo "Set test set to scenario only"
    MANILA_TESTS='manila_tempest_tests.tests.scenario'
elif [[ "$DRIVER" == "generic" ]]; then
    if [[ "$POSTGRES_ENABLED" == "True" ]]; then
        # Run only CIFS tests on PostgreSQL DB backend
        # to reduce amount of tests per job using 'generic' share driver.
        iniset $TEMPEST_CONFIG share enable_protocols cifs
    else
        # Run only NFS tests on MySQL DB backend to reduce amount of tests
        # per job using 'generic' share driver.
        iniset $TEMPEST_CONFIG share enable_protocols nfs
    fi
fi

# check if tempest plugin was installed correctly
echo 'import pkg_resources; print list(pkg_resources.iter_entry_points("tempest.test_plugins"))' | python

echo "Running tempest manila test suites"
sudo -H -u jenkins tox -eall-plugin $MANILA_TESTS -- --concurrency=$MANILA_TEMPEST_CONCURRENCY
