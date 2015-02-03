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

if [[ "$1" =~ "multibackend" ]]; then
    # if arg $1 has "multibackend", then we assume multibackend installation
    iniset $BASE/new/tempest/etc/tempest.conf share multi_backend True

    # Set share backends names, they are defined within pre_test_hook
    export BACKENDS_NAMES="LONDON,PARIS"
else
    export BACKENDS_NAMES="LONDON"
fi
iniset $BASE/new/tempest/etc/tempest.conf share backend_names $BACKENDS_NAMES

# Set two retries for CI jobs
iniset $BASE/new/tempest/etc/tempest.conf share share_creation_retry_number 2

# Suppress errors in cleanup of resources
iniset $BASE/new/tempest/etc/tempest.conf share suppress_errors_in_cleanup True

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
    iniset $BASE/new/tempest/etc/tempest.conf share multitenancy_enabled False
elif [[ $WITH_SHARE_SERVER_HANDLING_MODES -ge 1 ]]; then
    iniset $BASE/new/tempest/etc/tempest.conf share multitenancy_enabled True
else
    echo 'Should never get here. If get, then error occured.'
    exit 1
fi

# let us control if we die or not
set +o errexit
cd $BASE/new/tempest

export TEMPEST_CONCURRENCY=12
export MANILA_TESTS='tempest.cli.*manila*'
if [[ ! "$ZUUL_PROJECT" =~ python-manilaclient ]]; then
    MANILA_TESTS+=' tempest.api.share*';
fi

echo "Running tempest manila test suites"
sudo -H -u jenkins tox -eall $MANILA_TESTS -- --concurrency=$TEMPEST_CONCURRENCY
