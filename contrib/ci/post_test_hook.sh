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

sudo chown -R jenkins:stack $BASE/new/tempest
sudo chown -R jenkins:stack $BASE/data/tempest
sudo chmod -R o+rx $BASE/new/devstack/files

# Import devstack function 'iniset'
source $BASE/new/devstack/functions

if [[ "$1" =~ "multibackend" ]]; then
    # if arg $1 has "multibackend", then we assume multibackend installation
    iniset $BASE/new/tempest/etc/tempest.conf share multi_backend True

    # backend names are defined in pre_test_hook
    iniset $BASE/new/tempest/etc/tempest.conf share backend_names "LONDON,PARIS"
fi

# Set two retries for CI jobs
iniset $BASE/new/tempest/etc/tempest.conf share share_creation_retry_number 2

# Suppress errors in cleanup of resources
iniset $BASE/new/tempest/etc/tempest.conf share suppress_errors_in_cleanup True

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
