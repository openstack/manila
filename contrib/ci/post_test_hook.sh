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

if [[ "$1" == "1" ]]; then
    # if arg $1 is equal to "1", we assume multibackend installation
    source $BASE/new/devstack/functions
    iniset $BASE/new/tempest/etc/tempest.conf share multi_backend True
    iniset $BASE/new/tempest/etc/tempest.conf share backend_names "$MANILA_SHARE_BACKEND1_NAME,$MANILA_SHARE_BACKEND2_NAME"
fi

# let us control if we die or not
set +o errexit
cd $BASE/new/tempest
echo "Running tempest manila test suites"
sudo -H -u jenkins tox -evenv bash tools/pretty_tox.sh \"$MANILA_TESTS -- --concurrency=$TEMPEST_CONCURRENCY\"
