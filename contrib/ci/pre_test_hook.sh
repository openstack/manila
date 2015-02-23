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

# This script is executed inside pre_test_hook function in devstack gate.
# First argument ($1) expects boolean as value where:
# 'False' means share driver will not handle share servers
# 'True' means it will handle share servers.

# Install manila devstack integration
cp -r $BASE/new/manila/contrib/devstack/* $BASE/new/devstack

# Import devstack function 'trueorfalse'
source $BASE/new/devstack/functions

localrc_path=$BASE/new/devstack/localrc
echo "DEVSTACK_GATE_TEMPEST_ALLOW_TENANT_ISOLATION=1" >> $localrc_path
echo "API_RATE_LIMIT=False" >> $localrc_path
echo "TEMPEST_SERVICES+=,manila" >> $localrc_path
echo "VOLUME_BACKING_FILE_SIZE=22G" >> $localrc_path

echo "MANILA_BACKEND1_CONFIG_GROUP_NAME=london" >> $localrc_path
echo "MANILA_BACKEND2_CONFIG_GROUP_NAME=paris" >> $localrc_path
echo "MANILA_SHARE_BACKEND1_NAME=LONDON" >> $localrc_path
echo "MANILA_SHARE_BACKEND2_NAME=PARIS" >> $localrc_path

driver_handles_share_servers=$1
driver_handles_share_servers=$(trueorfalse True driver_handles_share_servers)

echo "MANILA_OPTGROUP_london_driver_handles_share_servers=$driver_handles_share_servers" >> $localrc_path
echo "MANILA_OPTGROUP_paris_driver_handles_share_servers=$driver_handles_share_servers" >> $localrc_path

# JOB_NAME is defined in openstack-infra/config project
# used by CI/CD, where this script is intended to be used.
if [[ "$JOB_NAME" =~ "multibackend" ]]; then
    echo "MANILA_MULTI_BACKEND=True" >> $localrc_path
else
    echo "MANILA_MULTI_BACKEND=False" >> $localrc_path
fi

# Go to Tempest dir and checkout stable commit to avoid possible
# incompatibilities for plugin stored in Manila repo.
TEMPEST_COMMIT="7d5ed596"  # 23 Feb, 2015
cd $BASE/new/tempest
git checkout $TEMPEST_COMMIT

# Print current Tempest status
git status

# Install Manila Tempest integration
cp -r $BASE/new/manila/contrib/tempest/tempest/* $BASE/new/tempest/tempest
