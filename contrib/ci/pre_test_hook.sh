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

# Import devstack function 'trueorfalse'
source $BASE/new/devstack/functions

localrc_path=$BASE/new/devstack/localrc
echo "DEVSTACK_GATE_TEMPEST_ALLOW_TENANT_ISOLATION=1" >> $localrc_path
echo "API_RATE_LIMIT=False" >> $localrc_path
echo "TEMPEST_SERVICES+=,manila" >> $localrc_path
echo "VOLUME_BACKING_FILE_SIZE=22G" >> $localrc_path
echo "CINDER_LVM_TYPE=thin" >> $localrc_path

# NOTE(mkoderer): switch to keystone v3 by default
echo "IDENTITY_API_VERSION=3" >> $localrc_path

# NOTE(vponomaryov): Set oversubscription ratio for Cinder LVM driver
# bigger than 1.0, because in CI we do not need such small value.
# It will allow us to avoid exceeding real capacity in CI test runs.
echo "CINDER_OVERSUBSCRIPTION_RATIO=20.0" >> $localrc_path
echo "MANILA_BACKEND1_CONFIG_GROUP_NAME=london" >> $localrc_path
echo "MANILA_BACKEND2_CONFIG_GROUP_NAME=paris" >> $localrc_path
echo "MANILA_SHARE_BACKEND1_NAME=LONDON" >> $localrc_path
echo "MANILA_SHARE_BACKEND2_NAME=PARIS" >> $localrc_path

# === Handle script arguments ===
# First argument is expected to be a boolean-like value for DHSS.
DHSS=$1
DHSS=$(trueorfalse True DHSS)

# Second argument is expected to have codename of a share driver.
DRIVER=$2

# Third argument is expected to contain value equal either to 'singlebackend'
# or 'multibackend' that defines how many back-ends should be configured.
BACK_END_TYPE=$3

echo "MANILA_OPTGROUP_london_driver_handles_share_servers=$DHSS" >> $localrc_path
echo "MANILA_OPTGROUP_paris_driver_handles_share_servers=$DHSS" >> $localrc_path

echo "MANILA_USE_SERVICE_INSTANCE_PASSWORD=True" >> $localrc_path

echo "MANILA_USE_DOWNGRADE_MIGRATIONS=True" >> $localrc_path

if [[ "$BACK_END_TYPE" == "multibackend" ]]; then
    echo "MANILA_MULTI_BACKEND=True" >> $localrc_path
else
    echo "MANILA_MULTI_BACKEND=False" >> $localrc_path
fi

MANILA_SERVICE_IMAGE_ENABLED=False
if [[ "$DRIVER" == "generic" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    echo "SHARE_DRIVER=manila.share.drivers.generic.GenericShareDriver" >> $localrc_path
elif [[ "$DRIVER" == "windows" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    echo "SHARE_DRIVER=manila.share.drivers.windows.windows_smb_driver.WindowsSMBDriver" >> $localrc_path
elif [[ "$DRIVER" == "lvm" ]]; then
    echo "SHARE_DRIVER=manila.share.drivers.lvm.LVMShareDriver" >> $localrc_path
    echo "SHARE_BACKING_FILE_SIZE=32000M" >> $localrc_path
elif [[ "$DRIVER" == "zfsonlinux" ]]; then
    echo "SHARE_DRIVER=manila.share.drivers.zfsonlinux.driver.ZFSonLinuxShareDriver" >> $localrc_path
    echo "RUN_MANILA_REPLICATION_TESTS=True" >> $localrc_path
    # Set the replica_state_update_interval to 60 seconds to make
    # replication tests run faster. The default is 300, which is greater than
    # the build timeout for ZFS on the gate.
    echo "MANILA_REPLICA_STATE_UPDATE_INTERVAL=60" >> $localrc_path
    echo "MANILA_ZFSONLINUX_USE_SSH=True" >> $localrc_path
fi

echo "MANILA_SERVICE_IMAGE_ENABLED=$MANILA_SERVICE_IMAGE_ENABLED" >> $localrc_path

# Enabling isolated metadata in Neutron is required because
# Tempest creates isolated networks and created vm's in scenario tests don't
# have access to Nova Metadata service. This leads to unavailability of
# created vm's in scenario tests.
echo 'ENABLE_ISOLATED_METADATA=True' >> $localrc_path


# Go to Tempest dir and checkout stable commit to avoid possible
# incompatibilities for plugin stored in Manila repo.
cd $BASE/new/tempest
source $BASE/new/manila/contrib/ci/common.sh
git checkout $MANILA_TEMPEST_COMMIT

# Print current Tempest status
git status
