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

# Import devstack function 'trueorfalse', 'deprecated'
source $BASE/new/devstack/functions

deprecated "Manila's pre_test_hook and post_test_hook scripts are DEPRECATED. Please use alternate tools to configure devstack's local.conf file"

localconf=$BASE/new/devstack/local.conf

echo "[[local|localrc]]" >> $localconf
echo "DEVSTACK_GATE_TEMPEST_ALLOW_TENANT_ISOLATION=1" >> $localconf
echo "API_RATE_LIMIT=False" >> $localconf
echo "VOLUME_BACKING_FILE_SIZE=22G" >> $localconf
echo "CINDER_LVM_TYPE=thin" >> $localconf

# Set DevStack's PYTHON3_VERSION variable if CI scripts specify it
if [[ ! -z "$PYTHON3_VERSION" ]]; then
    echo "PYTHON3_VERSION=$PYTHON3_VERSION" >> $localconf
fi

# NOTE(mkoderer): switch to keystone v3 by default
echo "IDENTITY_API_VERSION=3" >> $localconf

# NOTE(vponomaryov): Set oversubscription ratio for Cinder LVM driver
# bigger than 1.0, because in CI we do not need such small value.
# It will allow us to avoid exceeding real capacity in CI test runs.
echo "CINDER_OVERSUBSCRIPTION_RATIO=100.0" >> $localconf
echo "MANILA_ENABLED_BACKENDS=london,paris" >> $localconf

echo "MANILA_ALLOW_NAS_SERVER_PORTS_ON_HOST=${MANILA_ALLOW_NAS_SERVER_PORTS_ON_HOST:=False}" >> $localconf

# === Handle script arguments ===
# First argument is expected to be a boolean-like value for DHSS.
DHSS=$1
DHSS=$(trueorfalse True DHSS)

# Second argument is expected to have codename of a share driver.
DRIVER=$2

# Third argument is expected to contain value equal either to 'singlebackend'
# or 'multibackend' that defines how many back-ends should be configured.
BACK_END_TYPE=$3

echo "MANILA_OPTGROUP_london_driver_handles_share_servers=$DHSS" >> $localconf
echo "MANILA_OPTGROUP_paris_driver_handles_share_servers=$DHSS" >> $localconf
echo "MANILA_USE_SERVICE_INSTANCE_PASSWORD=True" >> $localconf
echo "MANILA_USE_DOWNGRADE_MIGRATIONS=True" >> $localconf

# Set MANILA_ADMIN_NET_RANGE for admin_network and data_service IP
echo "MANILA_ADMIN_NET_RANGE=${MANILA_ADMIN_NET_RANGE:=10.2.5.0/24}" >> $localconf
echo "MANILA_DATA_NODE_IP=${MANILA_DATA_NODE_IP:=$MANILA_ADMIN_NET_RANGE}" >> $localconf
echo "MANILA_DATA_COPY_CHECK_HASH=${MANILA_DATA_COPY_CHECK_HASH:=True}" >> $localconf

# Share Migration CI tests migration_continue period task interval
echo "MANILA_SHARE_MIGRATION_PERIOD_TASK_INTERVAL=${MANILA_SHARE_MIGRATION_PERIOD_TASK_INTERVAL:=1}" >> $localconf
# Share Server Migration CI tests migration_continue period task interval
echo "MANILA_SERVER_MIGRATION_PERIOD_TASK_INTERVAL=${MANILA_SERVER_MIGRATION_PERIOD_TASK_INTERVAL:=10}" >> $localconf

MANILA_SERVICE_IMAGE_ENABLED=${MANILA_SERVICE_IMAGE_ENABLED:-False}
DEFAULT_EXTRA_SPECS=${DEFAULT_EXTRA_SPECS:-"'snapshot_support=True create_share_from_snapshot_support=True'"}

if [[ "$DRIVER" == "windows" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    echo "SHARE_DRIVER=manila.share.drivers.windows.windows_smb_driver.WindowsSMBDriver" >> $localconf
fi

echo "MANILA_SERVICE_IMAGE_ENABLED=$MANILA_SERVICE_IMAGE_ENABLED" >> $localconf
if [[ "$MANILA_SERVICE_IMAGE_ENABLED" == True ]]; then
    echo "MANILA_SERVICE_IMAGE_URL=$MANILA_SERVICE_IMAGE_URL" >> $localconf
    echo "MANILA_SERVICE_IMAGE_NAME=$MANILA_SERVICE_IMAGE_NAME" >> $localconf
fi
echo "MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS=$DEFAULT_EXTRA_SPECS" >> $localconf
echo "MANILA_CONFIGURE_DEFAULT_TYPES=${MANILA_CONFIGURE_DEFAULT_TYPES:-True}" >> $localconf

# Enabling isolated metadata in Neutron is required because
# Tempest creates isolated networks and created vm's in scenario tests don't
# have access to Nova Metadata service. This leads to unavailability of
# created vm's in scenario tests.
echo "ENABLE_ISOLATED_METADATA=True" >> $localconf

echo "TEMPEST_USE_TEST_ACCOUNTS=True" >> $localconf
echo "TEMPEST_ALLOW_TENANT_ISOLATION=False" >> $localconf
echo "TEMPEST_CONCURRENCY=${MANILA_TEMPEST_CONCURRENCY:-8}" >> $localconf

MANILA_SETUP_IPV6=${MANILA_SETUP_IPV6:-False}
echo "MANILA_SETUP_IPV6=${MANILA_SETUP_IPV6}" >> $localconf
if [[ "$MANILA_SETUP_IPV6" == True ]]; then
    # When setting up proper IPv6 networks, we should do it ourselves so we can
    # use Neutron Dynamic Routing plugin with address scopes instead of the
    # regular Neutron DevStack configuration.
    echo "NEUTRON_CREATE_INITIAL_NETWORKS=False" >> $localconf
    echo "IP_VERSION=4+6" >> $localconf
    echo "MANILA_RESTORE_IPV6_DEFAULT_ROUTE=False" >> $localconf
fi
