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

localconf=$BASE/new/devstack/local.conf

echo "[[local|localrc]]" >> $localconf
echo "DEVSTACK_GATE_TEMPEST_ALLOW_TENANT_ISOLATION=1" >> $localconf
echo "API_RATE_LIMIT=False" >> $localconf
echo "TEMPEST_SERVICES+=,manila" >> $localconf
echo "VOLUME_BACKING_FILE_SIZE=22G" >> $localconf
echo "CINDER_LVM_TYPE=thin" >> $localconf

# NOTE(mkoderer): switch to keystone v3 by default
echo "IDENTITY_API_VERSION=3" >> $localconf

# NOTE(vponomaryov): Set oversubscription ratio for Cinder LVM driver
# bigger than 1.0, because in CI we do not need such small value.
# It will allow us to avoid exceeding real capacity in CI test runs.
echo "CINDER_OVERSUBSCRIPTION_RATIO=100.0" >> $localconf
echo "MANILA_BACKEND1_CONFIG_GROUP_NAME=london" >> $localconf
echo "MANILA_BACKEND2_CONFIG_GROUP_NAME=paris" >> $localconf
echo "MANILA_SHARE_BACKEND1_NAME=LONDON" >> $localconf
echo "MANILA_SHARE_BACKEND2_NAME=PARIS" >> $localconf

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

if [[ "$BACK_END_TYPE" == "multibackend" ]]; then
    echo "MANILA_MULTI_BACKEND=True" >> $localconf
else
    echo "MANILA_MULTI_BACKEND=False" >> $localconf
fi

# Set MANILA_ADMIN_NET_RANGE for admin_network and data_service IP
echo "MANILA_ADMIN_NET_RANGE=${MANILA_ADMIN_NET_RANGE:=10.2.5.0/24}" >> $localconf
echo "MANILA_DATA_NODE_IP=${MANILA_DATA_NODE_IP:=$MANILA_ADMIN_NET_RANGE}" >> $localconf
echo "MANILA_DATA_COPY_CHECK_HASH=${MANILA_DATA_COPY_CHECK_HASH:=True}" >> $localconf

# Share Migration CI tests migration_continue period task interval
echo "MANILA_SHARE_MIGRATION_PERIOD_TASK_INTERVAL=${MANILA_SHARE_MIGRATION_PERIOD_TASK_INTERVAL:=1}" >> $localconf

MANILA_SERVICE_IMAGE_ENABLED=${MANILA_SERVICE_IMAGE_ENABLED:-False}
DEFAULT_EXTRA_SPECS=${DEFAULT_EXTRA_SPECS:-"'snapshot_support=True create_share_from_snapshot_support=True'"}

if [[ "$DRIVER" == "generic"* ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    echo "SHARE_DRIVER=manila.share.drivers.generic.GenericShareDriver" >> $localconf
elif [[ "$DRIVER" == "windows" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    echo "SHARE_DRIVER=manila.share.drivers.windows.windows_smb_driver.WindowsSMBDriver" >> $localconf
elif [[ "$DRIVER" == "dummy" ]]; then
    driver_path="manila.tests.share.drivers.dummy.DummyDriver"
    DEFAULT_EXTRA_SPECS="'snapshot_support=True create_share_from_snapshot_support=True revert_to_snapshot_support=True mount_snapshot_support=True'"
    echo "MANILA_SERVICE_IMAGE_ENABLED=False" >> $localconf

    # Run dummy driver CI job using standalone approach for running
    # manila API service just because we need to test this approach too,
    # that is very useful for development needs.
    echo "MANILA_USE_MOD_WSGI=False" >> $localconf

    echo "SHARE_DRIVER=$driver_path" >> $localconf
    echo "SUPPRESS_ERRORS_IN_CLEANUP=False" >> $localconf
    echo "MANILA_REPLICA_STATE_UPDATE_INTERVAL=10" >> $localconf
    echo "MANILA_ENABLED_BACKENDS=alpha,beta,gamma,delta" >> $localconf
    echo "MANILA_CONFIGURE_GROUPS=alpha,beta,gamma,delta,membernet,adminnet" >> $localconf

    echo "MANILA_OPTGROUP_alpha_share_driver=$driver_path" >> $localconf
    echo "MANILA_OPTGROUP_alpha_driver_handles_share_servers=True" >> $localconf
    echo "MANILA_OPTGROUP_alpha_share_backend_name=ALPHA" >> $localconf
    echo "MANILA_OPTGROUP_alpha_network_config_group=membernet" >> $localconf
    echo "MANILA_OPTGROUP_alpha_admin_network_config_group=adminnet" >> $localconf

    echo "MANILA_OPTGROUP_beta_share_driver=$driver_path" >> $localconf
    echo "MANILA_OPTGROUP_beta_driver_handles_share_servers=True" >> $localconf
    echo "MANILA_OPTGROUP_beta_share_backend_name=BETA" >> $localconf
    echo "MANILA_OPTGROUP_beta_network_config_group=membernet" >> $localconf
    echo "MANILA_OPTGROUP_beta_admin_network_config_group=adminnet" >> $localconf

    echo "MANILA_OPTGROUP_gamma_share_driver=$driver_path" >> $localconf
    echo "MANILA_OPTGROUP_gamma_driver_handles_share_servers=False" >> $localconf
    echo "MANILA_OPTGROUP_gamma_share_backend_name=GAMMA" >> $localconf
    echo "MANILA_OPTGROUP_gamma_replication_domain=DUMMY_DOMAIN" >> $localconf

    echo "MANILA_OPTGROUP_delta_share_driver=$driver_path" >> $localconf
    echo "MANILA_OPTGROUP_delta_driver_handles_share_servers=False" >> $localconf
    echo "MANILA_OPTGROUP_delta_share_backend_name=DELTA" >> $localconf
    echo "MANILA_OPTGROUP_delta_replication_domain=DUMMY_DOMAIN" >> $localconf

    echo "MANILA_OPTGROUP_membernet_network_api_class=manila.network.standalone_network_plugin.StandaloneNetworkPlugin" >> $localconf
    echo "MANILA_OPTGROUP_membernet_standalone_network_plugin_gateway=10.0.0.1" >> $localconf
    echo "MANILA_OPTGROUP_membernet_standalone_network_plugin_mask=24" >> $localconf
    echo "MANILA_OPTGROUP_membernet_standalone_network_plugin_network_type=vlan" >> $localconf
    echo "MANILA_OPTGROUP_membernet_standalone_network_plugin_segmentation_id=1010" >> $localconf
    echo "MANILA_OPTGROUP_membernet_standalone_network_plugin_allowed_ip_ranges=10.0.0.10-10.0.0.209" >> $localconf
    echo "MANILA_OPTGROUP_membernet_standalone_network_plugin_ip_version=4" >> $localconf

    echo "MANILA_OPTGROUP_adminnet_network_api_class=manila.network.standalone_network_plugin.StandaloneNetworkPlugin" >> $localconf
    echo "MANILA_OPTGROUP_adminnet_standalone_network_plugin_gateway=11.0.0.1" >> $localconf
    echo "MANILA_OPTGROUP_adminnet_standalone_network_plugin_mask=24" >> $localconf
    echo "MANILA_OPTGROUP_adminnet_standalone_network_plugin_network_type=vlan" >> $localconf
    echo "MANILA_OPTGROUP_adminnet_standalone_network_plugin_segmentation_id=1011" >> $localconf
    echo "MANILA_OPTGROUP_adminnet_standalone_network_plugin_allowed_ip_ranges=11.0.0.10-11.0.0.19,11.0.0.30-11.0.0.39,11.0.0.50-11.0.0.199" >> $localconf
    echo "MANILA_OPTGROUP_adminnet_standalone_network_plugin_ip_version=4" >> $localconf

    export MANILA_TEMPEST_CONCURRENCY=24
    export MANILA_CONFIGURE_DEFAULT_TYPES=False

elif [[ "$DRIVER" == "lvm" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    DEFAULT_EXTRA_SPECS="'snapshot_support=True create_share_from_snapshot_support=True revert_to_snapshot_support=True mount_snapshot_support=True'"

    echo "SHARE_DRIVER=manila.share.drivers.lvm.LVMShareDriver" >> $localconf
    echo "SHARE_BACKING_FILE_SIZE=32000M" >> $localconf
    export MANILA_SETUP_IPV6=True
elif [[ "$DRIVER" == "zfsonlinux" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    echo "SHARE_DRIVER=manila.share.drivers.zfsonlinux.driver.ZFSonLinuxShareDriver" >> $localconf
    echo "RUN_MANILA_REPLICATION_TESTS=True" >> $localconf
    # Set the replica_state_update_interval to 60 seconds to make
    # replication tests run faster. The default is 300, which is greater than
    # the build timeout for ZFS on the gate.
    echo "MANILA_REPLICA_STATE_UPDATE_INTERVAL=60" >> $localconf
    echo "MANILA_ZFSONLINUX_USE_SSH=True" >> $localconf
    # Set proper host IP for user export to be able to run scenario tests correctly
    echo "MANILA_ZFSONLINUX_SHARE_EXPORT_IP=$HOST" >> $localconf
    echo "MANILA_ZFSONLINUX_SERVICE_IP=127.0.0.1" >> $localconf
elif [[ "$DRIVER" == "container"* ]]; then
    DEFAULT_EXTRA_SPECS="'snapshot_support=false'"
    echo "SHARE_DRIVER=manila.share.drivers.container.driver.ContainerShareDriver" >> $localconf
    echo "SHARE_BACKING_FILE_SIZE=64000M" >> $localconf
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
fi

if [[ "$DRIVER" == "generic"* ]]; then
    echo -e '[[post-config|${NOVA_CONF:-/etc/nova/nova.conf}]]\n[DEFAULT]\nquota_instances=30\n' >> $localconf
    echo -e '[[post-config|${NEUTRON_CONF:-/etc/neutron/neutron.conf}]]\n[DEFAULT]\nmax_fixed_ips_per_port=100\n' >> $localconf
    echo -e '[[post-config|${NEUTRON_CONF:-/etc/neutron/neutron.conf}]]\n[QUOTAS]\nquota_subnet=-1\n' >> $localconf
fi

# Required for "grenade" job that uses devstack config from 'old' directory.
if [[ -d "$BASE/old/devstack" ]]; then
    cp $localconf $BASE/old/devstack/local.conf
fi

cd $BASE/new/tempest
source $BASE/new/manila/contrib/ci/common.sh

# Print current Tempest status
git status
