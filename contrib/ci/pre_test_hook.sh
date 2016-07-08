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

function save_configuration {
    # $1 - name of key
    # $2 - value for key
    # $3 - write to local.conf instead of localrc
    write_to_local_conf=$3
    for location in old new; do
        if [[ -d "$BASE/$location" ]]; then
            if [[ $(trueorfalse False write_to_local_conf) == True ]]; then
                echo -e "$1=$2" >> $BASE/$location/devstack/local.conf
            else
                echo "$1=$2" >> $BASE/$location/devstack/localrc
            fi
        fi
    done
}

save_configuration "DEVSTACK_GATE_TEMPEST_ALLOW_TENANT_ISOLATION" "1"
save_configuration "API_RATE_LIMIT" "False"
save_configuration "TEMPEST_SERVICES+" ",manila"
save_configuration "VOLUME_BACKING_FILE_SIZE" "22G"
save_configuration "CINDER_LVM_TYPE" "thin"

# NOTE(mkoderer): switch to keystone v3 by default
save_configuration "IDENTITY_API_VERSION" "3"

# NOTE(vponomaryov): Set oversubscription ratio for Cinder LVM driver
# bigger than 1.0, because in CI we do not need such small value.
# It will allow us to avoid exceeding real capacity in CI test runs.
save_configuration "CINDER_OVERSUBSCRIPTION_RATIO" "100.0"
save_configuration "MANILA_BACKEND1_CONFIG_GROUP_NAME" "london"
save_configuration "MANILA_BACKEND2_CONFIG_GROUP_NAME" "paris"
save_configuration "MANILA_SHARE_BACKEND1_NAME" "LONDON"
save_configuration "MANILA_SHARE_BACKEND2_NAME" "PARIS"

# === Handle script arguments ===
# First argument is expected to be a boolean-like value for DHSS.
DHSS=$1
DHSS=$(trueorfalse True DHSS)

# Second argument is expected to have codename of a share driver.
DRIVER=$2

# Third argument is expected to contain value equal either to 'singlebackend'
# or 'multibackend' that defines how many back-ends should be configured.
BACK_END_TYPE=$3

save_configuration "MANILA_OPTGROUP_london_driver_handles_share_servers" "$DHSS"
save_configuration "MANILA_OPTGROUP_paris_driver_handles_share_servers" "$DHSS"
save_configuration "MANILA_USE_SERVICE_INSTANCE_PASSWORD" "True"
save_configuration "MANILA_USE_DOWNGRADE_MIGRATIONS" "True"

if [[ "$BACK_END_TYPE" == "multibackend" ]]; then
    save_configuration "MANILA_MULTI_BACKEND" "True"
else
    save_configuration "MANILA_MULTI_BACKEND" "False"
fi

# Set MANILA_ADMIN_NET_RANGE for admin_network and data_service IP
save_configuration "MANILA_ADMIN_NET_RANGE" "${MANILA_ADMIN_NET_RANGE:=10.2.5.0/24}"
save_configuration "MANILA_DATA_NODE_IP" "${MANILA_DATA_NODE_IP:=$MANILA_ADMIN_NET_RANGE}"
save_configuration "MANILA_DATA_COPY_CHECK_HASH" "${MANILA_DATA_COPY_CHECK_HASH:=True}"

# Share Migration CI tests migration_continue period task interval
save_configuration "MANILA_SHARE_MIGRATION_PERIOD_TASK_INTERVAL" "${MANILA_SHARE_MIGRATION_PERIOD_TASK_INTERVAL:=5}"

MANILA_SERVICE_IMAGE_ENABLED=${MANILA_SERVICE_IMAGE_ENABLED:-False}
DEFAULT_EXTRA_SPECS=${DEFAULT_EXTRA_SPECS:-"'snapshot_support=True create_share_from_snapshot_support=True'"}

if [[ "$DRIVER" == "generic" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    save_configuration "SHARE_DRIVER" "manila.share.drivers.generic.GenericShareDriver"
    save_configuration "[[post-config|${NOVA_CONF:-/etc/nova/nova.conf}]]\n[DEFAULT]\nquota_instances" "30\n" "True"
    save_configuration "[[post-config|${NEUTRON_CONF:-/etc/neutron/neutron.conf}]]\n[DEFAULT]\nmax_fixed_ips_per_port" "100\n" "True"
    save_configuration "[[post-config|${NEUTRON_CONF:-/etc/neutron/neutron.conf}]]\n[QUOTAS]\nquota_subnet" "-1\n" "True"
elif [[ "$DRIVER" == "windows" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    save_configuration "SHARE_DRIVER" "manila.share.drivers.windows.windows_smb_driver.WindowsSMBDriver"
elif [[ "$DRIVER" == "dummy" ]]; then
    driver_path="manila.tests.share.drivers.dummy.DummyDriver"
    DEFAULT_EXTRA_SPECS="'snapshot_support=True create_share_from_snapshot_support=True revert_to_snapshot_support=True mount_snapshot_support=True'"
    save_configuration "MANILA_SERVICE_IMAGE_ENABLED" "False"
    save_configuration "SHARE_DRIVER" "$driver_path"
    save_configuration "SUPPRESS_ERRORS_IN_CLEANUP" "False"
    save_configuration "MANILA_REPLICA_STATE_UPDATE_INTERVAL" "10"
    save_configuration "MANILA_ENABLED_BACKENDS" "alpha,beta,gamma,delta"
    save_configuration "MANILA_CONFIGURE_GROUPS" "alpha,beta,gamma,delta,membernet,adminnet"

    save_configuration "MANILA_OPTGROUP_alpha_share_driver" "$driver_path"
    save_configuration "MANILA_OPTGROUP_alpha_driver_handles_share_servers" "True"
    save_configuration "MANILA_OPTGROUP_alpha_share_backend_name" "ALPHA"
    save_configuration "MANILA_OPTGROUP_alpha_network_config_group" "membernet"
    save_configuration "MANILA_OPTGROUP_alpha_admin_network_config_group" "adminnet"

    save_configuration "MANILA_OPTGROUP_beta_share_driver" "$driver_path"
    save_configuration "MANILA_OPTGROUP_beta_driver_handles_share_servers" "True"
    save_configuration "MANILA_OPTGROUP_beta_share_backend_name" "BETA"
    save_configuration "MANILA_OPTGROUP_beta_network_config_group" "membernet"
    save_configuration "MANILA_OPTGROUP_beta_admin_network_config_group" "adminnet"

    save_configuration "MANILA_OPTGROUP_gamma_share_driver" "$driver_path"
    save_configuration "MANILA_OPTGROUP_gamma_driver_handles_share_servers" "False"
    save_configuration "MANILA_OPTGROUP_gamma_share_backend_name" "GAMMA"
    save_configuration "MANILA_OPTGROUP_gamma_replication_domain" "DUMMY_DOMAIN"

    save_configuration "MANILA_OPTGROUP_delta_share_driver" "$driver_path"
    save_configuration "MANILA_OPTGROUP_delta_driver_handles_share_servers" "False"
    save_configuration "MANILA_OPTGROUP_delta_share_backend_name" "DELTA"
    save_configuration "MANILA_OPTGROUP_delta_replication_domain" "DUMMY_DOMAIN"

    save_configuration "MANILA_OPTGROUP_membernet_network_api_class" "manila.network.standalone_network_plugin.StandaloneNetworkPlugin"
    save_configuration "MANILA_OPTGROUP_membernet_standalone_network_plugin_gateway" "10.0.0.1"
    save_configuration "MANILA_OPTGROUP_membernet_standalone_network_plugin_mask" "24"
    save_configuration "MANILA_OPTGROUP_membernet_standalone_network_plugin_network_type" "vlan"
    save_configuration "MANILA_OPTGROUP_membernet_standalone_network_plugin_segmentation_id" "1010"
    save_configuration "MANILA_OPTGROUP_membernet_standalone_network_plugin_allowed_ip_ranges" "10.0.0.10-10.0.0.209"
    save_configuration "MANILA_OPTGROUP_membernet_standalone_network_plugin_ip_version" "4"

    save_configuration "MANILA_OPTGROUP_adminnet_network_api_class" "manila.network.standalone_network_plugin.StandaloneNetworkPlugin"
    save_configuration "MANILA_OPTGROUP_adminnet_standalone_network_plugin_gateway" "11.0.0.1"
    save_configuration "MANILA_OPTGROUP_adminnet_standalone_network_plugin_mask" "24"
    save_configuration "MANILA_OPTGROUP_adminnet_standalone_network_plugin_network_type" "vlan"
    save_configuration "MANILA_OPTGROUP_adminnet_standalone_network_plugin_segmentation_id" "1011"
    save_configuration "MANILA_OPTGROUP_adminnet_standalone_network_plugin_allowed_ip_ranges" "11.0.0.10-11.0.0.19,11.0.0.30-11.0.0.39,11.0.0.50-11.0.0.199"
    save_configuration "MANILA_OPTGROUP_adminnet_standalone_network_plugin_ip_version" "4"

    export MANILA_TEMPEST_CONCURRENCY=24

elif [[ "$DRIVER" == "lvm" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    DEFAULT_EXTRA_SPECS="'snapshot_support=True create_share_from_snapshot_support=True revert_to_snapshot_support=True mount_snapshot_support=True'"
    save_configuration "SHARE_DRIVER" "manila.share.drivers.lvm.LVMShareDriver"
    save_configuration "SHARE_BACKING_FILE_SIZE" "32000M"
elif [[ "$DRIVER" == "zfsonlinux" ]]; then
    MANILA_SERVICE_IMAGE_ENABLED=True
    save_configuration "SHARE_DRIVER" "manila.share.drivers.zfsonlinux.driver.ZFSonLinuxShareDriver"
    save_configuration "RUN_MANILA_REPLICATION_TESTS" "True"
    # Set the replica_state_update_interval to 60 seconds to make
    # replication tests run faster. The default is 300, which is greater than
    # the build timeout for ZFS on the gate.
    save_configuration "MANILA_REPLICA_STATE_UPDATE_INTERVAL" "60"
    save_configuration "MANILA_ZFSONLINUX_USE_SSH" "True"
    # Set proper host IP for user export to be able to run scenario tests correctly
    save_configuration "MANILA_ZFSONLINUX_SHARE_EXPORT_IP" "$HOST"
    save_configuration "MANILA_ZFSONLINUX_SERVICE_IP" "127.0.0.1"
elif [[ "$DRIVER" == "container" ]]; then
    DEFAULT_EXTRA_SPECS="'snapshot_support=false'"
    save_configuration "SHARE_DRIVER" "manila.share.drivers.container.driver.ContainerShareDriver"
    save_configuration "SHARE_BACKING_FILE_SIZE" "64000M"
fi

save_configuration "MANILA_SERVICE_IMAGE_ENABLED" "$MANILA_SERVICE_IMAGE_ENABLED"
save_configuration "MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS" "$DEFAULT_EXTRA_SPECS"

# Enabling isolated metadata in Neutron is required because
# Tempest creates isolated networks and created vm's in scenario tests don't
# have access to Nova Metadata service. This leads to unavailability of
# created vm's in scenario tests.
save_configuration "ENABLE_ISOLATED_METADATA" "True"

save_configuration "TEMPEST_USE_TEST_ACCOUNTS" "True"
save_configuration "TEMPEST_ALLOW_TENANT_ISOLATION" "False"
save_configuration "TEMPEST_CONCURRENCY" "${MANILA_TEMPEST_CONCURRENCY:-8}"

# Go to Tempest dir and checkout stable commit to avoid possible
# incompatibilities for plugin stored in Manila repo.
cd $BASE/new/tempest
source $BASE/new/manila/contrib/ci/common.sh
git checkout $MANILA_TEMPEST_COMMIT

# Print current Tempest status
git status
