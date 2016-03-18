# Copyright (c) 2014 SUSE Linux Products GmbH.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

__all__ = [
    'list_opts'
]

import copy
import itertools

import oslo_concurrency.opts
import oslo_log._options
import oslo_middleware.opts
import oslo_policy.opts

import manila.api.common
import manila.api.middleware.auth
import manila.common.config
import manila.compute
import manila.compute.nova
import manila.db.api
import manila.db.base
import manila.exception
import manila.network
import manila.network.linux.interface
import manila.network.neutron.api
import manila.network.neutron.neutron_network_plugin
import manila.network.nova_network_plugin
import manila.network.standalone_network_plugin
import manila.quota
import manila.scheduler.drivers.base
import manila.scheduler.drivers.simple
import manila.scheduler.host_manager
import manila.scheduler.manager
import manila.scheduler.scheduler_options
import manila.scheduler.weighers
import manila.scheduler.weighers.capacity
import manila.scheduler.weighers.pool
import manila.service
import manila.share.api
import manila.share.driver
import manila.share.drivers.cephfs.cephfs_native
import manila.share.drivers.emc.driver
import manila.share.drivers.emc.plugins.isilon.isilon
import manila.share.drivers.generic
import manila.share.drivers.glusterfs
import manila.share.drivers.glusterfs.common
import manila.share.drivers.glusterfs.layout
import manila.share.drivers.glusterfs.layout_directory
import manila.share.drivers.glusterfs.layout_volume
import manila.share.drivers.hdfs.hdfs_native
import manila.share.drivers.hitachi.hds_hnas
import manila.share.drivers.hpe.hpe_3par_driver
import manila.share.drivers.huawei.huawei_nas
import manila.share.drivers.ibm.gpfs
import manila.share.drivers.netapp.options
import manila.share.drivers.quobyte.quobyte
import manila.share.drivers.service_instance
import manila.share.drivers.tegile.tegile
import manila.share.drivers.windows.service_instance
import manila.share.drivers.windows.winrm_helper
import manila.share.drivers.zfsonlinux.driver
import manila.share.drivers.zfssa.zfssashare
import manila.share.drivers_private_data
import manila.share.hook
import manila.share.manager
import manila.volume
import manila.volume.cinder
import manila.wsgi


# List of *all* options in [DEFAULT] namespace of manila.
# Any new option list or option needs to be registered here.
_global_opt_lists = [
    # Keep list alphabetically sorted
    manila.api.common.api_common_opts,
    [manila.api.middleware.auth.use_forwarded_for_opt],
    manila.common.config.core_opts,
    manila.common.config.debug_opts,
    manila.common.config.global_opts,
    manila.compute._compute_opts,
    manila.compute.nova.nova_opts,
    manila.db.api.db_opts,
    [manila.db.base.db_driver_opt],
    manila.exception.exc_log_opts,
    manila.network.linux.interface.OPTS,
    manila.network.network_opts,
    manila.network.neutron.api.neutron_opts,
    manila.network.neutron.neutron_network_plugin.
    neutron_single_network_plugin_opts,
    manila.network.nova_network_plugin.nova_single_network_plugin_opts,
    manila.network.standalone_network_plugin.standalone_network_plugin_opts,
    manila.quota.quota_opts,
    manila.scheduler.drivers.base.scheduler_driver_opts,
    manila.scheduler.host_manager.host_manager_opts,
    [manila.scheduler.manager.scheduler_driver_opt],
    [manila.scheduler.scheduler_options.scheduler_json_config_location_opt],
    manila.scheduler.drivers.simple.simple_scheduler_opts,
    manila.scheduler.weighers.capacity.capacity_weight_opts,
    manila.scheduler.weighers.pool.pool_weight_opts,
    manila.service.service_opts,
    manila.share.api.share_api_opts,
    manila.share.driver.ganesha_opts,
    manila.share.driver.share_opts,
    manila.share.driver.ssh_opts,
    manila.share.drivers_private_data.private_data_opts,
    manila.share.drivers.cephfs.cephfs_native.cephfs_native_opts,
    manila.share.drivers.emc.driver.EMC_NAS_OPTS,
    manila.share.drivers.generic.share_opts,
    manila.share.drivers.glusterfs.common.glusterfs_common_opts,
    manila.share.drivers.glusterfs.GlusterfsManilaShare_opts,
    manila.share.drivers.glusterfs.layout.glusterfs_share_layout_opts,
    manila.share.drivers.glusterfs.layout_directory.
    glusterfs_directory_mapped_opts,
    manila.share.drivers.glusterfs.layout_volume.glusterfs_volume_mapped_opts,
    manila.share.drivers.hdfs.hdfs_native.hdfs_native_share_opts,
    manila.share.drivers.hitachi.hds_hnas.hds_hnas_opts,
    manila.share.drivers.hpe.hpe_3par_driver.HPE3PAR_OPTS,
    manila.share.drivers.huawei.huawei_nas.huawei_opts,
    manila.share.drivers.ibm.gpfs.gpfs_share_opts,
    manila.share.drivers.netapp.options.netapp_proxy_opts,
    manila.share.drivers.netapp.options.netapp_connection_opts,
    manila.share.drivers.netapp.options.netapp_transport_opts,
    manila.share.drivers.netapp.options.netapp_basicauth_opts,
    manila.share.drivers.netapp.options.netapp_provisioning_opts,
    manila.share.drivers.netapp.options.netapp_replication_opts,
    manila.share.drivers.quobyte.quobyte.quobyte_manila_share_opts,
    manila.share.drivers.service_instance.common_opts,
    manila.share.drivers.service_instance.no_share_servers_handling_mode_opts,
    manila.share.drivers.service_instance.share_servers_handling_mode_opts,
    manila.share.drivers.tegile.tegile.tegile_opts,
    manila.share.drivers.windows.service_instance.windows_share_server_opts,
    manila.share.drivers.windows.winrm_helper.winrm_opts,
    manila.share.drivers.zfsonlinux.driver.zfsonlinux_opts,
    manila.share.drivers.zfssa.zfssashare.ZFSSA_OPTS,
    manila.share.hook.hook_options,
    manila.share.manager.share_manager_opts,
    manila.volume._volume_opts,
    manila.volume.cinder.cinder_opts,
    manila.wsgi.eventlet_opts,
    manila.wsgi.socket_opts,
]

_opts = [
    (None, list(itertools.chain(*_global_opt_lists))),
]

_opts.extend(oslo_concurrency.opts.list_opts())
_opts.extend(oslo_log._options.list_opts())
_opts.extend(oslo_middleware.opts.list_opts())
_opts.extend(oslo_policy.opts.list_opts())
_opts.extend(manila.network.neutron.api.list_opts())
_opts.extend(manila.compute.nova.list_opts())
_opts.extend(manila.volume.cinder.list_opts())


def list_opts():
    """Return a list of oslo.config options available in Manila."""
    return [(m, copy.deepcopy(o)) for m, o in _opts]
