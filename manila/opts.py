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


import manila.api.middleware.auth
import manila.api.middleware.sizelimit
import manila.common.config
import manila.compute
import manila.compute.nova
import manila.db.api
import manila.db.base
import manila.exception
import manila.network
import manila.network.linux.interface
import manila.network.neutron.api
import manila.openstack.common.eventlet_backdoor
import manila.openstack.common.lockutils
import manila.openstack.common.log
import manila.openstack.common.policy
import manila.quota
import manila.scheduler.driver
import manila.scheduler.host_manager
import manila.scheduler.manager
import manila.scheduler.scheduler_options
import manila.scheduler.simple
import manila.scheduler.weights
import manila.scheduler.weights.capacity
import manila.service
import manila.share.api
import manila.share.driver
import manila.share.drivers.emc.driver
import manila.share.drivers.generic
import manila.share.drivers.glusterfs
import manila.share.drivers.glusterfs_native
import manila.share.drivers.ibm.gpfs
import manila.share.drivers.netapp.cluster_mode
import manila.share.drivers.service_instance
import manila.share.drivers.zfssa.zfssashare
import manila.share.manager
import manila.volume
import manila.volume.cinder
import manila.wsgi

# List of *all* options in [DEFAULT] namespace of manila.
# Any new option list or option needs to be registered here.
_global_opt_lists = [
    # Keep list alphabetically sorted
    [manila.api.middleware.auth.use_forwarded_for_opt],
    [manila.api.middleware.sizelimit.max_request_body_size_opt],
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
    manila.openstack.common.eventlet_backdoor.eventlet_backdoor_opts,
    manila.openstack.common.lockutils.util_opts,
    manila.openstack.common.log.common_cli_opts,
    manila.openstack.common.log.generic_log_opts,
    manila.openstack.common.log.log_opts,
    manila.openstack.common.log.logging_cli_opts,
    manila.openstack.common.policy.policy_opts,
    manila.quota.quota_opts,
    manila.scheduler.driver.scheduler_driver_opts,
    manila.scheduler.host_manager.host_manager_opts,
    manila.scheduler.host_manager.host_manager_opts,
    [manila.scheduler.manager.scheduler_driver_opt],
    [manila.scheduler.scheduler_options.scheduler_json_config_location_opt],
    manila.scheduler.simple.simple_scheduler_opts,
    manila.scheduler.simple.simple_scheduler_opts,
    manila.scheduler.weights.capacity.capacity_weight_opts,
    manila.scheduler.weights.capacity.capacity_weight_opts,
    manila.service.service_opts,
    manila.share.api.share_api_opts,
    manila.share.driver.ganesha_opts,
    manila.share.driver.share_opts,
    manila.share.driver.ssh_opts,
    manila.share.drivers.emc.driver.EMC_NAS_OPTS,
    manila.share.drivers.generic.share_opts,
    manila.share.drivers.glusterfs.GlusterfsManilaShare_opts,
    manila.share.drivers.glusterfs_native.glusterfs_native_manila_share_opts,
    manila.share.drivers.ibm.gpfs.gpfs_share_opts,
    manila.share.drivers.netapp.cluster_mode.NETAPP_NAS_OPTS,
    manila.share.drivers.service_instance.server_opts,
    manila.share.drivers.zfssa.zfssashare.ZFSSA_OPTS,
    manila.share.manager.share_manager_opts,
    manila.volume._volume_opts,
    manila.volume.cinder.cinder_opts,
    manila.wsgi.eventlet_opts,
    manila.wsgi.socket_opts,
]

_opts = [
    (None, list(itertools.chain(*_global_opt_lists))),
]


def list_opts():
    """Return a list of oslo.config options available in Manila."""
    return [(m, copy.deepcopy(o)) for m, o in _opts]
