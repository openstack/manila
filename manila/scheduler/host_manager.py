# Copyright (c) 2011 OpenStack, LLC.
# Copyright (c) 2015 Rushil Chugh
# Copyright (c) 2015 Clinton Knight
# Copyright (c) 2015 EMC Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Manage hosts in the current zone.
"""

import re
try:
    from UserDict import IterableUserDict  # noqa
except ImportError:
    from collections import UserDict as IterableUserDict  # noqa

from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
import six

from manila import db
from manila import exception
from manila.scheduler.filters import base_host as base_host_filter
from manila.scheduler import utils as scheduler_utils
from manila.scheduler.weighers import base_host as base_host_weigher
from manila.share import utils as share_utils
from manila import utils


host_manager_opts = [
    cfg.ListOpt('scheduler_default_filters',
                default=[
                    'AvailabilityZoneFilter',
                    'CapacityFilter',
                    'CapabilitiesFilter',
                    'DriverFilter',
                    'ShareReplicationFilter',
                ],
                help='Which filter class names to use for filtering hosts '
                     'when not specified in the request.'),
    cfg.ListOpt('scheduler_default_weighers',
                default=[
                    'CapacityWeigher',
                    'GoodnessWeigher',
                ],
                help='Which weigher class names to use for weighing hosts.'),
    cfg.ListOpt(
        'scheduler_default_share_group_filters',
        default=[
            'AvailabilityZoneFilter',
            'ConsistentSnapshotFilter',
        ],
        help='Which filter class names to use for filtering hosts '
             'creating share group when not specified in the request.'),
]

CONF = cfg.CONF
CONF.register_opts(host_manager_opts)
CONF.import_opt('max_over_subscription_ratio', 'manila.share.driver')

LOG = log.getLogger(__name__)


class ReadOnlyDict(IterableUserDict):
    """A read-only dict."""

    def __init__(self, source=None):
        self.data = {}
        self.update(source)

    def __setitem__(self, key, item):
        raise TypeError

    def __delitem__(self, key):
        raise TypeError

    def clear(self):
        raise TypeError

    def pop(self, key, *args):
        raise TypeError

    def popitem(self):
        raise TypeError

    def update(self, source=None):
        if source is None:
            return
        elif isinstance(source, IterableUserDict):
            self.data = source.data
        elif isinstance(source, type({})):
            self.data = source
        else:
            raise TypeError


class HostState(object):
    """Mutable and immutable information tracked for a host."""

    def __init__(self, host, capabilities=None, service=None):
        self.capabilities = None
        self.service = None
        self.host = host
        self.update_capabilities(capabilities, service)

        self.share_backend_name = None
        self.vendor_name = None
        self.driver_version = 0
        self.storage_protocol = None
        self.qos = False
        # Mutable available resources.
        # These will change as resources are virtually "consumed".
        self.total_capacity_gb = 0
        self.free_capacity_gb = None
        self.reserved_percentage = 0
        self.allocated_capacity_gb = 0
        # NOTE(xyang): The apparent allocated space indicating how much
        # capacity has been provisioned. This could be the sum of sizes
        # of all shares on a backend, which could be greater than or
        # equal to the allocated_capacity_gb.
        self.provisioned_capacity_gb = 0
        self.max_over_subscription_ratio = 1.0
        self.thin_provisioning = False
        self.driver_handles_share_servers = False
        self.snapshot_support = True
        self.create_share_from_snapshot_support = True
        self.revert_to_snapshot_support = False
        self.mount_snapshot_support = False
        self.dedupe = False
        self.compression = False
        self.replication_type = None
        self.replication_domain = None
        self.ipv4_support = None
        self.ipv6_support = None

        # PoolState for all pools
        self.pools = {}
        self.updated = None

        # Share Group capabilities
        self.sg_consistent_snapshot_support = None

    def update_capabilities(self, capabilities=None, service=None):
        # Read-only capability dicts

        if capabilities is None:
            capabilities = {}
        self.capabilities = ReadOnlyDict(capabilities)
        if service is None:
            service = {}
        self.service = ReadOnlyDict(service)

    def update_from_share_capability(
            self, capability, service=None, context=None):
        """Update information about a host from its share_node info.

        'capability' is the status info reported by share backend, a typical
        capability looks like this::

            capability = {
                'share_backend_name': 'Local NFS',    #\
                'vendor_name': 'OpenStack',           #  backend level
                'driver_version': '1.0',              #  mandatory/fixed
                'storage_protocol': 'NFS',            #/ stats&capabilities

                'active_shares': 10,                  #\
                'IOPS_provisioned': 30000,            #  optional custom
                'fancy_capability_1': 'eat',          #  stats & capabilities
                'fancy_capability_2': 'drink',        #/

                'pools':[
                  {
                     'pool_name': '1st pool',         #\
                     'total_capacity_gb': 500,        #  mandatory stats
                     'free_capacity_gb': 230,         #   for pools
                     'allocated_capacity_gb': 270,    # |
                     'qos': 'False',                  # |
                     'reserved_percentage': 0,        #/

                     'dying_disks': 100,              #\
                     'super_hero_1': 'spider-man',    #  optional custom
                     'super_hero_2': 'flash',         #  stats &
                     'super_hero_3': 'neoncat',       #  capabilities
                     'super_hero_4': 'green lantern', #/
                   },
                  {
                     'pool_name': '2nd pool',
                     'total_capacity_gb': 1024,
                     'free_capacity_gb': 1024,
                     'allocated_capacity_gb': 0,
                     'qos': 'False',
                     'reserved_percentage': 0,

                     'dying_disks': 200,
                     'super_hero_1': 'superman',
                     'super_hero_2': 'Hulk',
                  }]
            }
        """
        self.update_capabilities(capability, service)

        if capability:
            if self.updated and self.updated > capability['timestamp']:
                return

            # Update backend level info
            self.update_backend(capability)

            # Update pool level info
            self.update_pools(capability, service, context=context)

    def update_pools(self, capability, service, context=None):
        """Update storage pools information from backend reported info."""
        if not capability:
            return

        pools = capability.get('pools', None)
        active_pools = set()
        if pools and isinstance(pools, list):
            # Update all pools stats according to information from list
            # of pools in share capacity
            for pool_cap in pools:
                pool_name = pool_cap['pool_name']
                self._append_backend_info(pool_cap)
                cur_pool = self.pools.get(pool_name, None)
                if not cur_pool:
                    # Add new pool
                    cur_pool = PoolState(self.host, pool_cap, pool_name)
                    self.pools[pool_name] = cur_pool
                cur_pool.update_from_share_capability(
                    pool_cap, service, context=context)

                active_pools.add(pool_name)
        elif pools is None:
            # To handle legacy driver that doesn't report pool
            # information in the capability, we have to prepare
            # a pool from backend level info, or to update the one
            # we created in self.pools.
            pool_name = self.share_backend_name
            if pool_name is None:
                # To get DEFAULT_POOL_NAME
                pool_name = share_utils.extract_host(self.host, 'pool', True)

            if len(self.pools) == 0:
                # No pool was there
                single_pool = PoolState(self.host, capability, pool_name)
                self._append_backend_info(capability)
                self.pools[pool_name] = single_pool
            else:
                # This is a update from legacy driver
                try:
                    single_pool = self.pools[pool_name]
                except KeyError:
                    single_pool = PoolState(self.host, capability, pool_name)
                    self._append_backend_info(capability)
                    self.pools[pool_name] = single_pool

            single_pool.update_from_share_capability(
                capability, service, context=context)
            active_pools.add(pool_name)

        # Remove non-active pools from self.pools
        nonactive_pools = set(self.pools.keys()) - active_pools
        for pool in nonactive_pools:
            LOG.debug("Removing non-active pool %(pool)s @ %(host)s "
                      "from scheduler cache.",
                      {'pool': pool, 'host': self.host})
            del self.pools[pool]

    def _append_backend_info(self, pool_cap):
        # Fill backend level info to pool if needed.
        if not pool_cap.get('share_backend_name'):
            pool_cap['share_backend_name'] = self.share_backend_name

        if not pool_cap.get('storage_protocol'):
            pool_cap['storage_protocol'] = self.storage_protocol

        if not pool_cap.get('vendor_name'):
            pool_cap['vendor_name'] = self.vendor_name

        if not pool_cap.get('driver_version'):
            pool_cap['driver_version'] = self.driver_version

        if not pool_cap.get('timestamp'):
            pool_cap['timestamp'] = self.updated

        if not pool_cap.get('storage_protocol'):
            pool_cap['storage_protocol'] = self.storage_protocol

        if 'driver_handles_share_servers' not in pool_cap:
            pool_cap['driver_handles_share_servers'] = (
                self.driver_handles_share_servers)

        if 'snapshot_support' not in pool_cap:
            pool_cap['snapshot_support'] = self.snapshot_support

        if 'create_share_from_snapshot_support' not in pool_cap:
            pool_cap['create_share_from_snapshot_support'] = (
                self.create_share_from_snapshot_support)

        if 'revert_to_snapshot_support' not in pool_cap:
            pool_cap['revert_to_snapshot_support'] = (
                self.revert_to_snapshot_support)

        if 'mount_snapshot_support' not in pool_cap:
            pool_cap['mount_snapshot_support'] = self.mount_snapshot_support

        if 'dedupe' not in pool_cap:
            pool_cap['dedupe'] = self.dedupe

        if 'compression' not in pool_cap:
            pool_cap['compression'] = self.compression

        if not pool_cap.get('replication_type'):
            pool_cap['replication_type'] = self.replication_type

        if not pool_cap.get('replication_domain'):
            pool_cap['replication_domain'] = self.replication_domain

        if 'sg_consistent_snapshot_support' not in pool_cap:
            pool_cap['sg_consistent_snapshot_support'] = (
                self.sg_consistent_snapshot_support)

        if self.ipv4_support is not None:
            pool_cap['ipv4_support'] = self.ipv4_support

        if self.ipv6_support is not None:
            pool_cap['ipv6_support'] = self.ipv6_support

    def update_backend(self, capability):
        self.share_backend_name = capability.get('share_backend_name')
        self.vendor_name = capability.get('vendor_name')
        self.driver_version = capability.get('driver_version')
        self.storage_protocol = capability.get('storage_protocol')
        self.driver_handles_share_servers = capability.get(
            'driver_handles_share_servers')
        self.snapshot_support = capability.get('snapshot_support')
        self.create_share_from_snapshot_support = capability.get(
            'create_share_from_snapshot_support')
        self.revert_to_snapshot_support = capability.get(
            'revert_to_snapshot_support', False)
        self.mount_snapshot_support = capability.get(
            'mount_snapshot_support', False)
        self.updated = capability['timestamp']
        self.replication_type = capability.get('replication_type')
        self.replication_domain = capability.get('replication_domain')
        self.sg_consistent_snapshot_support = capability.get(
            'share_group_stats', {}).get('consistent_snapshot_support')
        if capability.get('ipv4_support') is not None:
            self.ipv4_support = capability['ipv4_support']
        if capability.get('ipv6_support') is not None:
            self.ipv6_support = capability['ipv6_support']

    def consume_from_share(self, share):
        """Incrementally update host state from an share."""

        if (isinstance(self.free_capacity_gb, six.string_types)
                and self.free_capacity_gb != 'unknown'):
            raise exception.InvalidCapacity(
                name='free_capacity_gb',
                value=six.text_type(self.free_capacity_gb)
            )

        if self.free_capacity_gb != 'unknown':
            self.free_capacity_gb -= share['size']
        self.updated = timeutils.utcnow()

    def __repr__(self):
        return ("host: '%(host)s', free_capacity_gb: %(free)s, "
                "pools: %(pools)s" % {'host': self.host,
                                      'free': self.free_capacity_gb,
                                      'pools': self.pools}
                )


class PoolState(HostState):

    def __init__(self, host, capabilities, pool_name):
        new_host = share_utils.append_host(host, pool_name)
        super(PoolState, self).__init__(new_host, capabilities)
        self.pool_name = pool_name
        # No pools in pool
        self.pools = None

    def _estimate_provisioned_capacity(self, host_name, context=None):
        """Estimate provisioned capacity from share sizes on backend."""
        provisioned_capacity = 0

        instances = db.share_instances_get_all_by_host(
            context, host_name, with_share_data=True)

        for instance in instances:
            # Size of share instance that's still being created, will be None.
            provisioned_capacity += instance['size'] or 0
        return provisioned_capacity

    def update_from_share_capability(
            self, capability, service=None, context=None):
        """Update information about a pool from its share_node info."""
        self.update_capabilities(capability, service)
        if capability:
            if self.updated and self.updated > capability['timestamp']:
                return
            self.update_backend(capability)

            self.total_capacity_gb = capability['total_capacity_gb']
            self.free_capacity_gb = capability['free_capacity_gb']
            self.allocated_capacity_gb = capability.get(
                'allocated_capacity_gb', 0)
            self.qos = capability.get('qos', False)
            self.reserved_percentage = capability['reserved_percentage']
            # NOTE(xyang): provisioned_capacity_gb is the apparent total
            # capacity of all the shares created on a backend, which is
            # greater than or equal to allocated_capacity_gb, which is the
            # apparent total capacity of all the shares created on a backend
            # in Manila.
            # NOTE(nidhimittalhada): If 'provisioned_capacity_gb' is not set,
            # then calculating 'provisioned_capacity_gb' from share sizes
            # on host, as per information available in manila database.
            self.provisioned_capacity_gb = capability.get(
                'provisioned_capacity_gb') or (
                self._estimate_provisioned_capacity(self.host,
                                                    context=context))

            self.max_over_subscription_ratio = capability.get(
                'max_over_subscription_ratio',
                CONF.max_over_subscription_ratio)
            self.thin_provisioning = capability.get(
                'thin_provisioning', False)
            self.dedupe = capability.get(
                'dedupe', False)
            self.compression = capability.get(
                'compression', False)
            self.replication_type = capability.get(
                'replication_type', self.replication_type)
            self.replication_domain = capability.get(
                'replication_domain')
            self.sg_consistent_snapshot_support = capability.get(
                'sg_consistent_snapshot_support')

    def update_pools(self, capability):
        # Do nothing, since we don't have pools within pool, yet
        pass


class HostManager(object):
    """Base HostManager class."""

    host_state_cls = HostState

    def __init__(self):
        self.service_states = {}  # { <host>: {<service>: {cap k : v}}}
        self.host_state_map = {}
        self.filter_handler = base_host_filter.HostFilterHandler(
            'manila.scheduler.filters')
        self.filter_classes = self.filter_handler.get_all_classes()
        self.weight_handler = base_host_weigher.HostWeightHandler(
            'manila.scheduler.weighers')
        self.weight_classes = self.weight_handler.get_all_classes()

    def _choose_host_filters(self, filter_cls_names):
        """Choose acceptable filters.

        Since the caller may specify which filters to use we need to
        have an authoritative list of what is permissible. This
        function checks the filter names against a predefined set of
        acceptable filters.
        """
        if filter_cls_names is None:
            filter_cls_names = CONF.scheduler_default_filters
        if not isinstance(filter_cls_names, (list, tuple)):
            filter_cls_names = [filter_cls_names]
        good_filters = []
        bad_filters = []
        for filter_name in filter_cls_names:
            found_class = False
            for cls in self.filter_classes:
                if cls.__name__ == filter_name:
                    found_class = True
                    good_filters.append(cls)
                    break
            if not found_class:
                bad_filters.append(filter_name)
        if bad_filters:
            msg = ", ".join(bad_filters)
            raise exception.SchedulerHostFilterNotFound(filter_name=msg)
        return good_filters

    def _choose_host_weighers(self, weight_cls_names):
        """Choose acceptable weighers.

        Since the caller may specify which weighers to use, we need to
        have an authoritative list of what is permissible. This
        function checks the weigher names against a predefined set of
        acceptable weighers.
        """
        if weight_cls_names is None:
            weight_cls_names = CONF.scheduler_default_weighers
        if not isinstance(weight_cls_names, (list, tuple)):
            weight_cls_names = [weight_cls_names]

        good_weighers = []
        bad_weighers = []
        for weigher_name in weight_cls_names:
            found_class = False
            for cls in self.weight_classes:
                if cls.__name__ == weigher_name:
                    good_weighers.append(cls)
                    found_class = True
                    break
            if not found_class:
                bad_weighers.append(weigher_name)
        if bad_weighers:
            msg = ", ".join(bad_weighers)
            raise exception.SchedulerHostWeigherNotFound(weigher_name=msg)
        return good_weighers

    def get_filtered_hosts(self, hosts, filter_properties,
                           filter_class_names=None):
        """Filter hosts and return only ones passing all filters."""
        filter_classes = self._choose_host_filters(filter_class_names)
        return self.filter_handler.get_filtered_objects(filter_classes,
                                                        hosts,
                                                        filter_properties)

    def get_weighed_hosts(self, hosts, weight_properties,
                          weigher_class_names=None):
        """Weigh the hosts."""
        weigher_classes = self._choose_host_weighers(weigher_class_names)
        weight_properties['server_pools_mapping'] = {}
        for backend, info in self.service_states.items():
            weight_properties['server_pools_mapping'].update(
                info.get('server_pools_mapping', {}))
        return self.weight_handler.get_weighed_objects(weigher_classes,
                                                       hosts,
                                                       weight_properties)

    def update_service_capabilities(self, service_name, host, capabilities):
        """Update the per-service capabilities based on this notification."""
        if service_name not in ('share',):
            LOG.debug('Ignoring %(service_name)s service update '
                      'from %(host)s',
                      {'service_name': service_name, 'host': host})
            return

        # Copy the capabilities, so we don't modify the original dict
        capability_copy = dict(capabilities)
        capability_copy["timestamp"] = timeutils.utcnow()  # Reported time
        self.service_states[host] = capability_copy

        LOG.debug("Received %(service_name)s service update from "
                  "%(host)s: %(cap)s",
                  {'service_name': service_name, 'host': host,
                   'cap': capabilities})

    def _update_host_state_map(self, context):

        # Get resource usage across the available share nodes:
        topic = CONF.share_topic
        share_services = db.service_get_all_by_topic(context, topic)

        active_hosts = set()
        for service in share_services:
            host = service['host']

            # Warn about down services and remove them from host_state_map
            if not utils.service_is_up(service) or service['disabled']:
                LOG.warning("Share service is down. (host: %s).", host)
                continue

            # Create and register host_state if not in host_state_map
            capabilities = self.service_states.get(host, None)
            host_state = self.host_state_map.get(host)
            if not host_state:
                host_state = self.host_state_cls(
                    host,
                    capabilities=capabilities,
                    service=dict(service.items()))
                self.host_state_map[host] = host_state

            # Update capabilities and attributes in host_state
            host_state.update_from_share_capability(
                capabilities, service=dict(service.items()), context=context)
            active_hosts.add(host)

        # remove non-active hosts from host_state_map
        nonactive_hosts = set(self.host_state_map.keys()) - active_hosts
        for host in nonactive_hosts:
            LOG.info("Removing non-active host: %(host)s from "
                     "scheduler cache.", {'host': host})
            self.host_state_map.pop(host, None)

    def get_all_host_states_share(self, context):
        """Returns a dict of all the hosts the HostManager knows about.

        Each of the consumable resources in HostState are
        populated with capabilities scheduler received from RPC.

        For example:
          {'192.168.1.100': HostState(), ...}
        """

        self._update_host_state_map(context)

        # Build a pool_state map and return that map instead of host_state_map
        all_pools = {}
        for host, state in self.host_state_map.items():
            for key in state.pools:
                pool = state.pools[key]
                # Use host.pool_name to make sure key is unique
                pool_key = '.'.join([host, pool.pool_name])
                all_pools[pool_key] = pool

        return all_pools.values()

    def get_pools(self, context, filters=None):
        """Returns a dict of all pools on all hosts HostManager knows about."""
        self._update_host_state_map(context)

        all_pools = []
        for host, host_state in self.host_state_map.items():
            for pool in host_state.pools.values():

                fully_qualified_pool_name = share_utils.append_host(
                    host, pool.pool_name)
                host_name = share_utils.extract_host(
                    fully_qualified_pool_name, level='host')
                backend_name = (share_utils.extract_host(
                    fully_qualified_pool_name, level='backend').split('@')[1]
                    if '@' in fully_qualified_pool_name else None)
                pool_name = share_utils.extract_host(
                    fully_qualified_pool_name, level='pool')

                new_pool = {
                    'name': fully_qualified_pool_name,
                    'host': host_name,
                    'backend': backend_name,
                    'pool': pool_name,
                    'capabilities': pool.capabilities,
                }
                if self._passes_filters(new_pool, filters):
                    all_pools.append(new_pool)
        return all_pools

    def _passes_filters(self, dict_to_check, filter_dict):
        """Applies a set of regex filters to a dictionary.

        If no filter keys are supplied, the data passes unfiltered and
        the method returns True.  Otherwise, each key in the filter
        (filter_dict) must be present in the data (dict_to_check)
        and the filter values are applied as regex expressions to
        the data values.  If any of the filter values fail to match
        their corresponding data values, the method returns False.
        But if all filters match, the method returns True.
        """
        if not filter_dict:
            return True

        for filter_key, filter_value in filter_dict.items():
            if filter_key not in dict_to_check:
                return False
            if filter_key == 'capabilities':
                if not scheduler_utils.capabilities_satisfied(
                        dict_to_check.get(filter_key), filter_value):
                    return False
            elif not re.match(filter_value, dict_to_check.get(filter_key)):
                return False

        return True
