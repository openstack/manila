# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2016 EMC Corporation
#
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
from oslo_log import log
from oslo_utils import strutils

from manila.scheduler.filters import extra_specs_ops

LOG = log.getLogger(__name__)


def generate_stats(host_state, properties):
    """Generates statistics from host and share data."""

    host_stats = {
        'host': host_state.host,
        'share_backend_name': host_state.share_backend_name,
        'vendor_name': host_state.vendor_name,
        'driver_version': host_state.driver_version,
        'storage_protocol': host_state.storage_protocol,
        'qos': host_state.qos,
        'total_capacity_gb': host_state.total_capacity_gb,
        'allocated_capacity_gb': host_state.allocated_capacity_gb,
        'free_capacity_gb': host_state.free_capacity_gb,
        'reserved_percentage': host_state.reserved_percentage,
        'driver_handles_share_servers':
            host_state.driver_handles_share_servers,
        'thin_provisioning': host_state.thin_provisioning,
        'updated': host_state.updated,
        'dedupe': host_state.dedupe,
        'compression': host_state.compression,
        'snapshot_support': host_state.snapshot_support,
        'create_share_from_snapshot_support':
            host_state.create_share_from_snapshot_support,
        'revert_to_snapshot_support': host_state.revert_to_snapshot_support,
        'mount_snapshot_support': host_state.mount_snapshot_support,
        'replication_domain': host_state.replication_domain,
        'replication_type': host_state.replication_type,
        'provisioned_capacity_gb': host_state.provisioned_capacity_gb,
        'pools': host_state.pools,
        'max_over_subscription_ratio':
            host_state.max_over_subscription_ratio,
        'sg_consistent_snapshot_support': (
            host_state.sg_consistent_snapshot_support),
        'ipv4_support': host_state.ipv4_support,
        'ipv6_support': host_state.ipv6_support,
    }

    host_caps = host_state.capabilities

    share_type = properties.get('share_type', {})
    extra_specs = share_type.get('extra_specs', {})

    share_group_type = properties.get('share_group_type', {})
    group_specs = share_group_type.get('group_specs', {})

    request_spec = properties.get('request_spec', {})
    share_stats = request_spec.get('resource_properties', {})

    stats = {
        'host_stats': host_stats,
        'host_caps': host_caps,
        'share_type': share_type,
        'extra_specs': extra_specs,
        'share_stats': share_stats,
        'share_group_type': share_group_type,
        'group_specs': group_specs,
    }

    return stats


def use_thin_logic(share_type):
    # NOTE(xyang): To preserve the existing behavior, we use thin logic
    # to evaluate in two cases:
    # 1) 'thin_provisioning' is not set in extra specs (This is for
    #    backward compatibility. If not set, the scheduler behaves
    #    the same as before this bug fix).
    # 2) 'thin_provisioning' is set in extra specs and it is
    #    '<is> True' or 'True'.
    # Otherwise we use the thick logic to evaluate.
    use_thin_logic = True
    thin_spec = None
    try:
        thin_spec = share_type.get('extra_specs', {}).get(
            'thin_provisioning')
        if thin_spec is None:
            thin_spec = share_type.get('extra_specs', {}).get(
                'capabilities:thin_provisioning')
        # NOTE(xyang) 'use_thin_logic' and 'thin_provisioning' are NOT
        # the same thing. The first purpose of "use_thin_logic" is to
        # preserve the existing scheduler behavior if 'thin_provisioning'
        # is NOT in extra_specs (if thin_spec is None, use_thin_logic
        # should be True). The second purpose of 'use_thin_logic'
        # is to honor 'thin_provisioning' if it is in extra specs (if
        # thin_spec is set to True, use_thin_logic should be True; if
        # thin_spec is set to False, use_thin_logic should be False).
        use_thin_logic = strutils.bool_from_string(
            thin_spec, strict=True) if thin_spec is not None else True
    except ValueError:
        # Check if the value of thin_spec is '<is> True'.
        if thin_spec is not None and not extra_specs_ops.match(
                True, thin_spec):
            use_thin_logic = False
    return use_thin_logic


def thin_provisioning(host_state_thin_provisioning):
    # NOTE(xyang): host_state_thin_provisioning is reported by driver.
    # It can be either bool (True or False) or
    # list ([True, False], [True], [False]).
    thin_capability = [host_state_thin_provisioning] if not isinstance(
        host_state_thin_provisioning, list) else host_state_thin_provisioning
    return True in thin_capability


def capabilities_satisfied(capabilities, extra_specs):

    for key, req in extra_specs.items():
        # Either not scoped format, or in capabilities scope
        scope = key.split(':')

        # Ignore scoped (such as vendor-specific) capabilities
        if len(scope) > 1 and scope[0] != "capabilities":
            continue
        # Strip off prefix if spec started with 'capabilities:'
        elif scope[0] == "capabilities":
            del scope[0]

        cap = capabilities
        for index in range(len(scope)):
            try:
                cap = cap.get(scope[index])
            except AttributeError:
                cap = None
            if cap is None:
                LOG.debug("Host doesn't provide capability '%(cap)s' "
                          "listed in the extra specs",
                          {'cap': scope[index]})
                return False

        # Make all capability values a list so we can handle lists
        cap_list = [cap] if not isinstance(cap, list) else cap

        # Loop through capability values looking for any match
        for cap_value in cap_list:
            if extra_specs_ops.match(cap_value, req):
                break
        else:
            # Nothing matched, so bail out
            LOG.debug('Share type extra spec requirement '
                      '"%(key)s=%(req)s" does not match reported '
                      'capability "%(cap)s"',
                      {'key': key, 'req': req, 'cap': cap})
            return False
    return True
