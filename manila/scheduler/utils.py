# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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
        'consistency_group_support': host_state.consistency_group_support,
        'dedupe': host_state.dedupe,
        'compression': host_state.compression,
        'snapshot_support': host_state.snapshot_support,
        'replication_domain': host_state.replication_domain,
        'replication_type': host_state.replication_type,
        'provisioned_capacity_gb': host_state.provisioned_capacity_gb,
        'pools': host_state.pools,
        'max_over_subscription_ratio':
            host_state.max_over_subscription_ratio,
    }

    host_caps = host_state.capabilities

    share_type = properties.get('share_type', {})
    extra_specs = share_type.get('extra_specs', {})

    request_spec = properties.get('request_spec', {})
    share_stats = request_spec.get('resource_properties', {})

    stats = {
        'host_stats': host_stats,
        'host_caps': host_caps,
        'extra_specs': extra_specs,
        'share_stats': share_stats,
        'share_type': share_type,
    }

    return stats
