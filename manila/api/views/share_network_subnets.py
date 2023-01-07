# Copyright 2019 NetApp, Inc.
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

from manila.api import common


class ViewBuilder(common.ViewBuilder):
    """Model a server API response as a python dictionary."""

    _collection_name = 'share_network_subnets'
    _detail_version_modifiers = [
        "add_metadata"
    ]

    def build_share_network_subnet(self, request, share_network_subnet):
        return {
            'share_network_subnet': self._build_share_network_subnet_view(
                request, share_network_subnet)}

    def build_share_network_subnets(self, request, share_network_subnets):
        return {'share_network_subnets':
                [self._build_share_network_subnet_view(
                    request, share_network_subnet)
                 for share_network_subnet in share_network_subnets]}

    def _build_share_network_subnet_view(self, request, share_network_subnet):
        sns = {
            'id': share_network_subnet.get('id'),
            'availability_zone': share_network_subnet.get('availability_zone'),
            'share_network_id': share_network_subnet.get('share_network_id'),
            'share_network_name': share_network_subnet['share_network_name'],
            'created_at': share_network_subnet.get('created_at'),
            'segmentation_id': share_network_subnet.get('segmentation_id'),
            'neutron_subnet_id': share_network_subnet.get('neutron_subnet_id'),
            'updated_at': share_network_subnet.get('updated_at'),
            'neutron_net_id': share_network_subnet.get('neutron_net_id'),
            'ip_version': share_network_subnet.get('ip_version'),
            'cidr': share_network_subnet.get('cidr'),
            'network_type': share_network_subnet.get('network_type'),
            'mtu': share_network_subnet.get('mtu'),
            'gateway': share_network_subnet.get('gateway')
        }
        self.update_versioned_resource_dict(request, sns, share_network_subnet)
        return sns

    @common.ViewBuilder.versioned_method("2.78")
    def add_metadata(self, context, share_network_subnet_dict, sns):
        share_network_subnet_dict['metadata'] = sns.get('subnet_metadata')
