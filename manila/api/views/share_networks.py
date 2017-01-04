# Copyright 2014 OpenStack LLC.
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

    _collection_name = 'share_networks'
    _detail_version_modifiers = ["add_gateway", "add_mtu", "add_nova_net_id"]

    def build_share_network(self, request, share_network):
        """View of a share network."""

        return {'share_network': self._build_share_network_view(
            request, share_network)}

    def build_share_networks(self, request, share_networks, is_detail=True):
        return {'share_networks':
                [self._build_share_network_view(
                    request, share_network, is_detail)
                 for share_network in share_networks]}

    def _build_share_network_view(self, request, share_network,
                                  is_detail=True):
        sn = {
            'id': share_network.get('id'),
            'name': share_network.get('name'),
        }
        if is_detail:
            sn.update({
                'project_id': share_network.get('project_id'),
                'created_at': share_network.get('created_at'),
                'updated_at': share_network.get('updated_at'),
                'neutron_net_id': share_network.get('neutron_net_id'),
                'neutron_subnet_id': share_network.get('neutron_subnet_id'),
                'network_type': share_network.get('network_type'),
                'segmentation_id': share_network.get('segmentation_id'),
                'cidr': share_network.get('cidr'),
                'ip_version': share_network.get('ip_version'),
                'description': share_network.get('description'),
            })

            self.update_versioned_resource_dict(request, sn, share_network)
        return sn

    @common.ViewBuilder.versioned_method("2.18")
    def add_gateway(self, context, network_dict, network):
        network_dict['gateway'] = network.get('gateway')

    @common.ViewBuilder.versioned_method("2.20")
    def add_mtu(self, context, network_dict, network):
        network_dict['mtu'] = network.get('mtu')

    @common.ViewBuilder.versioned_method("1.0", "2.25")
    def add_nova_net_id(self, context, network_dict, network):
        network_dict['nova_net_id'] = None
