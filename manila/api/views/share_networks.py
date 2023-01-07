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
    _detail_version_modifiers = ["add_gateway", "add_mtu", "add_nova_net_id",
                                 "add_subnets",
                                 "add_status_and_sec_service_update_fields",
                                 "add_network_allocation_update_support_field",
                                 "add_subnet_with_metadata"]

    def build_share_network(self, request, share_network):
        """View of a share network."""

        return {'share_network': self._build_share_network_view(
            request, share_network)}

    def build_share_networks(self, request, share_networks, is_detail=True):
        return {'share_networks':
                [self._build_share_network_view(
                    request, share_network, is_detail)
                 for share_network in share_networks]}

    def build_security_service_update_check(self, request, params, result):
        """View of security service add or update check."""
        context = request.environ['manila.context']
        requested_operation = {
            'operation': ('update_security_service'
                          if params.get('current_service_id')
                          else 'add_security_service'),
            'current_security_service': params.get('current_service_id'),
            'new_security_service': (params.get('new_service_id') or
                                     params.get('security_service_id'))
        }
        view = {
            'compatible': result['compatible'],
            'requested_operation': requested_operation,
        }
        if context.is_admin:
            view['hosts_check_result'] = result['hosts_check_result']
        return view

    def build_share_network_subnet_create_check(self, request, result):
        """View of share network subnet create check."""
        context = request.environ['manila.context']
        view = {
            'compatible': result['compatible'],
        }
        if context.is_admin:
            view['hosts_check_result'] = result['hosts_check_result']
        return view

    def _update_share_network_info(self, request, share_network):
        for sns in share_network.get('share_network_subnets') or []:
            if sns.get('is_default') and sns.get('is_default') is True:
                share_network.update({
                    'neutron_net_id': sns.get('neutron_net_id'),
                    'neutron_subnet_id': sns.get('neutron_subnet_id'),
                    'network_type': sns.get('network_type'),
                    'segmentation_id': sns.get('segmentation_id'),
                    'cidr': sns.get('cidr'),
                    'ip_version': sns.get('ip_version'),
                    'gateway': sns.get('gateway'),
                    'mtu': sns.get('mtu'),
                })

    def _build_share_network_view(self, request, share_network,
                                  is_detail=True):
        sn = {
            'id': share_network.get('id'),
            'name': share_network.get('name'),
        }
        if is_detail:
            self._update_share_network_info(request, share_network)
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

    @common.ViewBuilder.versioned_method("2.51", "2.77")
    def add_subnets(self, context, network_dict, network):
        subnets = [{
            'id': sns.get('id'),
            'availability_zone': sns.get('availability_zone'),
            'created_at': sns.get('created_at'),
            'updated_at': sns.get('updated_at'),
            'segmentation_id': sns.get('segmentation_id'),
            'neutron_net_id': sns.get('neutron_net_id'),
            'neutron_subnet_id': sns.get('neutron_subnet_id'),
            'ip_version': sns.get('ip_version'),
            'cidr': sns.get('cidr'),
            'network_type': sns.get('network_type'),
            'mtu': sns.get('mtu'),
            'gateway': sns.get('gateway'),
        } for sns in network.get('share_network_subnets')]

        network_dict['share_network_subnets'] = subnets
        attr_to_remove = [
            'neutron_net_id', 'neutron_subnet_id', 'network_type',
            'segmentation_id', 'cidr', 'ip_version', 'gateway', 'mtu']
        for attr in attr_to_remove:
            network_dict.pop(attr)

    @common.ViewBuilder.versioned_method("2.18")
    def add_gateway(self, context, network_dict, network):
        network_dict['gateway'] = network.get('gateway')

    @common.ViewBuilder.versioned_method("2.20")
    def add_mtu(self, context, network_dict, network):
        network_dict['mtu'] = network.get('mtu')

    @common.ViewBuilder.versioned_method("1.0", "2.25")
    def add_nova_net_id(self, context, network_dict, network):
        network_dict['nova_net_id'] = None

    @common.ViewBuilder.versioned_method("2.63")
    def add_status_and_sec_service_update_fields(
            self, context, network_dict, network):
        network_dict['status'] = network.get('status')
        network_dict['security_service_update_support'] = network.get(
            'security_service_update_support')

    @common.ViewBuilder.versioned_method("2.70")
    def add_network_allocation_update_support_field(
            self, context, network_dict, network):
        network_dict['network_allocation_update_support'] = network.get(
            'network_allocation_update_support')

    @common.ViewBuilder.versioned_method("2.78")
    def add_subnet_with_metadata(self, context, network_dict, network):
        subnets = [{
            'id': sns.get('id'),
            'availability_zone': sns.get('availability_zone'),
            'created_at': sns.get('created_at'),
            'updated_at': sns.get('updated_at'),
            'segmentation_id': sns.get('segmentation_id'),
            'neutron_net_id': sns.get('neutron_net_id'),
            'neutron_subnet_id': sns.get('neutron_subnet_id'),
            'ip_version': sns.get('ip_version'),
            'cidr': sns.get('cidr'),
            'network_type': sns.get('network_type'),
            'mtu': sns.get('mtu'),
            'gateway': sns.get('gateway'),
            'metadata': sns.get('subnet_metadata'),
        } for sns in network.get('share_network_subnets')]

        network_dict['share_network_subnets'] = subnets
        attr_to_remove = [
            'neutron_net_id', 'neutron_subnet_id', 'network_type',
            'segmentation_id', 'cidr', 'ip_version', 'gateway', 'mtu']
        for attr in attr_to_remove:
            network_dict.pop(attr)
