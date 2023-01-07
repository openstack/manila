# Copyright (c) 2015 Mirantis, Inc.
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

import copy
import ddt
import itertools

from manila.api.openstack import api_version_request as api_version
from manila.api.views import share_networks
from manila import test
from manila.tests.api import fakes


@ddt.ddt
class ViewBuilderTestCase(test.TestCase):

    def setUp(self):
        super(ViewBuilderTestCase, self).setUp()
        self.builder = share_networks.ViewBuilder()

    def test__collection_name(self):
        self.assertEqual('share_networks', self.builder._collection_name)

    @ddt.data(*itertools.product(
        [
            {'id': 'fake_sn_id', 'name': 'fake_sn_name',
             'share_network_subnets': []},
            {'id': 'fake_sn_id', 'name': 'fake_sn_name',
             'share_network_subnets': [], 'fake_extra_key': 'foo'},
            {'id': 'fake_sn_id', 'name': 'fake_sn_name',
             'share_network_subnets': [
                 {'availability_zone_id': None,
                  'id': 'fake',
                  'availability_zone': None,
                  'is_default': False
                  }],
             'fake_extra_key': 'foo'},
        ],
        ["1.0", "2.0", "2.18", "2.20", "2.25", "2.26",
         "2.49", api_version._MAX_API_VERSION])
    )
    @ddt.unpack
    def test_build_share_network(self, share_network_data, microversion):
        gateway_support = (api_version.APIVersionRequest(microversion) >=
                           api_version.APIVersionRequest('2.18'))
        mtu_support = (api_version.APIVersionRequest(microversion) >=
                       api_version.APIVersionRequest('2.20'))
        nova_net_support = (api_version.APIVersionRequest(microversion) <
                            api_version.APIVersionRequest('2.26'))
        default_net_info_support = (api_version.APIVersionRequest(microversion)
                                    <= api_version.APIVersionRequest('2.49'))
        subnets_support = (api_version.APIVersionRequest(microversion) >
                           api_version.APIVersionRequest('2.49'))
        status_and_sec_serv_update = (
            api_version.APIVersionRequest(microversion) >=
            api_version.APIVersionRequest('2.63'))
        network_allocation_update_support = (
            api_version.APIVersionRequest(microversion) >=
            api_version.APIVersionRequest('2.69'))
        req = fakes.HTTPRequest.blank('/share-networks', version=microversion)
        expected_keys = {
            'id', 'name', 'project_id', 'created_at', 'updated_at',
            'description'}
        if subnets_support:
            expected_keys.add('share_network_subnets')
        else:
            if default_net_info_support:
                network_info = {
                    'neutron_net_id', 'neutron_subnet_id', 'network_type',
                    'segmentation_id', 'cidr', 'ip_version'}
                expected_keys.update(network_info)
            if gateway_support:
                expected_keys.add('gateway')
            if mtu_support:
                expected_keys.add('mtu')
            if nova_net_support:
                expected_keys.add('nova_net_id')
        if status_and_sec_serv_update:
            expected_keys.update({'status', 'security_service_update_support'})
        if network_allocation_update_support:
            expected_keys.add('network_allocation_update_support')

        result = self.builder.build_share_network(req, share_network_data)
        self.assertEqual(1, len(result))
        self.assertIn('share_network', result)
        self.assertEqual(share_network_data['id'],
                         result['share_network']['id'])
        self.assertEqual(share_network_data['name'],
                         result['share_network']['name'])
        self.assertEqual(len(expected_keys),
                         len(result['share_network']))
        for key in expected_keys:
            self.assertIn(key, result['share_network'])
        for key in result['share_network']:
            self.assertIn(key, expected_keys)

    @ddt.data(*itertools.product(
        [
            [],
            [{'id': 'fake_id',
              'name': 'fake_name',
              'project_id': 'fake_project_id',
              'created_at': 'fake_created_at',
              'updated_at': 'fake_updated_at',
              'neutron_net_id': 'fake_neutron_net_id',
              'neutron_subnet_id': 'fake_neutron_subnet_id',
              'network_type': 'fake_network_type',
              'segmentation_id': 'fake_segmentation_id',
              'cidr': 'fake_cidr',
              'ip_version': 'fake_ip_version',
              'description': 'fake_description'},
             {'id': 'fake_id2',
              'name': 'fake_name2'}],
        ],
        set(["1.0", "2.0", "2.18", "2.20", "2.25", "2.26", "2.49",
             api_version._MAX_API_VERSION]))
    )
    @ddt.unpack
    def test_build_share_networks_with_details(self, share_networks,
                                               microversion):
        gateway_support = (api_version.APIVersionRequest(microversion) >=
                           api_version.APIVersionRequest('2.18'))
        mtu_support = (api_version.APIVersionRequest(microversion) >=
                       api_version.APIVersionRequest('2.20'))
        nova_net_support = (api_version.APIVersionRequest(microversion) <
                            api_version.APIVersionRequest('2.26'))
        default_net_info_support = (api_version.APIVersionRequest(microversion)
                                    <= api_version.APIVersionRequest('2.49'))
        subnets_support = (api_version.APIVersionRequest(microversion) >
                           api_version.APIVersionRequest('2.49'))
        status_and_sec_serv_update = (
            api_version.APIVersionRequest(microversion) >=
            api_version.APIVersionRequest('2.63'))
        network_allocation_update_support = (
            api_version.APIVersionRequest(microversion) >=
            api_version.APIVersionRequest('2.69'))
        subnet_metadata_support = (
            api_version.APIVersionRequest(microversion) >=
            api_version.APIVersionRequest('2.78'))

        req = fakes.HTTPRequest.blank('/share-networks', version=microversion)
        expected_networks_list = []
        for share_network in share_networks:
            expected_data = {
                'id': share_network.get('id'),
                'name': share_network.get('name'),
                'project_id': share_network.get('project_id'),
                'created_at': share_network.get('created_at'),
                'updated_at': share_network.get('updated_at'),
                'description': share_network.get('description'),
            }
            if subnets_support:
                expected_subnet = {
                    'id': 'fake_subnet_id',
                    'availability_zone': 'fake_az',
                    'created_at': share_network.get('created_at'),
                    'updated_at': share_network.get('updated_at'),
                    'segmentation_id': share_network.get('segmentation_id'),
                    'neutron_net_id': share_network.get('neutron_net_id'),
                    'neutron_subnet_id': share_network.get(
                        'neutron_subnet_id'),
                    'ip_version': share_network.get('ip_version'),
                    'cidr': share_network.get('cidr'),
                    'network_type': share_network.get('network_type'),
                    'mtu': share_network.get('mtu'),
                    'gateway': share_network.get('gateway'),
                }
                subnet = expected_subnet
                if subnet_metadata_support:
                    subnet = copy.deepcopy(expected_subnet)
                    expected_subnet['metadata'] = {'fake_key': 'fake_value'}
                    subnet['subnet_metadata'] = expected_subnet['metadata']

                expected_data.update(
                    {'share_network_subnets': [expected_subnet]})
                share_network.update({'share_network_subnets': [subnet]})
            else:
                if default_net_info_support:
                    network_data = {
                        'neutron_net_id': share_network.get('neutron_net_id'),
                        'neutron_subnet_id': share_network.get(
                            'neutron_subnet_id'),
                        'network_type': share_network.get('network_type'),
                        'segmentation_id': share_network.get(
                            'segmentation_id'),
                        'cidr': share_network.get('cidr'),
                        'ip_version': share_network.get('ip_version'),
                    }
                    expected_data.update(network_data)
                if gateway_support:
                    share_network.update({'gateway': 'fake_gateway'})
                    expected_data.update({'gateway':
                                          share_network.get('gateway')})
                if mtu_support:
                    share_network.update({'mtu': 1509})
                    expected_data.update({'mtu': share_network.get('mtu')})
                if nova_net_support:
                    share_network.update({'nova_net_id': 'fake_nova_net_id'})
                    expected_data.update({'nova_net_id': None})
            if status_and_sec_serv_update:
                share_network.update(
                    {'status': 'active',
                     'security_service_update_support': False})
                expected_data.update(
                    {'status': 'active',
                     'security_service_update_support': False})
            if network_allocation_update_support:
                share_network.update(
                    {'network_allocation_update_support': None})
                expected_data.update(
                    {'network_allocation_update_support': None})
            expected_networks_list.append(expected_data)

        expected = {'share_networks': expected_networks_list}

        result = self.builder.build_share_networks(req, share_networks,
                                                   is_detail=True)

        self.assertEqual(expected, result)

    @ddt.data(*itertools.product(
        [
            [],
            [{'id': 'foo', 'name': 'bar'}],
            [{'id': 'id1', 'name': 'name1'}, {'id': 'id2', 'name': 'name2'}],
            [{'id': 'id1', 'name': 'name1'},
             {'id': 'id2', 'name': 'name2',
              'fake': 'I should not be returned'}]
        ],
        set(["1.0", "2.0", "2.18", "2.20", "2.25", "2.26", "2.49",
             api_version._MAX_API_VERSION]))
    )
    @ddt.unpack
    def test_build_share_networks_without_details(self, share_networks,
                                                  microversion):
        req = fakes.HTTPRequest.blank('/share-networks', version=microversion)
        expected = []
        for share_network in share_networks:
            expected.append({
                'id': share_network.get('id'),
                'name': share_network.get('name')
            })
        expected = {'share_networks': expected}

        result = self.builder.build_share_networks(req, share_networks,
                                                   is_detail=False)

        self.assertEqual(expected, result)

    @ddt.data(('update_security_service', True),
              ('add_security_service', False))
    @ddt.unpack
    def test_build_security_service_update_check(self, operation, is_admin):
        req = fakes.HTTPRequest.blank('/share-networks',
                                      use_admin_context=is_admin)
        params = {'new_service_id': 'new_id'}
        if operation == 'update_security_service':
            params['current_service_id'] = 'current_id'

        hosts_result = {
            'compatible': True,
            'hosts_check_result': {'hostA': True}
        }
        expected = {
            'compatible': True,
            'requested_operation': {
                'operation': operation,
                'current_security_service': params.get('current_service_id'),
                'new_security_service': params.get('new_service_id'),
            },
        }
        if is_admin:
            expected['hosts_check_result'] = hosts_result['hosts_check_result']

        result = self.builder.build_security_service_update_check(req,
                                                                  params,
                                                                  hosts_result)

        self.assertEqual(expected, result)

    @ddt.data(True, False)
    def test_build_share_network_subnet_create_check(self, is_admin):
        req = fakes.HTTPRequest.blank('/share-networks',
                                      use_admin_context=is_admin)
        hosts_result = {
            'compatible': True,
            'hosts_check_result': {'hostA': True}
        }
        expected = {'compatible': True}
        if is_admin:
            expected['hosts_check_result'] = hosts_result['hosts_check_result']

        result = self.builder.build_share_network_subnet_create_check(
            req, hosts_result)

        self.assertEqual(expected, result)
