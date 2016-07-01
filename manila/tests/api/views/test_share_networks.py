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

import ddt

from manila.api.views import share_networks
from manila import test
from manila.tests.api import fakes


@ddt.ddt
class ViewBuilderTestCase(test.TestCase):

    def setUp(self):
        super(ViewBuilderTestCase, self).setUp()
        self.builder = share_networks.ViewBuilder()
        self.req = fakes.HTTPRequest.blank('/share-networks', version="2.18")

    def test__collection_name(self):
        self.assertEqual('share_networks', self.builder._collection_name)

    @ddt.data(
        {'id': 'fake_sn_id', 'name': 'fake_sn_name'},
        {'id': 'fake_sn_id', 'name': 'fake_sn_name', 'fake_extra_key': 'foo'},
    )
    def test_build_share_network_v_2_18(self, sn):
        expected_keys = (
            'id', 'name', 'project_id', 'created_at', 'updated_at',
            'neutron_net_id', 'neutron_subnet_id', 'nova_net_id',
            'network_type', 'segmentation_id', 'cidr', 'ip_version',
            'gateway', 'description')

        result = self.builder.build_share_network(self.req, sn)

        self.assertEqual(1, len(result))
        self.assertIn('share_network', result)
        self.assertEqual(sn['id'], result['share_network']['id'])
        self.assertEqual(sn['name'], result['share_network']['name'])
        self.assertEqual(len(expected_keys), len(result['share_network']))
        for key in expected_keys:
            self.assertIn(key, result['share_network'])

    @ddt.data(
        [],
        [dict(id='fake_id',
              name='fake_name',
              project_id='fake_project_id',
              created_at='fake_created_at',
              updated_at='fake_updated_at',
              neutron_net_id='fake_neutron_net_id',
              neutron_subnet_id='fake_neutron_subnet_id',
              nova_net_id='fake_nova_net_id',
              network_type='fake_network_type',
              segmentation_id='fake_segmentation_id',
              cidr='fake_cidr',
              ip_version='fake_ip_version',
              gateway='fake_gateway',
              description='fake_description'),
         dict(id='fake_id2', name='fake_name2')],
    )
    def test_build_share_networks_with_details_v_2_18(self, share_networks):
        expected = []
        for share_network in share_networks:
            expected.append(dict(
                id=share_network.get('id'),
                name=share_network.get('name'),
                project_id=share_network.get('project_id'),
                created_at=share_network.get('created_at'),
                updated_at=share_network.get('updated_at'),
                neutron_net_id=share_network.get('neutron_net_id'),
                neutron_subnet_id=share_network.get('neutron_subnet_id'),
                nova_net_id=share_network.get('nova_net_id'),
                network_type=share_network.get('network_type'),
                segmentation_id=share_network.get('segmentation_id'),
                cidr=share_network.get('cidr'),
                ip_version=share_network.get('ip_version'),
                gateway=share_network.get('gateway'),
                description=share_network.get('description')))
        expected = {'share_networks': expected}

        result = self.builder.build_share_networks(
            self.req, share_networks, True)

        self.assertEqual(expected, result)

    @ddt.data(
        [],
        [{'id': 'foo', 'name': 'bar'}],
        [{'id': 'id1', 'name': 'name1'}, {'id': 'id2', 'name': 'name2'}],
        [{'id': 'id1', 'name': 'name1'},
         {'id': 'id2', 'name': 'name2', 'fake': 'I should not be returned'}],
    )
    def test_build_share_networks_without_details_v_2_18(self,
                                                         share_networks):
        expected = []
        for share_network in share_networks:
            expected.append(dict(
                id=share_network.get('id'), name=share_network.get('name')))
        expected = {'share_networks': expected}

        result = self.builder.build_share_networks(
            self.req, share_networks, False)

        self.assertEqual(expected, result)
