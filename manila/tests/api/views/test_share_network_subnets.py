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


import ddt

from manila.api.openstack import api_version_request as api_version
from manila.api.views import share_network_subnets
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils


@ddt.ddt
class ViewBuilderTestCase(test.TestCase):

    def setUp(self):
        super(ViewBuilderTestCase, self).setUp()
        self.builder = share_network_subnets.ViewBuilder()
        self.share_network = db_utils.create_share_network(
            name='fake_network', id='fake_sn_id')

    def _validate_is_detail_return(self, result, metadata_support=False):
        expected_keys = ['id', 'created_at', 'updated_at', 'neutron_net_id',
                         'neutron_subnet_id', 'network_type', 'cidr',
                         'segmentation_id', 'ip_version', 'share_network_id',
                         'availability_zone', 'gateway', 'mtu']
        if metadata_support:
            expected_keys.append('metadata')

        for key in expected_keys:
            self.assertIn(key, result)

    def test_build_share_network_subnet(self):
        req = fakes.HTTPRequest.blank('/subnets', version='2.51')

        subnet = db_utils.create_share_network_subnet(
            share_network_id=self.share_network['id'])

        result = self.builder.build_share_network_subnet(req, subnet)

        self.assertEqual(1, len(result))
        self.assertIn('share_network_subnet', result)
        self.assertEqual(subnet['id'],
                         result['share_network_subnet']['id'])
        self.assertEqual(subnet['share_network_id'],
                         result['share_network_subnet']['share_network_id'])
        self.assertIsNone(
            result['share_network_subnet']['availability_zone'])
        self._validate_is_detail_return(result['share_network_subnet'])

    @ddt.data("2.51", "2.78")
    def test_build_share_network_subnets(self, microversion):
        metadata_support = (api_version.APIVersionRequest(microversion) >=
                            api_version.APIVersionRequest('2.78'))

        req = fakes.HTTPRequest.blank('/subnets', version=microversion)

        share_network = db_utils.create_share_network(
            name='fake_network', id='fake_sn_id_1')

        expected_metadata = {'fake_key': 'fake_value'}
        subnet = db_utils.create_share_network_subnet(
            share_network_id=share_network['id'], metadata=expected_metadata)

        result = self.builder.build_share_network_subnets(req, [subnet])

        self.assertIn('share_network_subnets', result)
        self.assertEqual(1, len(result['share_network_subnets']))
        subnet_list = result['share_network_subnets']
        for subnet in subnet_list:
            self._validate_is_detail_return(subnet,
                                            metadata_support=metadata_support)
            if metadata_support:
                self.assertEqual(expected_metadata, subnet['metadata'])
