# Copyright 2015 Mirantis Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
Tests For Pool Weigher.
"""

import mock
from oslo_config import cfg
from oslo_utils import timeutils

from manila import context
from manila.db import api as db_api
from manila.scheduler.weighers import base_host
from manila.scheduler.weighers import pool
from manila.share import utils
from manila import test
from manila.tests.scheduler import fakes

CONF = cfg.CONF


class PoolWeigherTestCase(test.TestCase):
    def setUp(self):
        super(PoolWeigherTestCase, self).setUp()
        self.host_manager = fakes.FakeHostManager()
        self.weight_handler = base_host.HostWeightHandler(
            'manila.scheduler.weighers')
        share_servers = [
            {'id': 'fake_server_id0'},
            {'id': 'fake_server_id1'},
            {'id': 'fake_server_id2'},
            {'id': 'fake_server_id3'},
            {'id': 'fake_server_id4'},
        ]
        services = [
            dict(id=1, host='host1@AAA', topic='share', disabled=False,
                 availability_zone='zone1', updated_at=timeutils.utcnow()),
            dict(id=2, host='host2@BBB', topic='share', disabled=False,
                 availability_zone='zone1', updated_at=timeutils.utcnow()),
            dict(id=3, host='host3@CCC', topic='share', disabled=False,
                 availability_zone='zone2', updated_at=timeutils.utcnow()),
            dict(id=4, host='host@DDD', topic='share', disabled=False,
                 availability_zone='zone3', updated_at=timeutils.utcnow()),
            dict(id=5, host='host5@EEE', topic='share', disabled=False,
                 availability_zone='zone3', updated_at=timeutils.utcnow()),
        ]
        self.host_manager.service_states = (
            fakes.SHARE_SERVICE_STATES_WITH_POOLS)
        self.mock_object(db_api, 'share_server_get_all_by_host',
                         mock.Mock(return_value=share_servers))
        self.mock_object(db_api.IMPL, 'service_get_all_by_topic',
                         mock.Mock(return_value=services))

    def _get_weighed_host(self, hosts, weight_properties=None):
        if weight_properties is None:
            weight_properties = {
                'server_pools_mapping': {
                    'fake_server_id2': [{'pool_name': 'pool2'}, ],
                },
            }
        return self.weight_handler.get_weighed_objects(
            [pool.PoolWeigher],
            hosts,
            weight_properties)[0]

    def _get_all_hosts(self):
        ctxt = context.get_admin_context()
        host_states = self.host_manager.get_all_host_states_share(ctxt)
        db_api.IMPL.service_get_all_by_topic.assert_called_once_with(
            ctxt, CONF.share_topic)
        return host_states

    def test_no_server_pool_mapping(self):
        weight_properties = {
            'server_pools_mapping': {},
        }
        weighed_host = self._get_weighed_host(self._get_all_hosts(),
                                              weight_properties)
        self.assertEqual(0.0, weighed_host.weight)

    def test_choose_pool_with_existing_share_server(self):
        # host1: weight = 0*(1.0)
        # host2: weight = 1*(1.0)
        # host3: weight = 0*(1.0)
        # host4: weight = 0*(1.0)
        # host5: weight = 0*(1.0)

        # so, host2 should win:

        weighed_host = self._get_weighed_host(self._get_all_hosts())
        self.assertEqual(1.0, weighed_host.weight)
        self.assertEqual(
            'host2@BBB', utils.extract_host(weighed_host.obj.host))

    def test_pool_weight_multiplier_positive(self):
        self.flags(pool_weight_multiplier=2.0)

        # host1: weight = 0*(2.0)
        # host2: weight = 1*(2.0)
        # host3: weight = 0*(2.0)
        # host4: weight = 0*(2.0)
        # host5: weight = 0*(2.0)

        # so, host2 should win:

        weighed_host = self._get_weighed_host(self._get_all_hosts())
        self.assertEqual(2.0, weighed_host.weight)
        self.assertEqual(
            'host2@BBB', utils.extract_host(weighed_host.obj.host))

    def test_pool_weight_multiplier_negative(self):
        self.flags(pool_weight_multiplier=-1.0)
        weight_properties = {
            'server_pools_mapping': {
                'fake_server_id0': [{'pool_name': 'pool1'}],
                'fake_server_id2': [{'pool_name': 'pool3'}],
                'fake_server_id3': [
                    {'pool_name': 'pool4a'},
                    {'pool_name': 'pool4b'},
                ],
                'fake_server_id4': [
                    {'pool_name': 'pool5a'},
                    {'pool_name': 'pool5b'},
                ],
            },
        }

        # host1: weight = 1*(-1.0)
        # host2: weight = 0*(-1.0)
        # host3: weight = 1*(-1.0)
        # host4: weight = 1*(-1.0)
        # host5: weight = 1*(-1.0)

        # so, host2 should win:
        weighed_host = self._get_weighed_host(self._get_all_hosts(),
                                              weight_properties)
        self.assertEqual(0.0, weighed_host.weight)
        self.assertEqual(
            'host2@BBB', utils.extract_host(weighed_host.obj.host))

    def test_pool_weigher_all_pools_with_share_servers(self):
        weight_properties = {
            'server_pools_mapping': {
                'fake_server_id0': [{'pool_name': 'pool1'}],
                'fake_server_id1': [{'pool_name': 'pool2'}],
                'fake_server_id2': [{'pool_name': 'pool3'}],
                'fake_server_id3': [
                    {'pool_name': 'pool4a'},
                    {'pool_name': 'pool4b'},
                ],
                'fake_server_id4': [
                    {'pool_name': 'pool5a'},
                    {'pool_name': 'pool5b'},
                ],
            },
        }

        # host1: weight = 1*(1.0)
        # host2: weight = 1*(1.0)
        # host3: weight = 1*(1.0)
        # host4: weight = 1*(1.0)
        # host5: weight = 1*(1.0)

        # But after normalization all weighers will be 0

        weighed_host = self._get_weighed_host(self._get_all_hosts(),
                                              weight_properties)
        self.assertEqual(0.0, weighed_host.weight)
