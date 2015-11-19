# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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

import mock

from manila.api.v1 import scheduler_stats
from manila import context
from manila import policy
from manila.scheduler import rpcapi
from manila import test
from manila.tests.api import fakes


FAKE_POOLS = [
    {
        'name': 'host1@backend1#pool1',
        'host': 'host1',
        'backend': 'backend1',
        'pool': 'pool1',
        'capabilities': {
            'updated': None,
            'total_capacity': 1024,
            'free_capacity': 100,
            'share_backend_name': 'pool1',
            'reserved_percentage': 0,
            'driver_version': '1.0.0',
            'storage_protocol': 'iSCSI',
            'qos': 'False',
        },
    },
    {
        'name': 'host1@backend1#pool2',
        'host': 'host1',
        'backend': 'backend1',
        'pool': 'pool2',
        'capabilities': {
            'updated': None,
            'total_capacity': 512,
            'free_capacity': 200,
            'share_backend_name': 'pool2',
            'reserved_percentage': 0,
            'driver_version': '1.0.1',
            'storage_protocol': 'iSER',
            'qos': 'True',
        },
    },
]


class SchedulerStatsControllerTestCase(test.TestCase):
    def setUp(self):
        super(SchedulerStatsControllerTestCase, self).setUp()
        self.flags(host='fake')
        self.controller = scheduler_stats.SchedulerStatsController()
        self.resource_name = self.controller.resource_name
        self.ctxt = context.RequestContext('admin', 'fake', True)
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))

    def test_pools_index(self):
        mock_get_pools = self.mock_object(rpcapi.SchedulerAPI,
                                          'get_pools',
                                          mock.Mock(return_value=FAKE_POOLS))
        req = fakes.HTTPRequest.blank('/v1/fake_project/scheduler_stats/pools')
        req.environ['manila.context'] = self.ctxt

        result = self.controller.pools_index(req)

        expected = {
            'pools': [
                {
                    'name': 'host1@backend1#pool1',
                    'host': 'host1',
                    'backend': 'backend1',
                    'pool': 'pool1',
                },
                {
                    'name': 'host1@backend1#pool2',
                    'host': 'host1',
                    'backend': 'backend1',
                    'pool': 'pool2',
                }
            ]
        }

        self.assertDictMatch(result, expected)
        mock_get_pools.assert_called_once_with(self.ctxt, filters={})
        self.mock_policy_check.assert_called_once_with(
            self.ctxt, self.resource_name, 'index')

    def test_pools_index_with_filters(self):
        mock_get_pools = self.mock_object(rpcapi.SchedulerAPI,
                                          'get_pools',
                                          mock.Mock(return_value=FAKE_POOLS))

        url = '/v1/fake_project/scheduler-stats/pools/detail'
        url += '?backend=.%2A&host=host1&pool=pool%2A'

        req = fakes.HTTPRequest.blank(url)
        req.environ['manila.context'] = self.ctxt

        result = self.controller.pools_index(req)

        expected = {
            'pools': [
                {
                    'name': 'host1@backend1#pool1',
                    'host': 'host1',
                    'backend': 'backend1',
                    'pool': 'pool1',
                },
                {
                    'name': 'host1@backend1#pool2',
                    'host': 'host1',
                    'backend': 'backend1',
                    'pool': 'pool2',
                }
            ]
        }
        expected_filters = {'host': 'host1', 'pool': 'pool*', 'backend': '.*'}

        self.assertDictMatch(result, expected)
        mock_get_pools.assert_called_once_with(self.ctxt,
                                               filters=expected_filters)
        self.mock_policy_check.assert_called_once_with(
            self.ctxt, self.resource_name, 'index')

    def test_get_pools_detail(self):
        mock_get_pools = self.mock_object(rpcapi.SchedulerAPI,
                                          'get_pools',
                                          mock.Mock(return_value=FAKE_POOLS))
        req = fakes.HTTPRequest.blank(
            '/v1/fake_project/scheduler_stats/pools/detail')
        req.environ['manila.context'] = self.ctxt

        result = self.controller.pools_detail(req)

        expected = {
            'pools': [
                {
                    'name': 'host1@backend1#pool1',
                    'host': 'host1',
                    'backend': 'backend1',
                    'pool': 'pool1',
                    'capabilities': {
                        'updated': None,
                        'total_capacity': 1024,
                        'free_capacity': 100,
                        'share_backend_name': 'pool1',
                        'reserved_percentage': 0,
                        'driver_version': '1.0.0',
                        'storage_protocol': 'iSCSI',
                        'qos': 'False',
                    },
                },
                {
                    'name': 'host1@backend1#pool2',
                    'host': 'host1',
                    'backend': 'backend1',
                    'pool': 'pool2',
                    'capabilities': {
                        'updated': None,
                        'total_capacity': 512,
                        'free_capacity': 200,
                        'share_backend_name': 'pool2',
                        'reserved_percentage': 0,
                        'driver_version': '1.0.1',
                        'storage_protocol': 'iSER',
                        'qos': 'True',
                    },
                },
            ],
        }

        self.assertDictMatch(expected, result)
        mock_get_pools.assert_called_once_with(self.ctxt, filters={})
        self.mock_policy_check.assert_called_once_with(
            self.ctxt, self.resource_name, 'detail')


class SchedulerStatsTestCase(test.TestCase):

    def test_create_resource(self):
        result = scheduler_stats.create_resource()
        self.assertIsInstance(result.controller,
                              scheduler_stats.SchedulerStatsController)
