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

import copy

from manila.api.views import scheduler_stats
from manila import test


POOL1 = {
    'name': 'host1@backend1#pool1',
    'host': 'host1',
    'backend': 'backend1',
    'pool': 'pool1',
    'other': 'junk',
    'capabilities': {
        'pool_name': 'pool1',
        'driver_handles_share_servers': False,
        'qos': 'False',
        'timestamp': '2015-03-15T19:15:42.611690',
        'allocated_capacity_gb': 5,
        'total_capacity_gb': 10,
    },
}
POOL2 = {
    'name': 'host1@backend1#pool2',
    'host': 'host1',
    'backend': 'backend1',
    'pool': 'pool2',
    'capabilities': {
        'pool_name': 'pool2',
        'driver_handles_share_servers': False,
        'qos': 'False',
        'timestamp': '2015-03-15T19:15:42.611690',
        'allocated_capacity_gb': 15,
        'total_capacity_gb': 20,
    },
}
POOLS = [POOL1, POOL2]

POOLS_DETAIL_VIEW = {
    'pools': [
        {
            'name': 'host1@backend1#pool1',
            'host': 'host1',
            'backend': 'backend1',
            'pool': 'pool1',
            'capabilities': {
                'pool_name': 'pool1',
                'driver_handles_share_servers': False,
                'qos': 'False',
                'timestamp': '2015-03-15T19:15:42.611690',
                'allocated_capacity_gb': 5,
                'total_capacity_gb': 10,
            },
        }, {
            'name': 'host1@backend1#pool2',
            'host': 'host1',
            'backend': 'backend1',
            'pool': 'pool2',
            'capabilities': {
                'pool_name': 'pool2',
                'driver_handles_share_servers': False,
                'qos': 'False',
                'timestamp': '2015-03-15T19:15:42.611690',
                'allocated_capacity_gb': 15,
                'total_capacity_gb': 20,
            }
        }
    ]
}


class ViewBuilderTestCase(test.TestCase):

    def setUp(self):
        super(ViewBuilderTestCase, self).setUp()
        self.builder = scheduler_stats.ViewBuilder()

    def test_pools(self):

        result = self.builder.pools(POOLS)

        # Remove capabilities for summary view
        expected = copy.deepcopy(POOLS_DETAIL_VIEW)
        for pool in expected['pools']:
            del pool['capabilities']

        self.assertDictEqual(expected, result)

    def test_pools_with_details(self):

        result = self.builder.pools(POOLS, detail=True)

        expected = POOLS_DETAIL_VIEW
        self.assertDictEqual(expected, result)
