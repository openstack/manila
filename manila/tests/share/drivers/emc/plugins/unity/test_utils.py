# Copyright (c) 2016 EMC Corporation.
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

from manila.share.drivers.emc.plugins.unity import utils
from manila import test


@ddt.ddt
class TestUtils(test.TestCase):
    @ddt.data({'matcher': None,
               'matched': {'pool_1', 'pool_2', 'nas_server_pool'},
               'not_matched': set()},
              {'matcher': ['*'],
               'matched': {'pool_1', 'pool_2', 'nas_server_pool'},
               'not_matched': set()},
              {'matcher': ['pool_*'],
               'matched': {'pool_1', 'pool_2'},
               'not_matched': {'nas_server_pool'}},
              {'matcher': ['*pool'],
               'matched': {'nas_server_pool'},
               'not_matched': {'pool_1', 'pool_2'}},
              {'matcher': ['nas_server_pool'],
               'matched': {'nas_server_pool'},
               'not_matched': {'pool_1', 'pool_2'}},
              {'matcher': ['nas_*', 'pool_*'],
               'matched': {'pool_1', 'pool_2', 'nas_server_pool'},
               'not_matched': set()})
    def test_do_match(self, data):
        full = ['pool_1 ', ' pool_2', ' nas_server_pool ']
        matcher = data['matcher']
        expected_matched = data['matched']
        expected_not_matched = data['not_matched']

        matched, not_matched = utils.do_match(full, matcher)
        self.assertEqual(expected_matched, matched)
        self.assertEqual(expected_not_matched, not_matched)
