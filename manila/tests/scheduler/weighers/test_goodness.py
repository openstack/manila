# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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
"""
Tests For Goodness Weigher.
"""

from manila.scheduler.weighers import goodness
from manila import test
from manila.tests.scheduler import fakes


class GoodnessWeigherTestCase(test.TestCase):

    def test_goodness_weigher_with_no_goodness_function(self):
        weigher = goodness.GoodnessWeigher()
        host_state = fakes.FakeHostState('host1', {
            'host': 'host.example.com',
            'capabilities': {
                'foo': '50'
            }
        })

        weight_properties = {}
        weight = weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(0, weight)

    def test_goodness_weigher_passing_host(self):
        weigher = goodness.GoodnessWeigher()
        host_state = fakes.FakeHostState('host1', {
            'host': 'host.example.com',
            'capabilities': {
                'goodness_function': '100'
            }
        })
        host_state_2 = fakes.FakeHostState('host2', {
            'host': 'host2.example.com',
            'capabilities': {
                'goodness_function': '0'
            }
        })
        host_state_3 = fakes.FakeHostState('host3', {
            'host': 'host3.example.com',
            'capabilities': {
                'goodness_function': '100 / 2'
            }
        })

        weight_properties = {}
        weight = weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(100, weight)
        weight = weigher._weigh_object(host_state_2, weight_properties)
        self.assertEqual(0, weight)
        weight = weigher._weigh_object(host_state_3, weight_properties)
        self.assertEqual(50, weight)

    def test_goodness_weigher_capabilities_substitution(self):
        weigher = goodness.GoodnessWeigher()
        host_state = fakes.FakeHostState('host1', {
            'host': 'host.example.com',
            'capabilities': {
                'foo': 50,
                'goodness_function': '10 + capabilities.foo'
            }
        })

        weight_properties = {}
        weight = weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(60, weight)

    def test_goodness_weigher_extra_specs_substitution(self):
        weigher = goodness.GoodnessWeigher()
        host_state = fakes.FakeHostState('host1', {
            'host': 'host.example.com',
            'capabilities': {
                'goodness_function': '10 + extra.foo'
            }
        })

        weight_properties = {
            'share_type': {
                'extra_specs': {
                    'foo': 50
                }
            }
        }
        weight = weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(60, weight)

    def test_goodness_weigher_share_substitution(self):
        weigher = goodness.GoodnessWeigher()
        host_state = fakes.FakeHostState('host1', {
            'host': 'host.example.com',
            'capabilities': {
                'goodness_function': '10 + share.foo'
            }
        })

        weight_properties = {
            'request_spec': {
                'resource_properties': {
                    'foo': 50
                }
            }
        }
        weight = weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(60, weight)

    def test_goodness_weigher_stats_substitution(self):
        weigher = goodness.GoodnessWeigher()
        host_state = fakes.FakeHostState('host1', {
            'host': 'host.example.com',
            'capabilities': {
                'goodness_function': 'stats.free_capacity_gb > 20'
            },
            'free_capacity_gb': 50
        })

        weight_properties = {}
        weight = weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(100, weight)

    def test_goodness_weigher_invalid_substitution(self):
        weigher = goodness.GoodnessWeigher()
        host_state = fakes.FakeHostState('host1', {
            'host': 'host.example.com',
            'capabilities': {
                'goodness_function': '10 + stats.my_val'
            },
            'foo': 50
        })

        weight_properties = {}
        weight = weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(0, weight)

    def test_goodness_weigher_host_rating_out_of_bounds(self):
        weigher = goodness.GoodnessWeigher()
        host_state = fakes.FakeHostState('host1', {
            'host': 'host.example.com',
            'capabilities': {
                'goodness_function': '-10'
            }
        })
        host_state_2 = fakes.FakeHostState('host2', {
            'host': 'host2.example.com',
            'capabilities': {
                'goodness_function': '200'
            }
        })

        weight_properties = {}
        weight = weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(0, weight)
        weight = weigher._weigh_object(host_state_2, weight_properties)
        self.assertEqual(0, weight)

    def test_goodness_weigher_invalid_goodness_function(self):
        weigher = goodness.GoodnessWeigher()
        host_state = fakes.FakeHostState('host1', {
            'host': 'host.example.com',
            'capabilities': {
                'goodness_function': '50 / 0'
            }
        })

        weight_properties = {}
        weight = weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(0, weight)
