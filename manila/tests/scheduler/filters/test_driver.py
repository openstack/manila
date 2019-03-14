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

from manila.scheduler.filters import driver
from manila import test
from manila.tests.scheduler import fakes


class HostFiltersTestCase(test.TestCase):

    def setUp(self):
        super(HostFiltersTestCase, self).setUp()
        self.filter = driver.DriverFilter()

    def test_passing_function(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {
                    'filter_function': '1 == 1',
                }
            })

        filter_properties = {'share_type': {}}

        self.assertTrue(self.filter.host_passes(host1, filter_properties))

    def test_failing_function(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {
                    'filter_function': '1 == 2',
                }
            })

        filter_properties = {'share_type': {}}

        self.assertFalse(self.filter.host_passes(host1, filter_properties))

    def test_no_filter_function(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {
                    'filter_function': None,
                }
            })

        filter_properties = {'share_type': {}}

        self.assertTrue(self.filter.host_passes(host1, filter_properties))

    def test_not_implemented(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {}
            })

        filter_properties = {'share_type': {}}

        self.assertTrue(self.filter.host_passes(host1, filter_properties))

    def test_no_share_extra_specs(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {
                    'filter_function': '1 == 1',
                }
            })

        filter_properties = {'share_type': {}}

        self.assertTrue(self.filter.host_passes(host1, filter_properties))

    def test_function_extra_spec_replacement(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {
                    'filter_function': 'extra.var == 1',
                }
            })

        filter_properties = {
            'share_type': {
                'extra_specs': {
                    'var': 1,
                }
            }
        }

        self.assertTrue(self.filter.host_passes(host1, filter_properties))

    def test_function_stats_replacement(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'total_capacity_gb': 100,
                'capabilities': {
                    'filter_function': 'stats.total_capacity_gb < 200',
                }
            })

        filter_properties = {'share_type': {}}

        self.assertTrue(self.filter.host_passes(host1, filter_properties))

    def test_function_share_replacement(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {
                    'filter_function': 'share.size < 5',
                }
            })

        filter_properties = {
            'request_spec': {
                'resource_properties': {
                    'size': 1
                }
            }
        }

        self.assertTrue(self.filter.host_passes(host1, filter_properties))

    def test_function_exception_caught(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {
                    'filter_function': '1 / 0 == 0',
                }
            })

        filter_properties = {}

        self.assertFalse(self.filter.host_passes(host1, filter_properties))

    def test_capabilities(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {
                    'foo': 10,
                    'filter_function': 'capabilities.foo == 10',
                },
            })

        filter_properties = {}

        self.assertTrue(self.filter.host_passes(host1, filter_properties))

    def test_wrong_capabilities(self):
        host1 = fakes.FakeHostState(
            'host1', {
                'capabilities': {
                    'bar': 10,
                    'filter_function': 'capabilities.foo == 10',
                },
            })

        filter_properties = {}

        self.assertFalse(self.filter.host_passes(host1, filter_properties))
