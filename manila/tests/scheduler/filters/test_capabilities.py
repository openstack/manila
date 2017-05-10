# Copyright 2011 OpenStack Foundation.
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
Tests For CapabilitiesFilter.
"""

import ddt

from manila.scheduler.filters import capabilities
from manila import test
from manila.tests.scheduler import fakes


@ddt.ddt
class HostFiltersTestCase(test.TestCase):
    """Test case for CapabilitiesFilter."""

    def setUp(self):
        super(HostFiltersTestCase, self).setUp()
        self.filter = capabilities.CapabilitiesFilter()

    def _do_test_type_filter_extra_specs(self, ecaps, especs, passes):
        capabilities = {'enabled': True}
        capabilities.update(ecaps)
        service = {'disabled': False}
        filter_properties = {'resource_type': {'name': 'fake_type',
                                               'extra_specs': especs}}
        host = fakes.FakeHostState('host1',
                                   {'free_capacity_gb': 1024,
                                    'capabilities': capabilities,
                                    'service': service})
        assertion = self.assertTrue if passes else self.assertFalse
        assertion(self.filter.host_passes(host, filter_properties))

    def test_capability_filter_passes_extra_specs_simple(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'opt1': '1', 'opt2': '2'},
            especs={'opt1': '1', 'opt2': '2'},
            passes=True)

    def test_capability_filter_fails_extra_specs_simple(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'opt1': '1', 'opt2': '2'},
            especs={'opt1': '1', 'opt2': '222'},
            passes=False)

    def test_capability_filter_passes_extra_specs_complex(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'opt1': 10, 'opt2': 5},
            especs={'opt1': '>= 2', 'opt2': '<= 8'},
            passes=True)

    def test_capability_filter_fails_extra_specs_complex(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'opt1': 10, 'opt2': 5},
            especs={'opt1': '>= 2', 'opt2': '>= 8'},
            passes=False)

    def test_capability_filter_passes_extra_specs_list_simple(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'opt1': ['1', '2'], 'opt2': '2'},
            especs={'opt1': '1', 'opt2': '2'},
            passes=True)

    @ddt.data('<is> True', '<is> False')
    def test_capability_filter_passes_extra_specs_list_complex(self, opt1):
        self._do_test_type_filter_extra_specs(
            ecaps={'opt1': [True, False], 'opt2': ['1', '2']},
            especs={'opt1': opt1, 'opt2': '<= 8'},
            passes=True)

    def test_capability_filter_fails_extra_specs_list_simple(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'opt1': ['1', '2'], 'opt2': ['2']},
            especs={'opt1': '3', 'opt2': '2'},
            passes=False)

    def test_capability_filter_fails_extra_specs_list_complex(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'opt1': [True, False], 'opt2': ['1', '2']},
            especs={'opt1': 'fake', 'opt2': '<= 8'},
            passes=False)

    def test_capability_filter_passes_scope_extra_specs(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'scope_lv1': {'opt1': 10}},
            especs={'capabilities:scope_lv1:opt1': '>= 2'},
            passes=True)

    def test_capability_filter_passes_fakescope_extra_specs(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'scope_lv1': {'opt1': 10}, 'opt2': 5},
            especs={'scope_lv1:opt1': '= 2', 'opt2': '>= 3'},
            passes=True)

    def test_capability_filter_fails_scope_extra_specs(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'scope_lv1': {'opt1': 10}},
            especs={'capabilities:scope_lv1:opt1': '<= 2'},
            passes=False)

    def test_capability_filter_passes_multi_level_scope_extra_specs(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'scope_lv0': {'scope_lv1':
                                 {'scope_lv2': {'opt1': 10}}}},
            especs={'capabilities:scope_lv0:scope_lv1:scope_lv2:opt1': '>= 2'},
            passes=True)

    def test_capability_filter_fails_wrong_scope_extra_specs(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'scope_lv0': {'opt1': 10}},
            especs={'capabilities:scope_lv1:opt1': '>= 2'},
            passes=False)

    def test_capability_filter_passes_multi_level_scope_extra_specs_list(self):
        self._do_test_type_filter_extra_specs(
            ecaps={
                'scope_lv0': {
                    'scope_lv1': {
                        'scope_lv2': {
                            'opt1': [True, False],
                        },
                    },
                },
            },
            especs={
                'capabilities:scope_lv0:scope_lv1:scope_lv2:opt1': '<is> True',
            },
            passes=True)

    def test_capability_filter_fails_multi_level_scope_extra_specs_list(self):
        self._do_test_type_filter_extra_specs(
            ecaps={
                'scope_lv0': {
                    'scope_lv1': {
                        'scope_lv2': {
                            'opt1': [True, False],
                            'opt2': ['1', '2'],
                        },
                    },
                },
            },
            especs={
                'capabilities:scope_lv0:scope_lv1:scope_lv2:opt1': '<is> True',
                'capabilities:scope_lv0:scope_lv1:scope_lv2:opt2': '3',
            },
            passes=False)

    def test_capability_filter_fails_wrong_scope_extra_specs_list(self):
        self._do_test_type_filter_extra_specs(
            ecaps={'scope_lv0': {'opt1': [True, False]}},
            especs={'capabilities:scope_lv1:opt1': '<is> True'},
            passes=False)
