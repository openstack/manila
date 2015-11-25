# Copyright 2011 OpenStack LLC.  # All Rights Reserved.
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
Tests For CapacityFilter.
"""

import ddt

from manila import context
from manila.scheduler.filters import capacity
from manila import test
from manila.tests.scheduler import fakes
from manila import utils


@ddt.ddt
class HostFiltersTestCase(test.TestCase):
    """Test case CapacityFilter."""

    def setUp(self):
        super(HostFiltersTestCase, self).setUp()
        self.context = context.RequestContext('fake', 'fake')
        self.filter = capacity.CapacityFilter()

    def _stub_service_is_up(self, ret_value):
        def fake_service_is_up(service):
            return ret_value
        self.mock_object(utils, 'service_is_up', fake_service_is_up)

    @ddt.data(
        {'size': 100, 'share_on': None, 'host': 'host1'},
        {'size': 100, 'share_on': 'host1#pool1', 'host': 'host1#pools1'})
    @ddt.unpack
    def test_capacity_filter_passes(self, size, share_on, host):
        self._stub_service_is_up(True)
        filter_properties = {'size': size,
                             'share_exists_on': share_on}
        service = {'disabled': False}
        host = fakes.FakeHostState(host,
                                   {'total_capacity_gb': 500,
                                    'free_capacity_gb': 200,
                                    'updated_at': None,
                                    'service': service})
        self.assertTrue(self.filter.host_passes(host, filter_properties))

    @ddt.data(
        {'free_capacity': 120, 'total_capacity': 200,
         'reserved': 20},
        {'free_capacity': None, 'total_capacity': None,
         'reserved': None})
    @ddt.unpack
    def test_capacity_filter_fails(self, free_capacity, total_capacity,
                                   reserved):
        self._stub_service_is_up(True)
        filter_properties = {'size': 100}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'total_capacity_gb': total_capacity,
                                    'free_capacity_gb': free_capacity,
                                    'reserved_percentage': reserved,
                                    'updated_at': None,
                                    'service': service})
        self.assertFalse(self.filter.host_passes(host, filter_properties))

    def test_capacity_filter_passes_unknown(self):
        free = 'unknown'
        self._stub_service_is_up(True)
        filter_properties = {'size': 100}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'free_capacity_gb': free,
                                    'updated_at': None,
                                    'service': service})
        self.assertTrue(self.filter.host_passes(host, filter_properties))

    @ddt.data(
        {'free_capacity': 'unknown', 'total_capacity': 'unknown'},
        {'free_capacity': 200, 'total_capacity': 'unknown'})
    @ddt.unpack
    def test_capacity_filter_passes_total(self, free_capacity,
                                          total_capacity):
        self._stub_service_is_up(True)
        filter_properties = {'size': 100}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'free_capacity_gb': free_capacity,
                                    'total_capacity_gb': total_capacity,
                                    'reserved_percentage': 0,
                                    'updated_at': None,
                                    'service': service})
        self.assertTrue(self.filter.host_passes(host, filter_properties))

    @ddt.data(
        {'free': 200, 'total': 'unknown', 'reserved': 5},
        {'free': 50, 'total': 'unknown', 'reserved': 0},
        {'free': 200, 'total': 0, 'reserved': 0})
    @ddt.unpack
    def test_capacity_filter_fails_total(self, free, total, reserved):
        self._stub_service_is_up(True)
        filter_properties = {'size': 100}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'free_capacity_gb': free,
                                    'total_capacity_gb': total,
                                    'reserved_percentage': reserved,
                                    'updated_at': None,
                                    'service': service})
        self.assertFalse(self.filter.host_passes(host, filter_properties))

    @ddt.data(
        {'size': 100, 'cap_thin': '<is> True',
         'total': 500, 'free': 200, 'provisioned': 500,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True},
        {'size': 3000, 'cap_thin': '<is> True',
         'total': 500, 'free': 200, 'provisioned': 7000,
         'max_ratio': 20, 'reserved': 5, 'thin_prov': True},
        {'size': 100, 'cap_thin': '<is> False',
         'total': 500, 'free': 200, 'provisioned': 300,
         'max_ratio': 1.0, 'reserved': 5, 'thin_prov': False},
        {'size': 100, 'cap_thin': '<is> True',
         'total': 500, 'free': 200, 'provisioned': 400,
         'max_ratio': 1.0, 'reserved': 5, 'thin_prov': True},
        {'size': 100, 'cap_thin': '<is> True',
         'total': 500, 'free': 125, 'provisioned': 400,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True},
        {'size': 100, 'cap_thin': '<is> True',
         'total': 500, 'free': 80, 'provisioned': 600,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True},
        {'size': 100, 'cap_thin': '<is> True',
         'total': 500, 'free': 100, 'provisioned': 400,
         'max_ratio': 2.0, 'reserved': 0, 'thin_prov': True})
    @ddt.unpack
    def test_filter_thin_passes(self, size, cap_thin, total, free, provisioned,
                                max_ratio, reserved, thin_prov):
        self._stub_service_is_up(True)
        filter_properties = {'size': size,
                             'capabilities:thin_provisioning': cap_thin}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'total_capacity_gb': total,
                                    'free_capacity_gb': free,
                                    'provisioned_capacity_gb': provisioned,
                                    'max_over_subscription_ratio': max_ratio,
                                    'reserved_percentage': reserved,
                                    'thin_provisioning': thin_prov,
                                    'updated_at': None,
                                    'service': service})
        self.assertTrue(self.filter.host_passes(host, filter_properties))

    @ddt.data(
        {'size': 200, 'cap_thin': '<is> True',
         'total': 500, 'free': 100, 'provisioned': 400,
         'max_ratio': 0.8, 'reserved': 0, 'thin_prov': True},
        {'size': 100, 'cap_thin': '<is> True',
         'total': 500, 'free': 200, 'provisioned': 700,
         'max_ratio': 1.5, 'reserved': 5, 'thin_prov': True},
        {'size': 2000, 'cap_thin': '<is> True',
         'total': 500, 'free': 30, 'provisioned': 9000,
         'max_ratio': 20.0, 'reserved': 0, 'thin_prov': True},
        {'size': 100, 'cap_thin': '<is> True',
         'total': 500, 'free': 100, 'provisioned': 1000,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True},
        {'size': 100, 'cap_thin': '<is> False',
         'total': 500, 'free': 100, 'provisioned': 400,
         'max_ratio': 1.0, 'reserved': 5, 'thin_prov': False},
        {'size': 100, 'cap_thin': '<is> True',
         'total': 500, 'free': 0, 'provisioned': 800,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True},
        {'size': 100, 'cap_thin': '<is> True',
         'total': 500, 'free': 99, 'provisioned': 1000,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True},
        {'size': 400, 'cap_thin': '<is> True',
         'total': 500, 'free': 200, 'provisioned': 600,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True})
    @ddt.unpack
    def test_filter_thin_fails(self, size, cap_thin, total, free, provisioned,
                               max_ratio, reserved, thin_prov):
        self._stub_service_is_up(True)
        filter_properties = {'size': size,
                             'capabilities:thin_provisioning': cap_thin}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'total_capacity_gb': total,
                                    'free_capacity_gb': free,
                                    'provisioned_capacity_gb': provisioned,
                                    'max_over_subscription_ratio': max_ratio,
                                    'reserved_percentage': reserved,
                                    'thin_provisioning': thin_prov,
                                    'updated_at': None,
                                    'service': service})
        self.assertFalse(self.filter.host_passes(host, filter_properties))
