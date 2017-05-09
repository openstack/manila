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
Tests For AvailabilityZoneFilter.
"""

from oslo_context import context

from manila.scheduler.filters import availability_zone
from manila import test
from manila.tests.scheduler import fakes


class HostFiltersTestCase(test.TestCase):
    """Test case for AvailabilityZoneFilter."""

    def setUp(self):
        super(HostFiltersTestCase, self).setUp()
        self.filter = availability_zone.AvailabilityZoneFilter()

    @staticmethod
    def _make_zone_request(zone, is_admin=False):
        ctxt = context.RequestContext('fake', 'fake', is_admin=is_admin)
        return {
            'context': ctxt,
            'request_spec': {
                'resource_properties': {
                    'availability_zone_id': zone
                }
            }
        }

    def test_availability_zone_filter_same(self):
        service = {'availability_zone_id': 'nova'}
        request = self._make_zone_request('nova')
        host = fakes.FakeHostState('host1',
                                   {'service': service})
        self.assertTrue(self.filter.host_passes(host, request))

    def test_availability_zone_filter_different(self):
        service = {'availability_zone_id': 'nova'}
        request = self._make_zone_request('bad')
        host = fakes.FakeHostState('host1',
                                   {'service': service})
        self.assertFalse(self.filter.host_passes(host, request))

    def test_availability_zone_filter_empty(self):
        service = {'availability_zone_id': 'nova'}
        request = {}
        host = fakes.FakeHostState('host1',
                                   {'service': service})
        self.assertTrue(self.filter.host_passes(host, request))
