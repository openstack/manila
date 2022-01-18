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
import ddt
from oslo_context import context

from manila.scheduler.filters import availability_zone
from manila import test
from manila.tests.scheduler import fakes


@ddt.ddt
class HostFiltersTestCase(test.TestCase):
    """Test case for AvailabilityZoneFilter."""

    def setUp(self):
        super(HostFiltersTestCase, self).setUp()
        self.filter = availability_zone.AvailabilityZoneFilter()
        self.az_id = 'e3ecad6f-e984-4cd1-b149-d83c962374a8'
        self.fake_service = {
            'service': {
                'availability_zone_id': self.az_id,
                'availability_zone': {
                    'name': 'nova',
                    'id': self.az_id
                }
            }
        }

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
        request = self._make_zone_request(self.az_id)
        host = fakes.FakeHostState('host1', self.fake_service)
        self.assertTrue(self.filter.host_passes(host, request))

    def test_availability_zone_filter_different(self):
        request = self._make_zone_request('bad')
        host = fakes.FakeHostState('host1', self.fake_service)
        self.assertFalse(self.filter.host_passes(host, request))

    def test_availability_zone_filter_empty(self):
        request = {}
        host = fakes.FakeHostState('host1', self.fake_service)
        self.assertTrue(self.filter.host_passes(host, request))

    def test_availability_zone_filter_both_request_AZ_and_type_AZs_match(self):
        request = self._make_zone_request(
            '9382098d-d40f-42a2-8f31-8eb78ee18c02')
        request['request_spec']['availability_zones'] = [
            'nova', 'super nova', 'hypernova']
        service = {
            'availability_zone': {
                'name': 'nova',
                'id': '9382098d-d40f-42a2-8f31-8eb78ee18c02',
            },
            'availability_zone_id': '9382098d-d40f-42a2-8f31-8eb78ee18c02',
        }
        host = fakes.FakeHostState('host1', {'service': service})

        self.assertTrue(self.filter.host_passes(host, request))

    @ddt.data((['zone1', 'zone2', 'zone 4', 'zone3'], 'zone2', True),
              (['zone1zone2zone3'], 'zone2', False),
              (['zone1zone2zone3'], 'nova', False),
              (['zone1', 'zone2', 'zone 4', 'zone3'], 'zone 4', True))
    @ddt.unpack
    def test_availability_zone_filter_only_share_type_AZs(
            self, supported_azs, request_az, host_passes):
        service = {
            'availability_zone': {
                'name': request_az,
                'id': '9382098d-d40f-42a2-8f31-8eb78ee18c02',
            },
            'availability_zone_id': '9382098d-d40f-42a2-8f31-8eb78ee18c02',
        }
        request = self._make_zone_request(None)
        request['request_spec']['availability_zones'] = supported_azs
        request['request_spec']['az_request_multiple_subnet_support_map'] = \
            {'zone2': 2}
        host = fakes.FakeHostState('host1', {'service': service})

        self.assertEqual(host_passes, self.filter.host_passes(host, request))
