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
Tests for the ShareReplicationFilter.
"""
import ddt

from oslo_context import context

from manila.scheduler.filters import share_replication
from manila import test
from manila.tests.scheduler import fakes


@ddt.ddt
class ShareReplicationFilterTestCase(test.TestCase):
    """Test case for ShareReplicationFilter."""

    def setUp(self):
        super(ShareReplicationFilterTestCase, self).setUp()
        self.filter = share_replication.ShareReplicationFilter()
        self.debug_log = self.mock_object(share_replication.LOG, 'debug')

    @staticmethod
    def _create_replica_request(replication_domain='kashyyyk',
                                replication_type='dr',
                                active_replica_host=fakes.FAKE_HOST_STRING_1,
                                all_replica_hosts=fakes.FAKE_HOST_STRING_1,
                                is_admin=False):
        ctxt = context.RequestContext('fake', 'fake', is_admin=is_admin)
        return {
            'context': ctxt,
            'request_spec': {
                'active_replica_host': active_replica_host,
                'all_replica_hosts': all_replica_hosts,
            },
            'resource_type': {
                'extra_specs': {
                    'replication_type': replication_type,
                },
            },
            'replication_domain': replication_domain,
        }

    @ddt.data('tatooine', '')
    def test_share_replication_filter_fails_incompatible_domain(self, domain):
        request = self._create_replica_request()

        host = fakes.FakeHostState('host1',
                                   {
                                       'replication_domain': domain,
                                   })

        self.assertFalse(self.filter.host_passes(host, request))
        self.assertTrue(self.debug_log.called)

    def test_share_replication_filter_fails_no_replication_domain(self):
        request = self._create_replica_request()

        host = fakes.FakeHostState('host1',
                                   {
                                       'replication_domain': None,
                                   })

        self.assertFalse(self.filter.host_passes(host, request))
        self.assertTrue(self.debug_log.called)

    def test_share_replication_filter_fails_host_has_replicas(self):
        all_replica_hosts = ','.join(['host1', fakes.FAKE_HOST_STRING_1])
        request = self._create_replica_request(
            all_replica_hosts=all_replica_hosts)

        host = fakes.FakeHostState('host1',
                                   {
                                       'replication_domain': 'kashyyyk',
                                   })
        self.assertFalse(self.filter.host_passes(host, request))
        self.assertTrue(self.debug_log.called)

    def test_share_replication_filter_passes_no_replication_type(self):
        request = self._create_replica_request(replication_type=None)

        host = fakes.FakeHostState('host1',
                                   {
                                       'replication_domain': 'tatooine',
                                   })

        self.assertTrue(self.filter.host_passes(host, request))

    def test_share_replication_filter_passes_no_active_replica_host(self):
        request = self._create_replica_request(active_replica_host=None)

        host = fakes.FakeHostState('host1',
                                   {
                                       'replication_domain': 'tatooine',
                                   })

        self.assertTrue(self.filter.host_passes(host, request))

    def test_share_replication_filter_passes_happy_day(self):
        all_replica_hosts = ','.join(['host1', fakes.FAKE_HOST_STRING_1])
        request = self._create_replica_request(
            all_replica_hosts=all_replica_hosts)

        host = fakes.FakeHostState('host2',
                                   {
                                       'replication_domain': 'kashyyyk',
                                   })

        self.assertTrue(self.filter.host_passes(host, request))

    def test_share_replication_filter_empty(self):
        request = {}

        host = fakes.FakeHostState('host1',
                                   {
                                       'replication_domain': 'naboo',
                                   })

        self.assertTrue(self.filter.host_passes(host, request))
