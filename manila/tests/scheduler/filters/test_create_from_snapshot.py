# Copyright 2020 NetApp, Inc.
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
Tests for the CreateFromSnapshotFilter.
"""
import ddt

from manila.scheduler.filters import create_from_snapshot
from manila import test
from manila.tests.scheduler import fakes


@ddt.ddt
class CreateFromSnapshotFilterTestCase(test.TestCase):
    """Test case for CreateFromSnapshotFilter."""

    def setUp(self):
        super(CreateFromSnapshotFilterTestCase, self).setUp()
        self.filter = create_from_snapshot.CreateFromSnapshotFilter()

    @staticmethod
    def _create_request(snapshot_id=None,
                        snapshot_host=None,
                        replication_domain=None):
        return {
            'request_spec': {
                'snapshot_id': snapshot_id,
                'snapshot_host': snapshot_host,
            },
            'replication_domain': replication_domain,
        }

    @staticmethod
    def _create_host_state(host=None, rep_domain=None):
        return fakes.FakeHostState(host,
                                   {
                                       'replication_domain': rep_domain,
                                   })

    def test_without_snapshot_id(self):
        request = self._create_request()
        host = self._create_host_state(host='fake_host')

        self.assertTrue(self.filter.host_passes(host, request))

    def test_without_snapshot_host(self):
        request = self._create_request(snapshot_id='fake_snapshot_id',
                                       replication_domain="fake_domain")
        host = self._create_host_state(host='fake_host',
                                       rep_domain='fake_domain_2')

        self.assertTrue(self.filter.host_passes(host, request))

    @ddt.data(('host1@AAA#pool1', 'host1@AAA#pool1'),
              ('host1@AAA#pool1', 'host1@AAA#pool2'))
    @ddt.unpack
    def test_same_backend(self, request_host, host_state):
        request = self._create_request(snapshot_id='fake_snapshot_id',
                                       snapshot_host=request_host)
        host = self._create_host_state(host=host_state)

        self.assertTrue(self.filter.host_passes(host, request))

    def test_same_availability_zone(self):
        request = self._create_request(snapshot_id='fake_snapshot_id',
                                       snapshot_host='fake_host',
                                       replication_domain="fake_domain")
        host = self._create_host_state(host='fake_host_2',
                                       rep_domain='fake_domain')
        self.assertTrue(self.filter.host_passes(host, request))

    def test_different_backend_and_availability_zone(self):
        request = self._create_request(snapshot_id='fake_snapshot_id',
                                       snapshot_host='fake_host',
                                       replication_domain="fake_domain")
        host = self._create_host_state(host='fake_host_2',
                                       rep_domain='fake_domain_2')

        self.assertFalse(self.filter.host_passes(host, request))
