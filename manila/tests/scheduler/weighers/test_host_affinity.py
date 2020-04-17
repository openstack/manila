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
Tests for Host Affinity Weigher.
"""

from unittest import mock

from manila.common import constants
from manila.db import api as db_api
from manila.scheduler.weighers import host_affinity
from manila import test
from manila.tests import db_utils
from manila.tests.scheduler import fakes


class HostAffinityWeigherTestCase(test.TestCase):
    def setUp(self):
        super(HostAffinityWeigherTestCase, self).setUp()
        self.weigher = host_affinity.HostAffinityWeigher()

    @staticmethod
    def _create_weight_properties(snapshot_id=None,
                                  snapshot_host=None,
                                  availability_zone_id=None):
        return {
            'request_spec': {
                'snapshot_id': snapshot_id,
                'snapshot_host': snapshot_host,
            },
            'availability_zone_id': availability_zone_id,
        }

    def test_without_snapshot_id(self):
        host_state = fakes.FakeHostState('host1', {
            'host': 'host1@AAA#pool2',
        })
        weight_properties = self._create_weight_properties(
            snapshot_host='fake_snapshot_host')

        weight = self.weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(0, weight)

    def test_without_snapshot_host(self):
        host_state = fakes.FakeHostState('host1', {
            'host': 'host1@AAA#pool2',
        })
        weight_properties = self._create_weight_properties(
            snapshot_id='fake_snapshot_id')

        weight = self.weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(0, weight)

    def test_same_backend_and_pool(self):
        share = db_utils.create_share(host="host1@AAA#pool1",
                                      status=constants.STATUS_AVAILABLE)
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        self.mock_object(db_api, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))

        host_state = fakes.FakeHostState('host1@AAA#pool1', {})
        weight_properties = self._create_weight_properties(
            snapshot_id=snapshot['id'], snapshot_host=share['host'])

        weight = self.weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(100, weight)

    def test_same_backend_different_pool(self):
        share = db_utils.create_share(host="host1@AAA#pool1",
                                      status=constants.STATUS_AVAILABLE)
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        self.mock_object(db_api, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))

        host_state = fakes.FakeHostState('host1@AAA#pool2', {})
        weight_properties = self._create_weight_properties(
            snapshot_id=snapshot['id'], snapshot_host=share['host'])

        weight = self.weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(75, weight)

    def test_different_backend_same_availability_zone(self):
        share = db_utils.create_share(
            host="host1@AAA#pool1", status=constants.STATUS_AVAILABLE,
            availability_zone=fakes.FAKE_AZ_1['name'])
        snapshot = db_utils.create_snapshot(share_id=share['id'])

        self.mock_object(db_api, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))
        self.mock_object(db_api, 'availability_zone_get',
                         mock.Mock(return_value=type(
                             'FakeAZ', (object, ), {
                                 'id': fakes.FAKE_AZ_1['id'],
                                 'name': fakes.FAKE_AZ_1['name'],
                             })))
        host_state = fakes.FakeHostState('host2@BBB#pool1', {})
        weight_properties = self._create_weight_properties(
            snapshot_id=snapshot['id'], snapshot_host=share['host'],
            availability_zone_id='zone1')

        weight = self.weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(50, weight)

    def test_different_backend_and_availability_zone(self):
        share = db_utils.create_share(
            host="host1@AAA#pool1", status=constants.STATUS_AVAILABLE,
            availability_zone=fakes.FAKE_AZ_1['name'])
        snapshot = db_utils.create_snapshot(share_id=share['id'])

        self.mock_object(db_api, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))
        self.mock_object(db_api, 'availability_zone_get',
                         mock.Mock(return_value=type(
                             'FakeAZ', (object,), {
                                 'id': fakes.FAKE_AZ_2['id'],
                                 'name': fakes.FAKE_AZ_2['name'],
                             })))
        host_state = fakes.FakeHostState('host2@BBB#pool1', {})
        weight_properties = self._create_weight_properties(
            snapshot_id=snapshot['id'], snapshot_host=share['host'],
            availability_zone_id='zone1'
        )

        weight = self.weigher._weigh_object(host_state, weight_properties)
        self.assertEqual(25, weight)
