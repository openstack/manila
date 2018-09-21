# Copyright (c) 2017 Hitachi Data Systems, Inc.
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
from oslo_utils import uuidutils
import six
from tempest import config
import testtools
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base

CONF = config.CONF
LATEST_MICROVERSION = CONF.share.max_api_microversion


@base.skip_if_microversion_lt("2.32")
@testtools.skipUnless(CONF.share.run_mount_snapshot_tests and
                      CONF.share.run_snapshot_tests,
                      "Mountable snapshots tests are disabled.")
@ddt.ddt
class SnapshotExportLocationsTest(base.BaseSharesMixedTest):

    @classmethod
    def setup_clients(cls):
        super(SnapshotExportLocationsTest, cls).setup_clients()
        cls.admin_client = cls.admin_shares_v2_client

    @classmethod
    def resource_setup(cls):
        super(SnapshotExportLocationsTest, cls).resource_setup()
        # create share type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']
        # create share
        cls.share = cls.create_share(share_type_id=cls.share_type_id,
                                     client=cls.admin_client)
        cls.snapshot = cls.create_snapshot_wait_for_active(
            cls.share['id'], client=cls.admin_client)
        cls.snapshot = cls.admin_client.get_snapshot(cls.snapshot['id'])
        cls.snapshot_instances = cls.admin_client.list_snapshot_instances(
            snapshot_id=cls.snapshot['id'])

    def _verify_export_location_structure(
            self, export_locations, role='admin', detail=False):

        # Determine which keys to expect based on role, version and format
        summary_keys = ['id', 'path', 'links']
        if detail:
            summary_keys.extend(['created_at', 'updated_at'])

        admin_summary_keys = summary_keys + [
            'share_snapshot_instance_id', 'is_admin_only']

        if role == 'admin':
            expected_keys = admin_summary_keys
        else:
            expected_keys = summary_keys

        if not isinstance(export_locations, (list, tuple, set)):
            export_locations = (export_locations, )

        for export_location in export_locations:

            # Check that the correct keys are present
            self.assertEqual(len(expected_keys), len(export_location))
            for key in expected_keys:
                self.assertIn(key, export_location)

            # Check the format of ever-present summary keys
            self.assertTrue(uuidutils.is_uuid_like(export_location['id']))
            self.assertIsInstance(export_location['path'],
                                  six.string_types)

            if role == 'admin':
                self.assertIn(export_location['is_admin_only'], (True, False))
                self.assertTrue(uuidutils.is_uuid_like(
                    export_location['share_snapshot_instance_id']))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    def test_list_snapshot_export_location(self):
        export_locations = (
            self.admin_client.list_snapshot_export_locations(
                self.snapshot['id']))

        for el in export_locations:
            self._verify_export_location_structure(el)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    def test_get_snapshot_export_location(self):
        export_locations = (
            self.admin_client.list_snapshot_export_locations(
                self.snapshot['id']))

        for export_location in export_locations:
            el = self.admin_client.get_snapshot_export_location(
                self.snapshot['id'], export_location['id'])
            self._verify_export_location_structure(el, detail=True)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    def test_get_snapshot_instance_export_location(self):
        for snapshot_instance in self.snapshot_instances:
            export_locations = (
                self.admin_client.list_snapshot_instance_export_locations(
                    snapshot_instance['id']))
            for el in export_locations:
                el = self.admin_client.get_snapshot_instance_export_location(
                    snapshot_instance['id'], el['id'])
                self._verify_export_location_structure(el, detail=True)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    def test_snapshot_contains_all_export_locations_of_all_snapshot_instances(
            self):
        snapshot_export_locations = (
            self.admin_client.list_snapshot_export_locations(
                self.snapshot['id']))
        snapshot_instances_export_locations = []
        for snapshot_instance in self.snapshot_instances:
            snapshot_instance_export_locations = (
                self.admin_client.list_snapshot_instance_export_locations(
                    snapshot_instance['id']))
            snapshot_instances_export_locations.extend(
                snapshot_instance_export_locations)

        self.assertEqual(
            len(snapshot_export_locations),
            len(snapshot_instances_export_locations)
        )
        self.assertEqual(
            sorted(snapshot_export_locations, key=lambda el: el['id']),
            sorted(snapshot_instances_export_locations,
                   key=lambda el: el['id'])
        )
