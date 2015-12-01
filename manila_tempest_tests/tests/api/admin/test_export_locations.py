# Copyright 2015 Mirantis Inc.
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

from oslo_utils import timeutils
from oslo_utils import uuidutils
import six
from tempest import config
from tempest import test

from manila_tempest_tests import clients_share as clients
from manila_tempest_tests.tests.api import base

CONF = config.CONF


@base.skip_if_microversion_not_supported("2.9")
class ExportLocationsTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ExportLocationsTest, cls).resource_setup()
        cls.admin_client = cls.shares_v2_client
        cls.member_client = clients.Manager().shares_v2_client
        cls.share = cls.create_share()
        cls.share = cls.shares_v2_client.get_share(cls.share['id'])
        cls.share_instances = cls.shares_v2_client.get_instances_of_share(
            cls.share['id'])

    def _verify_export_location_structure(self, export_locations,
                                          role='admin'):
        expected_keys = [
            'created_at', 'updated_at', 'path', 'uuid',
        ]
        if role == 'admin':
            expected_keys.extend(['is_admin_only', 'share_instance_id'])

        if not isinstance(export_locations, (list, tuple, set)):
            export_locations = (export_locations, )

        for export_location in export_locations:
            self.assertEqual(len(expected_keys), len(export_location))
            for key in expected_keys:
                self.assertIn(key, export_location)
            if role == 'admin':
                self.assertIn(export_location['is_admin_only'], (True, False))
                self.assertTrue(
                    uuidutils.is_uuid_like(
                        export_location['share_instance_id']))
            self.assertTrue(uuidutils.is_uuid_like(export_location['uuid']))
            self.assertTrue(
                isinstance(export_location['path'], six.string_types))
            for time in (export_location['created_at'],
                         export_location['updated_at']):
                # If var 'time' has incorrect value then ValueError exception
                # is expected to be raised. So, just try parse it making
                # assertion that it has proper date value.
                timeutils.parse_strtime(time)

    @test.attr(type=["gate", ])
    def test_list_share_export_locations(self):
        export_locations = self.admin_client.list_share_export_locations(
            self.share['id'])

        self._verify_export_location_structure(export_locations)

    @test.attr(type=["gate", ])
    def test_get_share_export_location(self):
        export_locations = self.admin_client.list_share_export_locations(
            self.share['id'])

        for export_location in export_locations:
            el = self.admin_client.get_share_export_location(
                self.share['id'], export_location['uuid'])
            self._verify_export_location_structure(el)

    @test.attr(type=["gate", ])
    def test_list_share_export_locations_by_member(self):
        export_locations = self.member_client.list_share_export_locations(
            self.share['id'])

        self._verify_export_location_structure(export_locations, 'member')

    @test.attr(type=["gate", ])
    def test_get_share_export_location_by_member(self):
        export_locations = self.admin_client.list_share_export_locations(
            self.share['id'])

        for export_location in export_locations:
            el = self.member_client.get_share_export_location(
                self.share['id'], export_location['uuid'])
            self._verify_export_location_structure(el, 'member')

    @test.attr(type=["gate", ])
    def test_list_share_instance_export_locations(self):
        for share_instance in self.share_instances:
            export_locations = (
                self.admin_client.list_share_instance_export_locations(
                    share_instance['id']))
            self._verify_export_location_structure(export_locations)

    @test.attr(type=["gate", ])
    def test_get_share_instance_export_location(self):
        for share_instance in self.share_instances:
            export_locations = (
                self.admin_client.list_share_instance_export_locations(
                    share_instance['id']))
            for el in export_locations:
                el = self.admin_client.get_share_instance_export_location(
                    share_instance['id'], el['uuid'])
                self._verify_export_location_structure(el)

    @test.attr(type=["gate", ])
    def test_share_contains_all_export_locations_of_all_share_instances(self):
        share_export_locations = self.admin_client.list_share_export_locations(
            self.share['id'])
        share_instances_export_locations = []
        for share_instance in self.share_instances:
            share_instance_export_locations = (
                self.admin_client.list_share_instance_export_locations(
                    share_instance['id']))
            share_instances_export_locations.extend(
                share_instance_export_locations)

        self.assertEqual(
            len(share_export_locations),
            len(share_instances_export_locations)
        )
        self.assertEqual(
            sorted(share_export_locations, key=lambda el: el['uuid']),
            sorted(share_instances_export_locations, key=lambda el: el['uuid'])
        )
