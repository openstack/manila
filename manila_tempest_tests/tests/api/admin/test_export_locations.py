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

import ddt
from oslo_utils import timeutils
from oslo_utils import uuidutils
import six
from tempest import config
from tempest import test

from manila_tempest_tests import clients_share as clients
from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF
LATEST_MICROVERSION = CONF.share.max_api_microversion


@base.skip_if_microversion_not_supported("2.9")
@ddt.ddt
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

    def _verify_export_location_structure(
            self, export_locations, role='admin', version=LATEST_MICROVERSION,
            format='summary'):

        # Determine which keys to expect based on role, version and format
        summary_keys = ['id', 'path']
        if utils.is_microversion_ge(version, '2.14'):
            summary_keys += ['preferred']

        admin_summary_keys = summary_keys + [
            'share_instance_id', 'is_admin_only']

        detail_keys = summary_keys + ['created_at', 'updated_at']

        admin_detail_keys = admin_summary_keys + ['created_at', 'updated_at']

        if format == 'summary':
            if role == 'admin':
                expected_keys = admin_summary_keys
            else:
                expected_keys = summary_keys
        else:
            if role == 'admin':
                expected_keys = admin_detail_keys
            else:
                expected_keys = detail_keys

        if not isinstance(export_locations, (list, tuple, set)):
            export_locations = (export_locations, )

        for export_location in export_locations:

            # Check that the correct keys are present
            self.assertEqual(len(expected_keys), len(export_location))
            for key in expected_keys:
                self.assertIn(key, export_location)

            # Check the format of ever-present summary keys
            self.assertTrue(uuidutils.is_uuid_like(export_location['id']))
            self.assertTrue(isinstance(export_location['path'],
                                       six.string_types))

            if utils.is_microversion_ge(version, '2.14'):
                self.assertIn(export_location['preferred'], (True, False))

            if role == 'admin':
                self.assertIn(export_location['is_admin_only'], (True, False))
                self.assertTrue(uuidutils.is_uuid_like(
                    export_location['share_instance_id']))

            # Check the format of the detail keys
            if format == 'detail':
                for time in (export_location['created_at'],
                             export_location['updated_at']):
                    # If var 'time' has incorrect value then ValueError
                    # exception is expected to be raised. So, just try parse
                    # it making assertion that it has proper date value.
                    timeutils.parse_strtime(time)

    @test.attr(type=["gate", ])
    @utils.skip_if_microversion_not_supported('2.13')
    def test_list_share_export_locations(self):
        export_locations = self.admin_client.list_share_export_locations(
            self.share['id'], version='2.13')

        self._verify_export_location_structure(export_locations,
                                               version='2.13')

    @test.attr(type=["gate", ])
    @utils.skip_if_microversion_not_supported('2.14')
    def test_list_share_export_locations_with_preferred_flag(self):
        export_locations = self.admin_client.list_share_export_locations(
            self.share['id'], version='2.14')

        self._verify_export_location_structure(export_locations,
                                               version='2.14')

    @test.attr(type=["gate", ])
    def test_get_share_export_location(self):
        export_locations = self.admin_client.list_share_export_locations(
            self.share['id'])

        for export_location in export_locations:
            el = self.admin_client.get_share_export_location(
                self.share['id'], export_location['id'])
            self._verify_export_location_structure(el, format='detail')

    @test.attr(type=["gate", ])
    def test_list_share_export_locations_by_member(self):
        export_locations = self.member_client.list_share_export_locations(
            self.share['id'])

        self._verify_export_location_structure(export_locations, role='member')

    @test.attr(type=["gate", ])
    def test_get_share_export_location_by_member(self):
        export_locations = self.admin_client.list_share_export_locations(
            self.share['id'])

        for export_location in export_locations:
            if export_location['is_admin_only']:
                continue
            el = self.member_client.get_share_export_location(
                self.share['id'], export_location['id'])
            self._verify_export_location_structure(el, role='member',
                                                   format='detail')

    @test.attr(type=["gate", ])
    @utils.skip_if_microversion_not_supported('2.13')
    def test_list_share_instance_export_locations(self):
        for share_instance in self.share_instances:
            export_locations = (
                self.admin_client.list_share_instance_export_locations(
                    share_instance['id'], version='2.13'))
            self._verify_export_location_structure(export_locations,
                                                   version='2.13')

    @test.attr(type=["gate", ])
    @utils.skip_if_microversion_not_supported('2.14')
    def test_list_share_instance_export_locations_with_preferred_flag(self):
        for share_instance in self.share_instances:
            export_locations = (
                self.admin_client.list_share_instance_export_locations(
                    share_instance['id'], version='2.14'))
            self._verify_export_location_structure(export_locations,
                                                   version='2.14')

    @test.attr(type=["gate", ])
    def test_get_share_instance_export_location(self):
        for share_instance in self.share_instances:
            export_locations = (
                self.admin_client.list_share_instance_export_locations(
                    share_instance['id']))
            for el in export_locations:
                el = self.admin_client.get_share_instance_export_location(
                    share_instance['id'], el['id'])
                self._verify_export_location_structure(el, format='detail')

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
            sorted(share_export_locations, key=lambda el: el['id']),
            sorted(share_instances_export_locations, key=lambda el: el['id'])
        )
