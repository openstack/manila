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

from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import test

from manila_tempest_tests import clients_share as clients
from manila_tempest_tests.tests.api import base

CONF = config.CONF


@base.skip_if_microversion_not_supported("2.9")
class ExportLocationsNegativeTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ExportLocationsNegativeTest, cls).resource_setup()
        cls.admin_client = cls.shares_v2_client
        cls.member_client = clients.Manager().shares_v2_client
        cls.share = cls.create_share()
        cls.share = cls.shares_v2_client.get_share(cls.share['id'])
        cls.share_instances = cls.shares_v2_client.get_instances_of_share(
            cls.share['id'])

    @test.attr(type=["gate", "negative"])
    def test_get_export_locations_by_inexistent_share(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_client.list_share_export_locations,
            "fake-inexistent-share-id",
        )

    @test.attr(type=["gate", "negative"])
    def test_get_inexistent_share_export_location(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_client.get_share_export_location,
            self.share['id'],
            "fake-inexistent-share-instance-id",
        )

    @test.attr(type=["gate", "negative"])
    def test_get_export_locations_by_inexistent_share_instance(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_client.list_share_instance_export_locations,
            "fake-inexistent-share-instance-id",
        )

    @test.attr(type=["gate", "negative"])
    def test_get_inexistent_share_instance_export_location(self):
        for share_instance in self.share_instances:
            self.assertRaises(
                lib_exc.NotFound,
                self.admin_client.get_share_instance_export_location,
                share_instance['id'],
                "fake-inexistent-share-instance-id",
            )

    @test.attr(type=["gate", "negative"])
    def test_list_share_instance_export_locations_by_member(self):
        for share_instance in self.share_instances:
            self.assertRaises(
                lib_exc.Forbidden,
                self.member_client.list_share_instance_export_locations,
                "fake-inexistent-share-instance-id",
            )

    @test.attr(type=["gate", "negative"])
    def test_get_share_instance_export_location_by_member(self):
        for share_instance in self.share_instances:
            export_locations = (
                self.admin_client.list_share_instance_export_locations(
                    share_instance['id']))
            for el in export_locations:
                self.assertRaises(
                    lib_exc.Forbidden,
                    self.member_client.get_share_instance_export_location,
                    share_instance['id'], el['id'],
                )
