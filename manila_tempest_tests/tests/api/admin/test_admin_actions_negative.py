# Copyright 2014 Mirantis Inc.
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
import testtools

from manila_tempest_tests.tests.api import base

CONF = config.CONF


class AdminActionsNegativeTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(AdminActionsNegativeTest, cls).resource_setup()
        cls.admin_client = cls.admin_shares_v2_client
        cls.member_client = cls.shares_v2_client
        cls.sh = cls.create_share(client=cls.admin_client)
        cls.sh_instance = (
            cls.admin_client.get_instances_of_share(cls.sh["id"])[0]
        )
        if CONF.share.run_snapshot_tests:
            cls.sn = cls.create_snapshot_wait_for_active(
                cls.sh["id"], client=cls.admin_client)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    def test_reset_share_state_to_unacceptable_state(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.admin_client.reset_state,
                          self.sh["id"], status="fake")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    def test_reset_share_instance_state_to_unacceptable_state(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.reset_state,
            self.sh_instance["id"],
            s_type="share_instances",
            status="fake"
        )

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_reset_snapshot_state_to_unacceptable_state(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.admin_client.reset_state,
                          self.sn["id"], s_type="snapshots", status="fake")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    def test_try_reset_share_state_with_member(self):
        # Even if member from another tenant, it should be unauthorized
        self.assertRaises(lib_exc.Forbidden,
                          self.member_client.reset_state,
                          self.sh["id"])

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    def test_try_reset_share_instance_state_with_member(self):
        # Even if member from another tenant, it should be unauthorized
        self.assertRaises(lib_exc.Forbidden,
                          self.member_client.reset_state,
                          self.sh_instance["id"], s_type="share_instances")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_try_reset_snapshot_state_with_member(self):
        # Even if member from another tenant, it should be unauthorized
        self.assertRaises(lib_exc.Forbidden,
                          self.member_client.reset_state,
                          self.sn["id"], s_type="snapshots")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    def test_try_force_delete_share_with_member(self):
        # If a non-admin tries to do force_delete, it should be unauthorized
        self.assertRaises(lib_exc.Forbidden,
                          self.member_client.force_delete,
                          self.sh["id"])

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    def test_try_force_delete_share_instance_with_member(self):
        # If a non-admin tries to do force_delete, it should be unauthorized
        self.assertRaises(lib_exc.Forbidden,
                          self.member_client.force_delete,
                          self.sh_instance["id"], s_type="share_instances")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_try_force_delete_snapshot_with_member(self):
        # If a non-admin tries to do force_delete, it should be unauthorized
        self.assertRaises(lib_exc.Forbidden,
                          self.member_client.force_delete,
                          self.sn["id"], s_type="snapshots")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    def test_try_get_share_instance_with_member(self):
        # If a non-admin tries to get instance, it should be unauthorized
        self.assertRaises(lib_exc.Forbidden,
                          self.member_client.get_share_instance,
                          self.sh_instance["id"])

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    def test_try_get_instances_of_share_with_member(self):
        # If a non-admin tries to list instances of given share, it should be
        # unauthorized
        self.assertRaises(lib_exc.Forbidden,
                          self.member_client.get_instances_of_share,
                          self.sh['id'])

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.15")
    def test_reset_task_state_empty(self):
        self.assertRaises(
            lib_exc.BadRequest, self.admin_client.reset_task_state,
            self.sh['id'], None)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.15")
    def test_reset_task_state_invalid_state(self):
        self.assertRaises(
            lib_exc.BadRequest, self.admin_client.reset_task_state,
            self.sh['id'], 'fake_state')


class AdminActionsAPIOnlyNegativeTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(AdminActionsAPIOnlyNegativeTest, cls).resource_setup()
        cls.admin_client = cls.admin_shares_v2_client
        cls.member_client = cls.shares_v2_client

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API])
    def test_try_list_share_instance_with_member(self):
        # If a non-admin tries to list instances, it should be unauthorized
        self.assertRaises(lib_exc.Forbidden,
                          self.member_client.list_share_instances)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API])
    @base.skip_if_microversion_lt("2.15")
    def test_reset_task_state_share_not_found(self):
        self.assertRaises(
            lib_exc.NotFound, self.admin_client.reset_task_state,
            'fake_share', 'migration_error')

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_force_delete_nonexistent_snapshot(self):
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.force_delete,
                          "fake",
                          s_type="snapshots")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API])
    def test_force_delete_nonexistent_share(self):
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.force_delete, "fake")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API])
    def test_force_delete_nonexistent_share_instance(self):
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.force_delete,
                          "fake",
                          s_type="share_instances")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API])
    def test_reset_nonexistent_share_state(self):
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.reset_state, "fake")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API])
    def test_reset_nonexistent_share_instance_state(self):
        self.assertRaises(lib_exc.NotFound, self.admin_client.reset_state,
                          "fake", s_type="share_instances")

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_reset_nonexistent_snapshot_state(self):
        self.assertRaises(lib_exc.NotFound, self.admin_client.reset_state,
                          "fake", s_type="snapshots")
