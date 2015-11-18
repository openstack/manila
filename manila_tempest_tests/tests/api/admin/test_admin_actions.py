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

from tempest import config  # noqa
from tempest import test  # noqa
import testtools  # noqa

from manila_tempest_tests.tests.api import base


CONF = config.CONF


class AdminActionsTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(AdminActionsTest, cls).resource_setup()
        cls.states = ["error", "available"]
        cls.bad_status = "error_deleting"
        cls.sh = cls.create_share()
        cls.sh_instance = (
            cls.shares_v2_client.get_instances_of_share(cls.sh["id"])[0]
        )
        if CONF.share.run_snapshot_tests:
            cls.sn = cls.create_snapshot_wait_for_active(cls.sh["id"])

    @test.attr(type=["gate", ])
    def test_reset_share_state(self):
        for status in self.states:
            self.shares_v2_client.reset_state(self.sh["id"], status=status)
            self.shares_v2_client.wait_for_share_status(self.sh["id"], status)

    @test.attr(type=["gate", ])
    def test_reset_share_instance_state(self):
        id = self.sh_instance["id"]
        for status in self.states:
            self.shares_v2_client.reset_state(
                id, s_type="share_instances", status=status)
            self.shares_v2_client.wait_for_share_instance_status(id, status)

    @test.attr(type=["gate", ])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_reset_snapshot_state_to_error(self):
        for status in self.states:
            self.shares_v2_client.reset_state(
                self.sn["id"], s_type="snapshots", status=status)
            self.shares_v2_client.wait_for_snapshot_status(
                self.sn["id"], status)

    @test.attr(type=["gate", ])
    def test_force_delete_share(self):
        share = self.create_share()

        # Change status from 'available' to 'error_deleting'
        self.shares_v2_client.reset_state(share["id"], status=self.bad_status)

        # Check that status was changed
        check_status = self.shares_v2_client.get_share(share["id"])
        self.assertEqual(check_status["status"], self.bad_status)

        # Share with status 'error_deleting' should be deleted
        self.shares_v2_client.force_delete(share["id"])
        self.shares_v2_client.wait_for_resource_deletion(share_id=share["id"])

    @test.attr(type=["gate", ])
    def test_force_delete_share_instance(self):
        share = self.create_share(cleanup_in_class=False)
        instances = self.shares_v2_client.get_instances_of_share(share["id"])
        # Check that instance was created
        self.assertEqual(1, len(instances))

        instance = instances[0]

        # Change status from 'available' to 'error_deleting'
        self.shares_v2_client.reset_state(
            instance["id"], s_type="share_instances", status=self.bad_status)

        # Check that status was changed
        check_status = self.shares_v2_client.get_share_instance(instance["id"])
        self.assertEqual(self.bad_status, check_status["status"])

        # Share with status 'error_deleting' should be deleted
        self.shares_v2_client.force_delete(
            instance["id"], s_type="share_instances")
        self.shares_v2_client.wait_for_resource_deletion(
            share_instance_id=instance["id"])

    @test.attr(type=["gate", ])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_force_delete_snapshot(self):
        sn = self.create_snapshot_wait_for_active(self.sh["id"])

        # Change status from 'available' to 'error_deleting'
        self.shares_v2_client.reset_state(
            sn["id"], s_type="snapshots", status=self.bad_status)

        # Check that status was changed
        check_status = self.shares_v2_client.get_snapshot(sn["id"])
        self.assertEqual(check_status["status"], self.bad_status)

        # Snapshot with status 'error_deleting' should be deleted
        self.shares_v2_client.force_delete(sn["id"], s_type="snapshots")
        self.shares_v2_client.wait_for_resource_deletion(snapshot_id=sn["id"])
