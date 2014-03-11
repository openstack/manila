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

from tempest.api.share import base
from tempest import clients_share as clients
from tempest import config_share as config
from tempest import exceptions
from tempest import test

CONF = config.CONF


class AdminActionsNegativeTest(base.BaseSharesAdminTest):

    @classmethod
    def setUpClass(cls):
        super(AdminActionsNegativeTest, cls).setUpClass()
        __, cls.sh = cls.create_share_wait_for_active()
        __, cls.sn = cls.create_snapshot_wait_for_active(cls.sh["id"])
        cls.member_shares_client = clients.Manager().shares_client

    @test.attr(type=["gate", "negative", ])
    def test_reset_unexistant_share_state(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.reset_state, "fake")

    @test.attr(type=["gate", "negative", ])
    def test_reset_unexistant_snapshot_state(self):
        self.assertRaises(exceptions.NotFound, self.shares_client.reset_state,
                          "fake", s_type="snapshots")

    @test.attr(type=["gate", "negative", ])
    def test_reset_share_state_to_unacceptable_state(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.reset_state,
                          self.sh["id"], status="fake")

    @test.attr(type=["gate", "negative", ])
    def test_reset_snapshot_state_to_unacceptable_state(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.reset_state,
                          self.sn["id"], s_type="snapshots", status="fake")

    @test.attr(type=["gate", "negative", ])
    def test_try_reset_share_state_with_member(self):
        # Even if member from another tenant, it should be unauthorized
        self.assertRaises(exceptions.Unauthorized,
                          self.member_shares_client.reset_state,
                          self.sh["id"])

    @test.attr(type=["gate", "negative", ])
    def test_try_reset_snapshot_state_with_member(self):
        # Even if member from another tenant, it should be unauthorized
        self.assertRaises(exceptions.Unauthorized,
                          self.member_shares_client.reset_state,
                          self.sn["id"], s_type="snapshots")
