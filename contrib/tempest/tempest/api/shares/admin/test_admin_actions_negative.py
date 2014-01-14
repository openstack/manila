# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from tempest.api.shares import base
from tempest import clients_shares as clients
from tempest import config_shares as config
from tempest import exceptions
from tempest import test

import testtools

CONF = config.CONF


class AdminActionsNegativeTestJSON(base.BaseSharesAdminTest):

    @classmethod
    def setUpClass(cls):
        super(AdminActionsNegativeTestJSON, cls).setUpClass()

        # create share (available or error)
        __, cls.sh = cls.create_share_wait_for_active()

        # create snapshot (available or error)
        __, cls.sn = cls.create_snapshot_wait_for_active(cls.sh["id"])
        cls.member_shares_client = clients.Manager().shares_client

    @test.attr(type=['negative', ])
    def test_reset_unexistant_share_state(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.reset_state, "fake")

    @test.attr(type=['negative', ])
    def test_reset_unexistant_snapshot_state(self):
        self.assertRaises(exceptions.NotFound, self.shares_client.reset_state,
                          "fake", s_type="snapshots")

    @test.attr(type=['negative', ])
    def test_reset_share_state_to_unacceptable_state(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.reset_state,
                          self.sh["id"], status="fake")

    @test.attr(type=['negative', ])
    def test_reset_snapshot_state_to_unacceptable_state(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.reset_state,
                          self.sn["id"], s_type="snapshots", status="fake")

    @testtools.skipIf(not CONF.shares.only_admin_or_owner_for_action,
                      "Skipped, because not only admin allowed")
    @test.attr(type=['negative', ])
    def test_try_reset_share_state_with_member(self):
        # Even if member from another tenant, it should be unauthorized
        self.assertRaises(exceptions.Unauthorized,
                          self.member_shares_client.reset_state,
                          self.sh["id"])

    @testtools.skipIf(not CONF.shares.only_admin_or_owner_for_action,
                      "Skipped, because not only admin allowed")
    @test.attr(type=['negative', ])
    def test_try_reset_snapshot_state_with_member(self):
        # Even if member from another tenant, it should be unauthorized
        self.assertRaises(exceptions.Unauthorized,
                          self.member_shares_client.reset_state,
                          self.sn["id"], s_type="snapshots")


class AdminActionsNegativeTestXML(AdminActionsNegativeTestJSON):
    _interface = 'xml'
