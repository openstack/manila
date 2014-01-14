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

CONF = config.CONF


class SharesSecurityNegativeTestJSON(base.BaseSharesTest):

    @classmethod
    def setUpClass(cls):
        super(SharesSecurityNegativeTestJSON, cls).setUpClass()
        if not CONF.shares.only_admin_or_owner_for_action:
            skip_msg = "Disabled from tempest configuration"
            raise cls.skipException(skip_msg)
        cls.client = cls.shares_client
        cls.alt_client = clients.AltManager().shares_client
        _, cls.share = cls.create_share_wait_for_active()
        _, cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"])

    @test.attr(type='negative')
    def test_tenant_isolation_for_share_list(self):

        # list shares
        __, shares = self.client.list_shares()

        # our share id is in list and have no duplicates
        gen = [sid["id"] for sid in shares if sid["id"] in self.share["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEquals(len(gen), 1, msg)

        # list shares from another tenant
        __, alt_shares = self.alt_client.list_shares()

        # our share id is not in list
        gen = [s["id"] for s in alt_shares if s["id"] in self.share["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEquals(len(gen), 0, msg)

    @test.attr(type='negative')
    def test_tenant_isolation_share_delete(self):

        # try delete share from another tenant
        self.assertRaises(exceptions.Unauthorized,
                          self.alt_client.delete_share,
                          self.share["id"])

    @test.attr(type='negative')
    def test_tenant_isolation_share_get(self):

        # try delete share from another tenant
        self.assertRaises(exceptions.Unauthorized,
                          self.alt_client.get_share, self.share["id"])

    @test.attr(type='negative')
    def test_tenant_isolation_for_share_snapshot_list(self):

        # list share snapshots
        __, snaps = self.client.list_snapshots()

        # our share id is in list and have no duplicates
        gen = [sid["id"] for sid in snaps if sid["id"] in self.snap["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEquals(len(gen), 1, msg)

        # list shares from another tenant
        __, alt_snaps = self.alt_client.list_snapshots()

        # our snapshot id is not in list
        gen = [sid["id"] for sid in alt_snaps if sid["id"] in self.snap["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEquals(len(gen), 0, msg)

    @test.attr(type='negative')
    def test_tenant_isolation_share_snapshot_delete(self):

        # try delete share from another tenant
        self.assertRaises(exceptions.NotFound,
                          self.alt_client.delete_snapshot, self.snap["id"])

    @test.attr(type='negative')
    def test_tenant_isolation_share_snapshot_get(self):

        # try delete share from another tenant
        self.assertRaises(exceptions.NotFound,
                          self.alt_client.get_snapshot, self.snap["id"])

    @test.attr(type='negative')
    def test_tenant_isolation_share_access_list(self):

        # try list share rules
        self.assertRaises(exceptions.Unauthorized,  # NotFound or Unauthorized
                          self.alt_client.list_access_rules,
                          self.share["id"])

    @test.attr(type='negative')
    def test_tenant_isolation_share_access_rule_delete(self):

        # create rule
        resp, rule = self.client.create_access_rule(self.share["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.shares_client.wait_for_access_rule_status(self.share["id"],
                                                       rule["id"],
                                                       "active")

        # try delete rule
        self.assertRaises(exceptions.Unauthorized,  # NotFound or Unauthorized
                          self.alt_client.delete_access_rule,
                          self.share["id"], rule["id"])

    @test.attr(type='negative')
    def test_create_snapshot_from_alien_share(self):

        # try create snapshot in another tenant
        self.assertRaises(exceptions.Unauthorized,  # NotFound or Unauthorized
                          self.create_snapshot_wait_for_active,
                          share_id=self.share["id"],
                          client=self.alt_client)

    @test.attr(type='negative')
    def test_create_share_from_alien_snapshot(self):

        # try create share in another tenant from snap
        self.assertRaises(exceptions.NotFound,  # NotFound or Unauthorized
                          self.create_share_wait_for_active,
                          snapshot_id=self.snap["id"],
                          client=self.alt_client)

    @test.attr(type='negative')
    def test_create_access_rule_to_alien_share(self):

        # try create access rule from another tenant
        self.assertRaises(exceptions.Unauthorized,
                          self.alt_client.create_access_rule,
                          self.share["id"],
                          access_to="1.1.1.1")

# There is no need to perform security tests twice
#class SharesSecurityNegativeTestXML(SharesSecurityNegativeTestJSON):
#    _interface = 'xml'
