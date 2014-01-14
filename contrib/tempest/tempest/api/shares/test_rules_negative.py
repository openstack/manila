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
from tempest import exceptions
from tempest import test


class ShareRulesNegativeTestJSON(base.BaseSharesTest):

    @classmethod
    def setUpClass(cls):
        super(ShareRulesNegativeTestJSON, cls).setUpClass()

        # create share
        _, cls.share = cls.create_share_wait_for_active()

        # create snapshot
        _, cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"])

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_share_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.create_access_rule,
                          "wrong_share_id")

    @test.attr(type='negative')
    def test_delete_access_rule_ip_with_wrong_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_access_rule,
                          self.share["id"], "wrong_rule_id")

    @test.attr(type='negative')
    def test_create_try_access_rule_ip_to_snapshot(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.create_access_rule,
                          self.snap["id"])

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_type(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "wrong_type", "1.2.3.4")

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_target_1(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.256")

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_target_2(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.1.1.-")

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_target_3(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.4/33")

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_target_4(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.*")

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_target_5(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.*/23")

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_target_6(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.1|23")

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_target_7(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.1/-1")

    @test.attr(type='negative')
    def test_create_access_rule_ip_with_wrong_target_8(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.1/")


class ShareRulesNegativeTestXML(ShareRulesNegativeTestJSON):
    _interface = 'xml'
