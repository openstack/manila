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


class ShareRulesTestJSON(base.BaseSharesTest):

    @classmethod
    def setUpClass(cls):
        super(ShareRulesTestJSON, cls).setUpClass()
        _, cls.share = cls.create_share_wait_for_active()

    @test.attr(type='positive')
    def test_create_delete_access_rules_with_one_ip(self):

        # test data
        access_type = "ip"
        access_to = "1.2.3.4"

        # create rule
        resp, rule = self.shares_client.create_access_rule(self.share["id"],
                                                           access_type,
                                                           access_to)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.shares_client.wait_for_access_rule_status(self.share["id"],
                                                       rule["id"],
                                                       "active")
        # delete rule
        resp, _ = self.shares_client.delete_access_rule(self.share["id"],
                                                        rule["id"])
        self.assertIn(int(resp["status"]), [200, 202])

    @test.attr(type='positive')
    def test_create_delete_access_rule_with_cidr(self):

        # test data
        access_type = "ip"
        access_to = "1.2.3.4/32"

        # create rule
        resp, rule = self.shares_client.create_access_rule(self.share["id"],
                                                           access_type,
                                                           access_to)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.shares_client.wait_for_access_rule_status(self.share["id"],
                                                       rule["id"],
                                                       "active")
        # delete rule
        resp, _ = self.shares_client.delete_access_rule(self.share["id"],
                                                        rule["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type='positive')
    def test_list_access_rules(self):

        # test data
        access_type = "ip"
        access_to = "1.2.3.4"

        # create rule
        resp, rule = self.shares_client.create_access_rule(self.share["id"],
                                                           access_type,
                                                           access_to)

        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.shares_client.wait_for_access_rule_status(self.share["id"],
                                                       rule["id"],
                                                       "active")

        # list rules
        resp, rules = self.shares_client.list_access_rules(self.share["id"])

        # verify response
        msg = "We expected status 200, but got %s" % (str(resp["status"]))
        self.assertEqual(200, int(resp["status"]), msg)

        # verify keys
        keys = ["state", "id", "access_type", "access_to"]
        [self.assertIn(key, r.keys()) for r in rules for key in keys]

        # verify values
        self.assertEqual("active", rules[0]["state"])
        self.assertEqual(access_type, rules[0]["access_type"])
        self.assertEqual(access_to, rules[0]["access_to"])

        # our share id in list and have no duplicates
        gen = [r["id"] for r in rules if r["id"] in rule["id"]]
        msg = "expected id lists %s times in rule list" % (len(gen))
        self.assertEquals(len(gen), 1, msg)

    @test.attr(type='positive')
    def test_access_rules_deleted_if_share_deleted(self):

        # test data
        access_type = "ip"
        access_to = "1.2.3.0/24"

        # create share
        resp, share = self.create_share_wait_for_active()

        # create rule
        resp, rule = self.shares_client.create_access_rule(share["id"],
                                                           access_type,
                                                           access_to)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.shares_client.wait_for_access_rule_status(share["id"], rule["id"],
                                                       "active")

        # delete share
        resp, _ = self.shares_client.delete_share(share['id'])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.shares_client.wait_for_resource_deletion(share['id'])

        # verify absence of rules for nonexistent share id
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.list_access_rules,
                          share['id'])


class ShareRulesTestXML(ShareRulesTestJSON):
    _interface = 'xml'
