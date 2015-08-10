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

from tempest_lib import exceptions as lib_exc  # noqa
import testtools  # noqa

from tempest.api.share import base
from tempest import config_share as config
from tempest import test

CONF = config.CONF


class ShareIpRulesForNFSNegativeTest(base.BaseSharesTest):
    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(ShareIpRulesForNFSNegativeTest, cls).resource_setup()
        if not (cls.protocol in CONF.share.enable_protocols and
                cls.protocol in CONF.share.enable_ip_rules_for_protocols):
            msg = "IP rule tests for %s protocol are disabled" % cls.protocol
            raise cls.skipException(msg)
        # create share
        cls.share = cls.create_share(cls.protocol)
        if CONF.share.run_snapshot_tests:
            # create snapshot
            cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"])

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_target_1(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.256")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_target_2(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.1.1.-")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_target_3(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.4/33")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_target_4(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.*")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_target_5(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.*/23")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_target_6(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.1|23")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_target_7(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.1/-1")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_target_8(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "ip", "1.2.3.1/")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_with_wrong_level(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"],
                          'ip',
                          '2.2.2.2',
                          'su')

    @test.attr(type=["negative", "gate", ])
    def test_create_duplicate_of_ip_rule(self):
        # test data
        access_type = "ip"
        access_to = "1.2.3.4"

        # create rule
        rule = self.shares_client.create_access_rule(
            self.share["id"], access_type, access_to)
        self.shares_client.wait_for_access_rule_status(
            self.share["id"], rule["id"], "active")

        # try create duplicate of rule
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], access_type, access_to)


class ShareIpRulesForCIFSNegativeTest(ShareIpRulesForNFSNegativeTest):
    protocol = "cifs"


class ShareUserRulesForNFSNegativeTest(base.BaseSharesTest):
    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(ShareUserRulesForNFSNegativeTest, cls).resource_setup()
        if not (cls.protocol in CONF.share.enable_protocols and
                cls.protocol in CONF.share.enable_user_rules_for_protocols):
            msg = "USER rule tests for %s protocol are disabled" % cls.protocol
            raise cls.skipException(msg)
        # create share
        cls.share = cls.create_share(cls.protocol)
        if CONF.share.run_snapshot_tests:
            # create snapshot
            cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"])

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_user_with_wrong_input_2(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "user",
                          "try+")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_user_with_empty_key(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "user", "")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_user_with_too_little_key(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "user", "abc")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_user_with_too_big_key(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "user", "a" * 33)

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_user_with_wrong_input_1(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "user",
                          "try+")

    @test.attr(type=["negative", "gate", ])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_create_access_rule_user_to_snapshot(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.create_access_rule,
                          self.snap["id"],
                          access_type="user",
                          access_to="fakeuser")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_user_with_wrong_share_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.create_access_rule,
                          "wrong_share_id",
                          access_type="user",
                          access_to="fakeuser")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_with_wrong_level(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"],
                          'user',
                          CONF.share.username_for_user_rules,
                          'su')


class ShareUserRulesForCIFSNegativeTest(ShareUserRulesForNFSNegativeTest):
    protocol = "cifs"


class ShareRulesNegativeTest(base.BaseSharesTest):
    # Tests independent from rule type and share protocol

    @classmethod
    def resource_setup(cls):
        super(ShareRulesNegativeTest, cls).resource_setup()
        if not (any(p in CONF.share.enable_ip_rules_for_protocols
                    for p in cls.protocols) or
                any(p in CONF.share.enable_user_rules_for_protocols
                    for p in cls.protocols)):
            cls.message = "Rule tests are disabled"
            raise cls.skipException(cls.message)
        # create share
        cls.share = cls.create_share()
        if CONF.share.run_snapshot_tests:
            # create snapshot
            cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"])

    @test.attr(type=["negative", "gate", ])
    def test_delete_access_rule_with_wrong_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_access_rule,
                          self.share["id"], "wrong_rule_id")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_type(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_access_rule,
                          self.share["id"], "wrong_type", "1.2.3.4")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_ip_with_wrong_share_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.create_access_rule,
                          "wrong_share_id")

    @test.attr(type=["negative", "gate", ])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_create_access_rule_ip_to_snapshot(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.create_access_rule,
                          self.snap["id"])
