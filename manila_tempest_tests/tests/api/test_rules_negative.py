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

import ddt
from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import test
import testtools

from manila_tempest_tests import share_exceptions
from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF
LATEST_MICROVERSION = CONF.share.max_api_microversion


@ddt.ddt
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
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_target_1(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "ip", "1.2.3.256")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_target_2(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "ip", "1.1.1.-")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_target_3(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "ip", "1.2.3.4/33")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_target_4(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "ip", "1.2.3.*")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_target_5(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "ip", "1.2.3.*/23")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_target_6(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "ip", "1.2.3.1|23")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_target_7(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "ip", "1.2.3.1/-1")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_target_8(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "ip", "1.2.3.1/")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_with_wrong_level(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"],
                          'ip',
                          '2.2.2.2',
                          'su')

    @test.attr(type=["negative", "gate", ])
    @ddt.data('1.0', '2.9', LATEST_MICROVERSION)
    def test_create_duplicate_of_ip_rule(self, version):
        # test data
        access_type = "ip"
        access_to = "1.2.3.4"

        # create rule
        if utils.is_microversion_eq(version, '1.0'):
            rule = self.shares_client.create_access_rule(
                self.share["id"], access_type, access_to)
        else:
            rule = self.shares_v2_client.create_access_rule(
                self.share["id"], access_type, access_to, version=version)

        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.wait_for_access_rule_status(
                self.share["id"], rule["id"], "active")
        elif utils.is_microversion_eq(version, '2.9'):
            self.shares_v2_client.wait_for_access_rule_status(
                self.share["id"], rule["id"], "active")
        else:
            self.shares_v2_client.wait_for_share_status(
                self.share["id"], "active", status_attr='access_rules_status',
                version=version)

        # try create duplicate of rule
        if utils.is_microversion_eq(version, '1.0'):
            self.assertRaises(lib_exc.BadRequest,
                              self.shares_client.create_access_rule,
                              self.share["id"], access_type, access_to)
        else:
            self.assertRaises(lib_exc.BadRequest,
                              self.shares_v2_client.create_access_rule,
                              self.share["id"], access_type, access_to,
                              version=version)

        # delete rule and wait for deletion
        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.delete_access_rule(self.share["id"],
                                                  rule["id"])
            self.shares_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share["id"])
        else:
            self.shares_v2_client.delete_access_rule(self.share["id"],
                                                     rule["id"])
            self.shares_v2_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share["id"], version=version)


@ddt.ddt
class ShareIpRulesForCIFSNegativeTest(ShareIpRulesForNFSNegativeTest):
    protocol = "cifs"


@ddt.ddt
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
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_user_with_wrong_input_2(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "user",
                          "try+")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_user_with_empty_key(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "user", "")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_user_with_too_little_key(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "user", "abc")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_user_with_too_big_key(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "user", "a" * 33)

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_user_with_wrong_input_1(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "user",
                          "try+")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_create_access_rule_user_to_snapshot(self, client_name):
        self.assertRaises(lib_exc.NotFound,
                          getattr(self, client_name).create_access_rule,
                          self.snap["id"],
                          access_type="user",
                          access_to="fakeuser")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_user_with_wrong_share_id(self, client_name):
        self.assertRaises(lib_exc.NotFound,
                          getattr(self, client_name).create_access_rule,
                          "wrong_share_id",
                          access_type="user",
                          access_to="fakeuser")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_with_wrong_level(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"],
                          'user',
                          CONF.share.username_for_user_rules,
                          'su')


@ddt.ddt
class ShareUserRulesForCIFSNegativeTest(ShareUserRulesForNFSNegativeTest):
    protocol = "cifs"


@ddt.ddt
class ShareCertRulesForGLUSTERFSNegativeTest(base.BaseSharesTest):
    protocol = "glusterfs"

    @classmethod
    def resource_setup(cls):
        super(ShareCertRulesForGLUSTERFSNegativeTest, cls).resource_setup()
        if not (cls.protocol in CONF.share.enable_protocols and
                cls.protocol in CONF.share.enable_cert_rules_for_protocols):
            msg = "CERT rule tests for %s protocol are disabled" % cls.protocol
            raise cls.skipException(msg)
        # create share
        cls.share = cls.create_share(cls.protocol)
        if CONF.share.run_snapshot_tests:
            # create snapshot
            cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"])

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_cert_with_empty_common_name(self, client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "cert", "")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_cert_with_whitespace_common_name(self,
                                                                 client_name):
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "cert", " ")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_cert_with_too_big_common_name(self,
                                                              client_name):
        # common name cannot be more than 64 characters long
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "cert", "a" * 65)

    @test.attr(type=["negative", "gate", ])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_cert_to_snapshot(self, client_name):
        self.assertRaises(lib_exc.NotFound,
                          getattr(self, client_name).create_access_rule,
                          self.snap["id"],
                          access_type="cert",
                          access_to="fakeclient1.com")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_cert_with_wrong_share_id(self, client_name):
        self.assertRaises(lib_exc.NotFound,
                          getattr(self, client_name).create_access_rule,
                          "wrong_share_id",
                          access_type="cert",
                          access_to="fakeclient2.com")


@ddt.ddt
class ShareCephxRulesForCephFSNegativeTest(base.BaseSharesTest):
    protocol = "cephfs"

    @classmethod
    def resource_setup(cls):
        super(ShareCephxRulesForCephFSNegativeTest, cls).resource_setup()
        if not (cls.protocol in CONF.share.enable_protocols and
                cls.protocol in CONF.share.enable_cephx_rules_for_protocols):
            msg = ("CEPHX rule tests for %s protocol are disabled" %
                   cls.protocol)
            raise cls.skipException(msg)
        # create share
        cls.share = cls.create_share(cls.protocol)
        cls.access_type = "cephx"
        cls.access_to = "david"

    @test.attr(type=["negative", "gate", ])
    @ddt.data('jane.doe', u"bj\u00F6rn")
    def test_create_access_rule_cephx_with_invalid_cephx_id(self, access_to):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_v2_client.create_access_rule,
                          self.share["id"], self.access_type, access_to)

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_cephx_with_wrong_level(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_v2_client.create_access_rule,
                          self.share["id"], self.access_type, self.access_to,
                          access_level="su")

    @test.attr(type=["negative", "gate", ])
    def test_create_access_rule_cephx_with_unsupported_access_level_ro(self):
        rule = self.shares_v2_client.create_access_rule(
            self.share["id"], self.access_type, self.access_to,
            access_level="ro")
        self.assertRaises(
            share_exceptions.AccessRuleBuildErrorException,
            self.shares_client.wait_for_access_rule_status,
            self.share['id'], rule['id'], "active")


@ddt.ddt
class ShareRulesNegativeTest(base.BaseSharesTest):
    # Tests independent from rule type and share protocol

    @classmethod
    def resource_setup(cls):
        super(ShareRulesNegativeTest, cls).resource_setup()
        if not (any(p in CONF.share.enable_ip_rules_for_protocols
                    for p in cls.protocols) or
                any(p in CONF.share.enable_user_rules_for_protocols
                    for p in cls.protocols) or
                any(p in CONF.share.enable_cert_rules_for_protocols
                    for p in cls.protocols) or
                any(p in CONF.share.enable_cephx_rules_for_protocols
                    for p in cls.protocols)):
            cls.message = "Rule tests are disabled"
            raise cls.skipException(cls.message)
        # create share
        cls.share = cls.create_share()
        if CONF.share.run_snapshot_tests:
            # create snapshot
            cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"])

    def skip_if_cephx_access_type_not_supported_by_client(self, client):
        if client == 'shares_client':
            version = '1.0'
        else:
            version = LATEST_MICROVERSION
        if (CONF.share.enable_cephx_rules_for_protocols and
                utils.is_microversion_lt(version, '2.13')):
            msg = ("API version %s does not support cephx access type, "
                   "need version greater than 2.13." % version)
            raise self.skipException(msg)

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_delete_access_rule_with_wrong_id(self, client_name):
        self.skip_if_cephx_access_type_not_supported_by_client(client_name)
        self.assertRaises(lib_exc.NotFound,
                          getattr(self, client_name).delete_access_rule,
                          self.share["id"], "wrong_rule_id")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_type(self, client_name):
        self.skip_if_cephx_access_type_not_supported_by_client(client_name)
        self.assertRaises(lib_exc.BadRequest,
                          getattr(self, client_name).create_access_rule,
                          self.share["id"], "wrong_type", "1.2.3.4")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_access_rule_ip_with_wrong_share_id(self, client_name):
        self.skip_if_cephx_access_type_not_supported_by_client(client_name)
        self.assertRaises(lib_exc.NotFound,
                          getattr(self, client_name).create_access_rule,
                          "wrong_share_id")

    @test.attr(type=["negative", "gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_create_access_rule_ip_to_snapshot(self, client_name):
        self.skip_if_cephx_access_type_not_supported_by_client(client_name)
        self.assertRaises(lib_exc.NotFound,
                          getattr(self, client_name).create_access_rule,
                          self.snap["id"])
