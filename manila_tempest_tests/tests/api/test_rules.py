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

import itertools

import ddt
from tempest import config
from tempest.lib import exceptions as lib_exc
import testtools
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF
LATEST_MICROVERSION = CONF.share.max_api_microversion


def _create_delete_ro_access_rule(self, version):
    """Common test case for usage in test suites with different decorators.

    :param self: instance of test class
    """

    if utils.is_microversion_eq(version, '1.0'):
        rule = self.shares_client.create_access_rule(
            self.share["id"], self.access_type, self.access_to, 'ro')
    else:
        rule = self.shares_v2_client.create_access_rule(
            self.share["id"], self.access_type, self.access_to, 'ro',
            version=version)

    self.assertEqual('ro', rule['access_level'])
    for key in ('deleted', 'deleted_at', 'instance_mappings'):
        self.assertNotIn(key, rule.keys())

    # rules must start out in 'new' until 2.28 & 'queued_to_apply' after 2.28
    if utils.is_microversion_le(version, "2.27"):
        self.assertEqual("new", rule['state'])
    else:
        self.assertEqual("queued_to_apply", rule['state'])

    if utils.is_microversion_le(version, '2.9'):
        self.shares_client.wait_for_access_rule_status(
            self.share["id"], rule["id"], "active")
    else:
        self.shares_v2_client.wait_for_share_status(
            self.share["id"], "active", status_attr='access_rules_status',
            version=version)
        # If the 'access_rules_status' transitions to 'active',
        # rule state must too
        rules = self.shares_v2_client.list_access_rules(self.share['id'])
        rule = [r for r in rules if r['id'] == rule['id']][0]
        self.assertEqual("active", rule['state'])

    if utils.is_microversion_eq(version, '1.0'):
        self.shares_client.delete_access_rule(self.share["id"], rule["id"])
        self.shares_client.wait_for_resource_deletion(
            rule_id=rule["id"], share_id=self.share['id'])
    else:
        self.shares_v2_client.delete_access_rule(
            self.share["id"], rule["id"], version=version)
        self.shares_v2_client.wait_for_resource_deletion(
            rule_id=rule["id"], share_id=self.share['id'], version=version)


@ddt.ddt
class ShareIpRulesForNFSTest(base.BaseSharesMixedTest):
    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(ShareIpRulesForNFSTest, cls).resource_setup()
        if (cls.protocol not in CONF.share.enable_protocols or
                cls.protocol not in CONF.share.enable_ip_rules_for_protocols):
            msg = "IP rule tests for %s protocol are disabled" % cls.protocol
            raise cls.skipException(msg)
        # create share type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']

        # create share
        cls.share = cls.create_share(cls.protocol,
                                     share_type_id=cls.share_type_id)
        cls.access_type = "ip"
        cls.access_to = "2.2.2.2"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_create_delete_access_rules_with_one_ip(self, version):

        # test data
        access_to = "1.1.1.1"

        # create rule
        if utils.is_microversion_eq(version, '1.0'):
            rule = self.shares_client.create_access_rule(
                self.share["id"], self.access_type, access_to)
        else:
            rule = self.shares_v2_client.create_access_rule(
                self.share["id"], self.access_type, access_to,
                version=version)

        self.assertEqual('rw', rule['access_level'])
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())

        # rules must start out in 'new' until 2.28 & 'queued_to_apply' after
        if utils.is_microversion_le(version, "2.27"):
            self.assertEqual("new", rule['state'])
        else:
            self.assertEqual("queued_to_apply", rule['state'])

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

        # delete rule and wait for deletion
        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.delete_access_rule(self.share["id"], rule["id"])
            self.shares_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'])
        else:
            self.shares_v2_client.delete_access_rule(
                self.share["id"], rule["id"], version=version)
            self.shares_v2_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'], version=version)

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_create_delete_access_rule_with_cidr(self, version):

        # test data
        access_to = "1.2.3.4/32"

        # create rule
        if utils.is_microversion_eq(version, '1.0'):
            rule = self.shares_client.create_access_rule(
                self.share["id"], self.access_type, access_to)
        else:
            rule = self.shares_v2_client.create_access_rule(
                self.share["id"], self.access_type, access_to,
                version=version)

        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())
        self.assertEqual('rw', rule['access_level'])

        # rules must start out in 'new' until 2.28 & 'queued_to_apply' after
        if utils.is_microversion_le(version, "2.27"):
            self.assertEqual("new", rule['state'])
        else:
            self.assertEqual("queued_to_apply", rule['state'])

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

        # delete rule and wait for deletion
        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.delete_access_rule(self.share["id"], rule["id"])
            self.shares_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'])
        else:
            self.shares_v2_client.delete_access_rule(
                self.share["id"], rule["id"], version=version)
            self.shares_v2_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'], version=version)

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @testtools.skipIf(
        "nfs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for NFS protocol.")
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_create_delete_ro_access_rule(self, client_name):
        _create_delete_ro_access_rule(self, client_name)


@ddt.ddt
class ShareIpRulesForCIFSTest(ShareIpRulesForNFSTest):
    protocol = "cifs"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @testtools.skipIf(
        "cifs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for CIFS protocol.")
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_create_delete_ro_access_rule(self, version):
        _create_delete_ro_access_rule(self, version)


@ddt.ddt
class ShareUserRulesForNFSTest(base.BaseSharesMixedTest):
    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(ShareUserRulesForNFSTest, cls).resource_setup()
        if (cls.protocol not in CONF.share.enable_protocols or
                cls.protocol not in
                CONF.share.enable_user_rules_for_protocols):
            msg = "USER rule tests for %s protocol are disabled" % cls.protocol
            raise cls.skipException(msg)
        # create share type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']

        # create share
        cls.share = cls.create_share(cls.protocol,
                                     share_type_id=cls.share_type_id)

        cls.access_type = "user"
        cls.access_to = CONF.share.username_for_user_rules

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_create_delete_user_rule(self, version):

        # create rule
        if utils.is_microversion_eq(version, '1.0'):
            rule = self.shares_client.create_access_rule(
                self.share["id"], self.access_type, self.access_to)
        else:
            rule = self.shares_v2_client.create_access_rule(
                self.share["id"], self.access_type, self.access_to,
                version=version)

        self.assertEqual('rw', rule['access_level'])
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())

        # rules must start out in 'new' until 2.28 & 'queued_to_apply' after
        if utils.is_microversion_le(version, "2.27"):
            self.assertEqual("new", rule['state'])
        else:
            self.assertEqual("queued_to_apply", rule['state'])

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

        # delete rule and wait for deletion
        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.delete_access_rule(self.share["id"], rule["id"])
            self.shares_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'])
        else:
            self.shares_v2_client.delete_access_rule(
                self.share["id"], rule["id"], version=version)
            self.shares_v2_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'], version=version)

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @testtools.skipIf(
        "nfs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for NFS protocol.")
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_create_delete_ro_access_rule(self, version):
        _create_delete_ro_access_rule(self, version)


@ddt.ddt
class ShareUserRulesForCIFSTest(ShareUserRulesForNFSTest):
    protocol = "cifs"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @testtools.skipIf(
        "cifs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for CIFS protocol.")
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_create_delete_ro_access_rule(self, version):
        _create_delete_ro_access_rule(self, version)


@ddt.ddt
class ShareCertRulesForGLUSTERFSTest(base.BaseSharesMixedTest):
    protocol = "glusterfs"

    @classmethod
    def resource_setup(cls):
        super(ShareCertRulesForGLUSTERFSTest, cls).resource_setup()
        if (cls.protocol not in CONF.share.enable_protocols or
                cls.protocol not in
                CONF.share.enable_cert_rules_for_protocols):
            msg = "Cert rule tests for %s protocol are disabled" % cls.protocol
            raise cls.skipException(msg)
        # create share type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']

        # create share
        cls.share = cls.create_share(cls.protocol,
                                     share_type_id=cls.share_type_id)

        cls.access_type = "cert"
        # Provide access to a client identified by a common name (CN) of the
        # certificate that it possesses.
        cls.access_to = "client1.com"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_create_delete_cert_rule(self, version):

        # create rule
        if utils.is_microversion_eq(version, '1.0'):
            rule = self.shares_client.create_access_rule(
                self.share["id"], self.access_type, self.access_to)
        else:
            rule = self.shares_v2_client.create_access_rule(
                self.share["id"], self.access_type, self.access_to,
                version=version)

        self.assertEqual('rw', rule['access_level'])
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())

        # rules must start out in 'new' until 2.28 & 'queued_to_apply' after
        if utils.is_microversion_le(version, "2.27"):
            self.assertEqual("new", rule['state'])
        else:
            self.assertEqual("queued_to_apply", rule['state'])

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

        # delete rule
        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.delete_access_rule(self.share["id"], rule["id"])
            self.shares_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'])
        else:
            self.shares_v2_client.delete_access_rule(
                self.share["id"], rule["id"], version=version)
            self.shares_v2_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'], version=version)

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @testtools.skipIf(
        "glusterfs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for GLUSTERFS protocol.")
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_create_delete_cert_ro_access_rule(self, version):
        if utils.is_microversion_eq(version, '1.0'):
            rule = self.shares_client.create_access_rule(
                self.share["id"], 'cert', 'client2.com', 'ro')
        else:
            rule = self.shares_v2_client.create_access_rule(
                self.share["id"], 'cert', 'client2.com', 'ro',
                version=version)

        self.assertEqual('ro', rule['access_level'])
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())

        # rules must start out in 'new' until 2.28 & 'queued_to_apply' after
        if utils.is_microversion_le(version, "2.27"):
            self.assertEqual("new", rule['state'])
        else:
            self.assertEqual("queued_to_apply", rule['state'])

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

        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.delete_access_rule(self.share["id"], rule["id"])
            self.shares_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'])
        else:
            self.shares_v2_client.delete_access_rule(
                self.share["id"], rule["id"], version=version)
            self.shares_v2_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'], version=version)


@ddt.ddt
class ShareCephxRulesForCephFSTest(base.BaseSharesMixedTest):
    protocol = "cephfs"

    @classmethod
    def resource_setup(cls):
        super(ShareCephxRulesForCephFSTest, cls).resource_setup()
        if (cls.protocol not in CONF.share.enable_protocols or
                cls.protocol not in
                CONF.share.enable_cephx_rules_for_protocols):
            msg = ("Cephx rule tests for %s protocol are disabled." %
                   cls.protocol)
            raise cls.skipException(msg)
        # create share type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']

        # create share
        cls.share = cls.create_share(cls.protocol,
                                     share_type_id=cls.share_type_id)

        cls.access_type = "cephx"
        # Provide access to a client identified by a cephx auth id.
        cls.access_to = "bob"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @ddt.data(*itertools.product(
        set(['2.13', '2.27', '2.28', LATEST_MICROVERSION]),
        ("alice", "alice_bob", "alice bob")))
    @ddt.unpack
    def test_create_delete_cephx_rule(self, version, access_to):
        rule = self.shares_v2_client.create_access_rule(
            self.share["id"], self.access_type, access_to, version=version)

        self.assertEqual('rw', rule['access_level'])
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())
        self.shares_v2_client.wait_for_access_rule_status(
            self.share["id"], rule["id"], "active")

        self.shares_v2_client.delete_access_rule(
            self.share["id"], rule["id"], version=version)
        self.shares_v2_client.wait_for_resource_deletion(
            rule_id=rule["id"], share_id=self.share['id'])


@ddt.ddt
class ShareRulesTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(ShareRulesTest, cls).resource_setup()
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
        if CONF.share.enable_ip_rules_for_protocols:
            cls.protocol = CONF.share.enable_ip_rules_for_protocols[0]
            cls.access_type = "ip"
            cls.access_to = "8.8.8.8"
        elif CONF.share.enable_user_rules_for_protocols:
            cls.protocol = CONF.share.enable_user_rules_for_protocols[0]
            cls.access_type = "user"
            cls.access_to = CONF.share.username_for_user_rules
        elif CONF.share.enable_cert_rules_for_protocols:
            cls.protocol = CONF.share.enable_cert_rules_for_protocols[0]
            cls.access_type = "cert"
            cls.access_to = "client3.com"
        elif CONF.share.enable_cephx_rules_for_protocols:
            cls.protocol = CONF.share.enable_cephx_rules_for_protocols[0]
            cls.access_type = "cephx"
            cls.access_to = "eve"
        cls.shares_v2_client.share_protocol = cls.protocol
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']
        cls.share = cls.create_share(share_type_id=cls.share_type_id)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_list_access_rules(self, version):
        if (utils.is_microversion_lt(version, '2.13') and
                CONF.share.enable_cephx_rules_for_protocols):
            msg = ("API version %s does not support cephx access type, need "
                   "version >= 2.13." % version)
            raise self.skipException(msg)

        # create rule
        if utils.is_microversion_eq(version, '1.0'):
            rule = self.shares_client.create_access_rule(
                self.share["id"], self.access_type, self.access_to)
        else:
            rule = self.shares_v2_client.create_access_rule(
                self.share["id"], self.access_type, self.access_to,
                version=version)
        # rules must start out in 'new' until 2.28 & 'queued_to_apply' after
        if utils.is_microversion_le(version, "2.27"):
            self.assertEqual("new", rule['state'])
        else:
            self.assertEqual("queued_to_apply", rule['state'])

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

        # list rules
        if utils.is_microversion_eq(version, '1.0'):
            rules = self.shares_client.list_access_rules(self.share["id"])
        else:
            rules = self.shares_v2_client.list_access_rules(self.share["id"],
                                                            version=version)

        # verify keys
        keys = ("id", "access_type", "access_to", "access_level")
        if utils.is_microversion_ge(version, '2.21'):
            keys += ("access_key", )
        for key in keys:
            [self.assertIn(key, r.keys()) for r in rules]
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            [self.assertNotIn(key, r.keys()) for r in rules]

        # verify values
        self.assertEqual(self.access_type, rules[0]["access_type"])
        self.assertEqual(self.access_to, rules[0]["access_to"])
        self.assertEqual('rw', rules[0]["access_level"])
        if utils.is_microversion_ge(version, '2.21'):
            if self.access_type == 'cephx':
                self.assertIsNotNone(rules[0]['access_key'])
            else:
                self.assertIsNone(rules[0]['access_key'])

        # our share id in list and have no duplicates
        gen = [r["id"] for r in rules if r["id"] in rule["id"]]
        msg = "expected id lists %s times in rule list" % (len(gen))
        self.assertEqual(1, len(gen), msg)

        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.delete_access_rule(self.share["id"], rule["id"])
            self.shares_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'])
        else:
            self.shares_v2_client.delete_access_rule(
                self.share["id"], rule["id"], version=version)
            self.shares_v2_client.wait_for_resource_deletion(
                rule_id=rule["id"], share_id=self.share['id'], version=version)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    @ddt.data(*set(['1.0', '2.9', '2.27', '2.28', LATEST_MICROVERSION]))
    def test_access_rules_deleted_if_share_deleted(self, version):
        if (utils.is_microversion_lt(version, '2.13') and
                CONF.share.enable_cephx_rules_for_protocols):
            msg = ("API version %s does not support cephx access type, need "
                   "version >= 2.13." % version)
            raise self.skipException(msg)

        # create share
        share = self.create_share(share_type_id=self.share_type_id)

        # create rule
        if utils.is_microversion_eq(version, '1.0'):
            rule = self.shares_client.create_access_rule(
                share["id"], self.access_type, self.access_to)
        else:
            rule = self.shares_v2_client.create_access_rule(
                share["id"], self.access_type, self.access_to,
                version=version)

        # rules must start out in 'new' until 2.28 & 'queued_to_apply' after
        if utils.is_microversion_le(version, "2.27"):
            self.assertEqual("new", rule['state'])
        else:
            self.assertEqual("queued_to_apply", rule['state'])

        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.wait_for_access_rule_status(
                share["id"], rule["id"], "active")
        elif utils.is_microversion_eq(version, '2.9'):
            self.shares_v2_client.wait_for_access_rule_status(
                share["id"], rule["id"], "active")
        else:
            self.shares_v2_client.wait_for_share_status(
                share["id"], "active", status_attr='access_rules_status',
                version=version)

        # delete share
        if utils.is_microversion_eq(version, '1.0'):
            self.shares_client.delete_share(share['id'])
            self.shares_client.wait_for_resource_deletion(share_id=share['id'])
        else:
            self.shares_v2_client.delete_share(share['id'], version=version)
            self.shares_v2_client.wait_for_resource_deletion(
                share_id=share['id'], version=version)

        # verify absence of rules for nonexistent share id
        if utils.is_microversion_eq(version, '1.0'):
            self.assertRaises(lib_exc.NotFound,
                              self.shares_client.list_access_rules,
                              share['id'])
        else:
            self.assertRaises(lib_exc.NotFound,
                              self.shares_v2_client.list_access_rules,
                              share['id'], version)
