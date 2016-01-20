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
from tempest import config  # noqa
from tempest import test  # noqa
from tempest_lib import exceptions as lib_exc  # noqa
import testtools  # noqa

from manila_tempest_tests.tests.api import base

CONF = config.CONF


def _create_delete_ro_access_rule(self, client_name):
    """Common test case for usage in test suites with different decorators.

    :param self: instance of test class
    """
    rule = getattr(self, client_name).create_access_rule(
        self.share["id"], self.access_type, self.access_to, 'ro')

    self.assertEqual('ro', rule['access_level'])
    for key in ('deleted', 'deleted_at', 'instance_mappings'):
        self.assertNotIn(key, rule.keys())
    getattr(self, client_name).wait_for_access_rule_status(
        self.share["id"], rule["id"], "active")
    getattr(self, client_name).delete_access_rule(self.share["id"], rule["id"])
    getattr(self, client_name).wait_for_resource_deletion(
        rule_id=rule["id"], share_id=self.share['id'])


@ddt.ddt
class ShareIpRulesForNFSTest(base.BaseSharesTest):
    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(ShareIpRulesForNFSTest, cls).resource_setup()
        if (cls.protocol not in CONF.share.enable_protocols or
                cls.protocol not in CONF.share.enable_ip_rules_for_protocols):
            msg = "IP rule tests for %s protocol are disabled" % cls.protocol
            raise cls.skipException(msg)
        cls.share = cls.create_share(cls.protocol)
        cls.access_type = "ip"
        cls.access_to = "2.2.2.2"

    @test.attr(type=["gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_delete_access_rules_with_one_ip(self, client_name):

        # test data
        access_to = "1.1.1.1"

        # create rule
        rule = getattr(self, client_name).create_access_rule(
            self.share["id"], self.access_type, access_to)

        self.assertEqual('rw', rule['access_level'])
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())
        getattr(self, client_name).wait_for_access_rule_status(
            self.share["id"], rule["id"], "active")

        # delete rule and wait for deletion
        getattr(self, client_name).delete_access_rule(self.share["id"],
                                                      rule["id"])
        getattr(self, client_name).wait_for_resource_deletion(
            rule_id=rule["id"], share_id=self.share['id'])

    @test.attr(type=["gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_delete_access_rule_with_cidr(self, client_name):

        # test data
        access_to = "1.2.3.4/32"

        # create rule
        rule = getattr(self, client_name).create_access_rule(
            self.share["id"], self.access_type, access_to)

        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())
        self.assertEqual('rw', rule['access_level'])
        getattr(self, client_name).wait_for_access_rule_status(
            self.share["id"], rule["id"], "active")

        # delete rule and wait for deletion
        getattr(self, client_name).delete_access_rule(self.share["id"],
                                                      rule["id"])
        getattr(self, client_name).wait_for_resource_deletion(
            rule_id=rule["id"], share_id=self.share['id'])

    @test.attr(type=["gate", ])
    @testtools.skipIf(
        "nfs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for NFS protocol.")
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_delete_ro_access_rule(self, client_name):
        _create_delete_ro_access_rule(self, client_name)


@ddt.ddt
class ShareIpRulesForCIFSTest(ShareIpRulesForNFSTest):
    protocol = "cifs"

    @test.attr(type=["gate", ])
    @testtools.skipIf(
        "cifs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for CIFS protocol.")
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_delete_ro_access_rule(self, client_name):
        _create_delete_ro_access_rule(self, client_name)


@ddt.ddt
class ShareUserRulesForNFSTest(base.BaseSharesTest):
    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(ShareUserRulesForNFSTest, cls).resource_setup()
        if (cls.protocol not in CONF.share.enable_protocols or
                cls.protocol not in
                CONF.share.enable_user_rules_for_protocols):
            msg = "USER rule tests for %s protocol are disabled" % cls.protocol
            raise cls.skipException(msg)
        cls.share = cls.create_share(cls.protocol)
        cls.access_type = "user"
        cls.access_to = CONF.share.username_for_user_rules

    @test.attr(type=["gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_delete_user_rule(self, client_name):

        # create rule
        rule = getattr(self, client_name).create_access_rule(
            self.share["id"], self.access_type, self.access_to)

        self.assertEqual('rw', rule['access_level'])
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())
        getattr(self, client_name).wait_for_access_rule_status(
            self.share["id"], rule["id"], "active")

        # delete rule and wait for deletion
        getattr(self, client_name).delete_access_rule(self.share["id"],
                                                      rule["id"])
        getattr(self, client_name).wait_for_resource_deletion(
            rule_id=rule["id"], share_id=self.share['id'])

    @test.attr(type=["gate", ])
    @testtools.skipIf(
        "nfs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for NFS protocol.")
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_delete_ro_access_rule(self, client_name):
        _create_delete_ro_access_rule(self, client_name)


@ddt.ddt
class ShareUserRulesForCIFSTest(ShareUserRulesForNFSTest):
    protocol = "cifs"

    @test.attr(type=["gate", ])
    @testtools.skipIf(
        "cifs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for CIFS protocol.")
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_delete_ro_access_rule(self, client_name):
        _create_delete_ro_access_rule(self, client_name)


@ddt.ddt
class ShareCertRulesForGLUSTERFSTest(base.BaseSharesTest):
    protocol = "glusterfs"

    @classmethod
    def resource_setup(cls):
        super(ShareCertRulesForGLUSTERFSTest, cls).resource_setup()
        if (cls.protocol not in CONF.share.enable_protocols or
                cls.protocol not in
                CONF.share.enable_cert_rules_for_protocols):
            msg = "Cert rule tests for %s protocol are disabled" % cls.protocol
            raise cls.skipException(msg)
        cls.share = cls.create_share(cls.protocol)
        cls.access_type = "cert"
        # Provide access to a client identified by a common name (CN) of the
        # certificate that it possesses.
        cls.access_to = "client1.com"

    @test.attr(type=["gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_delete_cert_rule(self, client_name):

        # create rule
        rule = getattr(self, client_name).create_access_rule(
            self.share["id"], self.access_type, self.access_to)

        self.assertEqual('rw', rule['access_level'])
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())
        getattr(self, client_name).wait_for_access_rule_status(
            self.share["id"], rule["id"], "active")

        # delete rule
        getattr(self, client_name).delete_access_rule(self.share["id"],
                                                      rule["id"])

    @test.attr(type=["gate", ])
    @testtools.skipIf(
        "glusterfs" not in CONF.share.enable_ro_access_level_for_protocols,
        "RO access rule tests are disabled for GLUSTERFS protocol.")
    @ddt.data('shares_client', 'shares_v2_client')
    def test_create_delete_cert_ro_access_rule(self, client_name):
        rule = getattr(self, client_name).create_access_rule(
            self.share["id"], 'cert', 'client2.com', 'ro')

        self.assertEqual('ro', rule['access_level'])
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            self.assertNotIn(key, rule.keys())
        getattr(self, client_name).wait_for_access_rule_status(
            self.share["id"], rule["id"], "active")
        getattr(self, client_name).delete_access_rule(self.share["id"],
                                                      rule["id"])


@ddt.ddt
class ShareRulesTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(ShareRulesTest, cls).resource_setup()
        if not (any(p in CONF.share.enable_ip_rules_for_protocols
                    for p in cls.protocols) or
                any(p in CONF.share.enable_user_rules_for_protocols
                    for p in cls.protocols) or
                any(p in CONF.share.enable_cert_rules_for_protocols
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
        cls.shares_v2_client.share_protocol = cls.protocol
        cls.share = cls.create_share()

    @test.attr(type=["gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_list_access_rules(self, client_name):

        # create rule
        rule = getattr(self, client_name).create_access_rule(
            self.share["id"], self.access_type, self.access_to)

        getattr(self, client_name).wait_for_access_rule_status(
            self.share["id"], rule["id"], "active")

        # list rules
        rules = getattr(self, client_name).list_access_rules(self.share["id"])

        # verify keys
        for key in ("state", "id", "access_type", "access_to", "access_level"):
            [self.assertIn(key, r.keys()) for r in rules]
        for key in ('deleted', 'deleted_at', 'instance_mappings'):
            [self.assertNotIn(key, r.keys()) for r in rules]

        # verify values
        self.assertEqual("active", rules[0]["state"])
        self.assertEqual(self.access_type, rules[0]["access_type"])
        self.assertEqual(self.access_to, rules[0]["access_to"])
        self.assertEqual('rw', rules[0]["access_level"])

        # our share id in list and have no duplicates
        gen = [r["id"] for r in rules if r["id"] in rule["id"]]
        msg = "expected id lists %s times in rule list" % (len(gen))
        self.assertEqual(len(gen), 1, msg)

        getattr(self, client_name).delete_access_rule(
            self.share['id'], rule['id'])

        getattr(self, client_name).wait_for_resource_deletion(
            rule_id=rule["id"], share_id=self.share['id'])

    @test.attr(type=["gate", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_access_rules_deleted_if_share_deleted(self, client_name):

        # create share
        share = self.create_share()

        # create rule
        rule = getattr(self, client_name).create_access_rule(
            share["id"], self.access_type, self.access_to)
        getattr(self, client_name).wait_for_access_rule_status(
            share["id"], rule["id"], "active")

        # delete share
        getattr(self, client_name).delete_share(share['id'])
        getattr(self, client_name).wait_for_resource_deletion(
            share_id=share['id'])

        # verify absence of rules for nonexistent share id
        self.assertRaises(lib_exc.NotFound,
                          getattr(self, client_name).list_access_rules,
                          share['id'])
