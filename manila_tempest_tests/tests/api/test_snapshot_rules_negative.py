# Copyright 2016 Hitachi Data Systems
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
import testtools
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base
from manila_tempest_tests.tests.api import test_snapshot_rules

CONF = config.CONF


@base.skip_if_microversion_lt("2.32")
@testtools.skipUnless(CONF.share.run_mount_snapshot_tests and
                      CONF.share.run_snapshot_tests,
                      'Mountable snapshots tests are disabled.')
@ddt.ddt
class SnapshotIpRulesForNFSNegativeTest(
        test_snapshot_rules.BaseShareSnapshotRulesTest):
    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        if not (cls.protocol in CONF.share.enable_protocols and
                cls.protocol in CONF.share.enable_ip_rules_for_protocols):
            msg = "IP rule tests for %s protocol are disabled." % cls.protocol
            raise cls.skipException(msg)
        super(SnapshotIpRulesForNFSNegativeTest, cls).resource_setup()

        # create share
        cls.share = cls.create_share(cls.protocol)
        cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @ddt.data("1.2.3.256", "1.1.1.-", "1.2.3.4/33", "1.2.3.*", "1.2.3.*/23",
              "1.2.3.1|23", "1.2.3.1/",  "1.2.3.1/-1", "fe00::1",
              "fe80::217:f2ff:fe07:ed62", "2001:db8::/48", "::1/128",
              "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
              "2001:0db8:0000:85a3:0000:0000:ac1f:8001")
    def test_create_access_rule_ip_with_wrong_target(self, target):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_v2_client.create_snapshot_access_rule,
                          self.snap["id"], "ip", target)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_duplicate_of_ip_rule(self):
        self._test_duplicate_rules()
        self._test_duplicate_rules()

    def _test_duplicate_rules(self):
        # test data
        access_type = "ip"
        access_to = "1.2.3.4"

        # create rule
        rule = self.shares_v2_client.create_snapshot_access_rule(
            self.snap['id'], access_type, access_to)

        self.shares_v2_client.wait_for_snapshot_access_rule_status(
            self.snap['id'], rule['id'])

        # try create duplicate of rule
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_v2_client.create_snapshot_access_rule,
                          self.snap["id"], access_type, access_to)

        # delete rule and wait for deletion
        self.shares_v2_client.delete_snapshot_access_rule(self.snap['id'],
                                                          rule['id'])
        self.shares_v2_client.wait_for_snapshot_access_rule_deletion(
            self.snap['id'], rule['id'])

        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.delete_snapshot_access_rule,
                          self.snap['id'], rule['id'])
