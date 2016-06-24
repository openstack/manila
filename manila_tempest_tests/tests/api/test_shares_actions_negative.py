# Copyright 2015 Mirantis Inc.
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

from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import test
import testtools

from manila_tempest_tests.tests.api import base

CONF = config.CONF


class SharesActionsNegativeTest(base.BaseSharesMixedTest):
    @classmethod
    def resource_setup(cls):
        super(SharesActionsNegativeTest, cls).resource_setup()
        cls.admin_client = cls.admin_shares_v2_client
        cls.share = cls.create_share()

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    @testtools.skipUnless(
        CONF.share.run_quota_tests,
        "Quota tests are disabled.")
    def test_share_extend_over_quota(self):
        tenant_quotas = self.shares_client.show_quotas(
            self.shares_client.tenant_id)
        new_size = int(tenant_quotas["gigabytes"]) + 1

        # extend share with over quota and check result
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.extend_share,
                          self.share['id'],
                          new_size)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    def test_share_extend_with_less_size(self):
        new_size = int(self.share['size']) - 1

        # extend share with invalid size and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.extend_share,
                          self.share['id'],
                          new_size)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    def test_share_extend_with_same_size(self):
        new_size = int(self.share['size'])

        # extend share with invalid size and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.extend_share,
                          self.share['id'],
                          new_size)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    def test_share_extend_with_invalid_share_state(self):
        share = self.create_share(cleanup_in_class=False)
        new_size = int(share['size']) + 1

        # set "error" state
        self.admin_client.reset_state(share['id'])

        # run extend operation on same share and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.extend_share,
                          share['id'],
                          new_size)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(
        CONF.share.run_shrink_tests,
        "Share shrink tests are disabled.")
    def test_share_shrink_with_greater_size(self):
        new_size = int(self.share['size']) + 1

        # shrink share with invalid size and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.shrink_share,
                          self.share['id'],
                          new_size)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(
        CONF.share.run_shrink_tests,
        "Share shrink tests are disabled.")
    def test_share_shrink_with_same_size(self):
        new_size = int(self.share['size'])

        # shrink share with invalid size and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.shrink_share,
                          self.share['id'],
                          new_size)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @testtools.skipUnless(
        CONF.share.run_shrink_tests,
        "Share shrink tests are disabled.")
    def test_share_shrink_with_invalid_share_state(self):
        size = CONF.share.share_size + 1
        share = self.create_share(size=size, cleanup_in_class=False)
        new_size = int(share['size']) - 1

        # set "error" state
        self.admin_client.reset_state(share['id'])

        # run shrink operation on same share and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.shrink_share,
                          share['id'],
                          new_size)
