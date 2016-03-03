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

from tempest import config  # noqa
from tempest.lib import exceptions as lib_exc  # noqa
from tempest import test  # noqa
import testtools  # noqa

from manila_tempest_tests import clients_share as clients
from manila_tempest_tests.tests.api import base

CONF = config.CONF


class SharesActionsNegativeTest(base.BaseSharesTest):
    @classmethod
    def resource_setup(cls):
        super(SharesActionsNegativeTest, cls).resource_setup()
        cls.share = cls.create_share(
            size=1,
        )

    @test.attr(type=["negative", ])
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    def test_share_extend_over_quota(self):
        tenant_quotas = self.shares_client.show_quotas(
            self.shares_client.tenant_id)
        new_size = int(tenant_quotas["gigabytes"]) + 1

        # extend share with over quota and check result
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.extend_share,
                          self.share['id'],
                          new_size)

    @test.attr(type=["negative", ])
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

    @test.attr(type=["negative", ])
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

    @test.attr(type=["negative", ])
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    def test_share_extend_with_invalid_share_state(self):
        share = self.create_share(size=1, cleanup_in_class=False)
        new_size = int(share['size']) + 1

        # set "error" state
        admin_client = clients.AdminManager().shares_client
        admin_client.reset_state(share['id'])

        # run extend operation on same share and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.extend_share,
                          share['id'],
                          new_size)

    @test.attr(type=["negative", ])
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

    @test.attr(type=["negative", ])
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

    @test.attr(type=["negative", ])
    @testtools.skipUnless(
        CONF.share.run_shrink_tests,
        "Share shrink tests are disabled.")
    def test_share_shrink_with_invalid_share_state(self):
        share = self.create_share(size=2, cleanup_in_class=False)
        new_size = int(share['size']) - 1

        # set "error" state
        admin_client = clients.AdminManager().shares_client
        admin_client.reset_state(share['id'])

        # run shrink operation on same share and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.shrink_share,
                          share['id'],
                          new_size)
