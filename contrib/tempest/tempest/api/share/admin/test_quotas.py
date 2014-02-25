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

from tempest.api.share import base
from tempest import clients_share as clients
from tempest.common import isolated_creds
from tempest import config_share as config
from tempest import test

CONF = config.CONF


class SharesQuotasTest(base.BaseSharesAdminTest):

    @classmethod
    def setUpClass(cls):
        super(SharesQuotasTest, cls).setUpClass()

        # Use isolated creds
        cls.isolated_creds = isolated_creds.IsolatedCreds(cls.__name__)
        creds = cls.isolated_creds.get_admin_creds()
        username, tenant_name, password = creds
        cls.os = clients.Manager(username=username,
                                 password=password,
                                 tenant_name=tenant_name,
                                 interface=cls._interface)
        cls.shares_client = cls.os.shares_client

        # Get tenant and user
        cls.identity_client = cls._get_identity_admin_client()
        cls.tenant = cls.identity_client.get_tenant_by_name(
            cls.shares_client.auth_params["tenant"])
        cls.user = cls.identity_client.get_user_by_username(
            cls.tenant["id"], cls.shares_client.auth_params["user"])

        # set quotas before tests
        value = 1000
        cls.shares_client.update_quotas(cls.tenant["id"], shares=value,
                                        snapshots=value, gigabytes=value)
        cls.shares_client.update_quotas(cls.tenant["id"], cls.user["id"],
                                        shares=value, snapshots=value,
                                        gigabytes=value)

    @classmethod
    def tearDownClass(cls):
        super(SharesQuotasTest, cls).tearDownClass()
        cls.isolated_creds.clear_isolated_creds()

    @test.attr(type=['positive', 'smoke'])
    def test_limits_keys(self):

        # list limits
        resp, limits = self.shares_client.get_limits()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        keys = ["rate", "absolute"]
        [self.assertIn(key, limits.keys()) for key in keys]

        abs_keys = ["maxTotalShareGigabytes",
                    "maxTotalShares",
                    "maxTotalSnapshots"]
        [self.assertIn(key, limits["absolute"].keys()) for key in abs_keys]

    @test.attr(type=['positive', 'smoke'])
    def test_limits_values(self):

        # list limits
        resp, limits = self.shares_client.get_limits()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify integer values for absolute limits
        self.assertGreater(int(limits["absolute"]["maxTotalShareGigabytes"]),
                           -2)
        self.assertGreater(int(limits["absolute"]["maxTotalShares"]), -2)
        self.assertGreater(int(limits["absolute"]["maxTotalSnapshots"]), -2)

    @test.attr(type=['positive', ])
    def test_default_quotas(self):
        resp, quotas = self.shares_client.default_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)

    @test.attr(type=['positive', 'smoke'])
    def test_show_quotas(self):
        resp, quotas = self.shares_client.show_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)

    @test.attr(type=['positive', 'smoke'])
    def test_show_quotas_for_user(self):
        resp, quotas = self.shares_client.show_quotas(self.tenant["id"],
                                                      self.user["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)

    @test.attr(type=['positive', ])
    def test_default_quotas_with_empty_tenant_id(self):
        # it should return default quotas without any tenant-id
        resp, body = self.shares_client.default_quotas("")
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertTrue(len(body) > 0)

    @test.attr(type=['positive', ])
    def test_update_tenant_quota_shares(self):

        # get current quotas
        resp, quotas = self.shares_client.show_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        new_quota = int(quotas["shares"]) + 2

        # set new quota for shares
        resp, updated = self.shares_client.update_quotas(self.tenant["id"],
                                                         shares=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["shares"]), new_quota)

    @test.attr(type=['positive', ])
    def test_update_user_quota_shares(self):

        # get current quotas
        resp, quotas = self.shares_client.show_quotas(self.tenant["id"],
                                                      self.user["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        new_quota = int(quotas["shares"]) - 1

        # set new quota for shares
        resp, updated = self.shares_client.update_quotas(self.tenant["id"],
                                                         shares=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["shares"]), new_quota)

    @test.attr(type=['positive', ])
    def test_update_tenant_quota_snapshots(self):

        # get current quotas
        resp, quotas = self.shares_client.show_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        new_quota = int(quotas["snapshots"]) + 2

        # set new quota for snapshots
        resp, updated = self.shares_client.update_quotas(self.tenant["id"],
                                                         snapshots=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["snapshots"]), new_quota)

    @test.attr(type=['positive', ])
    def test_update_user_quota_snapshots(self):

        # get current quotas
        resp, quotas = self.shares_client.show_quotas(self.tenant["id"],
                                                      self.user["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        new_quota = int(quotas["snapshots"]) - 1

        # set new quota for snapshots
        resp, updated = self.shares_client.update_quotas(self.tenant["id"],
                                                         snapshots=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["snapshots"]), new_quota)

    @test.attr(type=['positive', ])
    def test_update_tenant_quota_gigabytes(self):

        # get current quotas
        resp, custom = self.shares_client.show_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # make quotas for update
        gigabytes = int(custom["gigabytes"]) + 2

        # set new quota for shares
        resp, updated = self.shares_client.update_quotas(self.tenant["id"],
                                                         gigabytes=gigabytes)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["gigabytes"]), gigabytes)

    @test.attr(type=['positive', ])
    def test_update_user_quota_gigabytes(self):

        # get current quotas
        resp, custom = self.shares_client.show_quotas(self.tenant["id"],
                                                      self.user["id"])

        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # make quotas for update
        gigabytes = int(custom["gigabytes"]) - 1

        # set new quota for shares
        resp, updated = self.shares_client.update_quotas(self.tenant["id"],
                                                         gigabytes=gigabytes)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["gigabytes"]), gigabytes)

    @test.attr(type=['positive', ])
    def test_reset_tenant_quotas(self):

        # get default_quotas
        resp, default = self.shares_client.default_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # get current quotas
        resp, custom = self.shares_client.show_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # make quotas for update
        shares = int(custom["shares"]) + 2
        snapshots = int(custom["snapshots"]) + 2
        gigabytes = int(custom["gigabytes"]) + 2

        # set new quota
        resp, updated = self.shares_client.update_quotas(self.tenant["id"],
                                                         shares=shares,
                                                         snapshots=snapshots,
                                                         gigabytes=gigabytes)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["shares"]), shares)
        self.assertEqual(int(updated["snapshots"]), snapshots)
        self.assertEqual(int(updated["gigabytes"]), gigabytes)

        # reset customized quotas
        resp, reset = self.shares_client.reset_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify quotas
        resp, after_delete = self.shares_client.show_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(after_delete["shares"]), int(default["shares"]))
        self.assertEqual(int(after_delete["snapshots"]),
                         int(default["snapshots"]))
        self.assertEqual(int(after_delete["gigabytes"]),
                         int(default["gigabytes"]))
