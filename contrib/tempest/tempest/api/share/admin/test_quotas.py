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
from tempest import config_share as config
from tempest import test

CONF = config.CONF


class SharesQuotasTest(base.BaseSharesAdminTest):

    @classmethod
    def setUpClass(cls):
        cls.os = clients.AdminManager(interface=cls._interface)
        super(SharesQuotasTest, cls).setUpClass()

        # Get tenant and user
        cls.identity_client = cls._get_identity_admin_client()
        cls.tenant = cls.identity_client.get_tenant_by_name(
            cls.shares_client.auth_params["tenant"])
        cls.user = cls.identity_client.get_user_by_username(
            cls.tenant["id"], cls.shares_client.auth_params["user"])

    @test.attr(type=["gate", "smoke", ])
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

    @test.attr(type=["gate", "smoke", ])
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

    @test.attr(type=["gate", "smoke", ])
    def test_default_quotas(self):
        resp, quotas = self.shares_client.default_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)

    @test.attr(type=["gate", "smoke", ])
    def test_show_quotas(self):
        resp, quotas = self.shares_client.show_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)

    @test.attr(type=["gate", "smoke", ])
    def test_show_quotas_for_user(self):
        resp, quotas = self.shares_client.show_quotas(self.tenant["id"],
                                                      self.user["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)

    @test.attr(type=["gate", "smoke", ])
    def test_default_quotas_with_empty_tenant_id(self):
        # it should return default quotas without any tenant-id
        resp, body = self.shares_client.default_quotas("")
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertTrue(len(body) > 0)


class SharesQuotasUpdateTest(base.BaseSharesAdminTest):

    force_tenant_isolation = True

    @test.attr(type=["gate", "smoke", ])
    def test_update_tenant_quota_shares(self):
        client = self.get_client_with_isolated_creads()

        # get current quotas
        resp, quotas = client.show_quotas(client.creds["tenant"]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        new_quota = int(quotas["shares"]) + 2

        # set new quota for shares
        resp, updated = client.update_quotas(client.creds["tenant"]["id"],
                                             shares=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["shares"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_update_user_quota_shares(self):
        client = self.get_client_with_isolated_creads()

        # get current quotas
        resp, quotas = client.show_quotas(client.creds["tenant"]["id"],
                                          client.creds["user"]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        new_quota = int(quotas["shares"]) - 1

        # set new quota for shares
        resp, updated = client.update_quotas(client.creds["tenant"]["id"],
                                             shares=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["shares"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_update_tenant_quota_snapshots(self):
        client = self.get_client_with_isolated_creads()

        # get current quotas
        resp, quotas = client.show_quotas(client.creds["tenant"]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        new_quota = int(quotas["snapshots"]) + 2

        # set new quota for snapshots
        resp, updated = client.update_quotas(client.creds["tenant"]["id"],
                                             snapshots=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["snapshots"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_update_user_quota_snapshots(self):
        client = self.get_client_with_isolated_creads()

        # get current quotas
        resp, quotas = client.show_quotas(client.creds["tenant"]["id"],
                                          client.creds["user"]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        new_quota = int(quotas["snapshots"]) - 1

        # set new quota for snapshots
        resp, updated = client.update_quotas(client.creds["tenant"]["id"],
                                             snapshots=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["snapshots"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_update_tenant_quota_gigabytes(self):
        client = self.get_client_with_isolated_creads()

        # get current quotas
        resp, custom = client.show_quotas(client.creds["tenant"]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # make quotas for update
        gigabytes = int(custom["gigabytes"]) + 2

        # set new quota for shares
        resp, updated = client.update_quotas(client.creds["tenant"]["id"],
                                             gigabytes=gigabytes)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["gigabytes"]), gigabytes)

    @test.attr(type=["gate", "smoke", ])
    def test_update_user_quota_gigabytes(self):
        client = self.get_client_with_isolated_creads()

        # get current quotas
        resp, custom = client.show_quotas(client.creds["tenant"]["id"],
                                          client.creds["user"]["id"])

        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # make quotas for update
        gigabytes = int(custom["gigabytes"]) - 1

        # set new quota for shares
        resp, updated = client.update_quotas(client.creds["tenant"]["id"],
                                             gigabytes=gigabytes)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["gigabytes"]), gigabytes)

    @test.attr(type=["gate", "smoke", ])
    def test_reset_tenant_quotas(self):
        client = self.get_client_with_isolated_creads()

        # get default_quotas
        resp, default = client.default_quotas(client.creds["tenant"]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # get current quotas
        resp, custom = client.show_quotas(client.creds["tenant"]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # make quotas for update
        shares = int(custom["shares"]) + 2
        snapshots = int(custom["snapshots"]) + 2
        gigabytes = int(custom["gigabytes"]) + 2

        # set new quota
        resp, updated = client.update_quotas(client.creds["tenant"]["id"],
                                             shares=shares,
                                             snapshots=snapshots,
                                             gigabytes=gigabytes)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(updated["shares"]), shares)
        self.assertEqual(int(updated["snapshots"]), snapshots)
        self.assertEqual(int(updated["gigabytes"]), gigabytes)

        # reset customized quotas
        resp, __ = client.reset_quotas(client.creds["tenant"]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify quotas
        resp, reseted = client.show_quotas(client.creds["tenant"]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(reseted["shares"]), int(default["shares"]))
        self.assertEqual(int(reseted["snapshots"]), int(default["snapshots"]))
        self.assertEqual(int(reseted["gigabytes"]), int(default["gigabytes"]))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_quota_for_gigabytes(self):
        client = self.get_client_with_isolated_creads()
        resp, __ = client.update_quotas(client.creds["tenant"]["id"],
                                        gigabytes=-1)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_user_quota_for_gigabytes(self):
        client = self.get_client_with_isolated_creads()
        resp, __ = client.update_quotas(client.creds["tenant"]["id"],
                                        client.creds["user"]["id"],
                                        gigabytes=-1)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
