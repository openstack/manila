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
from tempest import test


class SharesQuotasTestJSON(base.BaseSharesAdminTest):

    # Tests should be used without unlimited quotas (-1).
    # It is recommended to delete all entities in Manila before test run.

    @classmethod
    def setUpClass(cls):
        super(SharesQuotasTestJSON, cls).setUpClass()
        cls.identity_client = cls._get_identity_admin_client()
        cls.tenant = cls.identity_client\
                        .get_tenant_by_name(cls.shares_client.tenant_name)
        cls.user = cls.identity_client\
                      .get_user_by_username(cls.tenant["id"],
                                            cls.shares_client.username)

        # save quotas before tests
        __, cls.t_q = cls.shares_client.show_quotas(cls.tenant["id"])
        __, cls.u_q = cls.shares_client.show_quotas(cls.tenant["id"],
                                                    cls.user["id"])

        value = 1000
        # set quotas before tests
        cls.shares_client.update_quotas(cls.tenant["id"], shares=value,
                                        snapshots=value, gigabytes=value)
        cls.shares_client.update_quotas(cls.tenant["id"], cls.user["id"],
                                        shares=value, snapshots=value,
                                        gigabytes=value)

    @classmethod
    def tearDownClass(cls):
        super(SharesQuotasTestJSON, cls).tearDownClass()
        # back up quota values
        cls.shares_client.update_quotas(cls.tenant["id"],
                                        shares=cls.t_q["shares"],
                                        snapshots=cls.t_q["snapshots"],
                                        gigabytes=cls.t_q["gigabytes"])
        cls.shares_client.update_quotas(cls.tenant["id"],
                                        cls.user["id"],
                                        shares=cls.u_q["shares"],
                                        snapshots=cls.u_q["snapshots"],
                                        gigabytes=cls.u_q["gigabytes"])

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

    @test.attr(type='positive')
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

    @test.attr(type='positive')
    def test_default_quotas_with_empty_tenant_id(self):
        # it should return default quotas without any tenant-id
        resp, body = self.shares_client.default_quotas("")
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertTrue(len(body) > 0)

    @test.attr(type='positive')
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

    @test.attr(type='positive')
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

    @test.attr(type='positive')
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

    @test.attr(type='positive')
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

    @test.attr(type='positive')
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

    @test.attr(type='positive')
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

    @test.attr(type='positive')
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
        resp, reseted = self.shares_client.reset_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify quotas
        resp, after_delete = self.shares_client.show_quotas(self.tenant["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(int(after_delete["shares"]), int(default["shares"]))
        self.assertEqual(int(after_delete["snapshots"]),
                         int(default["snapshots"]))
        self.assertEqual(int(after_delete["gigabytes"]),
                         int(default["gigabytes"]))


class SharesQuotasTestXML(SharesQuotasTestJSON):
    _interface = 'xml'
