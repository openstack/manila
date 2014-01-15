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
from tempest import exceptions
from tempest import exceptions_shares
from tempest import test
import unittest


class SharesQuotasNegativeTestJSON(base.BaseSharesAdminTest):

    # Tests should be used without unlimited quotas (-1).
    # It is recommended to delete all entities in Manila before test run.

    @classmethod
    def setUpClass(cls):
        super(SharesQuotasNegativeTestJSON, cls).setUpClass()
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
        super(SharesQuotasNegativeTestJSON, cls).tearDownClass()
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

    @test.attr(type='negative')
    @unittest.skip("Skip until Bug #1234244 is fixed")
    def test_quotas_with_wrong_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_quotas, "wrong_tenant_id")

    @test.attr(type='negative')
    @unittest.skip("Skip until Bug #1234244 is fixed")
    def test_quotas_with_wrong_user_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_quotas,
                          self.tenant["id"],
                          "wrong_user_id")

    @test.attr(type='negative')
    def test_quotas_with_empty_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.show_quotas, "")

    @test.attr(type='negative')
    @unittest.skip("Skip until Bug #1233170 is fixed")
    def test_default_quotas_with_wrong_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.default_quotas, "wrong_tenant_id")

    @test.attr(type='negative')
    def test_reset_quotas_with_empty_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.reset_quotas, "")

    @test.attr(type='negative')
    def test_update_shares_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_quotas,
                          self.tenant["id"],
                          shares=-2)

    @test.attr(type='negative')
    def test_update_snapshots_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_quotas,
                          self.tenant["id"],
                          snapshots=-2)

    @test.attr(type='negative')
    def test_update_gigabytes_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_quotas,
                          self.tenant["id"],
                          gigabytes=-2)

    @test.attr(type='negative')
    def test_create_share_with_size_bigger_than_quota(self):

        new_quota = 25
        overquota = new_quota + 2

        # set quota for gigabytes
        resp, updated = self.shares_client.update_quotas(self.tenant["id"],
                                                         gigabytes=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # try schedule share with size, bigger than gigabytes quota
        self.assertRaises(exceptions.OverLimit,
                          self.create_share_wait_for_active,
                          size=overquota)

    @test.attr(type='negative')
    def test_unlimited_quota_for_gigabytes(self):

        # get current quota
        _, quotas = self.shares_client.show_quotas(self.tenant["id"])

        # set unlimited quota for gigabytes
        resp, __ = self.shares_client.update_quotas(self.tenant["id"],
                                                    gigabytes=-1)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        resp, __ = self.shares_client.update_quotas(self.tenant["id"],
                                                    self.user["id"],
                                                    gigabytes=-1)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # share should be scheduled
        self.assertRaises(exceptions_shares.ShareBuildErrorException,
                          self.create_share_wait_for_active, size=987654)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # return quotas as it was
        self.shares_client.update_quotas(self.tenant["id"],
                                         gigabytes=quotas["gigabytes"])
        self.shares_client.update_quotas(self.tenant["id"], self.user["id"],
                                         gigabytes=quotas["gigabytes"])

    @test.attr(type='negative')
    def test_try_set_user_quota_gigabytes_bigger_than_tenant_quota(self):

        # get current quotas for tenant
        _, tenant_quotas = self.shares_client.show_quotas(self.tenant["id"])

        # try set user quota for gigabytes bigger than tenant quota
        bigger_value = int(tenant_quotas["gigabytes"]) + 2
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_quotas,
                          self.tenant["id"],
                          self.user["id"],
                          gigabytes=bigger_value)

    @test.attr(type='negative')
    def test_try_set_user_quota_shares_bigger_than_tenant_quota(self):

        # get current quotas for tenant
        _, tenant_quotas = self.shares_client.show_quotas(self.tenant["id"])

        # try set user quota for shares bigger than tenant quota
        bigger_value = int(tenant_quotas["shares"]) + 2
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_quotas,
                          self.tenant["id"],
                          self.user["id"],
                          shares=bigger_value)

    @test.attr(type='negative')
    def test_try_set_user_quota_snaps_bigger_than_tenant_quota(self):

        # get current quotas for tenant
        _, tenant_quotas = self.shares_client.show_quotas(self.tenant["id"])

        # try set user quota for snapshots bigger than tenant quota
        bigger_value = int(tenant_quotas["snapshots"]) + 2
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_quotas,
                          self.tenant["id"],
                          self.user["id"],
                          snapshots=bigger_value)


class SharesQuotasNegativeTestXML(SharesQuotasNegativeTestJSON):
    _interface = 'xml'
