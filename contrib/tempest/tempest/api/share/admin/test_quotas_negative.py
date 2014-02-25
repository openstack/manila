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
from tempest import exceptions
from tempest import test

import testtools

CONF = config.CONF


class SharesQuotasNegativeTest(base.BaseSharesAdminTest):

    @classmethod
    def setUpClass(cls):
        super(SharesQuotasNegativeTest, cls).setUpClass()

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
        super(SharesQuotasNegativeTest, cls).tearDownClass()
        cls.isolated_creds.clear_isolated_creds()

    @test.attr(type=['negative', ])
    @testtools.skip("Skip until Bug #1234244 is fixed")
    def test_quotas_with_wrong_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_quotas, "wrong_tenant_id")

    @test.attr(type=['negative', ])
    @testtools.skip("Skip until Bug #1234244 is fixed")
    def test_quotas_with_wrong_user_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_quotas,
                          self.tenant["id"],
                          "wrong_user_id")

    @test.attr(type=['negative', ])
    def test_quotas_with_empty_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.show_quotas, "")

    @test.attr(type=['negative', ])
    @testtools.skip("Skip until Bug #1233170 is fixed")
    def test_default_quotas_with_wrong_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.default_quotas, "wrong_tenant_id")

    @test.attr(type=['negative', ])
    def test_reset_quotas_with_empty_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.reset_quotas, "")

    @test.attr(type=['negative', ])
    def test_update_shares_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_quotas,
                          self.tenant["id"],
                          shares=-2)

    @test.attr(type=['negative', ])
    def test_update_snapshots_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_quotas,
                          self.tenant["id"],
                          snapshots=-2)

    @test.attr(type=['negative', ])
    def test_update_gigabytes_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_quotas,
                          self.tenant["id"],
                          gigabytes=-2)

    @test.attr(type=['negative', ])
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

    @test.attr(type=['negative', ])
    def test_unlimited_quota_for_gigabytes(self):
        # set unlimited quota for gigabytes
        resp, __ = self.shares_client.update_quotas(self.tenant["id"],
                                                    gigabytes=-1)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=['negative', ])
    def test_unlimited_user_quota_for_gigabytes(self):
        resp, __ = self.shares_client.update_quotas(self.tenant["id"],
                                                    self.user["id"],
                                                    gigabytes=-1)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=['negative', ])
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

    @test.attr(type=['negative', ])
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

    @test.attr(type=['negative', ])
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
