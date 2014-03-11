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
from tempest import exceptions
from tempest import test

import testtools

CONF = config.CONF


class SharesQuotasNegativeTest(base.BaseSharesAdminTest):

    force_tenant_isolation = True

    @classmethod
    def setUpClass(cls):
        cls.os = clients.AdminManager(interface=cls._interface)
        super(SharesQuotasNegativeTest, cls).setUpClass()

        # Get tenant and user
        cls.identity_client = cls._get_identity_admin_client()
        cls.tenant = cls.identity_client.get_tenant_by_name(
            cls.shares_client.auth_params["tenant"])
        cls.user = cls.identity_client.get_user_by_username(
            cls.tenant["id"], cls.shares_client.auth_params["user"])

    @test.attr(type=["gate", "smoke", "negative"])
    @testtools.skip("Skip until Bug #1234244 is fixed")
    def test_quotas_with_wrong_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_quotas, "wrong_tenant_id")

    @test.attr(type=["gate", "smoke", "negative"])
    @testtools.skip("Skip until Bug #1234244 is fixed")
    def test_quotas_with_wrong_user_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_quotas,
                          self.tenant["id"],
                          "wrong_user_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_quotas_with_empty_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.show_quotas, "")

    @test.attr(type=["gate", "smoke", "negative"])
    @testtools.skip("Skip until Bug #1233170 is fixed")
    def test_default_quotas_with_wrong_tenant_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.default_quotas, "wrong_tenant_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_reset_quotas_with_empty_tenant_id(self):
        client = self.get_client_with_isolated_creads()
        self.assertRaises(exceptions.NotFound,
                          client.reset_quotas, "")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_update_shares_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        client = self.get_client_with_isolated_creads()
        self.assertRaises(exceptions.BadRequest,
                          client.update_quotas,
                          client.creds["tenant"]["id"],
                          shares=-2)

    @test.attr(type=["gate", "smoke", "negative"])
    def test_update_snapshots_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        client = self.get_client_with_isolated_creads()
        self.assertRaises(exceptions.BadRequest,
                          client.update_quotas,
                          client.creds["tenant"]["id"],
                          snapshots=-2)

    @test.attr(type=["gate", "smoke", "negative"])
    def test_update_gigabytes_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        client = self.get_client_with_isolated_creads()
        self.assertRaises(exceptions.BadRequest,
                          client.update_quotas,
                          client.creds["tenant"]["id"],
                          gigabytes=-2)

    @test.attr(type=["gate", "smoke", "negative"])
    def test_create_share_with_size_bigger_than_quota(self):
        client = self.get_client_with_isolated_creads()
        new_quota = 25
        overquota = new_quota + 2

        # set quota for gigabytes
        resp, __ = client.update_quotas(client.creds["tenant"]["id"],
                                        gigabytes=new_quota)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # try schedule share with size, bigger than gigabytes quota
        self.assertRaises(exceptions.OverLimit,
                          self.create_share_wait_for_active,
                          client=client,
                          size=overquota,
                          share_network_id=client.share_network_id)

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_set_user_quota_shares_bigger_than_tenant_quota(self):
        client = self.get_client_with_isolated_creads()

        # get current quotas for tenant
        __, tenant_quotas = client.show_quotas(client.creds["tenant"]["id"])

        # try set user quota for shares bigger than tenant quota
        bigger_value = int(tenant_quotas["shares"]) + 2
        self.assertRaises(exceptions.BadRequest,
                          client.update_quotas,
                          client.creds["tenant"]["id"],
                          client.creds["user"]["id"],
                          shares=bigger_value)

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_set_user_quota_snaps_bigger_than_tenant_quota(self):
        client = self.get_client_with_isolated_creads()

        # get current quotas for tenant
        __, tenant_quotas = client.show_quotas(client.creds["tenant"]["id"])

        # try set user quota for snapshots bigger than tenant quota
        bigger_value = int(tenant_quotas["snapshots"]) + 2
        self.assertRaises(exceptions.BadRequest,
                          client.update_quotas,
                          client.creds["tenant"]["id"],
                          client.creds["user"]["id"],
                          snapshots=bigger_value)

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_set_user_quota_gigabytes_bigger_than_tenant_quota(self):
        client = self.get_client_with_isolated_creads()

        # get current quotas for tenant
        __, tenant_quotas = client.show_quotas(client.creds["tenant"]["id"])

        # try set user quota for gigabytes bigger than tenant quota
        bigger_value = int(tenant_quotas["gigabytes"]) + 2
        self.assertRaises(exceptions.BadRequest,
                          client.update_quotas,
                          client.creds["tenant"]["id"],
                          client.creds["user"]["id"],
                          gigabytes=bigger_value)
