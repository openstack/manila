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

from tempest import config  # noqa
from tempest import test  # noqa

from manila_tempest_tests import clients_share as clients
from manila_tempest_tests.tests.api import base

CONF = config.CONF


class SharesAdminQuotasTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        cls.os = clients.AdminManager()
        super(SharesAdminQuotasTest, cls).resource_setup()
        cls.user_id = cls.shares_v2_client.user_id
        cls.tenant_id = cls.shares_v2_client.tenant_id

    @test.attr(type=["gate", "smoke", ])
    def test_default_quotas(self):
        quotas = self.shares_v2_client.default_quotas(self.tenant_id)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["snapshot_gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)
        self.assertGreater(int(quotas["share_networks"]), -2)

    @test.attr(type=["gate", "smoke", ])
    def test_show_quotas(self):
        quotas = self.shares_v2_client.show_quotas(self.tenant_id)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["snapshot_gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)
        self.assertGreater(int(quotas["share_networks"]), -2)

    @test.attr(type=["gate", "smoke", ])
    def test_show_quotas_for_user(self):
        quotas = self.shares_v2_client.show_quotas(
            self.tenant_id, self.user_id)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["snapshot_gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)
        self.assertGreater(int(quotas["share_networks"]), -2)


class SharesAdminQuotasUpdateTest(base.BaseSharesAdminTest):

    force_tenant_isolation = True
    client_version = '2'

    def setUp(self):
        super(self.__class__, self).setUp()
        self.client = self.get_client_with_isolated_creds(
            client_version=self.client_version)
        self.tenant_id = self.client.tenant_id
        self.user_id = self.client.user_id

    @test.attr(type=["gate", "smoke", ])
    def test_update_tenant_quota_shares(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id)
        new_quota = int(quotas["shares"]) + 2

        # set new quota for shares
        updated = self.client.update_quotas(self.tenant_id, shares=new_quota)
        self.assertEqual(int(updated["shares"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_update_user_quota_shares(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id, self.user_id)
        new_quota = int(quotas["shares"]) - 1

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id, shares=new_quota)
        self.assertEqual(int(updated["shares"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_update_tenant_quota_snapshots(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id)
        new_quota = int(quotas["snapshots"]) + 2

        # set new quota for snapshots
        updated = self.client.update_quotas(
            self.tenant_id, snapshots=new_quota)
        self.assertEqual(int(updated["snapshots"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_update_user_quota_snapshots(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id, self.user_id)
        new_quota = int(quotas["snapshots"]) - 1

        # set new quota for snapshots
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id, snapshots=new_quota)
        self.assertEqual(int(updated["snapshots"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_update_tenant_quota_gigabytes(self):
        # get current quotas
        custom = self.client.show_quotas(self.tenant_id)

        # make quotas for update
        gigabytes = int(custom["gigabytes"]) + 2

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id, gigabytes=gigabytes)
        self.assertEqual(int(updated["gigabytes"]), gigabytes)

    @test.attr(type=["gate", "smoke", ])
    def test_update_tenant_quota_snapshot_gigabytes(self):
        # get current quotas
        custom = self.client.show_quotas(self.tenant_id)

        # make quotas for update
        snapshot_gigabytes = int(custom["snapshot_gigabytes"]) + 2

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id,
            snapshot_gigabytes=snapshot_gigabytes)
        self.assertEqual(
            int(updated["snapshot_gigabytes"]), snapshot_gigabytes)

    @test.attr(type=["gate", "smoke", ])
    def test_update_user_quota_gigabytes(self):
        # get current quotas
        custom = self.client.show_quotas(self.tenant_id, self.user_id)

        # make quotas for update
        gigabytes = int(custom["gigabytes"]) - 1

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id, gigabytes=gigabytes)
        self.assertEqual(int(updated["gigabytes"]), gigabytes)

    @test.attr(type=["gate", "smoke", ])
    def test_update_user_quota_snapshot_gigabytes(self):
        # get current quotas
        custom = self.client.show_quotas(self.tenant_id, self.user_id)

        # make quotas for update
        snapshot_gigabytes = int(custom["snapshot_gigabytes"]) - 1

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id,
            snapshot_gigabytes=snapshot_gigabytes)
        self.assertEqual(
            int(updated["snapshot_gigabytes"]), snapshot_gigabytes)

    @test.attr(type=["gate", "smoke", ])
    def test_update_tenant_quota_share_networks(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id)
        new_quota = int(quotas["share_networks"]) + 2

        # set new quota for share-networks
        updated = self.client.update_quotas(
            self.tenant_id, share_networks=new_quota)
        self.assertEqual(int(updated["share_networks"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_update_user_quota_share_networks(self):
        # get current quotas
        quotas = self.client.show_quotas(
            self.tenant_id, self.user_id)
        new_quota = int(quotas["share_networks"]) - 1

        # set new quota for share-networks
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id,
            share_networks=new_quota)
        self.assertEqual(int(updated["share_networks"]), new_quota)

    @test.attr(type=["gate", "smoke", ])
    def test_reset_tenant_quotas(self):
        # get default_quotas
        default = self.client.default_quotas(self.tenant_id)

        # get current quotas
        custom = self.client.show_quotas(self.tenant_id)

        # make quotas for update
        shares = int(custom["shares"]) + 2
        snapshots = int(custom["snapshots"]) + 2
        gigabytes = int(custom["gigabytes"]) + 2
        snapshot_gigabytes = int(custom["snapshot_gigabytes"]) + 2
        share_networks = int(custom["share_networks"]) + 2

        # set new quota
        updated = self.client.update_quotas(
            self.tenant_id,
            shares=shares,
            snapshots=snapshots,
            gigabytes=gigabytes,
            snapshot_gigabytes=snapshot_gigabytes,
            share_networks=share_networks)
        self.assertEqual(int(updated["shares"]), shares)
        self.assertEqual(int(updated["snapshots"]), snapshots)
        self.assertEqual(int(updated["gigabytes"]), gigabytes)
        self.assertEqual(
            int(updated["snapshot_gigabytes"]), snapshot_gigabytes)
        self.assertEqual(int(updated["share_networks"]), share_networks)

        # reset customized quotas
        self.client.reset_quotas(self.tenant_id)

        # verify quotas
        reseted = self.client.show_quotas(self.tenant_id)
        self.assertEqual(int(reseted["shares"]), int(default["shares"]))
        self.assertEqual(int(reseted["snapshots"]), int(default["snapshots"]))
        self.assertEqual(int(reseted["gigabytes"]), int(default["gigabytes"]))
        self.assertEqual(int(reseted["share_networks"]),
                         int(default["share_networks"]))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_quota_for_shares(self):
        self.client.update_quotas(self.tenant_id, shares=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('shares'))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_user_quota_for_shares(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, shares=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('shares'))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_quota_for_snapshots(self):
        self.client.update_quotas(self.tenant_id, snapshots=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('snapshots'))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_user_quota_for_snapshots(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, snapshots=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('snapshots'))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_quota_for_gigabytes(self):
        self.client.update_quotas(self.tenant_id, gigabytes=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('gigabytes'))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_quota_for_snapshot_gigabytes(self):
        self.client.update_quotas(
            self.tenant_id, snapshot_gigabytes=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('snapshot_gigabytes'))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_user_quota_for_gigabytes(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, gigabytes=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('gigabytes'))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_user_quota_for_snapshot_gigabytes(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, snapshot_gigabytes=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('snapshot_gigabytes'))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_quota_for_share_networks(self):
        self.client.update_quotas(self.tenant_id, share_networks=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('share_networks'))

    @test.attr(type=["gate", "smoke", ])
    def test_unlimited_user_quota_for_share_networks(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, share_networks=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('share_networks'))
