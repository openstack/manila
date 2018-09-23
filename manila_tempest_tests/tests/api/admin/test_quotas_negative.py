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

import ddt
from tempest import config
from tempest.lib import exceptions as lib_exc
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@ddt.ddt
class SharesAdminQuotasNegativeTest(base.BaseSharesAdminTest):

    force_tenant_isolation = True

    @classmethod
    def resource_setup(cls):
        if not CONF.share.run_quota_tests:
            msg = "Quota tests are disabled."
            raise cls.skipException(msg)
        super(SharesAdminQuotasNegativeTest, cls).resource_setup()
        cls.user_id = cls.shares_client.user_id
        cls.tenant_id = cls.shares_client.tenant_id
        # create share type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_get_quotas_with_empty_tenant_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.show_quotas, "")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_reset_quotas_with_empty_tenant_id(self):
        client = self.get_client_with_isolated_creds()
        self.assertRaises(lib_exc.NotFound,
                          client.reset_quotas, "")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_update_shares_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        client = self.get_client_with_isolated_creds()
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          shares=-2)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_update_snapshots_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        client = self.get_client_with_isolated_creds()
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          snapshots=-2)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_update_gigabytes_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        client = self.get_client_with_isolated_creds()
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          gigabytes=-2)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_update_snapshot_gigabytes_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        client = self.get_client_with_isolated_creds()
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          snapshot_gigabytes=-2)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_update_share_networks_quota_with_wrong_data(self):
        # -1 is acceptable value as unlimited
        client = self.get_client_with_isolated_creds()
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          share_networks=-2)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_create_share_with_size_bigger_than_quota(self):
        quotas = self.shares_client.show_quotas(
            self.shares_client.tenant_id)
        overquota = int(quotas['gigabytes']) + 2

        # try schedule share with size, bigger than gigabytes quota
        self.assertRaises(lib_exc.OverLimit,
                          self.create_share,
                          size=overquota)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_set_user_quota_shares_bigger_than_tenant_quota(self):
        client = self.get_client_with_isolated_creds()

        # get current quotas for tenant
        tenant_quotas = client.show_quotas(client.tenant_id)

        # try set user quota for shares bigger than tenant quota
        bigger_value = int(tenant_quotas["shares"]) + 2
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          client.user_id,
                          shares=bigger_value)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_set_user_quota_snaps_bigger_than_tenant_quota(self):
        client = self.get_client_with_isolated_creds()

        # get current quotas for tenant
        tenant_quotas = client.show_quotas(client.tenant_id)

        # try set user quota for snapshots bigger than tenant quota
        bigger_value = int(tenant_quotas["snapshots"]) + 2
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          client.user_id,
                          snapshots=bigger_value)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_set_user_quota_gigabytes_bigger_than_tenant_quota(self):
        client = self.get_client_with_isolated_creds()

        # get current quotas for tenant
        tenant_quotas = client.show_quotas(client.tenant_id)

        # try set user quota for gigabytes bigger than tenant quota
        bigger_value = int(tenant_quotas["gigabytes"]) + 2
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          client.user_id,
                          gigabytes=bigger_value)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_set_user_quota_snap_gigabytes_bigger_than_tenant_quota(self):
        client = self.get_client_with_isolated_creds()

        # get current quotas for tenant
        tenant_quotas = client.show_quotas(client.tenant_id)

        # try set user quota for snapshot gigabytes bigger than tenant quota
        bigger_value = int(tenant_quotas["snapshot_gigabytes"]) + 2
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          client.user_id,
                          snapshot_gigabytes=bigger_value)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_set_user_quota_share_networks_bigger_than_tenant_quota(self):
        client = self.get_client_with_isolated_creds()

        # get current quotas for tenant
        tenant_quotas = client.show_quotas(client.tenant_id)

        # try set user quota for share_networks bigger than tenant quota
        bigger_value = int(tenant_quotas["share_networks"]) + 2
        self.assertRaises(lib_exc.BadRequest,
                          client.update_quotas,
                          client.tenant_id,
                          client.user_id,
                          share_networks=bigger_value)

    @ddt.data(
        ('quota-sets', '2.0', 'show_quotas'),
        ('quota-sets', '2.0', 'default_quotas'),
        ('quota-sets', '2.0', 'reset_quotas'),
        ('quota-sets', '2.0', 'update_quotas'),
        ('quota-sets', '2.6', 'show_quotas'),
        ('quota-sets', '2.6', 'default_quotas'),
        ('quota-sets', '2.6', 'reset_quotas'),
        ('quota-sets', '2.6', 'update_quotas'),
        ('os-quota-sets', '2.7', 'show_quotas'),
        ('os-quota-sets', '2.7', 'default_quotas'),
        ('os-quota-sets', '2.7', 'reset_quotas'),
        ('os-quota-sets', '2.7', 'update_quotas'),
    )
    @ddt.unpack
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @base.skip_if_microversion_not_supported("2.7")
    def test_show_quotas_with_wrong_versions(self, url, version, method_name):
        self.assertRaises(
            lib_exc.NotFound,
            getattr(self.shares_v2_client, method_name),
            self.shares_v2_client.tenant_id,
            version=version, url=url,
        )

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_show_quota_detail_with_wrong_versions(self):
        version = '2.24'
        url = 'quota-sets'

        self.assertRaises(
            lib_exc.NotFound,
            self.shares_v2_client.detail_quotas,
            self.shares_v2_client.tenant_id,
            version=version, url=url,
        )
