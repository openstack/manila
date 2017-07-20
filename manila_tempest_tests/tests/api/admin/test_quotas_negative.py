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
from tempest.lib.common.utils import data_utils
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
                          force=False,
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
                          force=False,
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
                          force=False,
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
                          force=False,
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
                          force=False,
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

    @ddt.data('show', 'reset', 'update')
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.39")
    def test_share_type_quotas_using_nonexistent_share_type(self, op):
        client = self.get_client_with_isolated_creds(client_version='2')

        kwargs = {"share_type": "fake_nonexistent_share_type"}
        if op == 'update':
            tenant_quotas = client.show_quotas(client.tenant_id)
            kwargs['shares'] = tenant_quotas['shares']

        self.assertRaises(
            lib_exc.NotFound,
            getattr(client, op + '_quotas'),
            client.tenant_id,
            **kwargs)

    def _create_share_type(self):
        share_type = self.create_share_type(
            data_utils.rand_name("tempest-manila"),
            cleanup_in_class=False,
            client=self.shares_v2_client,
            extra_specs=self.add_extra_specs_to_dict(),
        )
        if 'share_type' in share_type:
            share_type = share_type['share_type']
        return share_type

    @ddt.data('id', 'name')
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.39")
    def test_try_update_share_type_quota_for_share_networks(self, key):
        client = self.get_client_with_isolated_creds(client_version='2')
        share_type = self._create_share_type()
        tenant_quotas = client.show_quotas(client.tenant_id)

        # Try to set 'share_networks' quota for share type
        self.assertRaises(
            lib_exc.BadRequest,
            client.update_quotas,
            client.tenant_id,
            share_type=share_type[key],
            share_networks=int(tenant_quotas["share_networks"]),
        )

    @ddt.data('show', 'reset', 'update')
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.38")
    def test_share_type_quotas_using_too_old_microversion(self, op):
        client = self.get_client_with_isolated_creds(client_version='2')
        share_type = self._create_share_type()
        kwargs = {"version": "2.38", "share_type": share_type["name"]}
        if op == 'update':
            tenant_quotas = client.show_quotas(client.tenant_id)
            kwargs['shares'] = tenant_quotas['shares']

        self.assertRaises(
            lib_exc.BadRequest,
            getattr(client, op + '_quotas'),
            client.tenant_id,
            **kwargs)

    @ddt.data('show', 'reset', 'update')
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.39")
    def test_quotas_providing_share_type_and_user_id(self, op):
        client = self.get_client_with_isolated_creds(client_version='2')
        share_type = self._create_share_type()
        kwargs = {"share_type": share_type["name"], "user_id": client.user_id}
        if op == 'update':
            tenant_quotas = client.show_quotas(client.tenant_id)
            kwargs['shares'] = tenant_quotas['shares']

        self.assertRaises(
            lib_exc.BadRequest,
            getattr(client, op + '_quotas'),
            client.tenant_id,
            **kwargs)

    @ddt.data(11, -1)
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.39")
    def test_update_share_type_quotas_bigger_than_project_quota(self, st_q):
        client = self.get_client_with_isolated_creds(client_version='2')
        share_type = self._create_share_type()
        client.update_quotas(client.tenant_id, shares=10)

        self.assertRaises(
            lib_exc.BadRequest,
            client.update_quotas,
            client.tenant_id,
            share_type=share_type['name'],
            force=False,
            shares=st_q)
