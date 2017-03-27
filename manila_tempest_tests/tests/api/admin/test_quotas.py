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
class SharesAdminQuotasTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        if not CONF.share.run_quota_tests:
            msg = "Quota tests are disabled."
            raise cls.skipException(msg)
        super(SharesAdminQuotasTest, cls).resource_setup()
        cls.user_id = cls.shares_v2_client.user_id
        cls.tenant_id = cls.shares_v2_client.tenant_id

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_default_quotas(self):
        quotas = self.shares_v2_client.default_quotas(self.tenant_id)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["snapshot_gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)
        self.assertGreater(int(quotas["share_networks"]), -2)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_show_quotas(self):
        quotas = self.shares_v2_client.show_quotas(self.tenant_id)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["snapshot_gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)
        self.assertGreater(int(quotas["share_networks"]), -2)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_show_quotas_for_user(self):
        quotas = self.shares_v2_client.show_quotas(
            self.tenant_id, self.user_id)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["snapshot_gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)
        self.assertGreater(int(quotas["share_networks"]), -2)

    @ddt.data(
        ('id', True),
        ('name', False),
    )
    @ddt.unpack
    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.39")
    def test_show_share_type_quotas(self, share_type_key, is_st_public):
        # Create share type
        share_type = self.create_share_type(
            data_utils.rand_name("tempest-manila"),
            is_public=is_st_public,
            cleanup_in_class=False,
            extra_specs=self.add_extra_specs_to_dict(),
        )
        if 'share_type' in share_type:
            share_type = share_type['share_type']

        # Get current project quotas
        p_quotas = self.shares_v2_client.show_quotas(self.tenant_id)

        # Get current quotas
        st_quotas = self.shares_v2_client.show_quotas(
            self.tenant_id, share_type=share_type[share_type_key])

        # Share type quotas have values equal to project's
        for key in ('shares', 'gigabytes', 'snapshots', 'snapshot_gigabytes'):
            self.assertEqual(st_quotas[key], p_quotas[key])


@ddt.ddt
class SharesAdminQuotasUpdateTest(base.BaseSharesAdminTest):

    force_tenant_isolation = True
    client_version = '2'

    @classmethod
    def resource_setup(cls):
        if not CONF.share.run_quota_tests:
            msg = "Quota tests are disabled."
            raise cls.skipException(msg)
        super(SharesAdminQuotasUpdateTest, cls).resource_setup()

    def setUp(self):
        super(self.__class__, self).setUp()
        self.client = self.get_client_with_isolated_creds(
            client_version=self.client_version)
        self.tenant_id = self.client.tenant_id
        self.user_id = self.client.user_id

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_tenant_quota_shares(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id)
        new_quota = int(quotas["shares"]) + 2

        # set new quota for shares
        updated = self.client.update_quotas(self.tenant_id, shares=new_quota)
        self.assertEqual(new_quota, int(updated["shares"]))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_user_quota_shares(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id, self.user_id)
        new_quota = int(quotas["shares"]) - 1

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id, shares=new_quota)
        self.assertEqual(new_quota, int(updated["shares"]))

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

    @ddt.data(
        ('id', True),
        ('name', False),
    )
    @ddt.unpack
    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.39")
    def test_update_share_type_quota(self, share_type_key, is_st_public):
        share_type = self._create_share_type()

        # Get current quotas
        quotas = self.client.show_quotas(
            self.tenant_id, share_type=share_type[share_type_key])

        # Update quotas
        for q in ('shares', 'gigabytes', 'snapshots', 'snapshot_gigabytes'):
            new_quota = int(quotas[q]) - 1

            # Set new quota
            updated = self.client.update_quotas(
                self.tenant_id, share_type=share_type[share_type_key],
                **{q: new_quota})
            self.assertEqual(new_quota, int(updated[q]))

        current_quotas = self.client.show_quotas(
            self.tenant_id, share_type=share_type[share_type_key])

        for q in ('shares', 'gigabytes', 'snapshots', 'snapshot_gigabytes'):
            self.assertEqual(int(quotas[q]) - 1, current_quotas[q])

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_tenant_quota_snapshots(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id)
        new_quota = int(quotas["snapshots"]) + 2

        # set new quota for snapshots
        updated = self.client.update_quotas(
            self.tenant_id, snapshots=new_quota)
        self.assertEqual(new_quota, int(updated["snapshots"]))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_user_quota_snapshots(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id, self.user_id)
        new_quota = int(quotas["snapshots"]) - 1

        # set new quota for snapshots
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id, snapshots=new_quota)
        self.assertEqual(new_quota, int(updated["snapshots"]))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_tenant_quota_gigabytes(self):
        # get current quotas
        custom = self.client.show_quotas(self.tenant_id)

        # make quotas for update
        gigabytes = int(custom["gigabytes"]) + 2

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id, gigabytes=gigabytes)
        self.assertEqual(gigabytes, int(updated["gigabytes"]))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_tenant_quota_snapshot_gigabytes(self):
        # get current quotas
        custom = self.client.show_quotas(self.tenant_id)

        # make quotas for update
        snapshot_gigabytes = int(custom["snapshot_gigabytes"]) + 2

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id,
            snapshot_gigabytes=snapshot_gigabytes)
        self.assertEqual(snapshot_gigabytes,
                         int(updated["snapshot_gigabytes"]))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_user_quota_gigabytes(self):
        # get current quotas
        custom = self.client.show_quotas(self.tenant_id, self.user_id)

        # make quotas for update
        gigabytes = int(custom["gigabytes"]) - 1

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id, gigabytes=gigabytes)
        self.assertEqual(gigabytes, int(updated["gigabytes"]))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_user_quota_snapshot_gigabytes(self):
        # get current quotas
        custom = self.client.show_quotas(self.tenant_id, self.user_id)

        # make quotas for update
        snapshot_gigabytes = int(custom["snapshot_gigabytes"]) - 1

        # set new quota for shares
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id,
            snapshot_gigabytes=snapshot_gigabytes)
        self.assertEqual(snapshot_gigabytes,
                         int(updated["snapshot_gigabytes"]))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_tenant_quota_share_networks(self):
        # get current quotas
        quotas = self.client.show_quotas(self.tenant_id)
        new_quota = int(quotas["share_networks"]) + 2

        # set new quota for share-networks
        updated = self.client.update_quotas(
            self.tenant_id, share_networks=new_quota)
        self.assertEqual(new_quota, int(updated["share_networks"]))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_update_user_quota_share_networks(self):
        # get current quotas
        quotas = self.client.show_quotas(
            self.tenant_id, self.user_id)
        new_quota = int(quotas["share_networks"]) - 1

        # set new quota for share-networks
        updated = self.client.update_quotas(
            self.tenant_id, self.user_id,
            share_networks=new_quota)
        self.assertEqual(new_quota, int(updated["share_networks"]))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
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
        self.assertEqual(shares, int(updated["shares"]))
        self.assertEqual(snapshots, int(updated["snapshots"]))
        self.assertEqual(gigabytes, int(updated["gigabytes"]))
        self.assertEqual(snapshot_gigabytes,
                         int(updated["snapshot_gigabytes"]))
        self.assertEqual(share_networks, int(updated["share_networks"]))

        # reset customized quotas
        self.client.reset_quotas(self.tenant_id)

        # verify quotas
        reseted = self.client.show_quotas(self.tenant_id)
        self.assertEqual(int(default["shares"]), int(reseted["shares"]))
        self.assertEqual(int(default["snapshots"]), int(reseted["snapshots"]))
        self.assertEqual(int(default["gigabytes"]), int(reseted["gigabytes"]))
        self.assertEqual(int(default["share_networks"]),
                         int(reseted["share_networks"]))

    @ddt.data(
        ('id', True),
        ('name', False),
    )
    @ddt.unpack
    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.39")
    def test_reset_share_type_quotas(self, share_type_key, is_st_public):
        share_type = self._create_share_type()

        # get default_quotas
        default_quotas = self.client.default_quotas(self.tenant_id)

        # set new quota for project
        updated_p_quota = self.client.update_quotas(
            self.tenant_id,
            shares=int(default_quotas['shares']) + 5,
            snapshots=int(default_quotas['snapshots']) + 5,
            gigabytes=int(default_quotas['gigabytes']) + 5,
            snapshot_gigabytes=int(default_quotas['snapshot_gigabytes']) + 5)

        # set new quota for project
        self.client.update_quotas(
            self.tenant_id,
            share_type=share_type[share_type_key],
            shares=int(default_quotas['shares']) + 3,
            snapshots=int(default_quotas['snapshots']) + 3,
            gigabytes=int(default_quotas['gigabytes']) + 3,
            snapshot_gigabytes=int(default_quotas['snapshot_gigabytes']) + 3)

        # reset share type quotas
        self.client.reset_quotas(
            self.tenant_id, share_type=share_type[share_type_key])

        # verify quotas
        current_p_quota = self.client.show_quotas(self.tenant_id)
        current_st_quota = self.client.show_quotas(
            self.tenant_id, share_type=share_type[share_type_key])
        for key in ('shares', 'snapshots', 'gigabytes', 'snapshot_gigabytes'):
            self.assertEqual(updated_p_quota[key], current_p_quota[key])

            # Default share type quotas are current project quotas
            self.assertNotEqual(default_quotas[key], current_st_quota[key])
            self.assertEqual(current_p_quota[key], current_st_quota[key])

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_quota_for_shares(self):
        self.client.update_quotas(self.tenant_id, shares=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('shares'))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_user_quota_for_shares(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, shares=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('shares'))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_quota_for_snapshots(self):
        self.client.update_quotas(self.tenant_id, snapshots=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('snapshots'))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_user_quota_for_snapshots(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, snapshots=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('snapshots'))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_quota_for_gigabytes(self):
        self.client.update_quotas(self.tenant_id, gigabytes=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('gigabytes'))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_quota_for_snapshot_gigabytes(self):
        self.client.update_quotas(
            self.tenant_id, snapshot_gigabytes=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('snapshot_gigabytes'))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_user_quota_for_gigabytes(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, gigabytes=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('gigabytes'))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_user_quota_for_snapshot_gigabytes(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, snapshot_gigabytes=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('snapshot_gigabytes'))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_quota_for_share_networks(self):
        self.client.update_quotas(self.tenant_id, share_networks=-1)

        quotas = self.client.show_quotas(self.tenant_id)

        self.assertEqual(-1, quotas.get('share_networks'))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_unlimited_user_quota_for_share_networks(self):
        self.client.update_quotas(
            self.tenant_id, self.user_id, share_networks=-1)

        quotas = self.client.show_quotas(self.tenant_id, self.user_id)

        self.assertEqual(-1, quotas.get('share_networks'))

    @ddt.data(11, -1)
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_update_user_quotas_bigger_than_project_quota(self, user_quota):
        self.client.update_quotas(self.tenant_id, shares=10)
        self.client.update_quotas(
            self.tenant_id, user_id=self.user_id, force=True,
            shares=user_quota)

    @ddt.data(11, -1)
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.39")
    def test_update_share_type_quotas_bigger_than_project_quota(self, st_q):
        share_type = self._create_share_type()
        self.client.update_quotas(self.tenant_id, shares=10)

        self.client.update_quotas(
            self.tenant_id, share_type=share_type['name'], force=True,
            shares=st_q)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @base.skip_if_microversion_lt("2.39")
    def test_set_share_type_quota_bigger_than_users_quota(self):
        share_type = self._create_share_type()
        self.client.update_quotas(self.tenant_id, force=False, shares=13)
        self.client.update_quotas(
            self.tenant_id, user_id=self.user_id, force=False, shares=11)

        # Share type quota does not depend on user's quota, so we should be
        # able to update it.
        self.client.update_quotas(
            self.tenant_id, share_type=share_type['name'], force=False,
            shares=12)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.39")
    def test_quotas_usages(self):
        # Create share types
        st_1, st_2 = (self._create_share_type() for i in (1, 2))

        # Set quotas for project, user and both share types
        self.client.update_quotas(self.tenant_id, shares=3, gigabytes=10)
        self.client.update_quotas(
            self.tenant_id, user_id=self.user_id, shares=2, gigabytes=7)
        for st in (st_1['id'], st_2['name']):
            self.client.update_quotas(
                self.tenant_id, share_type=st, shares=2, gigabytes=4)

        # Create share, 4Gb, st1 - ok
        share_1 = self.create_share(
            size=4, share_type_id=st_1['id'], client=self.client,
            cleanup_in_class=False)

        # Try create shares twice, failing on user and share type quotas
        for size, st_id in ((3, st_1['id']), (4, st_2['id'])):
            self.assertRaises(
                lib_exc.OverLimit,
                self.create_share,
                size=size, share_type_id=st_id, client=self.client,
                cleanup_in_class=False)

        # Create share, 3Gb, st2 - ok
        share_2 = self.create_share(
            size=3, share_type_id=st_2['id'], client=self.client,
            cleanup_in_class=False)

        # Check quota usages
        for g_l, g_use, s_l, s_use, kwargs in (
                (10, 7, 3, 2, {}),
                (7, 7, 2, 2, {'user_id': self.user_id}),
                (4, 4, 2, 1, {'share_type': st_1['id']}),
                (4, 3, 2, 1, {'share_type': st_2['name']})):
            quotas = self.client.detail_quotas(
                tenant_id=self.tenant_id, **kwargs)
            self.assertEqual(0, quotas['gigabytes']['reserved'])
            self.assertEqual(g_l, quotas['gigabytes']['limit'])
            self.assertEqual(g_use, quotas['gigabytes']['in_use'])
            self.assertEqual(0, quotas['shares']['reserved'])
            self.assertEqual(s_l, quotas['shares']['limit'])
            self.assertEqual(s_use, quotas['shares']['in_use'])

        # Delete shares and then check usages
        for share_id in (share_1['id'], share_2['id']):
            self.client.delete_share(share_id)
            self.client.wait_for_resource_deletion(share_id=share_id)
        for kwargs in ({}, {'share_type': st_1['name']},
                       {'user_id': self.user_id}, {'share_type': st_2['id']}):
            quotas = self.client.detail_quotas(
                tenant_id=self.tenant_id, **kwargs)
            for key in ('shares', 'gigabytes'):
                self.assertEqual(0, quotas[key]['reserved'])
                self.assertEqual(0, quotas[key]['in_use'])
