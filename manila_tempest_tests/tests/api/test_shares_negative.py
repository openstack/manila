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

from tempest import config
from tempest.lib import exceptions as lib_exc
import testtools
from testtools import testcase as tc

from manila_tempest_tests import share_exceptions
from manila_tempest_tests.tests.api import base

CONF = config.CONF


class SharesNegativeTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(SharesNegativeTest, cls).resource_setup()
        # create share_type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']

        # create share
        cls.share = cls.create_share(
            name='public_share',
            description='public_share_desc',
            share_type_id=cls.share_type_id,
            is_public=True,
            metadata={'key': 'value'}
        )

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_update_share_with_wrong_public_value(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.update_share, self.share["id"],
                          is_public="truebar")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_try_delete_share_with_existing_snapshot(self):
        # share can not be deleted while snapshot exists

        # create share
        share = self.create_share(share_type_id=self.share_type_id)

        # create snapshot
        self.create_snapshot_wait_for_active(share["id"])

        # try delete share
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.delete_share, share["id"])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    @testtools.skipUnless(
        CONF.share.capability_create_share_from_snapshot_support,
        "Create share from snapshot tests are disabled.")
    def test_create_share_from_snap_with_less_size(self):
        # requires minimum 5Gb available space

        skip_msg = "Check disc space for this test"

        try:  # create share
            size = CONF.share.share_size + 1
            share = self.create_share(size=size,
                                      share_type_id=self.share_type_id,
                                      cleanup_in_class=False)
        except share_exceptions.ShareBuildErrorException:
            self.skip(skip_msg)

        try:  # create snapshot
            snap = self.create_snapshot_wait_for_active(
                share["id"], cleanup_in_class=False)
        except share_exceptions.SnapshotBuildErrorException:
            self.skip(skip_msg)

        # try create share from snapshot with less size
        self.assertRaises(lib_exc.BadRequest,
                          self.create_share,
                          share_type_id=self.share_type_id,
                          snapshot_id=snap["id"],
                          cleanup_in_class=False)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipIf(not CONF.share.multitenancy_enabled,
                      "Only for multitenancy.")
    def test_create_share_with_nonexistant_share_network(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.create_share,
                          share_type_id=self.share_type_id,
                          share_network_id="wrong_sn_id")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipIf(not CONF.share.multitenancy_enabled,
                      "Only for multitenancy.")
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    @testtools.skipUnless(
        CONF.share.capability_create_share_from_snapshot_support,
        "Create share from snapshot tests are disabled.")
    def test_create_share_from_snap_with_different_share_network(self):
        # We can't create a share from a snapshot whose base share does not
        # have 'create_share_from_snapshot_support'.

        # create share
        share = self.create_share(share_type_id=self.share_type_id,
                                  cleanup_in_class=False)

        # get parent's share network
        parent_share = self.shares_client.get_share(share["id"])
        parent_sn = self.shares_client.get_share_network(
            parent_share["share_network_id"])

        # create new share-network - net duplicate of parent's share
        new_duplicated_sn = self.create_share_network(
            cleanup_in_class=False,
            neutron_net_id=parent_sn["neutron_net_id"],
            neutron_subnet_id=parent_sn["neutron_subnet_id"],
        )

        # create snapshot of parent share
        snap = self.create_snapshot_wait_for_active(
            share["id"], cleanup_in_class=False)

        # try create share with snapshot using another share-network
        # 400 bad request is expected
        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share,
            share_type_id=self.share_type_id,
            cleanup_in_class=False,
            share_network_id=new_duplicated_sn["id"],
            snapshot_id=snap["id"],
        )

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_update_other_tenants_public_share(self):
        isolated_client = self.get_client_with_isolated_creds(
            type_of_creds='alt')
        self.assertRaises(lib_exc.Forbidden, isolated_client.update_share,
                          self.share["id"], name="new_name")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_delete_other_tenants_public_share(self):
        isolated_client = self.get_client_with_isolated_creds(
            type_of_creds='alt')
        self.assertRaises(lib_exc.Forbidden,
                          isolated_client.delete_share,
                          self.share['id'])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_set_metadata_of_other_tenants_public_share(self):
        isolated_client = self.get_client_with_isolated_creds(
            type_of_creds='alt')
        self.assertRaises(lib_exc.Forbidden,
                          isolated_client.set_metadata,
                          self.share['id'],
                          {'key': 'value'})

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_update_metadata_of_other_tenants_public_share(self):
        isolated_client = self.get_client_with_isolated_creds(
            type_of_creds='alt')
        self.assertRaises(lib_exc.Forbidden,
                          isolated_client.update_all_metadata,
                          self.share['id'],
                          {'key': 'value'})

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_delete_metadata_of_other_tenants_public_share(self):
        isolated_client = self.get_client_with_isolated_creds(
            type_of_creds='alt')
        self.assertRaises(lib_exc.Forbidden,
                          isolated_client.delete_metadata,
                          self.share['id'],
                          'key')


class SharesAPIOnlyNegativeTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(SharesAPIOnlyNegativeTest, cls).resource_setup()
        # create share_type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_unmanage_share_by_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.unmanage_share,
                          'fake-id')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_manage_share_by_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.manage_share,
                          'fake-host', 'nfs', '/export/path',
                          'fake-type')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_list_by_user_with_host_filter(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_v2_client.list_shares,
                          params={'host': 'fake_host'})

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_list_by_share_server_by_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.list_shares,
                          params={'share_server_id': 12345})

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_create_share_non_existent_az(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.create_share,
                          share_type_id=self.share_type_id,
                          availability_zone='fake_az')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_create_share_with_zero_size(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_share,
                          share_type_id=self.share_type_id,
                          size=0)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_create_share_with_invalid_size(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_share,
                          share_type_id=self.share_type_id,
                          size="#$%")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_create_share_with_out_passing_size(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_share,
                          share_type_id=self.share_type_id,
                          size="")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_delete_snapshot_with_wrong_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_snapshot,
                          "wrong_share_id")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_create_snapshot_with_wrong_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.create_snapshot,
                          "wrong_share_id")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_create_share_with_invalid_protocol(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_share,
                          share_type_id=self.share_type_id,
                          share_protocol="nonexistent_protocol")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_create_share_with_wrong_public_value(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_share,
                          share_type_id=self.share_type_id,
                          is_public='truebar')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_get_share_with_wrong_id(self):
        self.assertRaises(lib_exc.NotFound, self.shares_client.get_share,
                          "wrong_share_id")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_get_share_without_passing_share_id(self):
        # Should not be able to get share when empty ID is passed
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share, '')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_list_shares_nonadmin_with_nonexistent_share_server_filter(self):
        # filtering by share server allowed only for admins by default
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.list_shares_with_detail,
                          {'share_server_id': 'fake_share_server_id'})

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_delete_share_with_wrong_id(self):
        self.assertRaises(lib_exc.NotFound, self.shares_client.delete_share,
                          "wrong_share_id")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_delete_share_without_passing_share_id(self):
        # Should not be able to delete share when empty ID is passed
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_share, '')
