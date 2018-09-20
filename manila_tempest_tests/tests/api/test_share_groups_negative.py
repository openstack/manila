# Copyright 2016 Andrew Kerr
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
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
import testtools
from testtools import testcase as tc

from manila_tempest_tests.common import constants
from manila_tempest_tests.tests.api import base

CONF = config.CONF


@testtools.skipUnless(
    CONF.share.run_share_group_tests, 'Share Group tests disabled.')
@base.skip_if_microversion_lt(constants.MIN_SHARE_GROUP_MICROVERSION)
class ShareGroupsNegativeTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(ShareGroupsNegativeTest, cls).resource_setup()
        # Create a share type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']

        # Create a share group type
        cls.share_group_type = cls._create_share_group_type()
        cls.share_group_type_id = cls.share_group_type['id']

        # Create a share group
        cls.share_group_name = data_utils.rand_name("tempest-sg-name")
        cls.share_group_desc = data_utils.rand_name("tempest-sg-description")
        cls.share_group = cls.create_share_group(
            name=cls.share_group_name,
            description=cls.share_group_desc,
            share_group_type_id=cls.share_group_type_id,
            share_type_ids=[cls.share_type_id],
        )
        # Create a share in the share group
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        cls.share_size = 1
        cls.share = cls.create_share(
            name=cls.share_name,
            description=cls.share_desc,
            size=cls.share_size,
            share_type_id=cls.share_type_id,
            share_group_id=cls.share_group['id'],
            experimental=True,
        )
        # Create a share group snapshot of the share group
        cls.sg_snap_name = data_utils.rand_name("tempest-sg-snap-name")
        cls.sg_snap_desc = data_utils.rand_name(
            "tempest-group-snap-description")
        cls.sg_snapshot = cls.create_share_group_snapshot_wait_for_active(
            cls.share_group['id'],
            name=cls.sg_snap_name,
            description=cls.sg_snap_desc
        )

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_sg_with_invalid_source_sg_snapshot_id_value_min(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share_group,
            source_share_group_snapshot_id='foobar',
            cleanup_in_class=False,
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_sg_with_nonexistent_source_sg_snapshot_id_value_min(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share_group,
            source_share_group_snapshot_id=self.share['id'],
            cleanup_in_class=False,
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_sg_with_invalid_share_network_id_value_min(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share_group,
            share_network_id='foobar',
            cleanup_in_class=False,
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_group_with_nonexistent_share_network_id_value_min(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share_group,
            share_network_id=self.share['id'],
            cleanup_in_class=False,
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_sg_with_invalid_share_type_id_value_min(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share_group,
            share_type_ids=['foobar'],
            cleanup_in_class=False,
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_sg_with_nonexistent_share_type_id_value_min(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share_group,
            share_type_ids=[self.share['id']],
            cleanup_in_class=False,
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_sg_snapshot_with_invalid_sg_id_value_min(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share_group_snapshot_wait_for_active,
            'foobar',
            cleanup_in_class=False,
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_sg_snapshot_with_nonexistent_sg_id_value_min(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share_group_snapshot_wait_for_active,
            self.share['id'],
            cleanup_in_class=False,
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_get_sg_with_invalid_id_min(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.shares_v2_client.get_share_group,
            "invalid_share_group_id",
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_get_sg_without_passing_group_id_min(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.shares_v2_client.get_share_group,
            '', version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_update_sg_with_invalid_id_min(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.shares_v2_client.update_share_group,
            'invalid_share_group_id',
            name='new_name',
            description='new_description',
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_delete_sg_with_invalid_id_min(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.shares_v2_client.delete_share_group,
            "invalid_share_group_id",
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_delete_sg_without_passing_sg_id_min(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.shares_v2_client.delete_share_group,
            '', version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_delete_sg_in_use_by_sg_snapshot_min(self):
        self.assertRaises(
            lib_exc.Conflict,
            self.shares_v2_client.delete_share_group,
            self.share_group['id'],
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_delete_share_in_use_by_sg_snapshot_min(self):
        params = {'share_group_id': self.share['share_group_id']}
        self.assertRaises(
            lib_exc.Forbidden,
            self.shares_v2_client.delete_share,
            self.share['id'],
            params=params,
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_delete_sg_containing_a_share_min(self):
        self.assertRaises(
            lib_exc.Conflict,
            self.shares_v2_client.delete_share_group,
            self.share_group['id'],
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

        # Verify share group is not put into error state from conflict
        sg = self.shares_v2_client.get_share_group(
            self.share_group['id'],
            version=constants.MIN_SHARE_GROUP_MICROVERSION)
        self.assertEqual('available', sg['status'])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_filter_shares_on_invalid_group_id_min(self):
        shares = self.shares_v2_client.list_shares(
            detailed=True,
            params={'share_group_id': 'foobar'},
            version=constants.MIN_SHARE_GROUP_MICROVERSION,
        )
        self.assertEqual(0, len(shares), 'Incorrect number of shares returned')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_filter_shares_on_nonexistent_group_id_min(self):
        shares = self.shares_v2_client.list_shares(
            detailed=True,
            params={'share_group_id': self.share['id']},
            version=constants.MIN_SHARE_GROUP_MICROVERSION,
        )
        self.assertEqual(0, len(shares), 'Incorrect number of shares returned')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_filter_shares_on_empty_share_group_id_min(self):
        share_group = self.create_share_group(
            name='tempest_sg',
            description='tempest_sg_desc',
            share_group_type_id=self.share_group_type_id,
            share_type_ids=[self.share_type_id],
            cleanup_in_class=False,
            version=constants.MIN_SHARE_GROUP_MICROVERSION,
        )
        shares = self.shares_v2_client.list_shares(
            detailed=True,
            params={'share_group_id': share_group['id']},
            version=constants.MIN_SHARE_GROUP_MICROVERSION,
        )
        self.assertEqual(0, len(shares), 'Incorrect number of shares returned')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_sg_with_nonexistent_az_min(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.shares_v2_client.create_share_group,
            name='tempest_sg',
            description='tempest_sg_desc',
            availability_zone='fake_nonexistent_az',
            share_group_type_id=self.share_group_type_id,
            share_type_ids=[self.share_type_id],
            version=constants.MIN_SHARE_GROUP_MICROVERSION)

    @base.skip_if_microversion_lt("2.34")
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_sg_and_share_with_different_azs(self):
        azs = self.shares_v2_client.list_availability_zones()

        if len(azs) < 2:
            raise self.skipException(
                'Test requires presence of at least 2 availability zones.')
        else:
            share_group = self.shares_v2_client.get_share_group(
                self.share_group['id'], '2.34')
            different_az = [
                az['name']
                for az in azs
                if az['name'] != share_group['availability_zone']
            ][0]

        self.assertRaises(
            lib_exc.BadRequest,
            self.create_share,
            share_type_id=self.share_type_id,
            share_group_id=self.share_group['id'],
            availability_zone=different_az,
            version='2.34')
