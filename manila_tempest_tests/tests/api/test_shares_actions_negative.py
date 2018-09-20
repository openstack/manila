# Copyright 2015 Mirantis Inc.
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
import testtools
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@ddt.ddt
class SharesActionsNegativeTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(SharesActionsNegativeTest, cls).resource_setup()
        cls.admin_client = cls.admin_shares_v2_client
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        # create share_type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']
        # create share
        cls.share = cls.create_share(
            name=cls.share_name,
            description=cls.share_desc,
            share_type_id=cls.share_type_id)
        if CONF.share.run_snapshot_tests:
            # create snapshot
            cls.snap_name = data_utils.rand_name("tempest-snapshot-name")
            cls.snap_desc = data_utils.rand_name(
                "tempest-snapshot-description")
            cls.snap = cls.create_snapshot_wait_for_active(
                cls.share["id"], cls.snap_name, cls.snap_desc)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    @testtools.skipUnless(
        CONF.share.run_quota_tests,
        "Quota tests are disabled.")
    def test_share_extend_over_quota(self):
        tenant_quotas = self.shares_client.show_quotas(
            self.shares_client.tenant_id)
        new_size = int(tenant_quotas["gigabytes"]) + 1

        # extend share with over quota and check result
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.extend_share,
                          self.share['id'],
                          new_size)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    def test_share_extend_with_less_size(self):
        new_size = int(self.share['size']) - 1

        # extend share with invalid size and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.extend_share,
                          self.share['id'],
                          new_size)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    def test_share_extend_with_same_size(self):
        new_size = int(self.share['size'])

        # extend share with invalid size and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.extend_share,
                          self.share['id'],
                          new_size)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipUnless(
        CONF.share.run_extend_tests,
        "Share extend tests are disabled.")
    def test_share_extend_with_invalid_share_state(self):
        share = self.create_share(share_type_id=self.share_type_id,
                                  cleanup_in_class=False)
        new_size = int(share['size']) + 1

        # set "error" state
        self.admin_client.reset_state(share['id'])

        # run extend operation on same share and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.extend_share,
                          share['id'],
                          new_size)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipUnless(
        CONF.share.run_shrink_tests,
        "Share shrink tests are disabled.")
    def test_share_shrink_with_greater_size(self):
        new_size = int(self.share['size']) + 1

        # shrink share with invalid size and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.shrink_share,
                          self.share['id'],
                          new_size)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipUnless(
        CONF.share.run_shrink_tests,
        "Share shrink tests are disabled.")
    def test_share_shrink_with_same_size(self):
        new_size = int(self.share['size'])

        # shrink share with invalid size and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.shrink_share,
                          self.share['id'],
                          new_size)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @testtools.skipUnless(
        CONF.share.run_shrink_tests,
        "Share shrink tests are disabled.")
    def test_share_shrink_with_invalid_share_state(self):
        size = CONF.share.share_size + 1
        share = self.create_share(share_type_id=self.share_type_id,
                                  size=size,
                                  cleanup_in_class=False)
        new_size = int(share['size']) - 1

        # set "error" state
        self.admin_client.reset_state(share['id'])

        # run shrink operation on same share and check result
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.shrink_share,
                          share['id'],
                          new_size)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.34")
    @ddt.data('path', 'id')
    def test_list_shares_with_export_location_and_invalid_version(
            self, export_location_type):
        # In API versions <v2.35, querying the share API by export
        # location path or ID should have no effect. Those filters were
        # supported from v2.35
        filters = {
            'export_location_' + export_location_type: 'fake',
        }
        shares = self.shares_v2_client.list_shares(
            params=filters, version="2.34")

        self.assertGreater(len(shares), 0)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.35")
    @ddt.data('path', 'id')
    def test_list_shares_with_export_location_not_exist(
            self, export_location_type):
        filters = {
            'export_location_' + export_location_type: 'fake_not_exist',
        }
        shares = self.shares_v2_client.list_shares(
            params=filters)

        self.assertEqual(0, len(shares))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.36")
    def test_list_shares_with_like_filter_and_invalid_version(self):
        # In API versions < v2.36, querying the share API by inexact
        # filter (name or description) should have no effect. Those
        # filters were supported from v2.36
        filters = {
            'name~': 'fake',
            'description~': 'fake',
        }
        shares = self.shares_v2_client.list_shares(
            params=filters, version="2.35")

        self.assertGreater(len(shares), 0)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.36")
    def test_list_shares_with_like_filter_not_exist(self):
        filters = {
            'name~': 'fake_not_exist',
            'description~': 'fake_not_exist',
        }
        shares = self.shares_v2_client.list_shares(params=filters)

        self.assertEqual(0, len(shares))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_list_shares_with_name_not_exist(self):
        filters = {
            'name': "tempest-share",
        }
        shares = self.shares_v2_client.list_shares(params=filters)

        self.assertEqual(0, len(shares))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.36")
    def test_list_shares_with_description_not_exist(self):
        filters = {
            'description': "tempest-share",
        }
        shares = self.shares_v2_client.list_shares(params=filters)

        self.assertEqual(0, len(shares))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.36")
    def test_list_snapshots_with_description_not_exist(self):
        filters = {
            'description': "tempest-snapshot",
        }
        shares = self.shares_v2_client.list_snapshots_with_detail(
            params=filters)

        self.assertEqual(0, len(shares))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_list_snapshots_with_name_not_exist(self):
        filters = {
            'name': "tempest-snapshot",
        }
        shares = self.shares_v2_client.list_snapshots_with_detail(
            params=filters)

        self.assertEqual(0, len(shares))
