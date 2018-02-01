# Copyright 2016 Huawei
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

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@testtools.skipUnless(CONF.share.run_snapshot_tests,
                      'Snapshot tests are disabled.')
@base.skip_if_microversion_lt("2.19")
class SnapshotInstancesNegativeTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(SnapshotInstancesNegativeTest, cls).resource_setup()
        cls.admin_client = cls.admin_shares_v2_client
        cls.member_client = cls.shares_v2_client
        # create share type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']
        # create share
        cls.share = cls.create_share(share_type_id=cls.share_type_id,
                                     client=cls.admin_client)
        cls.snapshot = cls.create_snapshot_wait_for_active(
            cls.share["id"], client=cls.admin_client)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_list_snapshot_instances_with_snapshot_by_non_admin(self):
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_client.list_snapshot_instances,
            snapshot_id=self.snapshot['id'])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_get_snapshot_instance_by_non_admin(self):
        instances = self.admin_client.list_snapshot_instances(
            snapshot_id=self.snapshot['id'])
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_client.get_snapshot_instance,
            instance_id=instances[0]['id'])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_reset_snapshot_instance_status_by_non_admin(self):
        instances = self.admin_client.list_snapshot_instances(
            snapshot_id=self.snapshot['id'])
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_client.reset_snapshot_instance_status,
            instances[0]['id'],
            'error')


@testtools.skipUnless(CONF.share.run_snapshot_tests,
                      'Snapshot tests are disabled.')
@base.skip_if_microversion_lt("2.19")
class SnapshotInstancesNegativeNoResourceTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(SnapshotInstancesNegativeNoResourceTest, cls).resource_setup()
        cls.admin_client = cls.admin_shares_v2_client
        cls.member_client = cls.shares_v2_client

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_get_snapshot_instance_with_non_existent_instance(self):
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.get_snapshot_instance,
                          instance_id="nonexistent_instance")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_list_snapshot_instances_by_non_admin(self):
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_client.list_snapshot_instances)
