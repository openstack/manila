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

import ddt

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from testtools import testcase as tc

from manila_tempest_tests.common import constants
from manila_tempest_tests.tests.api import base

CONF = config.CONF


@base.skip_if_microversion_not_supported(
    constants.REVERT_TO_SNAPSHOT_MICROVERSION)
@ddt.ddt
class RevertToSnapshotNegativeTest(base.BaseSharesMixedTest):

    @classmethod
    def skip_checks(cls):
        super(RevertToSnapshotNegativeTest, cls).skip_checks()
        if not CONF.share.run_revert_to_snapshot_tests:
            msg = "Revert to snapshot tests are disabled."
            raise cls.skipException(msg)
        if not CONF.share.capability_snapshot_support:
            msg = "Snapshot support is disabled."
            raise cls.skipException(msg)
        if not CONF.share.run_snapshot_tests:
            msg = "Snapshot tests are disabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(RevertToSnapshotNegativeTest, cls).resource_setup()
        cls.admin_client = cls.admin_shares_v2_client
        pools = cls.admin_client.list_pools(detail=True)['pools']
        revert_support = [
            pool['capabilities'][constants.REVERT_TO_SNAPSHOT_SUPPORT]
            for pool in pools]
        if not any(revert_support):
            msg = "Revert to snapshot not supported."
            raise cls.skipException(msg)

        cls.share_type_name = data_utils.rand_name("share-type")
        extra_specs = {constants.REVERT_TO_SNAPSHOT_SUPPORT: True}
        cls.revert_enabled_extra_specs = cls.add_extra_specs_to_dict(
            extra_specs=extra_specs)

        cls.share_type = cls.create_share_type(
            cls.share_type_name,
            extra_specs=cls.revert_enabled_extra_specs,
            client=cls.admin_client)

        cls.st_id = cls.share_type['share_type']['id']

        cls.share = cls.create_share(share_type_id=cls.st_id)
        cls.share2 = cls.create_share(share_type_id=cls.st_id)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @ddt.data(
        *{constants.REVERT_TO_SNAPSHOT_MICROVERSION,
          CONF.share.max_api_microversion}
    )
    def test_revert_to_second_latest_snapshot(self, version):
        snapshot1 = self.create_snapshot_wait_for_active(
            self.share['id'], cleanup_in_class=False)
        self.create_snapshot_wait_for_active(self.share['id'],
                                             cleanup_in_class=False)

        self.assertRaises(exceptions.Conflict,
                          self.shares_v2_client.revert_to_snapshot,
                          self.share['id'],
                          snapshot1['id'],
                          version=version)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @ddt.data(
        *{constants.REVERT_TO_SNAPSHOT_MICROVERSION,
          CONF.share.max_api_microversion}
    )
    def test_revert_to_error_snapshot(self, version):
        snapshot = self.create_snapshot_wait_for_active(self.share['id'],
                                                        cleanup_in_class=False)

        self.admin_client.reset_state(snapshot['id'],
                                      status=constants.STATUS_ERROR,
                                      s_type='snapshots')

        self.assertRaises(exceptions.Conflict,
                          self.shares_v2_client.revert_to_snapshot,
                          self.share['id'],
                          snapshot['id'],
                          version=version)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @ddt.data(
        *{constants.REVERT_TO_SNAPSHOT_MICROVERSION,
          CONF.share.max_api_microversion}
    )
    def test_revert_error_share_to_snapshot(self, version):
        snapshot = self.create_snapshot_wait_for_active(self.share['id'],
                                                        cleanup_in_class=False)

        self.admin_client.reset_state(self.share['id'],
                                      status=constants.STATUS_ERROR,
                                      s_type='shares')

        self.addCleanup(self.admin_client.reset_state,
                        self.share['id'],
                        status=constants.STATUS_AVAILABLE,
                        s_type='shares')

        self.assertRaises(exceptions.Conflict,
                          self.shares_v2_client.revert_to_snapshot,
                          self.share['id'],
                          snapshot['id'],
                          version=version)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @ddt.data(
        *{constants.REVERT_TO_SNAPSHOT_MICROVERSION,
          CONF.share.max_api_microversion}
    )
    def test_revert_to_missing_snapshot(self, version):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_v2_client.revert_to_snapshot,
                          self.share['id'],
                          self.share['id'],
                          version=version)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @ddt.data(
        *{constants.REVERT_TO_SNAPSHOT_MICROVERSION,
          CONF.share.max_api_microversion}
    )
    def test_revert_to_invalid_snapshot(self, version):
        snapshot = self.create_snapshot_wait_for_active(
            self.share['id'], cleanup_in_class=False)

        self.assertRaises(exceptions.BadRequest,
                          self.shares_v2_client.revert_to_snapshot,
                          self.share2['id'],
                          snapshot['id'],
                          version=version)
