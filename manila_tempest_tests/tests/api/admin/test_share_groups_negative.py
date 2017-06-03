# Copyright 2017 Mirantis Inc.
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
import testtools
from testtools import testcase as tc

from manila_tempest_tests.common import constants
from manila_tempest_tests import share_exceptions
from manila_tempest_tests.tests.api import base

CONF = config.CONF


@testtools.skipUnless(
    CONF.share.run_share_group_tests, 'Share Group tests disabled.')
@base.skip_if_microversion_lt(constants.MIN_SHARE_GROUP_MICROVERSION)
class ShareGroupsNegativeTest(base.BaseSharesAdminTest):

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_create_share_group_with_wrong_consistent_snapshot_spec(self):
        # Create valid share type for share group type
        name = data_utils.rand_name("tempest-manila")
        extra_specs = self.add_extra_specs_to_dict()
        st = self.create_share_type(name, extra_specs=extra_specs)
        share_type = st['share_type'] if 'share_type' in st else st

        # Create share group type with wrong value for
        # 'consistent_snapshot_support' capability, we always expect
        # NoValidHostFound using this SG type.
        sg_type = self.create_share_group_type(
            name=name,
            share_types=[share_type['id']],
            group_specs={"consistent_snapshot_support": "fake"},
            cleanup_in_class=False)

        # Try create share group
        self.assertRaises(
            share_exceptions.ShareGroupBuildErrorException,
            self.create_share_group,
            share_type_ids=[share_type['id']],
            share_group_type_id=sg_type['id'],
            cleanup_in_class=False)
