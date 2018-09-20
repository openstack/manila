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
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base


@ddt.ddt
class ShareInstancesNegativeTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ShareInstancesNegativeTest, cls).resource_setup()
        # create share type
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']
        # create share
        cls.share = cls.create_share(share_type_id=cls.share_type_id)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.34")
    @ddt.data('path', 'id')
    def test_list_share_instances_with_export_location_and_invalid_version(
            self, export_location_type):
        # In API versions <v2.35, querying the share instance API by export
        # location path or ID should have no effect. Those filters were
        # supported from v2.35
        filters = {
            'export_location_' + export_location_type: 'fake',
        }
        share_instances = self.shares_v2_client.list_share_instances(
            params=filters, version="2.34")

        self.assertGreater(len(share_instances), 0)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.35")
    @ddt.data('path', 'id')
    def test_list_share_instances_with_export_location_not_exist(
            self, export_location_type):
        filters = {
            'export_location_' + export_location_type: 'fake_not_exist',
        }
        share_instances = self.shares_v2_client.list_share_instances(
            params=filters)

        self.assertEqual(0, len(share_instances))
