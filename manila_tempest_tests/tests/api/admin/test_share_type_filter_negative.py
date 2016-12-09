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
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@ddt.ddt
class ShareTypeFilterNegativeTest(base.BaseSharesAdminTest):

    @classmethod
    def _create_share_type(cls):
        name = data_utils.rand_name("unique_st_name")
        extra_specs = {
            'share_backend_name': uuidutils.generate_uuid(),
        }
        extra_specs = cls.add_required_extra_specs_to_dict(
            extra_specs=extra_specs)
        return cls.create_share_type(
            name, extra_specs=extra_specs,
            client=cls.admin_client)

    @classmethod
    def resource_setup(cls):
        super(ShareTypeFilterNegativeTest, cls).resource_setup()
        cls.admin_client = cls.shares_v2_client
        cls.st = cls._create_share_type()

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.23")
    @ddt.data(True, False)
    def test_get_pools_invalid_share_type_filter_with_detail(self, detail):
        share_type = self.st["share_type"]["name"]
        search_opts = {"share_type": share_type}
        pools = self.admin_client.list_pools(
            detail=detail, search_opts=search_opts)['pools']

        self.assertEmpty(pools)
