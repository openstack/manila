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
from tempest.lib import exceptions as lib_exc
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@ddt.ddt
class SharesQuotasNegativeTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        if not CONF.share.run_quota_tests:
            msg = "Quota tests are disabled."
            raise cls.skipException(msg)
        super(SharesQuotasNegativeTest, cls).resource_setup()

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_get_quotas_with_empty_tenant_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.show_quotas, "")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_reset_quotas_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_v2_client.reset_quotas,
                          self.shares_v2_client.tenant_id)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_update_quotas_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_v2_client.update_quotas,
                          self.shares_v2_client.tenant_id,
                          shares=9)

    @ddt.data("2.6", "2.7", "2.24")
    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_get_quotas_detail_with_wrong_version(self, microversion):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.detail_quotas,
                          self.shares_v2_client.tenant_id,
                          version=microversion)
