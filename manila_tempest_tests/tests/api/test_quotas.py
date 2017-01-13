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
import itertools
from tempest import config
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@ddt.ddt
class SharesQuotasTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        if not CONF.share.run_quota_tests:
            msg = "Quota tests are disabled."
            raise cls.skipException(msg)
        super(SharesQuotasTest, cls).resource_setup()
        cls.user_id = cls.shares_v2_client.user_id or cls.user_id
        cls.tenant_id = cls.shares_v2_client.tenant_id or cls.tenant_id

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    @ddt.data('shares_client', 'shares_v2_client')
    def test_default_quotas(self, client_name):
        quotas = getattr(self, client_name).default_quotas(self.tenant_id)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["snapshot_gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)
        self.assertGreater(int(quotas["share_networks"]), -2)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    @ddt.data('shares_client', 'shares_v2_client')
    def test_show_quotas(self, client_name):
        quotas = getattr(self, client_name).show_quotas(self.tenant_id)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["snapshot_gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)
        self.assertGreater(int(quotas["share_networks"]), -2)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    @ddt.data('shares_client', 'shares_v2_client')
    def test_show_quotas_for_user(self, client_name):
        quotas = getattr(self, client_name).show_quotas(
            self.tenant_id, self.user_id)
        self.assertGreater(int(quotas["gigabytes"]), -2)
        self.assertGreater(int(quotas["snapshot_gigabytes"]), -2)
        self.assertGreater(int(quotas["shares"]), -2)
        self.assertGreater(int(quotas["snapshots"]), -2)
        self.assertGreater(int(quotas["share_networks"]), -2)

    @ddt.data(
        *itertools.product(set(("2.25", CONF.share.max_api_microversion)),
                           (True, False))
    )
    @ddt.unpack
    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    @base.skip_if_microversion_not_supported("2.25")
    def test_show_quotas_detail(self, microversion, with_user):
        quota_args = {"tenant_id": self.tenant_id, "version": microversion, }
        if with_user:
            quota_args.update({"user_id": self.user_id})
        quotas = self.shares_v2_client.detail_quotas(**quota_args)
        quota_keys = list(quotas.keys())
        for outer in ('gigabytes', 'snapshot_gigabytes', 'shares',
                      'snapshots', 'share_networks'):
            self.assertIn(outer, quota_keys)
            outer_keys = list(quotas[outer].keys())
            for inner in ('in_use', 'limit', 'reserved'):
                self.assertIn(inner, outer_keys)
                self.assertGreater(int(quotas[outer][inner]), -2)
