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

from tempest import test  # noqa
from tempest_lib import exceptions as lib_exc  # noqa
import testtools  # noqa

from manila_tempest_tests.tests.api import base


class SharesQuotasNegativeTest(base.BaseSharesTest):

    @test.attr(type=["gate", "smoke", "negative"])
    def test_get_quotas_with_empty_tenant_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.show_quotas, "")

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_try_reset_quotas_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.reset_quotas,
                          self.shares_client.tenant_id)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_try_update_quotas_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.update_quotas,
                          self.shares_client.tenant_id,
                          shares=9)
