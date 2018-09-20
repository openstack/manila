# Copyright 2014 OpenStack Foundation
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

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base


class ShareTypesNegativeTest(base.BaseSharesMixedTest):

    @classmethod
    def resource_setup(cls):
        super(ShareTypesNegativeTest, cls).resource_setup()
        cls.st = cls._create_share_type()

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_create_share_type_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.create_share_type,
                          data_utils.rand_name("used_user_creds"),
                          client=self.shares_client)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_delete_share_type_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.delete_share_type,
                          self.st["id"])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_add_access_to_share_type_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.add_access_to_share_type,
                          self.st['id'],
                          self.shares_client.tenant_id)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_remove_access_from_share_type_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.remove_access_from_share_type,
                          self.st['id'],
                          self.shares_client.tenant_id)
