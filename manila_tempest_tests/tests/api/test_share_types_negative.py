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

from tempest.lib.common.utils import data_utils  # noqa
from tempest.lib import exceptions as lib_exc  # noqa
from tempest import test  # noqa

from manila_tempest_tests import clients_share as clients
from manila_tempest_tests.tests.api import base


class ShareTypesNegativeTest(base.BaseSharesTest):

    @classmethod
    def _create_share_type(cls):
        name = data_utils.rand_name("unique_st_name")
        extra_specs = cls.add_required_extra_specs_to_dict()
        return cls.create_share_type(
            name, extra_specs=extra_specs,
            client=clients.AdminManager().shares_client)

    @classmethod
    def resource_setup(cls):
        super(ShareTypesNegativeTest, cls).resource_setup()
        cls.st = cls._create_share_type()

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_create_share_type_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.create_share_type,
                          data_utils.rand_name("used_user_creds"),
                          client=self.shares_client)

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_delete_share_type_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.delete_share_type,
                          self.st["share_type"]["id"])

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_add_access_to_share_type_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.add_access_to_share_type,
                          self.st['share_type']['id'],
                          self.shares_client.tenant_id)

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_remove_access_from_share_type_with_user(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.remove_access_from_share_type,
                          self.st['share_type']['id'],
                          self.shares_client.tenant_id)
