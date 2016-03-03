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


class ShareTypesAdminNegativeTest(base.BaseSharesAdminTest):

    def _create_share_type(self):
        name = data_utils.rand_name("unique_st_name")
        extra_specs = self.add_required_extra_specs_to_dict({"key": "value"})
        return self.create_share_type(name, extra_specs=extra_specs)

    @classmethod
    def resource_setup(cls):
        super(ShareTypesAdminNegativeTest, cls).resource_setup()
        cls.member_shares_client = clients.Manager().shares_client

    @test.attr(type=["gate", "smoke", ])
    def test_create_share_with_nonexistent_share_type(self):
        self.assertRaises(lib_exc.NotFound,
                          self.create_share,
                          share_type_id=data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_create_share_type_with_empty_name(self):
        self.assertRaises(lib_exc.BadRequest, self.create_share_type, '')

    @test.attr(type=["gate", "smoke", ])
    def test_create_share_type_with_too_big_name(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_share_type,
                          "x" * 256)

    @test.attr(type=["gate", "smoke", ])
    def test_get_share_type_by_nonexistent_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_type,
                          data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_share_type_by_nonexistent_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_share_type,
                          data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_duplicate_of_share_type(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.Conflict,
                          self.create_share_type,
                          st["share_type"]["name"],
                          extra_specs=self.add_required_extra_specs_to_dict())

    @test.attr(type=["gate", "smoke", ])
    def test_add_share_type_allowed_for_public(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.Conflict,
                          self.shares_client.add_access_to_share_type,
                          st["share_type"]["id"],
                          self.shares_client.tenant_id)

    @test.attr(type=["gate", "smoke", ])
    def test_remove_share_type_allowed_for_public(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.Conflict,
                          self.shares_client.remove_access_from_share_type,
                          st["share_type"]["id"],
                          self.shares_client.tenant_id)

    @test.attr(type=["gate", "smoke", ])
    def test_add_share_type_by_nonexistent_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.add_access_to_share_type,
                          data_utils.rand_name("fake"),
                          self.shares_client.tenant_id)

    @test.attr(type=["gate", "smoke", ])
    def test_remove_share_type_by_nonexistent_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.remove_access_from_share_type,
                          data_utils.rand_name("fake"),
                          self.shares_client.tenant_id)
