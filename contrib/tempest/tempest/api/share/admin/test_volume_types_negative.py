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

from tempest.api.share import base
from tempest import clients_share as clients
from tempest.common.utils import data_utils
from tempest import exceptions
from tempest import test


class VolumeTypesAdminNegativeTest(base.BaseSharesAdminTest):

    def _create_volume_type(self):
        name = data_utils.rand_name("unique_vt_name")
        extra_specs = {"key": "value", }
        __, vt = self.create_volume_type(name, extra_specs=extra_specs)
        return vt

    @classmethod
    def setUpClass(cls):
        super(VolumeTypesAdminNegativeTest, cls).setUpClass()
        cls.member_shares_client = clients.Manager().shares_client

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_volume_type_with_user(self):
        self.assertRaises(exceptions.Unauthorized,
                          self.create_volume_type,
                          data_utils.rand_name("used_user_creds"),
                          client=self.member_shares_client)

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_volume_type_with_user(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.Unauthorized,
                          self.member_shares_client.delete_volume_type,
                          vt["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_create_share_with_nonexistent_volume_type(self):
        self.assertRaises(exceptions.NotFound,
                          self.create_share_wait_for_active,
                          volume_type_id=data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_create_volume_type_with_empty_name(self):
        self.assertRaises(exceptions.BadRequest, self.create_volume_type, '')

    @test.attr(type=["gate", "smoke", ])
    def test_create_volume_type_with_too_big_name(self):
        self.assertRaises(exceptions.BadRequest,
                          self.create_volume_type,
                          "x" * 256)

    @test.attr(type=["gate", "smoke", ])
    def test_get_volume_type_by_nonexistent_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_volume_type,
                          data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_volume_type_by_nonexistent_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_volume_type,
                          data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_duplicate_of_volume_type(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.Conflict,
                          self.create_volume_type,
                          vt["name"])
