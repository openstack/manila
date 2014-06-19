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


class ExtraSpecsAdminNegativeTest(base.BaseSharesAdminTest):

    def _create_volume_type(self):
        name = data_utils.rand_name("unique_vt_name")
        extra_specs = {"key": "value", }
        __, vt = self.create_volume_type(name, extra_specs=extra_specs)
        return vt

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(ExtraSpecsAdminNegativeTest, cls).setUpClass()
        cls.member_shares_client = clients.Manager().shares_client

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_extra_specs_with_user(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.Unauthorized,
            self.member_shares_client.create_volume_type_extra_specs,
            vt["id"], {"key": "new_value"})

    @test.attr(type=["gate", "smoke", ])
    def test_try_list_extra_specs_with_user(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.Unauthorized,
            self.member_shares_client.list_volume_types_extra_specs, vt["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_spec_with_user(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.Unauthorized,
            self.member_shares_client.get_volume_type_extra_spec,
            vt["id"], "key")

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_specs_with_user(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.Unauthorized,
            self.member_shares_client.get_volume_type_extra_specs, vt["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_extra_spec_with_user(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.Unauthorized,
            self.member_shares_client.update_volume_type_extra_spec,
            vt["id"], "key", "new_value")

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_extra_specs_with_user(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.Unauthorized,
            self.member_shares_client.update_volume_type_extra_specs,
            vt["id"], {"key": "new_value"})

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_extra_specs_with_user(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.Unauthorized,
            self.member_shares_client.delete_volume_type_extra_spec,
            vt["id"], "key")

    @test.attr(type=["gate", "smoke", ])
    def test_try_set_too_long_key(self):
        too_big_key = "k" * 256
        vt = self._create_volume_type()
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_volume_type_extra_specs,
                          vt["id"], {too_big_key: "value"})

    @test.attr(type=["gate", "smoke", ])
    def test_try_set_too_long_value_with_creation(self):
        too_big_value = "v" * 256
        vt = self._create_volume_type()
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_volume_type_extra_specs,
                          vt["id"], {"key": too_big_value})

    @test.attr(type=["gate", "smoke", ])
    def test_try_set_too_long_value_with_update(self):
        too_big_value = "v" * 256
        vt = self._create_volume_type()
        resp, body = self.shares_client.create_volume_type_extra_specs(
            vt["id"], {"key": "value"})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_volume_type_extra_specs,
                          vt["id"], {"key": too_big_value})

    @test.attr(type=["gate", "smoke", ])
    def test_try_set_too_long_value_with_update_of_one_key(self):
        too_big_value = "v" * 256
        vt = self._create_volume_type()
        resp, body = self.shares_client.create_volume_type_extra_specs(
            vt["id"], {"key": "value"})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_volume_type_extra_spec,
                          vt["id"], "key", too_big_value)

    @test.attr(type=["gate", "smoke", ])
    def test_try_list_es_with_empty_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.list_volume_types_extra_specs, "")

    @test.attr(type=["gate", "smoke", ])
    def test_try_list_es_with_invalid_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.list_volume_types_extra_specs,
                          data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_es_with_empty_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.create_volume_type_extra_specs,
                          "", {"key1": "value1", })

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_es_with_invalid_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.create_volume_type_extra_specs,
                          data_utils.rand_name("fake"), {"key1": "value1", })

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_es_with_empty_specs(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_volume_type_extra_specs,
                          vt["id"], "")

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_es_with_invalid_specs(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_volume_type_extra_specs,
                          vt["id"], {"": "value_with_empty_key"})

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_spec_with_empty_key(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_volume_type_extra_spec,
                          vt["id"], "")

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_spec_with_invalid_key(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_volume_type_extra_spec,
                          vt["id"], data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_specs_with_empty_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_volume_type_extra_specs,
                          "")

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_specs_with_invalid_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_volume_type_extra_specs,
                          data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_es_key_with_empty_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_volume_type_extra_spec,
                          "", "key", )

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_es_key_with_invalid_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_volume_type_extra_spec,
                          data_utils.rand_name("fake"), "key", )

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_with_invalid_key(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_volume_type_extra_spec,
                          vt["id"], data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_spec_with_empty_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_volume_type_extra_spec,
                          "", "key", "new_value")

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_spec_with_invalid_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_volume_type_extra_spec,
                          data_utils.rand_name("fake"), "key", "new_value")

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_spec_with_empty_key(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_volume_type_extra_spec,
                          vt["id"], "", "new_value")

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_with_invalid_vol_type_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_volume_type_extra_specs,
                          data_utils.rand_name("fake"), {"key": "new_value"})

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_with_invalid_specs(self):
        vt = self._create_volume_type()
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_volume_type_extra_specs,
                          vt["id"], {"": "new_value"})
