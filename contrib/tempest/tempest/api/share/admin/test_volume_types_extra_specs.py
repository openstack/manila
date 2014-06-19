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
from tempest.common.utils import data_utils
from tempest import test


class ExtraSpecsAdminTest(base.BaseSharesAdminTest):

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(ExtraSpecsAdminTest, cls).setUpClass()
        vol_type_name = data_utils.rand_name("volume-type")
        __, cls.volume_type = cls.create_volume_type(vol_type_name)

    @test.attr(type=["gate", "smoke", ])
    def test_volume_type_extra_specs_list(self):
        extra_specs = {
            "key1": "value1",
            "key2": "value2",
        }
        resp, es_create = self.shares_client.create_volume_type_extra_specs(
            self.volume_type["id"], extra_specs)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(extra_specs, es_create)

        resp, es_list = self.shares_client.list_volume_types_extra_specs(
            self.volume_type["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(extra_specs, es_list)

    @test.attr(type=["gate", "smoke", ])
    def test_update_one_volume_type_extra_spec(self):
        extra_specs = {
            "key1": "value1",
            "key2": "value2",
        }

        # Create extra specs for volume type
        resp, es_create = self.shares_client.create_volume_type_extra_specs(
            self.volume_type['id'], extra_specs)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(extra_specs, es_create)

        # Update extra specs of volume type
        extra_specs["key1"] = "fake_value1_updated"
        resp, update_one = self.shares_client.update_volume_type_extra_spec(
            self.volume_type["id"], "key1", extra_specs["key1"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual({"key1": extra_specs["key1"]}, update_one)

    @test.attr(type=["gate", "smoke", ])
    def test_update_all_volume_type_extra_specs(self):
        extra_specs = {
            "key1": "value1",
            "key2": "value2",
        }

        # Create extra specs for volume type
        resp, es_create = self.shares_client.create_volume_type_extra_specs(
            self.volume_type['id'], extra_specs)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(extra_specs, es_create)

        # Update extra specs of volume type
        extra_specs["key2"] = "value2_updated"
        resp, update_all = self.shares_client.update_volume_type_extra_specs(
            self.volume_type["id"], extra_specs)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(extra_specs, update_all)

    @test.attr(type=["gate", "smoke", ])
    def test_get_all_volume_type_extra_specs(self):
        extra_specs = {
            "key1": "value1",
            "key2": "value2",
        }

        # Create extra specs for volume type
        resp, es_create = self.shares_client.create_volume_type_extra_specs(
            self.volume_type['id'], extra_specs)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(extra_specs, es_create)

        # Get all extra specs for volume type
        resp, es_get_all = self.shares_client.get_volume_type_extra_specs(
            self.volume_type["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(extra_specs, es_get_all)

    @test.attr(type=["gate", "smoke", ])
    def test_get_one_volume_type_extra_spec(self):
        extra_specs = {
            "key1": "value1",
            "key2": "value2",
        }

        # Create extra specs for volume type
        resp, es_create = self.shares_client.create_volume_type_extra_specs(
            self.volume_type['id'], extra_specs)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(extra_specs, es_create)

        # Get one extra spec for volume type
        resp, es_get_one = self.shares_client.get_volume_type_extra_spec(
            self.volume_type["id"], "key1")
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual({"key1": "value1", }, es_get_one)

    @test.attr(type=["gate", "smoke", ])
    def test_delete_one_volume_type_extra_spec(self):
        extra_specs = {
            "key1": "value1",
            "key2": "value2",
        }

        # Create extra specs for volume type
        resp, es_create = self.shares_client.create_volume_type_extra_specs(
            self.volume_type['id'], extra_specs)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(extra_specs, es_create)

        # Delete one extra spec for volume type
        resp, __ = self.shares_client.delete_volume_type_extra_spec(
            self.volume_type["id"], "key1")
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # Get all extra specs for volume type
        resp, es_get_all = self.shares_client.get_volume_type_extra_specs(
            self.volume_type["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual({"key2": "value2", }, es_get_all)
