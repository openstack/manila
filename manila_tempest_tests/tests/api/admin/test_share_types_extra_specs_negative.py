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


class ExtraSpecsAdminNegativeTest(base.BaseSharesAdminTest):

    def _create_share_type(self):
        name = data_utils.rand_name("unique_st_name")
        extra_specs = self.add_required_extra_specs_to_dict({"key": "value"})
        return self.create_share_type(name, extra_specs=extra_specs)

    @classmethod
    def resource_setup(cls):
        super(ExtraSpecsAdminNegativeTest, cls).resource_setup()
        cls.member_shares_client = clients.Manager().shares_client

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_shares_client.create_share_type_extra_specs,
            st["share_type"]["id"],
            self.add_required_extra_specs_to_dict({"key": "new_value"}))

    @test.attr(type=["gate", "smoke", ])
    def test_try_list_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_shares_client.get_share_type_extra_specs,
            st["share_type"]["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_spec_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_shares_client.get_share_type_extra_spec,
            st["share_type"]["id"], "key")

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_shares_client.get_share_type_extra_specs,
            st["share_type"]["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_try_read_extra_specs_on_share_type_with_user(self):
        st = self._create_share_type()
        share_type = self.member_shares_client.get_share_type(
            st['share_type']['id'])
        # Verify a non-admin can only read the required extra-specs
        expected_keys = ['driver_handles_share_servers', 'snapshot_support']
        actual_keys = share_type['share_type']['extra_specs'].keys()
        self.assertEqual(sorted(expected_keys), sorted(actual_keys),
                         'Incorrect extra specs visible to non-admin user; '
                         'expected %s, got %s' % (expected_keys, actual_keys))

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_extra_spec_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_shares_client.update_share_type_extra_spec,
            st["share_type"]["id"], "key", "new_value")

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_shares_client.update_share_type_extra_specs,
            st["share_type"]["id"], {"key": "new_value"})

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.member_shares_client.delete_share_type_extra_spec,
            st["share_type"]["id"], "key")

    @test.attr(type=["gate", "smoke", ])
    def test_try_set_too_long_key(self):
        too_big_key = "k" * 256
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.BadRequest,
            self.shares_client.create_share_type_extra_specs,
            st["share_type"]["id"],
            self.add_required_extra_specs_to_dict({too_big_key: "value"}))

    @test.attr(type=["gate", "smoke", ])
    def test_try_set_too_long_value_with_creation(self):
        too_big_value = "v" * 256
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.BadRequest,
            self.shares_client.create_share_type_extra_specs,
            st["share_type"]["id"],
            self.add_required_extra_specs_to_dict({"key": too_big_value}))

    @test.attr(type=["gate", "smoke", ])
    def test_try_set_too_long_value_with_update(self):
        too_big_value = "v" * 256
        st = self._create_share_type()
        self.shares_client.create_share_type_extra_specs(
            st["share_type"]["id"],
            self.add_required_extra_specs_to_dict({"key": "value"}))
        self.assertRaises(
            lib_exc.BadRequest,
            self.shares_client.update_share_type_extra_specs,
            st["share_type"]["id"],
            self.add_required_extra_specs_to_dict({"key": too_big_value}))

    @test.attr(type=["gate", "smoke", ])
    def test_try_set_too_long_value_with_update_of_one_key(self):
        too_big_value = "v" * 256
        st = self._create_share_type()
        self.shares_client.create_share_type_extra_specs(
            st["share_type"]["id"],
            self.add_required_extra_specs_to_dict({"key": "value"}))
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.update_share_type_extra_spec,
                          st["share_type"]["id"], "key", too_big_value)

    @test.attr(type=["gate", "smoke", ])
    def test_try_list_es_with_empty_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_type_extra_specs, "")

    @test.attr(type=["gate", "smoke", ])
    def test_try_list_es_with_invalid_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_type_extra_specs,
                          data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_es_with_empty_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.create_share_type_extra_specs,
                          "", {"key1": "value1", })

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_es_with_invalid_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.create_share_type_extra_specs,
                          data_utils.rand_name("fake"), {"key1": "value1", })

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_es_with_empty_specs(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_share_type_extra_specs,
                          st["share_type"]["id"], "")

    @test.attr(type=["gate", "smoke", ])
    def test_try_create_es_with_invalid_specs(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.create_share_type_extra_specs,
                          st["share_type"]["id"], {"": "value_with_empty_key"})

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_spec_with_empty_key(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_type_extra_spec,
                          st["share_type"]["id"], "")

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_spec_with_invalid_key(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_type_extra_spec,
                          st["share_type"]["id"], data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_specs_with_empty_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_type_extra_specs,
                          "")

    @test.attr(type=["gate", "smoke", ])
    def test_try_get_extra_specs_with_invalid_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_type_extra_specs,
                          data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_es_key_with_empty_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_share_type_extra_spec,
                          "", "key", )

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_es_key_with_invalid_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_share_type_extra_spec,
                          data_utils.rand_name("fake"), "key", )

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_with_invalid_key(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_share_type_extra_spec,
                          st["share_type"]["id"], data_utils.rand_name("fake"))

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_spec_with_empty_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.update_share_type_extra_spec,
                          "", "key", "new_value")

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_spec_with_invalid_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.update_share_type_extra_spec,
                          data_utils.rand_name("fake"), "key", "new_value")

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_spec_with_empty_key(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.update_share_type_extra_spec,
                          st["share_type"]["id"], "", "new_value")

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_with_invalid_shr_type_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.update_share_type_extra_specs,
                          data_utils.rand_name("fake"), {"key": "new_value"})

    @test.attr(type=["gate", "smoke", ])
    def test_try_update_with_invalid_specs(self):
        st = self._create_share_type()
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_client.update_share_type_extra_specs,
                          st["share_type"]["id"], {"": "new_value"})

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_spec_driver_handles_share_servers(self):
        st = self._create_share_type()

        # Try delete extra spec 'driver_handles_share_servers'
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.delete_share_type_extra_spec,
                          st["share_type"]["id"],
                          "driver_handles_share_servers")

    @test.attr(type=["gate", "smoke", ])
    def test_try_delete_spec_snapshot_support(self):
        st = self._create_share_type()

        # Try delete extra spec 'snapshot_support'
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.delete_share_type_extra_spec,
                          st["share_type"]["id"],
                          "snapshot_support")
