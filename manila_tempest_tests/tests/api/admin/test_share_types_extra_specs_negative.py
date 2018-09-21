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

import ddt
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from testtools import testcase as tc

from manila_tempest_tests.common import constants
from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


@ddt.ddt
class ExtraSpecsAdminNegativeTest(base.BaseSharesMixedTest):

    def _create_share_type(self):
        name = data_utils.rand_name("unique_st_name")
        extra_specs = self.add_extra_specs_to_dict({"key": "value"})
        return self.create_share_type(
            name,
            extra_specs=extra_specs,
            client=self.admin_shares_v2_client)["share_type"]

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_create_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.shares_v2_client.create_share_type_extra_specs,
            st["id"],
            self.add_extra_specs_to_dict({"key": "new_value"}))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_list_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.shares_v2_client.get_share_type_extra_specs,
            st["id"])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_get_extra_spec_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.shares_v2_client.get_share_type_extra_spec,
            st["id"], "key")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_get_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.shares_v2_client.get_share_type_extra_specs,
            st["id"])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_read_extra_specs_on_share_type_with_user(self):
        st = self._create_share_type()
        share_type = self.shares_v2_client.get_share_type(st['id'])
        # Verify a non-admin can only read the required extra-specs
        expected_keys = ['driver_handles_share_servers', 'snapshot_support']
        if utils.is_microversion_ge(CONF.share.max_api_microversion, '2.24'):
            expected_keys.append('create_share_from_snapshot_support')
        if utils.is_microversion_ge(CONF.share.max_api_microversion,
                                    constants.REVERT_TO_SNAPSHOT_MICROVERSION):
            expected_keys.append('revert_to_snapshot_support')
        if utils.is_microversion_ge(CONF.share.max_api_microversion, '2.32'):
            expected_keys.append('mount_snapshot_support')
        actual_keys = share_type['share_type']['extra_specs'].keys()
        self.assertEqual(sorted(expected_keys), sorted(actual_keys),
                         'Incorrect extra specs visible to non-admin user; '
                         'expected %s, got %s' % (expected_keys, actual_keys))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_update_extra_spec_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.shares_v2_client.update_share_type_extra_spec,
            st["id"], "key", "new_value")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_update_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.shares_v2_client.update_share_type_extra_specs,
            st["id"], {"key": "new_value"})

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_delete_extra_specs_with_user(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.Forbidden,
            self.shares_v2_client.delete_share_type_extra_spec,
            st["id"], "key")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_set_too_long_key(self):
        too_big_key = "k" * 256
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_shares_v2_client.create_share_type_extra_specs,
            st["id"],
            self.add_extra_specs_to_dict({too_big_key: "value"}))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_set_too_long_value_with_creation(self):
        too_big_value = "v" * 256
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_shares_v2_client.create_share_type_extra_specs,
            st["id"],
            self.add_extra_specs_to_dict({"key": too_big_value}))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_set_too_long_value_with_update(self):
        too_big_value = "v" * 256
        st = self._create_share_type()
        self.admin_shares_v2_client.create_share_type_extra_specs(
            st["id"],
            self.add_extra_specs_to_dict({"key": "value"}))
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_shares_v2_client.update_share_type_extra_specs,
            st["id"],
            self.add_extra_specs_to_dict({"key": too_big_value}))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_set_too_long_value_with_update_of_one_key(self):
        too_big_value = "v" * 256
        st = self._create_share_type()
        self.admin_shares_v2_client.create_share_type_extra_specs(
            st["id"],
            self.add_extra_specs_to_dict({"key": "value"}))
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_shares_v2_client.update_share_type_extra_spec,
            st["id"], "key", too_big_value)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_list_es_with_empty_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.get_share_type_extra_specs, "")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_list_es_with_invalid_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.get_share_type_extra_specs,
            data_utils.rand_name("fake"))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_create_es_with_empty_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.create_share_type_extra_specs,
            "", {"key1": "value1", })

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_create_es_with_invalid_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.create_share_type_extra_specs,
            data_utils.rand_name("fake"), {"key1": "value1", })

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_create_es_with_empty_specs(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_shares_v2_client.create_share_type_extra_specs,
            st["id"], "")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_create_es_with_invalid_specs(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_shares_v2_client.create_share_type_extra_specs,
            st["id"], {"": "value_with_empty_key"})

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_get_extra_spec_with_empty_key(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.get_share_type_extra_spec,
            st["id"], "")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_get_extra_spec_with_invalid_key(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.get_share_type_extra_spec,
            st["id"], data_utils.rand_name("fake"))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_get_extra_specs_with_empty_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.get_share_type_extra_specs,
            "")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_get_extra_specs_with_invalid_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.get_share_type_extra_specs,
            data_utils.rand_name("fake"))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_delete_es_key_with_empty_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.delete_share_type_extra_spec,
            "", "key", )

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_delete_es_key_with_invalid_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.delete_share_type_extra_spec,
            data_utils.rand_name("fake"), "key", )

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_delete_with_invalid_key(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.delete_share_type_extra_spec,
            st["id"], data_utils.rand_name("fake"))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_update_spec_with_empty_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.update_share_type_extra_spec,
            "", "key", "new_value")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_update_spec_with_invalid_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.update_share_type_extra_spec,
            data_utils.rand_name("fake"), "key", "new_value")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_update_spec_with_empty_key(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.update_share_type_extra_spec,
            st["id"], "", "new_value")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_update_with_invalid_shr_type_id(self):
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_shares_v2_client.update_share_type_extra_specs,
            data_utils.rand_name("fake"), {"key": "new_value"})

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_update_with_invalid_specs(self):
        st = self._create_share_type()
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_shares_v2_client.update_share_type_extra_specs,
            st["id"], {"": "new_value"})

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_try_delete_spec_driver_handles_share_servers(self):
        st = self._create_share_type()

        # Try delete extra spec 'driver_handles_share_servers'
        self.assertRaises(
            lib_exc.Forbidden,
            self.admin_shares_v2_client.delete_share_type_extra_spec,
            st["id"],
            "driver_handles_share_servers")

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    @ddt.data('2.0', '2.23')
    def test_try_delete_required_spec_snapshot_support_version(self, version):
        self.skip_if_microversion_not_supported(version)
        st = self._create_share_type()
        # Try delete extra spec 'snapshot_support'
        self.assertRaises(
            lib_exc.Forbidden,
            self.admin_shares_v2_client.delete_share_type_extra_spec,
            st["id"], "snapshot_support", version=version)
