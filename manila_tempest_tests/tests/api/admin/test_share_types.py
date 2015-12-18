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
from tempest import config  # noqa
from tempest import test  # noqa
from tempest_lib.common.utils import data_utils  # noqa
from tempest_lib import exceptions as lib_exc  # noqa

from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


@ddt.ddt
class ShareTypesAdminTest(base.BaseSharesAdminTest):

    @test.attr(type=["gate", "smoke", ])
    def test_share_type_create_delete(self):
        name = data_utils.rand_name("tempest-manila")
        extra_specs = self.add_required_extra_specs_to_dict()

        # Create share type
        st_create = self.shares_v2_client.create_share_type(
            name, extra_specs=extra_specs)
        self.assertEqual(name, st_create['share_type']['name'])
        st_id = st_create['share_type']['id']

        # Delete share type
        self.shares_v2_client.delete_share_type(st_id)

        # Verify deletion of share type
        self.shares_v2_client.wait_for_resource_deletion(st_id=st_id)
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_share_type,
                          st_id)

    def _verify_is_public_key_name(self, share_type, version):
        old_key_name = 'os-share-type-access:is_public'
        new_key_name = 'share_type_access:is_public'
        if utils.is_microversion_gt(version, "2.6"):
            self.assertIn(new_key_name, share_type)
            self.assertNotIn(old_key_name, share_type)
        else:
            self.assertIn(old_key_name, share_type)
            self.assertNotIn(new_key_name, share_type)

    @test.attr(type=["gate", "smoke", ])
    @ddt.data('2.0', '2.6', '2.7')
    def test_share_type_create_get(self, version):
        self.skip_if_microversion_not_supported(version)

        name = data_utils.rand_name("tempest-manila")
        extra_specs = self.add_required_extra_specs_to_dict({"key": "value", })

        # Create share type
        st_create = self.create_share_type(
            name, extra_specs=extra_specs, version=version)
        self.assertEqual(name, st_create['share_type']['name'])
        self._verify_is_public_key_name(st_create['share_type'], version)
        st_id = st_create["share_type"]["id"]

        # Get share type
        get = self.shares_v2_client.get_share_type(st_id, version=version)
        self.assertEqual(name, get["share_type"]["name"])
        self.assertEqual(st_id, get["share_type"]["id"])
        self.assertEqual(extra_specs, get["share_type"]["extra_specs"])
        self._verify_is_public_key_name(get['share_type'], version)

        # Check that backwards compatibility didn't break
        self.assertDictMatch(get["volume_type"], get["share_type"])

    @test.attr(type=["gate", "smoke", ])
    @ddt.data('2.0', '2.6', '2.7')
    def test_share_type_create_list(self, version):
        self.skip_if_microversion_not_supported(version)

        name = data_utils.rand_name("tempest-manila")
        extra_specs = self.add_required_extra_specs_to_dict()

        # Create share type
        st_create = self.create_share_type(
            name, extra_specs=extra_specs, version=version)
        self._verify_is_public_key_name(st_create['share_type'], version)
        st_id = st_create["share_type"]["id"]

        # list share types
        st_list = self.shares_v2_client.list_share_types(version=version)
        sts = st_list["share_types"]
        self.assertTrue(len(sts) >= 1)
        self.assertTrue(any(st_id in st["id"] for st in sts))
        for st in sts:
            self._verify_is_public_key_name(st, version)

        # Check that backwards compatibility didn't break
        vts = st_list["volume_types"]
        self.assertEqual(len(sts), len(vts))
        for i in range(len(sts)):
            self.assertDictMatch(sts[i], vts[i])

    @test.attr(type=["gate", "smoke", ])
    def test_get_share_with_share_type(self):

        # Data
        share_name = data_utils.rand_name("share")
        shr_type_name = data_utils.rand_name("share-type")
        extra_specs = self.add_required_extra_specs_to_dict({
            "storage_protocol": CONF.share.capability_storage_protocol,
        })

        # Create share type
        st_create = self.create_share_type(
            shr_type_name, extra_specs=extra_specs)

        # Create share with share type
        share = self.create_share(
            name=share_name, share_type_id=st_create["share_type"]["id"])
        self.assertEqual(share["name"], share_name)
        self.shares_client.wait_for_share_status(share["id"], "available")

        # Verify share info
        get = self.shares_v2_client.get_share(share["id"], version="2.5")
        self.assertEqual(share_name, get["name"])
        self.assertEqual(share["id"], get["id"])
        self.assertEqual(shr_type_name, get["share_type"])

        get = self.shares_v2_client.get_share(share["id"], version="2.6")
        self.assertEqual(st_create["share_type"]["id"], get["share_type"])
        self.assertEqual(shr_type_name, get["share_type_name"])

    def test_private_share_type_access(self):
        name = data_utils.rand_name("tempest-manila")
        extra_specs = self.add_required_extra_specs_to_dict({"key": "value", })
        project_id = self.shares_client.tenant_id

        # Create private share type
        st_create = self.create_share_type(
            name, False, extra_specs=extra_specs)
        self.assertEqual(name, st_create['share_type']['name'])
        st_id = st_create["share_type"]["id"]

        # It should not be listed without access
        st_list = self.shares_v2_client.list_share_types()
        sts = st_list["share_types"]
        self.assertFalse(any(st_id in st["id"] for st in sts))

        # List projects that have access for share type - none expected
        access = self.shares_v2_client.list_access_to_share_type(st_id)
        self.assertEqual([], access)

        # Add project access to share type
        access = self.shares_v2_client.add_access_to_share_type(
            st_id, project_id)

        # Now it should be listed
        st_list = self.shares_client.list_share_types()
        sts = st_list["share_types"]
        self.assertTrue(any(st_id in st["id"] for st in sts))

        # List projects that have access for share type - one expected
        access = self.shares_v2_client.list_access_to_share_type(st_id)
        expected = [{'share_type_id': st_id, 'project_id': project_id}, ]
        self.assertEqual(expected, access)

        # Remove project access from share type
        access = self.shares_v2_client.remove_access_from_share_type(
            st_id, project_id)

        # It should not be listed without access
        st_list = self.shares_client.list_share_types()
        sts = st_list["share_types"]
        self.assertFalse(any(st_id in st["id"] for st in sts))

        # List projects that have access for share type - none expected
        access = self.shares_v2_client.list_access_to_share_type(st_id)
        self.assertEqual([], access)
