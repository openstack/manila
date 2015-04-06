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

from tempest_lib.common.utils import data_utils  # noqa
from tempest_lib import exceptions as lib_exc  # noqa

from tempest.api.share import base
from tempest import config_share as config
from tempest import test

CONF = config.CONF


class ShareTypesAdminTest(base.BaseSharesAdminTest):

    @test.attr(type=["gate", "smoke", ])
    def test_share_type_create_delete(self):
        name = data_utils.rand_name("tempest-manila")
        extra_specs = self.add_required_extra_specs_to_dict()

        # Create share type
        resp, st_create = self.shares_client.create_share_type(
            name, extra_specs=extra_specs)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(name, st_create['share_type']['name'])
        st_id = st_create['share_type']['id']

        # Delete share type
        resp, __ = self.shares_client.delete_share_type(st_id)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

        # Verify deletion of share type
        self.shares_client.wait_for_resource_deletion(st_id=st_id)
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_type,
                          st_id)

    @test.attr(type=["gate", "smoke", ])
    def test_share_type_create_get(self):
        name = data_utils.rand_name("tempest-manila")
        extra_specs = self.add_required_extra_specs_to_dict({"key": "value", })

        # Create share type
        resp, st_create = self.create_share_type(name,
                                                 extra_specs=extra_specs)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(name, st_create['share_type']['name'])
        st_id = st_create["share_type"]["id"]

        # Get share type
        resp, get = self.shares_client.get_share_type(st_id)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(name, get["share_type"]["name"])
        self.assertEqual(st_id, get["share_type"]["id"])
        self.assertEqual(extra_specs, get["share_type"]["extra_specs"])

        # Check that backwards compatibility didn't break
        self.assertDictMatch(get["volume_type"], get["share_type"])

    @test.attr(type=["gate", "smoke", ])
    def test_share_type_create_list(self):
        name = data_utils.rand_name("tempest-manila")
        extra_specs = self.add_required_extra_specs_to_dict()

        # Create share type
        resp, st_create = self.create_share_type(name, extra_specs=extra_specs)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        st_id = st_create["share_type"]["id"]

        # list share types
        resp, st_list = self.shares_client.list_share_types()
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        sts = st_list["share_types"]
        self.assertTrue(len(sts) >= 1)
        self.assertTrue(any(st_id in st["id"] for st in sts))

        # Check that backwards compatibility didn't break
        vts = st_list["volume_types"]
        self.assertEqual(len(sts), len(vts))
        for i in xrange(len(sts)):
            self.assertDictMatch(sts[i], vts[i])

    @test.attr(type=["gate", "smoke", ])
    def test_get_share_with_share_type(self):

        # Data
        share_name = data_utils.rand_name("share")
        shr_type_name = data_utils.rand_name("share-type")
        extra_specs = self.add_required_extra_specs_to_dict({
            "storage_protocol": CONF.share.storage_protocol,
        })

        # Create share type
        resp, st_create = self.create_share_type(shr_type_name,
                                                 extra_specs=extra_specs)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

        # Create share with share type
        resp, share = self.create_share(
            name=share_name, share_type_id=st_create["share_type"]["id"])
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(share["name"], share_name)
        self.shares_client.wait_for_share_status(share["id"], "available")

        # Verify share info
        resp, get = self.shares_client.get_share(share["id"])
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(share_name, get["name"])
        self.assertEqual(share["id"], get["id"])
        self.assertEqual(shr_type_name, get["share_type"])

    def test_private_share_type_access(self):
        name = data_utils.rand_name("tempest-manila")
        extra_specs = self.add_required_extra_specs_to_dict({"key": "value", })
        project_id = self.shares_client.tenant_id

        # Create private share type
        resp, st_create = self.create_share_type(
            name, False, extra_specs=extra_specs)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(name, st_create['share_type']['name'])
        st_id = st_create["share_type"]["id"]

        # It should not be listed without access
        resp, st_list = self.shares_client.list_share_types()
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        sts = st_list["share_types"]
        self.assertFalse(any(st_id in st["id"] for st in sts))

        # List projects that have access for share type - none expected
        resp, access = self.shares_client.list_access_to_share_type(st_id)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual([], access)

        # Add project access to share type
        resp, access = self.shares_client.add_access_to_share_type(
            st_id, project_id)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

        # Now it should be listed
        resp, st_list = self.shares_client.list_share_types()
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        sts = st_list["share_types"]
        self.assertTrue(any(st_id in st["id"] for st in sts))

        # List projects that have access for share type - one expected
        resp, access = self.shares_client.list_access_to_share_type(st_id)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        expected = [{'share_type_id': st_id, 'project_id': project_id}, ]
        self.assertEqual(expected, access)

        # Remove project access from share type
        resp, access = self.shares_client.remove_access_from_share_type(
            st_id, project_id)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

        # It should not be listed without access
        resp, st_list = self.shares_client.list_share_types()
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        sts = st_list["share_types"]
        self.assertFalse(any(st_id in st["id"] for st in sts))

        # List projects that have access for share type - none expected
        resp, access = self.shares_client.list_access_to_share_type(st_id)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual([], access)
