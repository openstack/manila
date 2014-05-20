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
from tempest import config_share as config
from tempest import exceptions
from tempest import test

CONF = config.CONF


class VolumeTypesAdminTest(base.BaseSharesAdminTest):

    @test.attr(type=["gate", "smoke", ])
    def test_volume_type_create_delete(self):
        name = data_utils.rand_name("tempest-manila")

        # Create volume type
        resp, vt_create = self.shares_client.create_volume_type(name)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(name, vt_create['name'])

        # Delete volume type
        resp, __ = self.shares_client.delete_volume_type(vt_create['id'])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # Verify deletion of volume type
        self.shares_client.wait_for_resource_deletion(vt_id=vt_create['id'])
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_volume_type,
                          vt_create['id'])

    @test.attr(type=["gate", "smoke", ])
    def test_volume_type_create_get(self):
        name = data_utils.rand_name("tempest-manila")
        extra_specs = {"key": "value", }

        # Create volume type
        resp, vt_create = self.create_volume_type(name,
                                                  extra_specs=extra_specs)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(name, vt_create['name'])

        # Get volume type
        resp, get = self.shares_client.get_volume_type(vt_create['id'])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(name, get["name"])
        self.assertEqual(vt_create["id"], get["id"])
        self.assertEqual(extra_specs, get["extra_specs"])

    @test.attr(type=["gate", "smoke", ])
    def test_volume_type_create_list(self):
        name = data_utils.rand_name("tempest-manila")

        # Create volume type
        resp, vt_create = self.create_volume_type(name)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # list volume types
        resp, vt_list = self.shares_client.list_volume_types()
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertTrue(len(vt_list) >= 1)
        self.assertTrue(any(vt_create["id"] in vt["id"] for vt in vt_list))

    @test.attr(type=["gate", "smoke", ])
    def test_get_share_with_volume_type(self):

        # Data
        share_name = data_utils.rand_name("share")
        vol_type_name = data_utils.rand_name("volume-type")
        extra_specs = {
            "storage_protocol": CONF.share.storage_protocol,
        }

        # Create volume type
        resp, vt_create = self.create_volume_type(vol_type_name,
                                                  extra_specs=extra_specs)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # Create share with volume type
        resp, share = self.create_share(
            name=share_name, volume_type_id=vt_create["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(share["name"], share_name)
        self.shares_client.wait_for_share_status(share["id"], "available")

        # Verify share info
        resp, get = self.shares_client.get_share(share["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(share_name, get["name"])
        self.assertEqual(share["id"], get["id"])
        self.assertEqual(vol_type_name, get["volume_type"])
