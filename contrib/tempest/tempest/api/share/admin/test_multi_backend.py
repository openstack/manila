# Copyright 2014 Mirantis Inc.
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
from tempest import test

CONF = config.CONF


class ShareMultiBackendTest(base.BaseSharesAdminTest):

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(ShareMultiBackendTest, cls).setUpClass()
        if not CONF.share.multi_backend:
            raise cls.skipException("Manila multi-backend tests are disabled.")
        elif len(CONF.share.backend_names) < 2:
            raise cls.skipException("For running multi-backend tests required"
                                    " two names in config. Skipping.")
        elif any(not name for name in CONF.share.backend_names):
            raise cls.skipException("Share backend names can not be empty. "
                                    "Skipping.")
        cls.vts = []
        cls.shares = []

        # Create volume types
        for i in [0, 1]:
            vt_name = data_utils.rand_name("volume-type-%s" % str(i))
            extra_specs = {
                "share_backend_name": CONF.share.backend_names[i],
            }
            __, vt = cls.create_volume_type(name=vt_name,
                                            extra_specs=extra_specs)
            cls.vts.append(vt)

        # Create shares
        for vt in cls.vts:
            __, share = cls.create_share(volume_type_id=vt["id"],
                                         wait_for_active=False)
            cls.shares.append(share)

        # Wait for active statuses of shares
        for share in cls.shares:
            cls.shares_client.wait_for_share_status(share["id"], "available")

    @test.attr(type=["gate", "smoke", ])
    def test_share_backend_name_reporting(self):
        # Share's 'host' should be like "hostname@backend_name"
        for share in self.shares:
            __, get = self.shares_client.get_share(share['id'])
            self.assertTrue(len(get["host"].split("@")) == 2)

    @test.attr(type=["gate", "smoke", ])
    def test_share_volume_type(self):
        # Volume type should be the same as provided with share creation
        for i in [0, 1]:
            __, get = self.shares_client.get_share(self.shares[i]['id'])
            self.assertEqual(get["volume_type"], self.vts[i]["name"])

    @test.attr(type=["gate", ])
    def test_share_export_locations(self):
        # Different backends have different IPs on interfaces
        # and export locations should be different too.
        if CONF.share.backend_names[0] == CONF.share.backend_names[1]:
            raise self.skipException("Share backends "
                                     "configured with same name. Skipping.")
        ips = []
        for share in self.shares:
            __, get = self.shares_client.get_share(share['id'])
            if get["share_proto"].lower() == "nfs":
                # %ip%:/%share_path%
                ip = get["export_location"].split(":")[0]
                ips.append(ip)
            elif get["share_proto"].lower() == "cifs":
                # //%ip%/%share_path%
                ip = get["export_location"][2:].split("/")[0]
                ips.append(ip)
        self.assertNotEqual(ips[0], ips[1])

    @test.attr(type=["gate", ])
    def test_share_backend_name_distinction(self):
        # Different share backends should have different host records
        if CONF.share.backend_names[0] == CONF.share.backend_names[1]:
            raise self.skipException("Share backends "
                                     "configured with same name. Skipping.")
        __, get1 = self.shares_client.get_share(self.shares[0]['id'])
        __, get2 = self.shares_client.get_share(self.shares[1]['id'])
        self.assertNotEqual(get1["host"], get2["host"])
