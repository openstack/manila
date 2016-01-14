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

from tempest import config  # noqa
from tempest import test  # noqa
from tempest_lib.common.utils import data_utils  # noqa

from manila_tempest_tests.tests.api import base


CONF = config.CONF


class ShareMultiBackendTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ShareMultiBackendTest, cls).resource_setup()
        if not CONF.share.multi_backend:
            raise cls.skipException("Manila multi-backend tests are disabled.")
        elif len(CONF.share.backend_names) < 2:
            raise cls.skipException("For running multi-backend tests required"
                                    " two names in config. Skipping.")
        elif any(not name for name in CONF.share.backend_names):
            raise cls.skipException("Share backend names can not be empty. "
                                    "Skipping.")
        cls.sts = []
        cls.shares = []
        share_data_list = []

        # Create share types
        for i in [0, 1]:
            st_name = data_utils.rand_name("share-type-%s" % str(i))
            extra_specs = {
                "share_backend_name": CONF.share.backend_names[i],
            }
            st = cls.create_share_type(
                name=st_name,
                extra_specs=cls.add_required_extra_specs_to_dict(extra_specs))
            cls.sts.append(st["share_type"])
            st_id = st["share_type"]["id"]
            share_data_list.append({"kwargs": {"share_type_id": st_id}})

        # Create shares using precreated share types
        cls.shares = cls.create_shares(share_data_list)

    @test.attr(type=["gate", "smoke", ])
    def test_share_backend_name_reporting(self):
        # Share's 'host' should be like "hostname@backend_name"
        for share in self.shares:
            get = self.shares_client.get_share(share['id'])
            self.assertTrue(len(get["host"].split("@")) == 2)

    @test.attr(type=["gate", "smoke", ])
    def test_share_share_type(self):
        # Share type should be the same as provided with share creation
        for i in [0, 1]:
            get = self.shares_v2_client.get_share(self.shares[i]['id'],
                                                  version="2.5")
            self.assertEqual(get["share_type"], self.sts[i]["name"])

    @test.attr(type=["gate", "smoke", ])
    def test_share_share_type_v_2_6(self):
        # Share type should be the same as provided with share creation
        for i in [0, 1]:
            get = self.shares_v2_client.get_share(self.shares[i]['id'],
                                                  version="2.6")
            self.assertEqual(get["share_type"], self.sts[i]["id"])
            self.assertEqual(get["share_type_name"], self.sts[i]["name"])

    @test.attr(type=["gate", ])
    def test_share_backend_name_distinction(self):
        # Different share backends should have different host records
        if CONF.share.backend_names[0] == CONF.share.backend_names[1]:
            raise self.skipException("Share backends "
                                     "configured with same name. Skipping.")
        get1 = self.shares_client.get_share(self.shares[0]['id'])
        get2 = self.shares_client.get_share(self.shares[1]['id'])
        self.assertNotEqual(get1["host"], get2["host"])
