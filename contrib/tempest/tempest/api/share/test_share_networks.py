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
from tempest import test


class ShareNetworksTest(base.BaseSharesTest):

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(ShareNetworksTest, cls).setUpClass()
        cls.data = cls.generate_share_network_data()
        __, cls.sn = cls.create_share_network(cleanup_in_class=True,
                                              **cls.data)

    @test.attr(type=["gate", "smoke", ])
    def test_create_delete_share_network(self):
        # generate data for share network
        data = self.generate_share_network_data()

        # create share network
        resp, created = self.shares_client.create_share_network(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, created)

        # Delete share_network
        resp, __ = self.shares_client.delete_share_network(created["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", "smoke", ])
    def test_get_share_network(self):
        resp, get = self.shares_client.get_share_network(self.sn["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(self.data, get)

    @test.attr(type=["gate", "smoke", ])
    def test_update_share_network(self):
        update_data = self.generate_share_network_data()
        resp, updated = self.shares_client.update_share_network(self.sn["id"],
                                                                **update_data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(update_data, updated)

    @test.attr(type=["gate", "smoke"])
    def test_update_valid_keys_sh_server_exists(self):
        resp, share = self.create_share(cleanup_in_class=False)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        update_dict = {
            "name": "new_name",
            "description": "new_description",
        }
        resp, updated = self.shares_client.update_share_network(
            self.shares_client.share_network_id, **update_dict)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(update_dict, updated)

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_networks(self):
        resp, listed = self.shares_client.list_share_networks()
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        any(self.sn["id"] in sn["id"] for sn in listed)

        # verify keys
        keys = ["name", "id", "status"]
        [self.assertIn(key, sn.keys()) for sn in listed for key in keys]

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_networks_with_detail(self):
        resp, listed = self.shares_client.list_share_networks_with_detail()
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        any(self.sn["id"] in sn["id"] for sn in listed)

        # verify keys
        keys = [
            "name", "id", "status", "description", "network_type",
            "project_id", "cidr", "ip_version",
            "neutron_net_id", "neutron_subnet_id",
            "created_at", "updated_at", "segmentation_id",
        ]
        [self.assertIn(key, sn.keys()) for sn in listed for key in keys]

    @test.attr(type=["gate", "smoke", ])
    def test_recreate_share_network(self):
        # generate data for share network
        data = self.generate_share_network_data()

        # create share network
        resp, sn1 = self.shares_client.create_share_network(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, sn1)

        # Delete first share network
        resp, __ = self.shares_client.delete_share_network(sn1["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # create second share network with same data
        resp, sn2 = self.shares_client.create_share_network(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, sn2)

        # Delete second share network
        resp, __ = self.shares_client.delete_share_network(sn2["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", "smoke", ])
    def test_create_two_share_networks_with_same_net_and_subnet(self):
        # generate data for share network
        data = self.generate_share_network_data()

        # create first share network
        resp, sn1 = self.create_share_network(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, sn1)

        # create second share network
        resp, sn2 = self.create_share_network(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, sn2)
