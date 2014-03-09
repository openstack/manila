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
from tempest import exceptions
from tempest import test


class ShareNetworksNegativeTest(base.BaseSharesTest):

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_get_share_network_without_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_share_network, "")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_get_share_network_with_wrong_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_share_network, "wrong_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_delete_share_network_without_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_share_network, "")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_delete_share_network_with_wrong_type(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_share_network, "wrong_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_update_nonexistant_share_network(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_share_network,
                          "wrong_id", name="name")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_update_share_network_with_empty_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_share_network,
                          "", name="name")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_get_deleted_share_network(self):
        data = self.generate_share_network_data()
        resp, sn = self.create_share_network(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, sn)

        resp, __ = self.shares_client.delete_share_network(sn["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # try get deleted share network entity
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_security_service,
                          sn["id"])

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_create_duplicate_of_share_network(self):
        data = self.generate_share_network_data()
        resp, sn = self.create_share_network(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, sn)

        # try create duplicate of share network entity
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_share_network,
                          **data)

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_create_duplicate_of_share_network_via_update(self):
        data1 = self.generate_share_network_data()
        resp, sn1 = self.create_share_network(**data1)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data1, sn1)

        data2 = self.generate_share_network_data()
        resp, sn2 = self.create_share_network(**data2)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data2, sn2)

        # try create duplicate of share network entity via update
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.update_share_network,
                          sn2["id"], **data1)
