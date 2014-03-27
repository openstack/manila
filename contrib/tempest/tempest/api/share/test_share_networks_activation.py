# Copyright 2014 mirantis Inc.
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
from tempest import clients_share as clients
from tempest import exceptions
from tempest import test


class SharenetworkActivationTest(base.BaseSharesTest):
    """For testing activation of share-networks.

    Here all test cases were combined in one test method,
    because its too expensive to activate new share-network
    for each test. Activation can take about 2 minutes.
    """

    @classmethod
    def setUpClass(cls):
        cls.os = clients.Manager(interface=cls._interface)

        # Redefine share_network_id, because we do not need it
        cls.os.shares_client.share_network_id = "fake"
        super(SharenetworkActivationTest, cls).setUpClass()

    @test.attr(type=["gate", ])
    def test_share_network_activation_deactivation(self):

        # Get isolated client
        client = self.get_client_with_isolated_creads(type_of_creds="admin")

        # Try create share with inactive share-network
        self.assertRaises(exceptions.BadRequest,
                          client.create_share,
                          share_network_id=client.share_network_id, )

        # Activate share-network
        resp, __ = client.activate_share_network(client.share_network_id)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        client.wait_for_share_network_status(client.share_network_id)

        # Create share
        resp, share = self.create_share_wait_for_active(client=client)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # Try deactivate
        self.assertRaises(exceptions.BadRequest,
                          client.deactivate_share_network,
                          client.share_network_id)

        # Delete share
        resp, __ = client.delete_share(share["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        client.wait_for_resource_deletion(share_id=share["id"])

        # Deactivate
        resp, __ = client.deactivate_share_network(client.share_network_id)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        client.wait_for_share_network_status(client.share_network_id,
                                             "inactive")

        # Try create share with inactive share-network
        self.assertRaises(exceptions.BadRequest,
                          client.create_share,
                          share_network_id=client.share_network_id, )

        # Verify that no shares exist
        resp, shares = client.list_shares()
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(0, len(shares))
