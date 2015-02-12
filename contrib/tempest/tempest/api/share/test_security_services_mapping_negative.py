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

import testtools  # noqa

from tempest.api.share import base
from tempest import config_share as config
from tempest import exceptions
from tempest import test

CONF = config.CONF


class SecServicesMappingNegativeTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(SecServicesMappingNegativeTest, cls).resource_setup()
        __, cls.sn = cls.create_share_network(cleanup_in_class=True)
        __, cls.ss = cls.create_security_service(cleanup_in_class=True)
        cls.cl = cls.shares_client

    @test.attr(type=["gate", "smoke", "negative"])
    def test_add_sec_service_twice_to_share_network(self):
        resp, __ = self.cl.add_sec_service_to_share_network(self.sn["id"],
                                                            self.ss["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertRaises(exceptions.Conflict,
                          self.cl.add_sec_service_to_share_network,
                          self.sn["id"], self.ss["id"])

    @test.attr(type=["gate", "smoke", "negative"])
    def test_add_nonexistant_sec_service_to_share_network(self):
        self.assertRaises(exceptions.NotFound,
                          self.cl.add_sec_service_to_share_network,
                          self.sn["id"], "wrong_ss_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_add_empty_sec_service_id_to_share_network(self):
        self.assertRaises(exceptions.NotFound,
                          self.cl.add_sec_service_to_share_network,
                          self.sn["id"], "")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_add_sec_service_to_nonexistant_share_network(self):
        self.assertRaises(exceptions.NotFound,
                          self.cl.add_sec_service_to_share_network,
                          "wrong_sn_id", self.ss["id"])

    @test.attr(type=["gate", "smoke", "negative"])
    def test_add_sec_service_to_share_network_with_empty_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.cl.add_sec_service_to_share_network,
                          "", self.ss["id"])

    @test.attr(type=["gate", "smoke", "negative"])
    def test_list_sec_services_for_nonexistant_share_network(self):
        self.assertRaises(exceptions.NotFound,
                          self.cl.list_sec_services_for_share_network,
                          "wrong_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_delete_nonexistant_sec_service_from_share_network(self):
        self.assertRaises(exceptions.NotFound,
                          self.cl.remove_sec_service_from_share_network,
                          self.sn["id"], "wrong_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_delete_sec_service_from_nonexistant_share_network(self):
        self.assertRaises(exceptions.NotFound,
                          self.cl.remove_sec_service_from_share_network,
                          "wrong_id", self.ss["id"])

    @test.attr(type=["gate", "smoke", "negative"])
    def test_delete_nonexistant_ss_from_nonexistant_sn(self):
        self.assertRaises(exceptions.NotFound,
                          self.cl.remove_sec_service_from_share_network,
                          "wrong_id", "wrong_id")

    @test.attr(type=["gate", "smoke", "negative"])
    @testtools.skipIf(
        not CONF.share.multitenancy_enabled, "Only for multitenancy.")
    def test_delete_ss_from_sn_used_by_share_server(self):
        sn = self.shares_client.get_share_network(
            self.os.shares_client.share_network_id)[1]
        resp, fresh_sn = self.create_share_network(
            neutron_net_id=sn["neutron_net_id"],
            neutron_subnet_id=sn["neutron_subnet_id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        resp, body = self.shares_client.add_sec_service_to_share_network(
            fresh_sn["id"], self.ss["id"])
        resp, share = self.create_share(share_network_id=fresh_sn["id"],
                                        cleanup_in_class=False)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertRaises(exceptions.Unauthorized,
                          self.cl.remove_sec_service_from_share_network,
                          fresh_sn["id"],
                          self.ss["id"])

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_map_two_ss_with_same_type_to_sn(self):
        # create share network
        data = self.generate_share_network_data()

        resp, sn = self.create_share_network(client=self.cl, **data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, sn)

        # create security services with same type
        security_services = []
        for i in range(2):
            data = self.generate_security_service_data()
            resp, ss = self.create_security_service(client=self.cl, **data)
            self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
            self.assertDictContainsSubset(data, ss)
            security_services.insert(i, ss)

        # Add security service to share network
        resp, __ = self.cl.add_sec_service_to_share_network(
            sn["id"], security_services[0]["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # Try to add security service with same type
        self.assertRaises(exceptions.Conflict,
                          self.cl.add_sec_service_to_share_network,
                          sn["id"], security_services[1]["id"])

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_delete_ss_that_assigned_to_sn(self):
        # create share network
        data = self.generate_share_network_data()

        resp, sn = self.create_share_network(client=self.cl, **data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, sn)

        # create security service
        data = self.generate_security_service_data()

        resp, ss = self.create_security_service(client=self.cl, **data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, ss)

        # Add security service to share network
        resp, __ = self.cl.add_sec_service_to_share_network(sn["id"],
                                                            ss["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # Try delete ss, that has been assigned to some sn
        self.assertRaises(exceptions.Unauthorized,
                          self.cl.delete_security_service,
                          ss["id"], )

        # remove seurity service from share-network
        resp, __ = self.cl.remove_sec_service_from_share_network(sn["id"],
                                                                 ss["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
