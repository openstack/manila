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


class SecurityServicesNegativeTest(base.BaseSharesAdminTest):

    @test.attr(type=['negative', ])
    def test_try_create_security_service_with_empty_type(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_security_service, "")

    @test.attr(type=['negative', ])
    def test_try_create_security_service_with_wrong_type(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_security_service,
                          "wrong_type")

    @test.attr(type=['negative', ])
    def test_try_get_security_service_without_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_security_service, "")

    @test.attr(type=['negative', ])
    def test_try_get_security_service_with_wrong_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_security_service,
                          "wrong_id")

    @test.attr(type=['negative', ])
    def test_try_delete_security_service_without_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_security_service, "")

    @test.attr(type=['negative', ])
    def test_try_delete_security_service_with_wrong_type(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_security_service,
                          "wrong_id")

    @test.attr(type=['negative', ])
    def test_try_update_nonexistant_security_service(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_security_service,
                          "wrong_id", name="name")

    @test.attr(type=['negative', ])
    def test_try_update_security_service_with_empty_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_security_service,
                          "", name="name")

    @test.attr(type=['negative', ])
    def test_get_deleted_security_service(self):
        data = self.generate_security_service_data()
        resp, ss = self.create_security_service(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, ss)

        resp, __ = self.shares_client.delete_security_service(ss["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # try get deleted security service entity
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_security_service,
                          ss["id"])
