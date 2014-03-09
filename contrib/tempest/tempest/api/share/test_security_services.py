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


class SecurityServicesTest(base.BaseSharesTest):

    @test.attr(type=["gate", "smoke"])
    def test_create_delete_security_service(self):
        data = self.generate_security_service_data()
        self.service_names = ["ldap", "kerberos", "active_directory"]
        for ss_name in self.service_names:
            resp, ss = self.create_security_service(ss_name, **data)
            self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
            self.assertDictContainsSubset(data, ss)
            self.assertEqual(ss_name, ss["type"])

            resp, __ = self.shares_client.delete_security_service(ss["id"])
            self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", "smoke"])
    def test_get_security_service(self):
        data = self.generate_security_service_data()
        resp, ss = self.create_security_service(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, ss)

        resp, get = self.shares_client.get_security_service(ss["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, get)

    @test.attr(type=["gate", "smoke"])
    def test_update_security_service(self):
        data = self.generate_security_service_data()
        resp, ss = self.create_security_service(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, ss)

        upd_data = self.generate_security_service_data()
        resp, updated = self.shares_client.update_security_service(ss["id"],
                                                                   **upd_data)

        resp, get = self.shares_client.get_security_service(ss["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(upd_data, updated)
        self.assertDictContainsSubset(upd_data, get)

    @test.attr(type=["gate", "smoke"])
    def test_list_security_services(self):
        data = self.generate_security_service_data()
        resp, ss = self.create_security_service(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, ss)

        resp, listed = self.shares_client.list_security_services()
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        any(ss["id"] in ss["id"] for ss in listed)

        # verify keys
        keys = ["name", "id", "status"]
        [self.assertIn(key, s_s.keys()) for s_s in listed for key in keys]

    @test.attr(type=["gate", "smoke"])
    def test_list_security_services_with_detail(self):
        data = self.generate_security_service_data()
        resp, ss = self.create_security_service(**data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertDictContainsSubset(data, ss)

        resp, listed = self.shares_client.list_security_services_with_detail()
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        any(ss["id"] in ss["id"] for ss in listed)

        # verify keys
        keys = ["name", "id", "status", "description",
                "domain", "server", "dns_ip", "sid", "password", "type",
                "created_at", "updated_at"]
        [self.assertIn(key, s_s.keys()) for s_s in listed for key in keys]
