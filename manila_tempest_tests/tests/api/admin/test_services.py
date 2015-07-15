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

from tempest import test  # noqa

from manila_tempest_tests.tests.api import base


class ServicesAdminTest(base.BaseSharesAdminTest):

    def setUp(self):
        super(ServicesAdminTest, self).setUp()
        self.services = self.shares_client.list_services()

    @test.attr(type=["gate", "smoke", ])
    def test_list_services(self):
        services = self.shares_client.list_services()
        self.assertNotEqual(0, len(services))

        for service in services:
            self.assertIsNotNone(service['id'])

    @test.attr(type=["gate", "smoke", ])
    def test_get_services_by_host_name(self):
        host = self.services[0]["host"]
        params = {"host": host}
        services = self.shares_client.list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(host, service["host"])

    @test.attr(type=["gate", "smoke", ])
    def test_get_services_by_binary_name(self):
        binary = self.services[0]["binary"]
        params = {"binary": binary, }
        services = self.shares_client.list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(binary, service["binary"])

    @test.attr(type=["gate", "smoke", ])
    def test_get_services_by_availability_zone(self):
        zone = self.services[0]["zone"]
        params = {"zone": zone, }
        services = self.shares_client.list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(zone, service["zone"])

    @test.attr(type=["gate", "smoke", ])
    def test_get_services_by_status(self):
        status = self.services[0]["status"]
        params = {"status": status, }
        services = self.shares_client.list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(status, service["status"])

    @test.attr(type=["gate", "smoke", ])
    def test_get_services_by_state(self):
        state = self.services[0]["state"]
        params = {"state": state, }
        services = self.shares_client.list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(state, service["state"])

    @test.attr(type=["gate", "smoke", ])
    def test_get_services_by_all_filters(self):
        params = {
            "host": self.services[0]["host"],
            "binary": self.services[0]["binary"],
            "zone": self.services[0]["zone"],
            "status": self.services[0]["status"],
            "state": self.services[0]["state"],
        }
        services = self.shares_client.list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(params["host"], service["host"])
            self.assertEqual(params["binary"], service["binary"])
            self.assertEqual(params["zone"], service["zone"])
            self.assertEqual(params["status"], service["status"])
            self.assertEqual(params["state"], service["state"])
