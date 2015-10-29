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

import ddt
from tempest import test

from manila_tempest_tests.tests.api import base


@ddt.ddt
class ServicesAdminTest(base.BaseSharesAdminTest):

    def setUp(self):
        super(ServicesAdminTest, self).setUp()
        self.services = self.shares_client.list_services()

    @test.attr(type=["gate", "smoke", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_list_services(self, client_name):
        services = getattr(self, client_name).list_services()
        self.assertNotEqual(0, len(services))

        for service in services:
            self.assertIsNotNone(service['id'])

    @test.attr(type=["gate", "smoke", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_get_services_by_host_name(self, client_name):
        host = self.services[0]["host"]
        params = {"host": host}
        services = getattr(self, client_name).list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(host, service["host"])

    @test.attr(type=["gate", "smoke", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_get_services_by_binary_name(self, client_name):
        binary = self.services[0]["binary"]
        params = {"binary": binary, }
        services = getattr(self, client_name).list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(binary, service["binary"])

    @test.attr(type=["gate", "smoke", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_get_services_by_availability_zone(self, client_name):
        zone = self.services[0]["zone"]
        params = {"zone": zone, }
        services = getattr(self, client_name).list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(zone, service["zone"])

    @test.attr(type=["gate", "smoke", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_get_services_by_status(self, client_name):
        status = self.services[0]["status"]
        params = {"status": status, }
        services = getattr(self, client_name).list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(status, service["status"])

    @test.attr(type=["gate", "smoke", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_get_services_by_state(self, client_name):
        state = self.services[0]["state"]
        params = {"state": state, }
        services = getattr(self, client_name).list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(state, service["state"])

    @test.attr(type=["gate", "smoke", ])
    @ddt.data('shares_client', 'shares_v2_client')
    def test_get_services_by_all_filters(self, client_name):
        params = {
            "host": self.services[0]["host"],
            "binary": self.services[0]["binary"],
            "zone": self.services[0]["zone"],
            "status": self.services[0]["status"],
            "state": self.services[0]["state"],
        }
        services = getattr(self, client_name).list_services(params)
        self.assertNotEqual(0, len(services))
        for service in services:
            self.assertEqual(params["host"], service["host"])
            self.assertEqual(params["binary"], service["binary"])
            self.assertEqual(params["zone"], service["zone"])
            self.assertEqual(params["status"], service["status"])
            self.assertEqual(params["state"], service["state"])
