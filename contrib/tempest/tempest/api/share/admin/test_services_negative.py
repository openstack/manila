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

from tempest_lib import exceptions as lib_exc  # noqa

from tempest.api.share import base
from tempest import clients_share as clients
from tempest import test


class ServicesAdminNegativeTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ServicesAdminNegativeTest, cls).resource_setup()
        user_clients = clients.Manager()
        cls.user_shares_client = user_clients.shares_client

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_list_services_with_non_admin_user(self):
        self.assertRaises(lib_exc.Unauthorized,
                          self.user_shares_client.list_services)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_get_service_by_invalid_params(self):
        # All services are expected if send the request with invalid parameter
        resp, services = self.shares_client.list_services()
        params = {'fake_param': 'fake_param_value'}
        resp, services_fake = self.shares_client.list_services(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(len(services), len(services_fake))

        # "update_at" field could be updated before second request,
        # so do not take it in account.
        for service in services + services_fake:
            service["updated_at"] = "removed_possible_difference"
        self.assertEqual(services, services_fake)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_get_service_by_invalid_host(self):
        params = {'host': 'fake_host'}
        resp, services_fake = self.shares_client.list_services(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(0, len(services_fake))

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_get_service_by_invalid_binary(self):
        params = {'binary': 'fake_binary'}
        resp, services_fake = self.shares_client.list_services(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(0, len(services_fake))

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_get_service_by_invalid_zone(self):
        params = {'zone': 'fake_zone'}
        resp, services_fake = self.shares_client.list_services(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(0, len(services_fake))

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_get_service_by_invalid_status(self):
        params = {'status': 'fake_status'}
        resp, services_fake = self.shares_client.list_services(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(0, len(services_fake))

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_get_service_by_invalid_state(self):
        params = {'state': 'fake_state'}
        resp, services_fake = self.shares_client.list_services(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(0, len(services_fake))
