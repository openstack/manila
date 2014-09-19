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

import six  # noqa

from tempest.api.share import base
from tempest import exceptions
from tempest.openstack.common import log as logging
from tempest import test

LOG = logging.getLogger(__name__)


class SecurityServicesNegativeTest(base.BaseSharesTest):

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_create_security_service_with_empty_type(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_security_service, "")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_create_security_service_with_wrong_type(self):
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.create_security_service,
                          "wrong_type")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_get_security_service_without_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_security_service, "")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_get_security_service_with_wrong_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_security_service,
                          "wrong_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_delete_security_service_without_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_security_service, "")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_delete_security_service_with_wrong_type(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.delete_security_service,
                          "wrong_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_update_nonexistant_security_service(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_security_service,
                          "wrong_id", name="name")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_update_security_service_with_empty_id(self):
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.update_security_service,
                          "", name="name")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_update_invalid_keys_sh_server_exists(self):
        ss_data = self.generate_security_service_data()
        resp, ss = self.create_security_service(**ss_data)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        sn = self.shares_client.get_share_network(
            self.os.shares_client.share_network_id)[1]
        resp, fresh_sn = self.create_share_network(
            neutron_net_id=sn["neutron_net_id"],
            neutron_subnet_id=sn["neutron_subnet_id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        resp, body = self.shares_client.add_sec_service_to_share_network(
            fresh_sn["id"], ss["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # Security service with fake data is used, so if we use backend driver
        # that fails on wrong data, we expect error here.
        # We require any share that uses our share-network.
        try:
            resp, share = self.create_share(share_network_id=fresh_sn["id"],
                                            cleanup_in_class=False)
        except Exception as e:
            # we do wait for either 'error' or 'available' status because
            # it is the only available statuses for proper deletion.
            LOG.warning("Caught exception. It is expected in case backend "
                        "fails having security-service with improper data "
                        "that leads to share-server creation error. "
                        "%s" % six.text_type(e))

        self.assertRaises(exceptions.Unauthorized,
                          self.shares_client.update_security_service,
                          ss["id"],
                          user="new_user")

    @test.attr(type=["gate", "smoke", "negative"])
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
