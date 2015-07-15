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

from tempest import config  # noqa
from tempest import test  # noqa
from tempest_lib import exceptions as lib_exc  # noqa
import testtools  # noqa

from manila_tempest_tests.tests.api import base

CONF = config.CONF


class ShareNetworksNegativeTest(base.BaseSharesTest):

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_get_share_network_without_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_network, "")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_get_share_network_with_wrong_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share_network, "wrong_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_delete_share_network_without_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_share_network, "")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_delete_share_network_with_wrong_type(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_share_network, "wrong_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_update_nonexistant_share_network(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.update_share_network,
                          "wrong_id", name="name")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_update_share_network_with_empty_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.update_share_network,
                          "", name="name")

    @test.attr(type=["gate", "smoke", "negative"])
    @testtools.skipIf(
        not CONF.share.multitenancy_enabled, "Only for multitenancy.")
    def test_try_update_invalid_keys_sh_server_exists(self):
        self.create_share(cleanup_in_class=False)

        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.update_share_network,
                          self.shares_client.share_network_id,
                          neutron_net_id="new_net_id")

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_get_deleted_share_network(self):
        data = self.generate_share_network_data()
        sn = self.create_share_network(**data)
        self.assertDictContainsSubset(data, sn)

        self.shares_client.delete_share_network(sn["id"])

        # try get deleted share network entity
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_security_service,
                          sn["id"])

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_list_share_networks_all_tenants(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.list_share_networks_with_detail,
                          params={'all_tenants': 1})

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_list_share_networks_project_id(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_client.list_share_networks_with_detail,
                          params={'project_id': 'some_project'})

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_list_share_networks_wrong_created_since_value(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.shares_client.list_share_networks_with_detail,
            params={'created_since': '2014-10-23T08:31:58.000000'})

    @test.attr(type=["gate", "smoke", "negative"])
    def test_try_list_share_networks_wrong_created_before_value(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self.shares_client.list_share_networks_with_detail,
            params={'created_before': '2014-10-23T08:31:58.000000'})

    @test.attr(type=["gate", "smoke", "negative"])
    @testtools.skipIf(not CONF.share.multitenancy_enabled,
                      'Can run only with drivers that do handle share servers '
                      'creation. Skipping.')
    def test_try_delete_share_network_with_existing_shares(self):
        # Get valid network data for successful share creation
        share_network = self.shares_client.get_share_network(
            self.shares_client.share_network_id)
        new_sn = self.create_share_network(
            neutron_net_id=share_network['neutron_net_id'],
            neutron_subnet_id=share_network['neutron_subnet_id'],
            nova_net_id=share_network['nova_net_id'],
            cleanup_in_class=False)

        # Create share with share network
        self.create_share(
            share_network_id=new_sn['id'], cleanup_in_class=False)

        # Try delete share network
        self.assertRaises(
            lib_exc.Conflict,
            self.shares_client.delete_share_network, new_sn['id'])
