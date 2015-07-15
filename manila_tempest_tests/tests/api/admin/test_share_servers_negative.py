# Copyright 2014 OpenStack Foundation
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
from tempest_lib.common.utils import data_utils  # noqa
from tempest_lib import exceptions as lib_exc  # noqa

from manila_tempest_tests import clients_share as clients
from manila_tempest_tests.tests.api import base


class ShareServersNegativeAdminTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ShareServersNegativeAdminTest, cls).resource_setup()
        cls.member_shares_client = clients.Manager().shares_client

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_try_list_share_servers_with_member(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.member_shares_client.list_share_servers)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_try_show_share_server_with_member(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.member_shares_client.show_share_server,
                          'fake_id')

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_try_show_share_server_details_with_member(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.member_shares_client.show_share_server_details,
                          'fake_id')

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_show_share_server_with_inexistent_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.show_share_server,
                          'fake_id')

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_show_share_server_details_with_inexistent_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.show_share_server_details,
                          'fake_id')

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_list_share_servers_with_wrong_filter_key(self):
        search_opts = {'fake_filter_key': 'ACTIVE'}
        servers = self.shares_client.list_share_servers(search_opts)
        self.assertEqual(len(servers), 0)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_list_share_servers_with_wrong_filter_value(self):
        search_opts = {'host': 123}
        servers = self.shares_client.list_share_servers(search_opts)
        self.assertEqual(len(servers), 0)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_list_share_servers_with_fake_status(self):
        search_opts = {"status": data_utils.rand_name("fake_status")}
        servers = self.shares_client.list_share_servers(search_opts)
        self.assertEqual(len(servers), 0)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_list_share_servers_with_fake_host(self):
        search_opts = {"host": data_utils.rand_name("fake_host")}
        servers = self.shares_client.list_share_servers(search_opts)
        self.assertEqual(len(servers), 0)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_list_share_servers_with_fake_project(self):
        search_opts = {"project_id": data_utils.rand_name("fake_project_id")}
        servers = self.shares_client.list_share_servers(search_opts)
        self.assertEqual(len(servers), 0)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_list_share_servers_with_fake_share_network(self):
        search_opts = {
            "share_network": data_utils.rand_name("fake_share_network"),
        }
        servers = self.shares_client.list_share_servers(search_opts)
        self.assertEqual(len(servers), 0)

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_delete_share_server_with_nonexistent_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.delete_share_server,
                          "fake_nonexistent_share_server_id")

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_delete_share_server_with_member(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.member_shares_client.delete_share_server,
                          "fake_nonexistent_share_server_id")
