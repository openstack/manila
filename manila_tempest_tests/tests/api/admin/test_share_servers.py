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

import re

import six  # noqa
from tempest import config  # noqa
from tempest import test  # noqa
from tempest_lib import exceptions as lib_exc  # noqa

from manila_tempest_tests.tests.api import base

CONF = config.CONF


class ShareServersAdminTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ShareServersAdminTest, cls).resource_setup()
        if not CONF.share.multitenancy_enabled:
            msg = ("Share servers can be tested only with multitenant drivers."
                   " Skipping.")
            raise cls.skipException(msg)
        cls.share = cls.create_share()
        cls.share_network = cls.shares_client.get_share_network(
            cls.shares_client.share_network_id)
        if not cls.share_network["name"]:
            sn_id = cls.share_network["id"]
            cls.share_network = cls.shares_client.update_share_network(
                sn_id, name="sn_%s" % sn_id)
        cls.sn_name_and_id = [
            cls.share_network["name"],
            cls.share_network["id"],
        ]

        # Date should be like '2014-13-12T11:10:09.000000'
        cls.date_re = re.compile("^([0-9]{4}-[0-9]{2}-[0-9]{2}[A-Z]{1}"
                                 "[0-9]{2}:[0-9]{2}:[0-9]{2}).*$")

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_servers_without_filters(self):
        servers = self.shares_client.list_share_servers()
        self.assertTrue(len(servers) > 0)
        keys = [
            "id",
            "host",
            "status",
            "share_network_name",
            "updated_at",
            "project_id",
        ]
        for server in servers:
            # All expected keys are present
            for key in keys:
                self.assertIn(key, server.keys())
            # 'Updated at' is valid date if set
            if server["updated_at"]:
                self.assertTrue(self.date_re.match(server["updated_at"]))
            # Host is not empty
            self.assertTrue(len(server["host"]) > 0)
            # Id is not empty
            self.assertTrue(len(server["id"]) > 0)
            # Project id is not empty
            self.assertTrue(len(server["project_id"]) > 0)

        # Do not verify statuses because we get all share servers from whole
        # cluster and here can be servers with any state.
        # Server we used is present.
        any(s["share_network_name"] in self.sn_name_and_id for s in servers)

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_servers_with_host_filter(self):
        # Get list of share servers and remember 'host' name
        servers = self.shares_client.list_share_servers()
        # Remember name of server that was used by this test suite
        # to be sure it will be still existing.
        host = ""
        for server in servers:
            if server["share_network_name"] in self.sn_name_and_id:
                if not server["host"]:
                    msg = ("Server '%s' has wrong value for host - "
                           "'%s'.") % (server["id"], server["host"])
                    raise lib_exc.InvalidContentType(message=msg)
                host = server["host"]
                break
        if not host:
            msg = ("Appropriate server was not found. Its share_network_data"
                   ": '%s'. List of servers: '%s'.") % (self.sn_name_and_id,
                                                        str(servers))
            raise lib_exc.NotFound(message=msg)
        search_opts = {"host": host}
        servers = self.shares_client.list_share_servers(search_opts)
        self.assertTrue(len(servers) > 0)
        for server in servers:
            self.assertEqual(server["host"], host)

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_servers_with_status_filter(self):
        # Get list of share servers
        servers = self.shares_client.list_share_servers()
        # Remember status of server that was used by this test suite
        # to be sure it will be still existing.
        status = ""
        for server in servers:
            if server["share_network_name"] in self.sn_name_and_id:
                if not server["status"]:
                    msg = ("Server '%s' has wrong value for status - "
                           "'%s'.") % (server["id"], server["host"])
                    raise lib_exc.InvalidContentType(message=msg)
                status = server["status"]
                break
        if not status:
            msg = ("Appropriate server was not found. Its share_network_data"
                   ": '%s'. List of servers: '%s'.") % (self.sn_name_and_id,
                                                        str(servers))
            raise lib_exc.NotFound(message=msg)
        search_opts = {"status": status}
        servers = self.shares_client.list_share_servers(search_opts)
        self.assertTrue(len(servers) > 0)
        for server in servers:
            self.assertEqual(server["status"], status)

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_servers_with_project_id_filter(self):
        search_opts = {"project_id": self.share_network["project_id"]}
        servers = self.shares_client.list_share_servers(search_opts)
        # Should exist, at least, one share server, used by this test suite.
        self.assertTrue(len(servers) > 0)
        for server in servers:
            self.assertEqual(server["project_id"],
                             self.share_network["project_id"])

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_servers_with_share_network_name_filter(self):
        search_opts = {"share_network": self.share_network["name"]}
        servers = self.shares_client.list_share_servers(search_opts)
        # Should exist, at least, one share server, used by this test suite.
        self.assertTrue(len(servers) > 0)
        for server in servers:
            self.assertEqual(server["share_network_name"],
                             self.share_network["name"])

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_servers_with_share_network_id_filter(self):
        search_opts = {"share_network": self.share_network["id"]}
        servers = self.shares_client.list_share_servers(search_opts)
        # Should exist, at least, one share server, used by this test suite.
        self.assertTrue(len(servers) > 0)
        for server in servers:
            self.assertIn(server["share_network_name"],
                          self.sn_name_and_id)

    @test.attr(type=["gate", "smoke", ])
    def test_show_share_server(self):
        servers = self.shares_client.list_share_servers()
        server = self.shares_client.show_share_server(servers[0]["id"])
        keys = [
            "id",
            "host",
            "project_id",
            "status",
            "share_network_name",
            "created_at",
            "updated_at",
            "backend_details",
        ]
        # all expected keys are present
        for key in keys:
            self.assertIn(key, server.keys())
        # 'created_at' is valid date
        self.assertTrue(self.date_re.match(server["created_at"]))
        # 'updated_at' is valid date if set
        if server["updated_at"]:
            self.assertTrue(self.date_re.match(server["updated_at"]))
        # Host is not empty
        self.assertTrue(len(server["host"]) > 0)
        # Id is not empty
        self.assertTrue(len(server["id"]) > 0)
        # Project id is not empty
        self.assertTrue(len(server["project_id"]) > 0)
        # Status is not empty
        self.assertTrue(len(server["status"]) > 0)
        # share_network_name is not empty
        self.assertTrue(len(server["share_network_name"]) > 0)
        # backend_details should be a dict
        self.assertIsInstance(server["backend_details"], dict)

    @test.attr(type=["gate", "smoke", ])
    def test_show_share_server_details(self):
        servers = self.shares_client.list_share_servers()
        details = self.shares_client.show_share_server_details(
            servers[0]["id"])
        # If details are present they and their values should be only strings
        for k, v in details.iteritems():
            self.assertIsInstance(k, six.string_types)
            self.assertIsInstance(v, six.string_types)

    @test.attr(type=["gate", "smoke", ])
    def _delete_share_server(self, delete_share_network):
        # Get network and subnet from existing share_network and reuse it
        # to be able to delete share_server after test ends.
        # TODO(vponomaryov): attach security-services too. If any exist from
        #                    donor share-network.
        new_sn = self.create_share_network(
            neutron_net_id=self.share_network['neutron_net_id'],
            neutron_subnet_id=self.share_network['neutron_subnet_id'])

        # Create server with share
        share = self.create_share(share_network_id=new_sn['id'])

        # List share servers, filtered by share_network_id
        search_opts = {"share_network": new_sn["id"]}
        servers = self.shares_client.list_share_servers(search_opts)

        # There can be more than one share server for share network when retry
        # was used and share was created successfully not from first time.
        # So, iterate all share-servers, release all created resources. It will
        # allow share network to be deleted in cleanup.
        for serv in servers:
            # Verify that filtering worked as expected.
            self.assertEqual(new_sn["id"], serv["share_network_id"])

            # List shares by share server id
            params = {"share_server_id": serv["id"]}
            shares = self.shares_client.list_shares_with_detail(params)
            for s in shares:
                self.assertEqual(new_sn["id"], s["share_network_id"])
            self.assertTrue(any(share["id"] == s["id"] for s in shares))

            # Delete shares, so we will have share server without shares
            for s in shares:
                self.shares_client.delete_share(s["id"])

            # Wait for shares deletion
            for s in shares:
                self.shares_client.wait_for_resource_deletion(share_id=s["id"])

            # List shares by share server id, we expect empty list
            params = {"share_server_id": serv["id"]}
            empty = self.shares_client.list_shares_with_detail(params)
            self.assertEqual(len(empty), 0)

            if delete_share_network:
                # Delete share network, it should trigger share server deletion
                self.shares_client.delete_share_network(new_sn["id"])
            else:
                # Delete share server
                self.shares_client.delete_share_server(serv["id"])

            # Wait for share server deletion
            self.shares_client.wait_for_resource_deletion(server_id=serv["id"])

            if delete_share_network:
                self.shares_client.wait_for_resource_deletion(
                    sn_id=new_sn["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_delete_share_server(self):
        self._delete_share_server(False)

    @test.attr(type=["gate", "smoke", ])
    def test_delete_share_server_by_deletion_of_share_network(self):
        self._delete_share_server(True)
