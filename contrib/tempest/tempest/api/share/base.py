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

from tempest import clients_share as clients
from tempest.common.utils import data_utils
from tempest import config_share as config
from tempest import exceptions
from tempest import test

CONF = config.CONF


class BaseSharesTest(test.BaseTestCase):
    """Base test case class for all Manila API tests."""

    _interface = "json"
    resources_of_tests = []
    protocols = ["nfs", "cifs"]

    @classmethod
    def setUpClass(cls):
        if not any(p in CONF.share.enable_protocols for p in cls.protocols):
            skip_msg = "Manila is disabled"
            raise cls.skipException(skip_msg)
        super(BaseSharesTest, cls).setUpClass()
        cls.os = clients.Manager(interface=cls._interface)
        cls.shares_client = cls.os.shares_client

    @classmethod
    def tearDownClass(cls):
        super(BaseSharesTest, cls).tearDownClass()
        cls.clear_resources()

    @classmethod
    def create_share_wait_for_active(cls, share_protocol=None, size=1,
                                     name=None, snapshot_id=None,
                                     description=None, metadata={},
                                     share_network_id=None, client=None):
        if client is None:
            client = cls.shares_client
        if description is None:
            description = "Tempest's share"
        r, s = client.create_share(share_protocol=share_protocol, size=size,
                                   name=name, snapshot_id=snapshot_id,
                                   description=description,
                                   metadata=metadata,
                                   share_network_id=share_network_id)
        resource = {"type": "share", "body": s, "deleted": False}
        cls.resources_of_tests.insert(0, resource)  # last in first out (LIFO)
        client.wait_for_share_status(s["id"], "available")
        return r, s

    @classmethod
    def create_snapshot_wait_for_active(cls, share_id, name=None,
                                        description=None, force=False,
                                        client=None):
        if client is None:
            client = cls.shares_client
        if description is None:
            description = "Tempest's snapshot"
        r, s = client.create_snapshot(share_id, name, description, force)
        resource = {"type": "snapshot", "body": s, "deleted": False}
        cls.resources_of_tests.insert(0, resource)  # last in first out (LIFO)
        client.wait_for_snapshot_status(s["id"], "available")
        return r, s

    @classmethod
    def create_share_network(cls, client=None, **kwargs):
        if client is None:
            client = cls.shares_client
        resp, sn = client.create_share_network(**kwargs)
        resource = {"type": "share_network", "body": sn, "deleted": False}
        cls.resources_of_tests.insert(0, resource)  # last in first out (LIFO)
        return resp, sn

    @classmethod
    def create_security_service(cls, ss_type="ldap", client=None, **kwargs):
        if client is None:
            client = cls.shares_client
        resp, ss = client.create_security_service(ss_type, **kwargs)
        resource = {"type": "security_service", "body": ss, "deleted": False}
        cls.resources_of_tests.insert(0, resource)  # last in first out (LIFO)
        return resp, ss

    @classmethod
    def clear_resources(cls, client=None):
        if client is None:
            client = cls.shares_client
        # Here we expect, that all resources were added as LIFO
        # due to restriction of deletion resources, that is in the chain
        for index, res in enumerate(cls.resources_of_tests):
            if not(res["deleted"]):
                try:
                    if res["type"] is "share":
                        client.delete_share(res["body"]['id'])
                    elif res["type"] is "snapshot":
                        client.delete_snapshot(res["body"]['id'])
                    elif res["type"] is "share_network":
                        client.delete_share_network(res["body"]['id'])
                    elif res["type"] is "security_service":
                        client.delete_security_service(res["body"]['id'])
                except exceptions.NotFound:
                    pass
                cls.resources_of_tests[index]["deleted"] = True
                client.wait_for_resource_deletion(res["body"]['id'])

    @classmethod
    def generate_share_network_data(self):
        data = {
            "name": data_utils.rand_name("sn-name"),
            "description": data_utils.rand_name("sn-desc"),
            "neutron_net_id": data_utils.rand_name("net-id"),
            "neutron_subnet_id": data_utils.rand_name("subnet-id"),
        }
        return data

    @classmethod
    def generate_security_service_data(self):
        data = {
            "name": data_utils.rand_name("ss-name"),
            "description": data_utils.rand_name("ss-desc"),
            "dns_ip": data_utils.rand_name("ss-dns_ip"),
            "server": data_utils.rand_name("ss-server"),
            "domain": data_utils.rand_name("ss-domain"),
            "sid": data_utils.rand_name("ss-sid"),
            "password": data_utils.rand_name("ss-password"),
        }
        return data


class BaseSharesAdminTest(BaseSharesTest):
    """Base test case class for all Shares Admin API tests."""

    @classmethod
    def setUpClass(cls):
        super(BaseSharesAdminTest, cls).setUpClass()
        cls.adm_user = CONF.identity.admin_username
        cls.adm_pass = CONF.identity.admin_password
        cls.adm_tenant = CONF.identity.admin_tenant_name
        if not all((cls.adm_user, cls.adm_pass, cls.adm_tenant)):
            msg = ("Missing Shares Admin API credentials "
                   "in configuration.")
            raise cls.skipException(msg)
        cls.os_adm = clients.AdminManager(interface=cls._interface)
        cls.shares_client = cls.os_adm.shares_client
        cls.shares_client.share_network_id = CONF.share.admin_share_network_id
