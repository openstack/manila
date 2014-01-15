# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from tempest import clients_shares as clients
from tempest.common import isolated_creds
from tempest import config_shares as config
from tempest import exceptions
from tempest import test

CONF = config.CONF


class BaseSharesTest(test.BaseTestCase):

    """Base test case class for all Manila API tests."""

    _interface = "json"
    resources_of_tests = []

    @classmethod
    def setUpClass(cls):
        if not CONF.service_available.manila:
            skip_msg = "Manila not available"
            raise cls.skipException(skip_msg)
        super(BaseSharesTest, cls).setUpClass()
        cls.isolated_creds = isolated_creds.IsolatedCreds(cls.__name__)
        if CONF.compute.allow_tenant_isolation:
            creds = cls.isolated_creds.get_primary_creds()
            username, tenant_name, password = creds
            cls.os = clients.Manager(username=username,
                                     password=password,
                                     tenant_name=tenant_name,
                                     interface=cls._interface)
        else:
            cls.os = clients.Manager(interface=cls._interface)
        cls.shares_client = cls.os.shares_client
        cls.build_interval = CONF.shares.build_interval
        cls.build_timeout = CONF.shares.build_timeout

    @classmethod
    def tearDownClass(cls):
        super(BaseSharesTest, cls).tearDownClass()
        cls.isolated_creds.clear_isolated_creds()
        cls.clear_resources()

    @classmethod
    def create_share_wait_for_active(cls,
                                     share_protocol=None,
                                     size=1,
                                     name=None,
                                     snapshot_id=None,
                                     description="tempests share",
                                     metadata={},
                                     client=None):
        if client is None:
            client = cls.shares_client
        r, s = client.create_share(share_protocol=share_protocol, size=size,
                                   name=name, snapshot_id=snapshot_id,
                                   description=description,
                                   metadata=metadata)
        resource = {"type": "share", "body": s, "deleted": False}
        cls.resources_of_tests.insert(0, resource)  # last in first out (LIFO)
        client.wait_for_share_status(s["id"], "available")
        return r, s

    @classmethod
    def create_snapshot_wait_for_active(cls,
                                        share_id,
                                        name=None,
                                        description="tempests share-ss",
                                        force=False,
                                        client=None):
        if client is None:
            client = cls.shares_client
        r, s = client.create_snapshot(share_id, name, description, force)
        resource = {"type": "snapshot", "body": s, "deleted": False}
        cls.resources_of_tests.insert(0, resource)  # last in first out (LIFO)
        client.wait_for_snapshot_status(s["id"], "available")
        return r, s

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
                    cls.resources_of_tests[index]["deleted"] = True
                except exceptions.NotFound:
                    pass
                client.wait_for_resource_deletion(res["body"]['id'])


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
        if CONF.compute.allow_tenant_isolation:
            creds = cls.isolated_creds.get_admin_creds()
            admin_username, admin_tenant_name, admin_password = creds
            cls.os_adm = clients.Manager(username=admin_username,
                                         password=admin_password,
                                         tenant_name=admin_tenant_name,
                                         interface=cls._interface)
        else:
            cls.os_adm = clients.AdminManager(interface=cls._interface)
        cls.shares_client = cls.os_adm.shares_client
