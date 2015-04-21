# Copyright 2015 Deutsche Telekom AG
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

from oslo_log import log  # noqa
from tempest_lib.common.utils import data_utils  # noqa

from tempest import clients_share
from tempest.common.utils.linux import remote_client
from tempest import config
from tempest.scenario import manager

CONF = config.CONF

LOG = log.getLogger(__name__)


class ShareScenarioTest(manager.NetworkScenarioTest):
    """Provide harness to do Manila scenario tests."""

    @classmethod
    def resource_setup(cls):
        cls.set_network_resources()
        super(ShareScenarioTest, cls).resource_setup()

        os = clients_share.Manager(
            credentials=cls.credentials()
        )
        # Manila clients
        cls.shares_client = os.shares_client
        cls.shares_admin_client = clients_share.AdminManager().shares_client

    def _create_share(self, share_protocol=None, size=1, name=None,
                      snapshot_id=None, description=None, metadata=None,
                      share_network_id=None, share_type_id=None,
                      client=None, cleanup_in_class=True):
        """Create a share

        :param share_protocol: NFS or CIFS
        :param size: size in GB
        :param name: name of the share (otherwise random)
        :param snapshot_id: snapshot as basis for the share
        :param description: description of the share
        :param metadata: adds additional metadata
        :param share_network_id: id of network to be used
        :param share_type_id: type of the share to be created
        :param client: client object
        :param cleanup_in_class: default: True
        :returns: a created share
        """
        client = client or self.shares_client
        description = description or "Tempest's share"
        if not name:
            name = data_utils.rand_name("manila-scenario")
        share_network_id = share_network_id or client.share_network_id or None
        metadata = metadata or {}
        kwargs = {
            'share_protocol': share_protocol,
            'size': size,
            'name': name,
            'snapshot_id': snapshot_id,
            'description': description,
            'metadata': metadata,
            'share_network_id': share_network_id,
            'share_type_id': share_type_id,
        }
        share = self.shares_client.create_share(**kwargs)

        self.addCleanup(client.wait_for_resource_deletion,
                        share_id=share['id'])
        self.addCleanup(client.delete_share,
                        share['id'])

        client.wait_for_share_status(share['id'], 'available')
        return share

    def _wait_for_share_server_deletion(self, sn_id, client=None):
        """Wait for a share server to be deleted

        :param sn_id: shared network id
        :param client: client object
        """
        client = client or self.shares_admin_client
        servers = client.list_share_servers(
            search_opts={"share_network": sn_id})
        for server in servers:
            client.delete_share_server(server['id'])
            client.wait_for_resource_deletion(server_id=server['id'])

    def _create_share_network(self, client=None, **kwargs):
        """Create a share network

        :param client: client object
        :returns: a created share network
        """

        client = client or self.shares_client
        sn = client.create_share_network(**kwargs)

        self.addCleanup(client.wait_for_resource_deletion,
                        sn_id=sn['id'])
        self.addCleanup(client.delete_share_network,
                        sn['id'])
        self.addCleanup(self._wait_for_share_server_deletion,
                        sn['id'])
        return sn

    def _allow_access(self, share_id, client=None,
                      access_type="ip", access_to="0.0.0.0"):
        """Allow share access

        :param share_id: id of the share
        :param client: client object
        :param access_type: "ip", "user" or "cert"
        :param access_to
        :returns: access object
        """
        client = client or self.shares_client
        access = client.create_access_rule(share_id, access_type, access_to)
        client.wait_for_access_rule_status(share_id, access['id'], "active")
        self.addCleanup(client.delete_access_rule,
                        share_id, access['id'])
        return access

    def _create_router_interface(self, subnet_id, client=None,
                                 tenant_id=None, router_id=None):
        """Create a router interface

        :param subnet_id: id of the subnet
        :param client: client object
        :param tenant_id
        """
        if not client:
            client = self.network_client
        if not tenant_id:
            tenant_id = client.tenant_id
        if not router_id:
            router_id = self._get_router()['id']
        client.add_router_interface_with_subnet_id(router_id,
                                                   subnet_id)
        self.addCleanup(client.remove_router_interface_with_subnet_id,
                        router_id, subnet_id)

    def get_remote_client(self, *args, **kwargs):
        if not CONF.share.image_with_share_tools:
            return super(ShareScenarioTest,
                         self).get_remote_client(*args, **kwargs)
        # HINT(mkoderer): as workaround for bug #1421104 we have to ignore the
        # keypair and use the configured username and password
        server_or_ip = kwargs['server_or_ip']
        if isinstance(server_or_ip, six.string_types):
            ip = server_or_ip
        else:
            addr = server_or_ip['addresses'][CONF.compute.network_for_ssh][0]
            ip = addr['addr']

        username = CONF.share.image_username
        password = CONF.share.image_password

        linux_client = remote_client.RemoteClient(ip, username=username,
                                                  password=password, pkey=None)
        try:
            linux_client.validate_authentication()
        except Exception:
            LOG.exception('Initializing SSH connection to %s failed' % ip)
            self._log_console_output()
            raise

        return linux_client
