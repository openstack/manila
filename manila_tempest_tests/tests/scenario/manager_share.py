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

from oslo_log import log
import six

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.scenario import manager

from manila_tempest_tests.common import constants
from manila_tempest_tests.common import remote_client
from manila_tempest_tests.services.share.json import shares_client
from manila_tempest_tests.services.share.v2.json import (
    shares_client as shares_v2_client)

CONF = config.CONF
LOG = log.getLogger(__name__)


class ShareScenarioTest(manager.NetworkScenarioTest):
    """Provide harness to do Manila scenario tests."""

    credentials = ('admin', 'primary')

    @classmethod
    def resource_setup(cls):
        cls.set_network_resources()
        super(ShareScenarioTest, cls).resource_setup()

        # Manila clients
        cls.shares_client = shares_client.SharesClient(
            cls.os_primary.auth_provider)
        cls.shares_v2_client = shares_v2_client.SharesV2Client(
            cls.os_primary.auth_provider)
        cls.shares_admin_client = shares_client.SharesClient(
            cls.os_admin.auth_provider)
        cls.shares_admin_v2_client = shares_v2_client.SharesV2Client(
            cls.os_admin.auth_provider)

    @classmethod
    def skip_checks(cls):
        super(ShareScenarioTest, cls).skip_checks()
        if not CONF.service_available.manila:
            raise cls.skipException("Manila support is required")

    def _create_share(self, share_protocol=None, size=None, name=None,
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
        if CONF.share.multitenancy_enabled:
            share_network_id = (share_network_id or client.share_network_id)
        else:
            share_network_id = None
        metadata = metadata or {}
        kwargs = {
            'share_protocol': share_protocol,
            'size': size or CONF.share.share_size,
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

    def _create_snapshot(self, share_id, client=None, **kwargs):
        client = client or self.shares_v2_client
        snapshot = client.create_snapshot(share_id, **kwargs)
        self.addCleanup(
            client.wait_for_resource_deletion, snapshot_id=snapshot['id'])
        self.addCleanup(client.delete_snapshot, snapshot['id'])
        client.wait_for_snapshot_status(snapshot["id"], "available")
        return snapshot

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
        for server in servers:
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
                      access_type="ip", access_to="0.0.0.0", cleanup=True):
        """Allow share access

        :param share_id: id of the share
        :param client: client object
        :param access_type: "ip", "user" or "cert"
        :param access_to
        :returns: access object
        """
        client = client or self.shares_client
        access = client.create_access_rule(share_id, access_type, access_to)

        # NOTE(u_glide): Ignore provided client, because we always need v2
        # client to make this call
        self.shares_v2_client.wait_for_share_status(
            share_id, "active", status_attr='access_rules_status')

        if cleanup:
            self.addCleanup(client.delete_access_rule, share_id, access['id'])
        return access

    def _create_router_interface(self, subnet_id, client=None, router_id=None):
        """Create a router interface

        :param subnet_id: id of the subnet
        :param client: client object
        """
        if not client:
            client = self.routers_client
        if not router_id:
            router_id = self._get_router()['id']
        client.add_router_interface(router_id, subnet_id=subnet_id)
        self.addCleanup(
            client.remove_router_interface, router_id, subnet_id=subnet_id)

    def get_remote_client(self, *args, **kwargs):
        if not CONF.share.image_with_share_tools:
            return super(ShareScenarioTest,
                         self).get_remote_client(*args, **kwargs)
        # NOTE(u_glide): We need custom implementation of this method until
        # original implementation depends on CONF.compute.ssh_auth_method
        # option.
        server_or_ip = kwargs['server_or_ip']
        if isinstance(server_or_ip, six.string_types):
            ip = server_or_ip
        else:
            addr = server_or_ip['addresses'][CONF.compute.network_for_ssh][0]
            ip = addr['addr']

        # NOTE(u_glide): Both options (pkey and password) are required here to
        # support service images without Nova metadata support
        client_params = {
            'username': kwargs['username'],
            'password': CONF.share.image_password,
            'pkey': kwargs.get('private_key'),
        }

        linux_client = remote_client.RemoteClient(ip, **client_params)
        try:
            linux_client.validate_authentication()
        except Exception:
            LOG.exception('Initializing SSH connection to %s failed' % ip)
            self._log_console_output()
            raise

        return linux_client

    def _migrate_share(self, share_id, dest_host, status, force_host_assisted,
                       client=None):
        client = client or self.shares_admin_v2_client
        client.migrate_share(
            share_id, dest_host, writable=False, preserve_metadata=False,
            nondisruptive=False, preserve_snapshots=False,
            force_host_assisted_migration=force_host_assisted)
        share = client.wait_for_migration_status(share_id, dest_host, status)
        return share

    def _migration_complete(self, share_id, dest_host, client=None, **kwargs):
        client = client or self.shares_admin_v2_client
        client.migration_complete(share_id, **kwargs)
        share = client.wait_for_migration_status(
            share_id, dest_host, constants.TASK_STATE_MIGRATION_SUCCESS,
            **kwargs)
        return share

    def _create_share_type(self, name, is_public=True, **kwargs):
        share_type = self.shares_admin_v2_client.create_share_type(name,
                                                                   is_public,
                                                                   **kwargs)
        self.addCleanup(self.shares_admin_v2_client.delete_share_type,
                        share_type['share_type']['id'])
        return share_type
