# Copyright (c) 2014 EMC Corporation.
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

"""
EMC specific NAS storage driver. This driver is a pluggable driver
that allows specific EMC NAS devices to be plugged-in as the underlying
backend. Use the Manila configuration variable "share_backend_name"
to specify, which backend plugins to use.
"""

from oslo_config import cfg

from manila.share import driver
from manila.share.drivers.dell_emc import plugin_manager as manager

EMC_NAS_OPTS = [
    cfg.StrOpt('emc_nas_login',
               help='User name for the EMC server.'),
    cfg.StrOpt('emc_nas_password',
               help='Password for the EMC server.'),
    cfg.HostAddressOpt('emc_nas_server',
                       help='EMC server hostname or IP address.'),
    cfg.PortOpt('emc_nas_server_port',
                default=8080,
                help='Port number for the EMC server.'),
    cfg.BoolOpt('emc_nas_server_secure',
                default=True,
                help='Use secure connection to server.'),
    cfg.StrOpt('emc_share_backend',
               ignore_case=True,
               choices=['isilon', 'vnx', 'unity', 'vmax'],
               help='Share backend.'),
    cfg.StrOpt('emc_nas_root_dir',
               help='The root directory where shares will be located.'),
    cfg.BoolOpt('emc_ssl_cert_verify',
                default=True,
                help='If set to False the https client will not validate the '
                     'SSL certificate of the backend endpoint.'),
    cfg.StrOpt('emc_ssl_cert_path',
               help='Can be used to specify a non default path to a '
                    'CA_BUNDLE file or directory with certificates of trusted '
                    'CAs, which will be used to validate the backend.')
]

CONF = cfg.CONF
CONF.register_opts(EMC_NAS_OPTS)


class EMCShareDriver(driver.ShareDriver):
    """EMC specific NAS driver. Allows for NFS and CIFS NAS storage usage."""

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.get('configuration', None)
        if self.configuration:
            self.configuration.append_config_values(EMC_NAS_OPTS)
            self.backend_name = self.configuration.safe_get(
                'emc_share_backend')
        else:
            self.backend_name = CONF.emc_share_backend
        self.backend_name = self.backend_name or 'EMC_NAS_Storage'
        self.plugin_manager = manager.EMCPluginManager(
            namespace='manila.share.drivers.dell_emc.plugins')
        self.plugin = self.plugin_manager.load_plugin(
            self.backend_name,
            configuration=self.configuration)
        super(EMCShareDriver, self).__init__(
            self.plugin.driver_handles_share_servers, *args, **kwargs)

        if hasattr(self.plugin, 'ipv6_implemented'):
            self.ipv6_implemented = self.plugin.ipv6_implemented

    def create_share(self, context, share, share_server=None):
        """Is called to create share."""
        location = self.plugin.create_share(context, share, share_server)

        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        location = self.plugin.create_share_from_snapshot(
            context, share, snapshot, share_server)

        return location

    def extend_share(self, share, new_size, share_server=None):
        """Is called to extend share."""
        self.plugin.extend_share(share, new_size, share_server)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create snapshot."""
        self.plugin.create_snapshot(context, snapshot, share_server)

    def delete_share(self, context, share, share_server=None):
        """Is called to remove share."""
        self.plugin.delete_share(context, share, share_server)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove snapshot."""
        self.plugin.delete_snapshot(context, snapshot, share_server)

    def ensure_share(self, context, share, share_server=None):
        """Invoked to sure that share is exported."""
        self.plugin.ensure_share(context, share, share_server)

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        self.plugin.allow_access(context, share, access, share_server)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        self.plugin.deny_access(context, share, access, share_server)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access to the share."""
        self.plugin.update_access(context, share, access_rules, add_rules,
                                  delete_rules, share_server)

    def check_for_setup_error(self):
        """Check for setup error."""
        self.plugin.check_for_setup_error()

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""
        self.plugin.connect(self, context)

    def _update_share_stats(self):
        """Retrieve stats info from share."""

        backend_name = self.configuration.safe_get(
            'share_backend_name') or "EMC_NAS_Storage"
        data = dict(
            share_backend_name=backend_name,
            vendor_name='Dell EMC',
            storage_protocol='NFS_CIFS',
            snapshot_support=True,
            create_share_from_snapshot_support=True)
        self.plugin.update_share_stats(data)
        super(EMCShareDriver, self)._update_share_stats(data)

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return self.plugin.get_network_allocations_number()

    def _setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""
        return self.plugin.setup_server(network_info, metadata)

    def _teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        return self.plugin.teardown_server(server_details, security_services)

    def get_configured_ip_versions(self):
        if self.ipv6_implemented:
            return [4, 6]
        else:
            return [4]
