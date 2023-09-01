# Copyright (c) 2023 Dell Inc. or its subsidiaries.
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
PowerFlex specific NAS backend plugin.
"""
from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.plugins import base as driver
from manila.share.drivers.dell_emc.plugins.powerflex import (
    object_manager as manager)

"""Version history:
    1.0 - Initial version
"""

VERSION = "1.0"

CONF = cfg.CONF

LOG = log.getLogger(__name__)

POWERFLEX_OPTS = [
    cfg.StrOpt('powerflex_storage_pool',
               help='Storage pool used to provision NAS.'),
    cfg.StrOpt('powerflex_protection_domain',
               help='Protection domain to use.'),
    cfg.StrOpt('dell_nas_backend_host',
               help='Dell NAS backend hostname or IP address.'),
    cfg.StrOpt('dell_nas_backend_port',
               help='Port number to use with the Dell NAS backend.'),
    cfg.StrOpt('dell_nas_server',
               help='Root directory or NAS server which owns the shares.'),
    cfg.StrOpt('dell_nas_login',
               help='User name for the Dell NAS backend.'),
    cfg.StrOpt('dell_nas_password',
               secret=True,
               help='Password for the Dell NAS backend.')

]


class PowerFlexStorageConnection(driver.StorageConnection):
    """Implements PowerFlex specific functionality for Dell Manila driver."""

    def __init__(self, *args, **kwargs):
        """Do initialization"""

        LOG.debug('Invoking base constructor for Manila \
                  Dell PowerFlex SDNAS Driver.')
        super(PowerFlexStorageConnection,
              self).__init__(*args, **kwargs)

        LOG.debug('Setting up attributes for Manila \
                  Dell PowerFlex SDNAS Driver.')
        if 'configuration' in kwargs:
            kwargs['configuration'].append_config_values(POWERFLEX_OPTS)

        self.manager = None
        self.server = None
        self._username = None
        self._password = None
        self._server_url = None
        self._root_dir = None
        self._verify_ssl_cert = None
        self._shares = {}
        self.verify_certificate = None
        self.certificate_path = None
        self.export_path = None

        self.driver_handles_share_servers = False

        self.reserved_percentage = None
        self.reserved_snapshot_percentage = None
        self.reserved_share_extend_percentage = None
        self.max_over_subscription_ratio = None

    def connect(self, dell_share_driver, context):
        """Connects to Dell PowerFlex SDNAS server."""
        LOG.debug('Reading configuration parameters for Manila \
                  Dell PowerFlex SDNAS Driver.')
        config = dell_share_driver.configuration
        get_config_value = config.safe_get
        self.verify_certificate = get_config_value("dell_ssl_cert_verify")
        self.rest_ip = get_config_value("dell_nas_backend_host")
        self.rest_port = (int(get_config_value("dell_nas_backend_port")) or
                          443)
        self.nas_server = get_config_value("dell_nas_server")
        self.storage_pool = get_config_value("powerflex_storage_pool")
        self.protection_domain = get_config_value(
            "powerflex_protection_domain")
        self.rest_username = get_config_value("dell_nas_login")
        self.rest_password = get_config_value("dell_nas_password")
        if self.verify_certificate:
            self.certificate_path = get_config_value(
                "dell_ssl_certificate_path")
        if not all([self.rest_ip,
                    self.rest_username,
                    self.rest_password]):
            message = _("REST server IP, username and password"
                        " must be specified.")
            raise exception.BadConfigurationException(reason=message)
        # validate certificate settings
        if self.verify_certificate and not self.certificate_path:
            message = _("Path to REST server's certificate must be specified.")
            raise exception.BadConfigurationException(reason=message)

        LOG.debug('Initializing Dell PowerFlex SDNAS Layer.')
        self.host_url = ("https://%(server_ip)s:%(server_port)s" %
                         {
                             "server_ip": self.rest_ip,
                             "server_port": self.rest_port})
        LOG.info("REST server IP: %(ip)s, port: %(port)s, "
                 "username: %(user)s. Verify server's certificate: "
                 "%(verify_cert)s.",
                 {
                     "ip": self.rest_ip,
                     "port": self.rest_port,
                     "user": self.rest_username,
                     "verify_cert": self.verify_certificate,
                 })

        self.manager = manager.StorageObjectManager(self.host_url,
                                                    self.rest_username,
                                                    self.rest_password,
                                                    self.export_path,
                                                    self.certificate_path,
                                                    self.verify_certificate)

        # configuration for share status update
        self.reserved_percentage = config.safe_get(
            'reserved_share_percentage')
        if self.reserved_percentage is None:
            self.reserved_percentage = 0

        self.reserved_snapshot_percentage = config.safe_get(
            'reserved_share_from_snapshot_percentage')
        if self.reserved_snapshot_percentage is None:
            self.reserved_snapshot_percentage = self.reserved_percentage

        self.reserved_share_extend_percentage = config.safe_get(
            'reserved_share_extend_percentage')
        if self.reserved_share_extend_percentage is None:
            self.reserved_share_extend_percentage = self.reserved_percentage

        self.max_over_subscription_ratio = config.safe_get(
            'max_over_subscription_ratio')

    def create_share(self, context, share, share_server):
        """Is called to create a share."""
        LOG.debug(f'Creating {share["share_proto"]} share.')
        location = self._create_nfs_share(share)

        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Is called to create a share from an existing snapshot."""
        raise NotImplementedError()

    def allow_access(self, context, share, access, share_server):
        """Is called to allow access to a share."""
        raise NotImplementedError()

    def check_for_setup_error(self):
        """Is called to check for setup error."""

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Is called to update share access."""
        LOG.debug(f'Updating access to {share["share_proto"]} share.')
        return self._update_nfs_access(share, access_rules)

    def create_snapshot(self, context, snapshot, share_server):
        """Is called to create snapshot."""
        export_name = snapshot['share_name']
        LOG.debug(f'Retrieving filesystem ID for share {export_name}')
        filesystem_id = self.manager.get_fsid_from_export_name(export_name)
        LOG.debug(f'Retrieving snapshot ID for filesystem {filesystem_id}')
        snapshot_id = self.manager.create_snapshot(snapshot['name'],
                                                   filesystem_id)
        if snapshot_id:
            LOG.info("Snapshot %(id)s successfully created.",
                     {'id': snapshot['id']})

    def delete_snapshot(self, context, snapshot, share_server):
        """Is called to delete snapshot."""
        snapshot_name = snapshot['name']
        filesystem_id = self.manager.get_fsid_from_snapshot_name(snapshot_name)
        LOG.debug(f'Retrieving filesystem ID for snapshot {snapshot_name}')
        snapshot_deleted = self.manager.delete_filesystem(filesystem_id)
        if not snapshot_deleted:
            message = (
                _('Failed to delete snapshot "%(snapshot)s".') %
                {'snapshot': snapshot['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        else:
            LOG.info("Snapshot %(id)s successfully deleted.",
                     {'id': snapshot['id']})

    def delete_share(self, context, share, share_server):
        """Is called to delete a share."""
        LOG.debug(f'Deleting {share["share_proto"]} share.')
        self._delete_nfs_share(share)

    def deny_access(self, context, share, access, share_server):
        """Is called to deny access to a share."""
        raise NotImplementedError()

    def ensure_share(self, context, share, share_server):
        """Is called to ensure a share is exported."""

    def extend_share(self, share, new_size, share_server=None):
        """Is called to extend a share."""
        # Converts the size from GiB to Bytes
        new_size_in_bytes = new_size * units.Gi
        LOG.debug(f"Extending {share['name']} to {new_size}GiB")
        filesystem_id = self.manager.get_filesystem_id(share['name'])
        self.manager.extend_export(filesystem_id,
                                   new_size_in_bytes)

    def setup_server(self, network_info, metadata=None):
        """Is called to set up a share server.

        Requires driver_handles_share_servers to be True.
        """
        raise NotImplementedError()

    def teardown_server(self, server_details, security_services=None):
        """Is called to teardown a share server.

        Requires driver_handles_share_servers to be True.
        """
        raise NotImplementedError()

    def _create_nfs_share(self, share):
        """Creates an NFS share.

        In PowerFlex, an export (share) belongs to a filesystem.
        This function creates a filesystem and an export.
        """
        LOG.debug(f'Retrieving Storage Pool ID for {self.storage_pool}')
        storage_pool_id = self.manager.get_storage_pool_id(
            self.protection_domain,
            self.storage_pool)
        nas_server_id = self.manager.get_nas_server_id(self.nas_server)
        LOG.debug(f"Creating filesystem {share['name']}")
        size_in_bytes = share['size'] * units.Gi
        filesystem_id = self.manager.create_filesystem(storage_pool_id,
                                                       self.nas_server,
                                                       share['name'],
                                                       size_in_bytes)
        if not filesystem_id:
            message = {
                _('The requested NFS export "%(export)s"'
                    ' was not created.') %
                {'export': share['name']}}
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        LOG.debug(f"Creating export {share['name']}")
        export_id = self.manager.create_nfs_export(filesystem_id,
                                                   share['name'])
        if not export_id:
            message = (
                _('The requested NFS export "%(export)s"'
                    ' was not created.') %
                {'export': share['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        file_interfaces = self.manager.get_nas_server_interfaces(
            nas_server_id)
        export_path = self.manager.get_nfs_export_name(export_id)
        locations = self._get_nfs_location(file_interfaces,
                                           export_path)
        return locations

    def _delete_nfs_share(self, share):
        """Deletes a filesystem and its associated export."""
        filesystem_id = self.manager.get_filesystem_id(share['name'])
        LOG.debug(f"Retrieving filesystem ID for filesystem {share['name']}")
        if filesystem_id is None:
            message = ('Attempted to delete NFS export "%s",'
                       ' but the export does not appear to exist.')
            LOG.warning(message, share['name'])
        else:
            LOG.debug(f"Deleting filesystem ID {filesystem_id}")
            share_deleted = self.manager.delete_filesystem(filesystem_id)
            if not share_deleted:
                message = (
                    _('Failed to delete NFS export "%(export)s".') %
                    {'export': share['name']})
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)

    def _update_nfs_access(self, share, access_rules):
        """Updates access rules for NFS share type."""
        nfs_rw_ips = set()
        nfs_ro_ips = set()
        access_updates = {}

        for rule in access_rules:
            if rule['access_type'].lower() != 'ip':
                message = (_("Only IP access type currently supported for "
                             "NFS. Share provided %(share)s with rule type "
                             "%(type)s") % {'share': share['display_name'],
                                            'type': rule['access_type']})
                LOG.error(message)
                access_updates.update({rule['access_id']: {'state': 'error'}})

            else:
                if rule['access_level'] == const.ACCESS_LEVEL_RW:
                    nfs_rw_ips.add(rule['access_to'])
                elif rule['access_level'] == const.ACCESS_LEVEL_RO:
                    nfs_ro_ips.add(rule['access_to'])
                access_updates.update({rule['access_id']: {'state': 'active'}})

        share_id = self.manager.get_nfs_export_id(share['name'])
        share_updated = self.manager.set_export_access(share_id,
                                                       nfs_rw_ips,
                                                       nfs_ro_ips)
        if not share_updated:
            message = (
                _('Failed to update NFS access rules for "%(export)s".') %
                {'export': share['display_name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        return access_updates

    def update_share_stats(self, stats_dict):
        """Retrieve stats info from share."""
        stats_dict['driver_version'] = VERSION
        stats_dict['storage_protocol'] = 'NFS'
        stats_dict['create_share_from_snapshot_support'] = False
        stats_dict['pools'] = []
        storage_pool_id = self.manager.get_storage_pool_id(
            self.protection_domain,
            self.storage_pool
            )
        total = free = used = provisioned = 0
        statistic = self.manager.get_storage_pool_statistic(storage_pool_id)
        if statistic:
            total = statistic.get('maxCapacityInKb') // units.Mi
            free = statistic.get('netUnusedCapacityInKb') // units.Mi
            used = statistic.get('capacityInUseInKb') // units.Mi
            provisioned = statistic.get('primaryVacInKb') // units.Mi
        pool_stat = {
            'pool_name': self.storage_pool,
            'thin_provisioning': True,
            'total_capacity_gb': total,
            'free_capacity_gb': free,
            'allocated_capacity_gb': used,
            'provisioned_capacity_gb': provisioned,
            'qos': False,
            'reserved_percentage': self.reserved_percentage,
            'reserved_snapshot_percentage':
                self.reserved_snapshot_percentage,
            'reserved_share_extend_percentage':
                self.reserved_share_extend_percentage,
            'max_over_subscription_ratio':
                self.max_over_subscription_ratio
        }
        stats_dict['pools'].append(pool_stat)

    def _get_nfs_location(self, file_interfaces, export_path):
        export_locations = []
        for interface in file_interfaces:
            export_locations.append(
                {'path': f"{interface}:/{export_path}"})
        return export_locations

    def get_default_filter_function(self):
        return 'share.size >= 3'
