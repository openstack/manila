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
PowerStore specific NAS backend plugin.
"""
from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.plugins import base as driver
from manila.share.drivers.dell_emc.plugins.powerstore import client

"""Version history:
    1.0 - Initial version
"""
VERSION = "1.0"

CONF = cfg.CONF

LOG = log.getLogger(__name__)

POWERSTORE_OPTS = [
    cfg.StrOpt('dell_nas_backend_host',
               help='Dell NAS backend hostname or IP address.'),
    cfg.StrOpt('dell_nas_server',
               help='Root directory or NAS server which owns the shares.'),
    cfg.StrOpt('dell_ad_domain',
               help='Domain name of the active directory '
               'joined by the NAS server.'),
    cfg.StrOpt('dell_nas_login',
               help='User name for the Dell NAS backend.'),
    cfg.StrOpt('dell_nas_password',
               secret=True,
               help='Password for the Dell NAS backend.'),
    cfg.BoolOpt('dell_ssl_cert_verify',
                default=False,
                help='If set to False the https client will not validate the '
                     'SSL certificate of the backend endpoint.'),
    cfg.StrOpt('dell_ssl_cert_path',
               help='Can be used to specify a non default path to a '
                    'CA_BUNDLE file or directory with certificates of trusted '
                    'CAs, which will be used to validate the backend.')
]


class PowerStoreStorageConnection(driver.StorageConnection):
    """Implements PowerStore specific functionality for Dell Manila driver."""

    def __init__(self, *args, **kwargs):
        """Do initialization"""

        LOG.debug('Invoking base constructor for Manila'
                  ' Dell PowerStore Driver.')
        super(PowerStoreStorageConnection,
              self).__init__(*args, **kwargs)

        LOG.debug('Setting up attributes for Manila'
                  ' Dell PowerStore Driver.')
        if 'configuration' in kwargs:
            kwargs['configuration'].append_config_values(POWERSTORE_OPTS)

        self.client = None
        self.verify_certificate = None
        self.certificate_path = None
        self.ipv6_implemented = True
        self.revert_to_snap_support = True
        self.shrink_share_support = True

        # props from super class
        self.driver_handles_share_servers = False
        # props for share status update
        self.reserved_percentage = None
        self.reserved_snapshot_percentage = None
        self.reserved_share_extend_percentage = None
        self.max_over_subscription_ratio = None

    def connect(self, dell_share_driver, context):
        """Connects to Dell PowerStore"""
        LOG.debug('Reading configuration parameters for Manila'
                  ' Dell PowerStore Driver.')
        config = dell_share_driver.configuration
        get_config_value = config.safe_get
        self.rest_ip = get_config_value("dell_nas_backend_host")
        self.rest_username = get_config_value("dell_nas_login")
        self.rest_password = get_config_value("dell_nas_password")
        # validate IP, username and password
        if not all([self.rest_ip,
                    self.rest_username,
                    self.rest_password]):
            message = _("REST server IP, username and password"
                        " must be specified.")
            raise exception.BadConfigurationException(reason=message)
        self.nas_server = get_config_value("dell_nas_server")
        self.ad_domain = get_config_value("dell_ad_domain")
        self.verify_certificate = (get_config_value("dell_ssl_cert_verify") or
                                   False)
        if self.verify_certificate:
            self.certificate_path = get_config_value(
                "dell_ssl_cert_path")

        LOG.debug('Initializing Dell PowerStore REST Client.')
        LOG.info("REST server IP: %(ip)s, username: %(user)s. "
                 "Verify server's certificate: %(verify_cert)s.",
                 {
                     "ip": self.rest_ip,
                     "user": self.rest_username,
                     "verify_cert": self.verify_certificate,
                 })

        self.client = client.PowerStoreClient(self.rest_ip,
                                              self.rest_username,
                                              self.rest_password,
                                              self.verify_certificate,
                                              self.certificate_path)

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
        locations = self._create_share(share)
        return locations

    def _create_share(self, share):
        """Creates a NFS or SMB share.

        In PowerStore, an export (share) belongs to a filesystem.
        This function creates a filesystem and an export.
        """
        share_name = share['name']
        size_in_bytes = share['size'] * units.Gi
        # create a filesystem
        nas_server_id = self.client.get_nas_server_id(self.nas_server)
        LOG.debug(f"Creating filesystem {share_name}")
        filesystem_id = self.client.create_filesystem(nas_server_id,
                                                      share_name,
                                                      size_in_bytes)
        if not filesystem_id:
            message = {
                _('The filesystem "%(export)s" was not created.') %
                {'export': share_name}}
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        # create a share
        locations = self._create_share_NFS_CIFS(nas_server_id, filesystem_id,
                                                share_name,
                                                share['share_proto'].upper())
        return locations

    def _create_share_NFS_CIFS(self, nas_server_id, filesystem_id, share_name,
                               protocol):
        LOG.debug(f"Get file interfaces of {nas_server_id}")
        file_interfaces = self.client.get_nas_server_interfaces(
            nas_server_id)
        LOG.debug(f"Creating {protocol} export {share_name}")
        if protocol == 'NFS':
            export_id = self.client.create_nfs_export(filesystem_id,
                                                      share_name)
            if not export_id:
                message = (
                    _('The requested NFS export "%(export)s"'
                        ' was not created.') %
                    {'export': share_name})
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)
            locations = self._get_nfs_location(file_interfaces, share_name)
        elif protocol == 'CIFS':
            export_id = self.client.create_smb_share(filesystem_id,
                                                     share_name)
            if not export_id:
                message = (
                    _('The requested SMB share "%(export)s"'
                        ' was not created.') %
                    {'export': share_name})
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)
            locations = self._get_cifs_location(file_interfaces,
                                                share_name)
        return locations

    def _get_nfs_location(self, file_interfaces, share_name):
        export_locations = []
        for interface in file_interfaces:
            export_locations.append(
                {'path': f"{interface['ip']}:/{share_name}",
                 'metadata': {
                     'preferred': interface['preferred']
                     }
                 })
        return export_locations

    def _get_cifs_location(self, file_interfaces, share_name):
        export_locations = []
        for interface in file_interfaces:
            export_locations.append(
                {'path': f"\\\\{interface['ip']}\\{share_name}",
                 'metadata': {
                     'preferred': interface['preferred']
                     }
                 })
        return export_locations

    def delete_share(self, context, share, share_server):
        """Is called to delete a share."""
        LOG.debug(f'Deleting {share["share_proto"]} share.')
        self._delete_share(share)

    def _delete_share(self, share):
        """Deletes a filesystem and its associated export."""
        LOG.debug(f"Retrieving filesystem ID for filesystem {share['name']}")
        filesystem_id = self.client.get_filesystem_id(share['name'])
        if not filesystem_id:
            LOG.warning(
                f'Filesystem with share name {share["name"]} is not found.')
        else:
            LOG.debug(f"Deleting filesystem ID {filesystem_id}")
            share_deleted = self.client.delete_filesystem(filesystem_id)
            if not share_deleted:
                message = (
                    _('Failed to delete share "%(export)s".') %
                    {'export': share['name']})
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)

    def extend_share(self, share, new_size, share_server):
        """Is called to extend a share."""
        LOG.debug(f"Extending {share['name']} to {new_size}GiB")
        self._resize_filesystem(share, new_size)

    def shrink_share(self, share, new_size, share_server):
        """Is called to shrink a share."""
        LOG.debug(f"Shrinking {share['name']} to {new_size}GiB")
        self._resize_filesystem(share, new_size)

    def _resize_filesystem(self, share, new_size):
        """Is called to resize a filesystem"""

        # Converts the size from GiB to Bytes
        new_size_in_bytes = new_size * units.Gi
        filesystem_id = self.client.get_filesystem_id(share['name'])
        is_success, detail = self.client.resize_filesystem(filesystem_id,
                                                           new_size_in_bytes)
        if not is_success:
            message = (_('Failed to resize share "%(export)s".') %
                       {'export': share['name']})
            LOG.error(message)
            if detail:
                raise exception.ShareShrinkingPossibleDataLoss(
                    share_id=share['id'])
            raise exception.ShareBackendException(msg=message)

    def allow_access(self, context, share, access, share_server):
        """Allow access to the share."""
        raise NotImplementedError()

    def deny_access(self, context, share, access, share_server):
        """Deny access to the share."""
        raise NotImplementedError()

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Is called to update share access."""
        protocol = share['share_proto'].upper()
        LOG.debug(f'Updating access to {protocol} share.')
        if protocol == 'NFS':
            return self._update_nfs_access(share, access_rules)
        elif protocol == 'CIFS':
            return self._update_cifs_access(share, access_rules)

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

        share_id = self.client.get_nfs_export_id(share['name'])
        share_updated = self.client.set_export_access(share_id,
                                                      nfs_rw_ips,
                                                      nfs_ro_ips)
        if not share_updated:
            message = (
                _('Failed to update NFS access rules for "%(export)s".') %
                {'export': share['display_name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        return access_updates

    def _update_cifs_access(self, share, access_rules):
        """Updates access rules for CIFS share type."""
        cifs_rw_users = set()
        cifs_ro_users = set()
        access_updates = {}

        for rule in access_rules:
            if rule['access_type'].lower() != 'user':
                message = (_("Only user access type currently supported for "
                             "CIFS. Share provided %(share)s with rule type "
                             "%(type)s") % {'share': share['display_name'],
                                            'type': rule['access_type']})
                LOG.error(message)
                access_updates.update({rule['access_id']: {'state': 'error'}})

            else:
                prefix = (
                    self.ad_domain or
                    self.client.get_nas_server_smb_netbios(self.nas_server)
                )
                if not prefix:
                    message = (
                        _('Failed to get daomain/netbios name of '
                          '"%(nas_server)s".'
                          ) % {'nas_server': self.nas_server})
                    LOG.error(message)
                    access_updates.update({rule['access_id']:
                                           {'state': 'error'}})
                    continue

                prefix = prefix + '\\'
                if rule['access_level'] == const.ACCESS_LEVEL_RW:
                    cifs_rw_users.add(prefix + rule['access_to'])
                elif rule['access_level'] == const.ACCESS_LEVEL_RO:
                    cifs_ro_users.add(prefix + rule['access_to'])
                access_updates.update({rule['access_id']: {'state': 'active'}})

        share_id = self.client.get_smb_share_id(share['name'])
        share_updated = self.client.set_acl(share_id,
                                            cifs_rw_users,
                                            cifs_ro_users)
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
        stats_dict['storage_protocol'] = 'NFS_CIFS'
        stats_dict['reserved_percentage'] = self.reserved_percentage
        stats_dict['reserved_snapshot_percentage'] = (
            self.reserved_snapshot_percentage)
        stats_dict['reserved_share_extend_percentage'] = (
            self.reserved_share_extend_percentage)
        stats_dict['max_over_subscription_ratio'] = (
            self.max_over_subscription_ratio)

        cluster_id = self.client.get_cluster_id()
        total, used = self.client.retreive_cluster_capacity_metrics(cluster_id)
        if total and used:
            free = total - used
            stats_dict['total_capacity_gb'] = total // units.Gi
            stats_dict['free_capacity_gb'] = free // units.Gi

    def create_snapshot(self, context, snapshot, share_server):
        """Is called to create snapshot."""
        export_name = snapshot['share_name']
        LOG.debug(f'Retrieving filesystem ID for share {export_name}')
        filesystem_id = self.client.get_filesystem_id(export_name)
        if not filesystem_id:
            message = (
                _('Failed to get filesystem id for export "%(export)s".') %
                {'export': export_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        snapshot_name = snapshot['name']
        LOG.debug(
            f'Creating snapshot {snapshot_name} for filesystem {filesystem_id}'
            )
        snapshot_id = self.client.create_snapshot(filesystem_id,
                                                  snapshot_name)
        if not snapshot_id:
            message = (
                _('Failed to create snapshot "%(snapshot)s".') %
                {'snapshot': snapshot_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        else:
            LOG.info("Snapshot %(snapshot)s successfully created.",
                     {'snapshot': snapshot_name})

    def delete_snapshot(self, context, snapshot, share_server):
        """Is called to delete snapshot."""
        snapshot_name = snapshot['name']
        LOG.debug(f'Retrieving filesystem ID for snapshot {snapshot_name}')
        filesystem_id = self.client.get_filesystem_id(snapshot_name)
        LOG.debug(f'Deleting filesystem ID {filesystem_id}')
        snapshot_deleted = self.client.delete_filesystem(filesystem_id)
        if not snapshot_deleted:
            message = (
                _('Failed to delete snapshot "%(snapshot)s".') %
                {'snapshot': snapshot_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        else:
            LOG.info("Snapshot %(snapshot)s successfully deleted.",
                     {'snapshot': snapshot_name})

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        """Reverts a share (in place) to the specified snapshot."""
        snapshot_name = snapshot['name']
        snapshot_id = self.client.get_filesystem_id(snapshot_name)
        snapshot_restored = self.client.restore_snapshot(snapshot_id)
        if not snapshot_restored:
            message = (
                _('Failed to restore snapshot "%(snapshot)s".') %
                {'snapshot': snapshot_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        else:
            LOG.info("Snapshot %(snapshot)s successfully restored.",
                     {'snapshot': snapshot_name})

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Create a share from a snapshot - clone a snapshot."""
        LOG.debug(f'Creating {share["share_proto"]} share.')
        locations = self._create_share_from_snapshot(share, snapshot)

        if share['size'] != snapshot['size']:
            LOG.debug(f"Resizing {share['name']} to {share['size']}GiB")
            self._resize_filesystem(share, share['size'])

        return locations

    def _create_share_from_snapshot(self, share, snapshot):
        LOG.debug(f"Retrieving snapshot id of snapshot {snapshot['name']}")
        snapshot_id = self.client.get_filesystem_id(snapshot['name'])
        share_name = share['name']
        LOG.debug(
            f"Cloning filesystem {share_name} from snapshot {snapshot_id}"
            )
        filesystem_id = self.client.clone_snapshot(snapshot_id,
                                                   share_name)
        if not filesystem_id:
            message = {
                _('The filesystem "%(export)s" was not created.') %
                {'export': share_name}}
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        # create a share
        nas_server_id = self.client.get_nas_server_id(self.nas_server)
        locations = self._create_share_NFS_CIFS(nas_server_id, filesystem_id,
                                                share_name,
                                                share['share_proto'].upper())
        return locations

    def ensure_share(self, context, share, share_server):
        """Invoked to ensure that share is exported."""

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""

    def check_for_setup_error(self):
        """Is called to check for setup error."""

    def get_default_filter_function(self):
        return 'share.size >= 3'
