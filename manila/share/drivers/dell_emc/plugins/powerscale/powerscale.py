# Copyright 2015 EMC Corporation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
PowerScale specific NAS backend plugin.
"""
import os

from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.plugins import base
from manila.share.drivers.dell_emc.plugins.powerscale import powerscale_api

"""Version history:
    0.1.0 - Initial version
    1.0.0 - Fix Http auth issue, SSL verification error and etc
    1.0.1 - Add support for update share stats
    1.0.2 - Add support for ensure shares
    1.0.3 - Add support for thin provisioning
    1.0.4 - Rename isilon to powerscale
"""
VERSION = "1.0.4"

CONF = cfg.CONF

LOG = log.getLogger(__name__)

POWERSCALE_OPTS = [
    cfg.StrOpt('powerscale_dir_permission',
               default='0777',
               help='Predefined ACL value or POSIX mode '
                    'for PowerScale directories.'),
    cfg.IntOpt('powerscale_threshold_limit',
               default=0,
               help='Specifies the threshold limit (in percentage) '
                    'for triggering SmartQuotas alerts in PowerScale')
]


class PowerScaleStorageConnection(base.StorageConnection):
    """Implements PowerScale specific functionality for EMC Manila driver."""

    def __init__(self, *args, **kwargs):
        super(PowerScaleStorageConnection, self).__init__(*args, **kwargs)
        LOG.debug('Setting up attributes for Manila '
                  'Dell PowerScale Driver.')
        if 'configuration' in kwargs:
            kwargs['configuration'].append_config_values(POWERSCALE_OPTS)

        self._server = None
        self._port = None
        self._username = None
        self._password = None
        self._server_url = None
        self._root_dir = None
        self._verify_ssl_cert = None
        self._ssl_cert_path = None
        self._containers = {}
        self._shares = {}
        self._snapshots = {}

        self._powerscale_api = None
        self.driver_handles_share_servers = False
        self.ipv6_implemented = True
        # props for share status update
        self.reserved_percentage = None
        self.reserved_snapshot_percentage = None
        self.reserved_share_extend_percentage = None
        self.max_over_subscription_ratio = None
        self._threshold_limit = 0

    def _get_container_path(self, share):
        """Return path to a container."""
        return os.path.join(self._root_dir, share['name'])

    def create_share(self, context, share, share_server):
        """Is called to create share."""
        LOG.debug(f'Creating {share["share_proto"]} share.')
        if share['share_proto'] == 'NFS':
            location = self._create_nfs_share(share)
        elif share['share_proto'] == 'CIFS':
            location = self._create_cifs_share(share)
        else:
            message = (_('Unsupported share protocol: %(proto)s.') %
                       {'proto': share['share_proto']})
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

        # apply directory quota based on share size
        max_share_size = share['size'] * units.Gi
        self._powerscale_api.quota_create(
            self._get_container_path(share), 'directory', max_share_size)

        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server):
        """Creates a share from the snapshot."""
        LOG.debug(f'Creating {share["share_proto"]} share from snapshot.')
        # Create share at new location
        location = self.create_share(context, share, share_server)

        # Clone snapshot to new location
        fq_target_dir = self._get_container_path(share)
        self._powerscale_api.clone_snapshot(snapshot['name'], fq_target_dir)

        return location

    def _create_nfs_share(self, share):
        """Is called to create nfs share."""
        LOG.debug(f'Creating NFS share {share["name"]}.')
        # Create directory
        container_path = self._get_container_path(share)
        self._create_directory(container_path)
        # Create nfs share
        share_created = self._powerscale_api.create_nfs_export(container_path)
        if not share_created:
            message = (
                _('The requested NFS share "%(share)s" was not created.') %
                {'share': share['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        location = self._get_location(self._format_nfs_path(container_path))
        return location

    def _create_cifs_share(self, share):
        """Is called to create cifs share."""
        LOG.debug(f'Creating CIFS share {share["name"]}.')
        # Create directory
        container_path = self._get_container_path(share)
        self._create_directory(container_path)
        # Create smb share
        share_created = self._powerscale_api.create_smb_share(
            share['name'], container_path)
        if not share_created:
            message = (
                _('The requested CIFS share "%(share)s" was not created.') %
                {'share': share['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        location = self._get_location(self._format_smb_path(share['name']))
        return location

    def _create_directory(self, path, recursive=False):
        """Is called to create a directory."""
        dir_created = self._powerscale_api.create_directory(path, recursive)
        if not dir_created:
            message = (
                _('Failed to create directory "%(dir)s".') %
                {'dir': path})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

    def create_snapshot(self, context, snapshot, share_server):
        """Is called to create snapshot."""
        LOG.debug(f'Creating snapshot {snapshot["name"]}.')
        snapshot_path = os.path.join(self._root_dir, snapshot['share_name'])
        snap_created = self._powerscale_api.create_snapshot(
            snapshot['name'], snapshot_path)
        if not snap_created:
            message = (
                _('Failed to create snapshot "%(snap)s".') %
                {'snap': snapshot['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

    def delete_share(self, context, share, share_server):
        """Is called to remove share."""
        LOG.debug(f'Deleting {share["share_proto"]} share.')
        if share['share_proto'] == 'NFS':
            self._delete_nfs_share(share)
        elif share['share_proto'] == 'CIFS':
            self._delete_cifs_share(share)
        else:
            message = (_('Unsupported share type: %(type)s.') %
                       {'type': share['share_proto']})
            LOG.warning(message)
            return

        dir_path = self._get_container_path(share)
        # remove quota
        self._delete_quota(dir_path)
        # remove directory
        self._delete_directory(dir_path)

    def _delete_quota(self, path):
        """Is called to remove quota."""
        quota = self._powerscale_api.quota_get(path, 'directory')
        if quota:
            LOG.debug(f'Removing quota {quota["id"]}')
            deleted = self._powerscale_api.delete_quota(quota['id'])
            if not deleted:
                message = (
                    _('Failed to delete quota "%(quota_id)s" for '
                      'directory "%(dir)s".') %
                    {'quota_id': quota['id'], 'dir': path})
                LOG.error(message)
        else:
            LOG.warning(f'Quota not found for {path}')

    def _delete_directory(self, path):
        """Is called to remove directory."""
        path_exist = self._powerscale_api.is_path_existent(path)
        if path_exist:
            LOG.debug(f'Removing directory {path}')
            deleted = self._powerscale_api.delete_path(path, recursive=True)
            if not deleted:
                message = (
                    _('Failed to delete directory "%(dir)s".') %
                    {'dir': path})
                LOG.error(message)
        else:
            LOG.warning(f'Directory not found for {path}')

    def _delete_nfs_share(self, share):
        """Is called to remove nfs share."""
        share_id = self._powerscale_api.lookup_nfs_export(
            self._get_container_path(share))

        if share_id is None:
            lw = ('Attempted to delete NFS Share "%s", but the share does '
                  'not appear to exist.')
            LOG.warning(lw, share['name'])
        else:
            # attempt to delete the share
            export_deleted = self._powerscale_api.delete_nfs_share(share_id)
            if not export_deleted:
                message = _('Error deleting NFS share: %s') % share['name']
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)

    def _delete_cifs_share(self, share):
        """Is called to remove CIFS share."""
        smb_share = self._powerscale_api.lookup_smb_share(share['name'])
        if smb_share is None:
            lw = ('Attempted to delete CIFS Share "%s", but the share does '
                  'not appear to exist.')
            LOG.warning(lw, share['name'])
        else:
            share_deleted = self._powerscale_api.delete_smb_share(
                share['name'])
            if not share_deleted:
                message = _('Error deleting CIFS share: %s') % share['name']
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)

    def delete_snapshot(self, context, snapshot, share_server):
        """Is called to remove snapshot."""
        LOG.debug(f'Deleting snapshot {snapshot["name"]}')
        deleted = self._powerscale_api.delete_snapshot(snapshot['name'])
        if not deleted:
            message = (
                _('Failed to delete snapshot "%(snap)s".') %
                {'snap': snapshot['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

    def ensure_share(self, context, share, share_server):
        """Invoked to ensure that share is exported."""
        raise NotImplementedError()

    def extend_share(self, share, new_size, share_server=None):
        """Extends a share."""
        LOG.debug('Extending share %(name)s to %(size)sG.', {
            'name': share['name'], 'size': new_size
        })
        new_quota_size = new_size * units.Gi
        self._powerscale_api.quota_set(
            self._get_container_path(share), 'directory', new_quota_size)

    def allow_access(self, context, share, access, share_server):
        """Allow access to the share."""
        raise NotImplementedError()

    def deny_access(self, context, share, access, share_server):
        """Deny access to the share."""
        raise NotImplementedError()

    def check_for_setup_error(self):
        """Check for setup error."""

    def connect(self, emc_share_driver, context):
        """Connect to an PowerScale cluster."""
        LOG.debug('Reading configuration parameters for Manila'
                  ' Dell PowerScale Driver.')
        config = emc_share_driver.configuration
        self._server = config.safe_get("emc_nas_server")
        self._port = config.safe_get("emc_nas_server_port")
        self._username = config.safe_get("emc_nas_login")
        self._password = config.safe_get("emc_nas_password")
        self._root_dir = config.safe_get("emc_nas_root_dir")
        self._threshold_limit = config.safe_get("powerscale_threshold_limit")

        # validate IP, username and password
        if not all([self._server,
                    self._username,
                    self._password]):
            message = _("REST server IP, username and password"
                        " must be specified.")
            raise exception.BadConfigurationException(reason=message)

        self._server_url = f'https://{self._server}:{self._port}'

        self._verify_ssl_cert = config.safe_get("emc_ssl_cert_verify")
        if self._verify_ssl_cert:
            self._ssl_cert_path = config.safe_get("emc_ssl_cert_path")
        self._dir_permission = config.safe_get("powerscale_dir_permission")
        self._powerscale_api = powerscale_api.PowerScaleApi(
            self._server_url, self._username, self._password,
            self._verify_ssl_cert, self._ssl_cert_path,
            self._dir_permission,
            self._threshold_limit)

        if not self._powerscale_api.is_path_existent(self._root_dir):
            self._create_directory(self._root_dir, recursive=True)

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

    def update_share_stats(self, stats_dict):
        """Retrieve stats info from share."""
        stats_dict['driver_version'] = VERSION
        stats_dict['storage_protocol'] = 'NFS_CIFS'
        # PowerScale does not support pools.
        # To align with manila scheduler 'pool-aware' strategic,
        # report with one pool structure.
        pool_stat = {
            'pool_name': stats_dict['share_backend_name'],
            'qos': False,
            'reserved_percentage': self.reserved_percentage,
            'reserved_snapshot_percentage':
                self.reserved_snapshot_percentage,
            'reserved_share_extend_percentage':
                self.reserved_share_extend_percentage,
            'max_over_subscription_ratio':
                self.max_over_subscription_ratio,
            'thin_provisioning': True,
        }
        spaces = self._powerscale_api.get_space_stats()
        if spaces:
            pool_stat['total_capacity_gb'] = spaces['total'] // units.Gi
            pool_stat['free_capacity_gb'] = spaces['free'] // units.Gi
        allocated_space = self._powerscale_api.get_allocated_space()
        pool_stat['allocated_capacity_gb'] = allocated_space

        stats_dict['pools'] = [pool_stat]

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        # TODO(Shaun Edwards)
        return 0

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""
        # TODO(Shaun Edwards): Look into supporting share servers

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        # TODO(Shaun Edwards): Look into supporting share servers

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update share access."""
        LOG.debug(f'Updaing access for share {share["name"]}.')
        if share['share_proto'] == 'NFS':
            state_map = self._update_access_nfs(share, access_rules)
        if share['share_proto'] == 'CIFS':
            state_map = self._update_access_cifs(share, access_rules)
        return state_map

    def _update_access_nfs(self, share, access_rules):
        """Updates access on a NFS share."""
        nfs_rw_ips = set()
        nfs_ro_ips = set()
        rule_state_map = {}
        for rule in access_rules:
            rule_state_map[rule['access_id']] = {
                'state': 'error'
            }

        for rule in access_rules:
            if rule['access_level'] == const.ACCESS_LEVEL_RW:
                nfs_rw_ips.add(rule['access_to'])
            elif rule['access_level'] == const.ACCESS_LEVEL_RO:
                nfs_ro_ips.add(rule['access_to'])

        export_id = self._powerscale_api.lookup_nfs_export(
            self._get_container_path(share))
        if export_id is None:
            # share does not exist on backend (set all rules to error state)
            message = _('Failed to update access for NFS share %s: '
                        'share not found.') % share['name']
            LOG.error(message)
            return rule_state_map

        r = self._powerscale_api.modify_nfs_export_access(
            export_id, ro_ips=list(nfs_ro_ips), rw_ips=list(nfs_rw_ips))
        if not r:
            return rule_state_map

        # if we finish the bulk rule update with no error set rules to active
        for rule in access_rules:
            rule_state_map[rule['access_id']]['state'] = 'active'
        return rule_state_map

    def _update_access_cifs(self, share, access_rules):
        """Update access on a CIFS share."""
        rule_state_map = {}
        ip_access_rules = []
        user_access_rules = []
        for rule in access_rules:
            if rule['access_type'] == 'ip':
                ip_access_rules.append(rule)
            elif rule['access_type'] == 'user':
                user_access_rules.append(rule)
            else:
                message = (_("Access type %(type)s is not supported for CIFS."
                             ) % {'type': rule['access_type']})
                LOG.error(message)
                rule_state_map.update({rule['access_id']: {'state': 'error'}})
        ips = self._get_cifs_ip_list(ip_access_rules, rule_state_map)
        user_permissions = self._get_cifs_user_permissions(
            user_access_rules, rule_state_map)

        share_updated = self._powerscale_api.modify_smb_share_access(
            share['name'],
            host_acl=ips,
            permissions=user_permissions)

        if not share_updated:
            message = (
                _(
                    'Failed to update access rules for CIFS share '
                    '"%(share)s".'
                ) % {'share': share['name']}
            )
            LOG.error(message)
            for rule in access_rules:
                rule_state_map[rule['access_id']] = {
                    'state': 'error'
                }

        return rule_state_map

    def _get_cifs_ip_list(self, access_rules, rule_state_map):
        """Get CIFS ip list."""
        cifs_ips = []
        for rule in access_rules:
            if rule['access_level'] != const.ACCESS_LEVEL_RW:
                message = ('Only RW access level is supported '
                           'for CIFS IP access.')
                LOG.error(message)
                rule_state_map.update({rule['access_id']: {'state': 'error'}})
                continue
            cifs_ips.append('allow:' + rule['access_to'])
            rule_state_map.update({rule['access_id']: {'state': 'active'}})
        return cifs_ips

    def _get_cifs_user_permissions(self, access_rules, rule_state_map):
        """Get CIFS user permissions."""
        cifs_user_permissions = []
        for rule in access_rules:
            if rule['access_level'] == const.ACCESS_LEVEL_RW:
                smb_permission = powerscale_api.SmbPermission.rw
            elif rule['access_level'] == const.ACCESS_LEVEL_RO:
                smb_permission = powerscale_api.SmbPermission.ro
            else:
                message = ('Only RW and RO access levels are supported '
                           'for CIFS user access.')
                LOG.error(message)
                rule_state_map.update({rule['access_id']: {'state': 'error'}})
                continue

            user_sid = self._powerscale_api.get_user_sid(rule['access_to'])
            if user_sid:
                cifs_user_permissions.append({
                    'permission': smb_permission.value,
                    'permission_type': 'allow',
                    'trustee': user_sid
                })
                rule_state_map.update({rule['access_id']: {'state': 'active'}})
            else:
                message = _('Failed to get user sid by %(user)s.' %
                            {'user': rule['access_to']})
                LOG.error(message)
                rule_state_map.update({rule['access_id']: {'state': 'error'}})
        return cifs_user_permissions

    def get_backend_info(self, context):
        """Get driver and array configuration parameters.

        :returns: A dictionary containing driver-specific info.
        """
        LOG.debug("Retrieving PowerScale backend info.")
        cluster_version = self._powerscale_api.get_cluster_version()
        return {'driver_version': VERSION,
                'cluster_version': cluster_version,
                'rest_server': self._server,
                'rest_port': self._port}

    def ensure_shares(self, context, shares):
        """Invoked to ensure that shares are exported.

        :shares: A list of all shares for updates.
        :returns: None or a dictionary of updates in the format.
        """
        LOG.debug("Ensuring PowerScale shares.")
        updates = {}
        for share in shares:
            if share['share_proto'] == 'NFS':
                container_path = self._get_container_path(share)
                share_id = self._powerscale_api.lookup_nfs_export(
                    container_path)
                if share_id:
                    location = self._format_nfs_path(container_path)
                    updates[share['id']] = {
                        'export_locations': [location],
                        'status': 'available',
                        'reapply_access_rules': True,
                    }
                else:
                    LOG.warning(f'NFS Share {share["name"]} is not found.')
            elif share['share_proto'] == 'CIFS':
                smb_share = self._powerscale_api.lookup_smb_share(
                    share['name'])
                if smb_share:
                    location = self._format_smb_path(share['name'])
                    updates[share['id']] = {
                        'export_locations': [location],
                        'status': 'available',
                        'reapply_access_rules': True,
                    }
                else:
                    LOG.warning(f'CIFS Share {share["name"]} is not found.')

            if share['id'] not in updates:
                updates[share['id']] = {
                    'export_locations': [],
                    'status': 'error',
                    'reapply_access_rules': False,
                }
        return updates

    def _format_smb_path(self, share_name):
        return '\\\\{0}\\{1}'.format(self._server, share_name)

    def _format_nfs_path(self, container_path):
        return '{0}:{1}'.format(self._server, container_path)

    def _get_location(self, path):
        export_locations = [{'path': path,
                             'is_admin_only': False,
                             'metadata': {"preferred": True}}]
        return export_locations
