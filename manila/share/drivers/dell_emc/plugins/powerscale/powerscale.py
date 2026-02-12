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
    1.0.5 - Add support for share shrink
    1.0.6 - Add support of manage/unmanage share and snapshot
    1.0.7 - Add support of mount snapshot

"""
VERSION = "1.0.7"

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
        self.manage_existing_snapshot_support = True
        # props for share status update
        self.reserved_percentage = None
        self.reserved_snapshot_percentage = None
        self.reserved_share_extend_percentage = None
        self.max_over_subscription_ratio = None
        self._threshold_limit = 0
        self.shrink_share_support = True
        self.manage_existing_support = True
        self.mount_snapshot_support = True
        self._snapshot_root_dir = '/ifs/.snapshot'

    def _get_container_path(self, share):
        """Return path to a container."""
        return os.path.join(self._root_dir, share['name'])

    def _get_snapshot_path(self, snapshot):
        return os.path.join(self._snapshot_root_dir, snapshot['name'])

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
        self._powerscale_api.clone_snapshot(snapshot['name'], fq_target_dir,
                                            snapshot['provider_location'])

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
        snap_id = self._powerscale_api.create_snapshot(
            snapshot['name'], snapshot_path)
        result = {}
        if snap_id is None:
            message = (
                _('Failed to create snapshot "%(snap)s".') %
                {'snap': snapshot['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        result['provider_location'] = snap_id
        if snapshot['share']['mount_snapshot_support']:
            snap_result = self._create_snap_export_path(snapshot=snapshot,
                                                        snap_actual_name=None)
            result.update(snap_result)
        return result

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
        self._delete_export(proto="NFS",
                            name=share['name'],
                            path=self._get_container_path(share))

    def _delete_cifs_share(self, share):
        """Is called to remove CIFS share."""
        self._delete_export(proto="CIFS", name=share['name'])

    def delete_snapshot(self, context, snapshot, share_server):
        """Is called to remove snapshot."""
        snap_name = snapshot['name']
        proto = snapshot['share']['share_proto']
        snap_path = self._get_snapshot_path(snapshot)
        LOG.debug('Deleting snapshot %s', snap_name)
        if snapshot.get('provider_location'):
            deleted = (self._powerscale_api.
                       delete_snapshot_by_id(snapshot['provider_location']))
        else:
            deleted = self._powerscale_api.delete_snapshot(snapshot['name'])
        if not deleted:
            message = (_('Failed to delete snapshot "%(snap)s".') %
                       {'snap': snapshot['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        self._delete_export(proto=proto,
                            name=snap_name,
                            path=snap_path)

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

    def manage_existing(self, share, driver_options):
        """Import an external NFS/CIFS share into Manila."""
        export_path = (
            share.get('export_location')
            or share.get('export_locations', [None])[0]
        )
        protocol = share.get('share_proto')
        LOG.info(
            "Managing existing share with protocol: %s, export path: %s",
            protocol,
            export_path,
        )
        if protocol == 'NFS':
            nfs_path = export_path.split(':', 1)[1]
            export_id = self._powerscale_api.lookup_nfs_export(nfs_path)
            if not export_id:
                raise exception.ShareBackendException(
                    msg=f"NFS export {nfs_path} not found."
                )
            backend_quota_path = nfs_path
            export_location = export_path
        elif protocol == 'CIFS':
            share_name = export_path.split('\\')[-1]
            smb_share = self._powerscale_api.lookup_smb_share(share_name)
            if not smb_share:
                raise exception.ShareBackendException(
                    msg=f"CIFS share {share_name} not found."
                )
            backend_quota_path = smb_share.get('path')
            if not backend_quota_path:
                raise exception.ShareBackendException(
                    msg=(
                        "Unable to resolve OneFS path for CIFS share "
                        f"{share_name}."
                    )
                )
            export_location = export_path
        share_quota = self._powerscale_api.quota_get(
            backend_quota_path, 'directory'
        )
        size_bytes = (
            share_quota.get('thresholds', {}).get('hard')
            if share_quota else 0
        )
        if not size_bytes:
            raise exception.ManageInvalidShare(
                reason=(
                    "Managing existing share requires a directory quota hard "
                    "limit on backend path %s." % backend_quota_path
                )
            )
        size_gb = size_bytes // units.Gi
        return {
            'size': size_gb,
            'export_locations': [export_location],
        }

    def shrink_share(self, share, new_size, share_server=None):
        """Shrink a share by lowering its directory hard quota.

        Rejects shrink if current logical usage exceeds the requested size.
        """
        LOG.debug(
            'Shrinking share %(name)s to %(size)sG.',
            {'name': share['name'], 'size': new_size}
        )
        path = self._get_container_path(share)
        quota_json = self._powerscale_api.quota_get(path, 'directory')
        used_bytes = 0
        if quota_json:
            used_bytes = quota_json.get('usage', {}).get('logical', 0)
        new_quota_bytes = new_size * units.Gi
        if used_bytes > new_quota_bytes:
            message = (_(
                'Cannot shrink share "%(name)s" to %(size)sG: '
                'used space (%(used)s bytes) exceeds new size.'
            ) % {
                'name': share['name'],
                'size': new_size,
                'used': used_bytes
            })
            LOG.error(message)
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share.get('id', share.get('name')),
                reason=message,
            )
        self._powerscale_api.quota_set(path, 'directory', new_quota_bytes)

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
            'mount_snapshot_support': True,
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
        share_name = share["name"]
        LOG.debug(f'Updaing access for share {share_name}.')
        state_map = {}
        if share['share_proto'] == 'NFS':
            path = self._get_container_path(share)
            state_map = self._update_access_nfs(share_name, path, access_rules)
        if share['share_proto'] == 'CIFS':
            state_map = self._update_access_cifs(share_name, access_rules)
        return state_map

    def _update_access_nfs(self, share_name, path, access_rules):
        """Updates access on a NFS share."""
        nfs_rw_ips = set()
        nfs_ro_ips = set()
        rule_state_map = {}
        for rule in access_rules:
            rule_state_map[rule['access_id']] = {
                'state': 'error'
            }

        for rule in access_rules:
            access_level = const.ACCESS_LEVEL_RO
            if rule.get('access_level'):
                access_level = rule.get('access_level')
            if access_level == const.ACCESS_LEVEL_RW:
                nfs_rw_ips.add(rule['access_to'])
            elif access_level == const.ACCESS_LEVEL_RO:
                nfs_ro_ips.add(rule['access_to'])

        export_id = self._powerscale_api.lookup_nfs_export(path)
        if export_id is None:
            # share does not exist on backend (set all rules to error state)
            message = _('Failed to update access for NFS share %s: '
                        'share not found.') % share_name
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

    def _update_access_cifs(self, share_name, access_rules, read_only=False):
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
        ips = self._get_cifs_ip_list(ip_access_rules, rule_state_map,
                                     read_only)
        user_permissions = self._get_cifs_user_permissions(
            user_access_rules, rule_state_map)
        if read_only and len(user_permissions) == 0:
            user_permissions = [{
                "permission": "read",
                "permission_type": "allow",
                "trustee": {
                    "id": "SID:S-1-1-0",
                    "name": "Everyone",
                    "type": "wellknown"
                }
            }]
        share_updated = self._powerscale_api.modify_smb_share_access(
            share_name,
            host_acl=ips,
            permissions=user_permissions)

        if not share_updated:
            message = (
                _(
                    'Failed to update access rules for CIFS share '
                    '"%(share)s".'
                ) % {'share': share_name}
            )
            LOG.error(message)
            for rule in access_rules:
                rule_state_map[rule['access_id']] = {
                    'state': 'error'
                }

        return rule_state_map

    def _get_cifs_ip_list(self, access_rules, rule_state_map, read_only):
        """Get CIFS ip list."""
        cifs_ips = []
        for rule in access_rules:
            if not read_only and rule['access_level'] != const.ACCESS_LEVEL_RW:
                message = ('Only RW access level is supported '
                           'for CIFS IP access.')
                LOG.error(message)
                rule_state_map.update({rule['access_id']: {'state': 'error'}})
                continue
            cifs_ips.append('allow:' + rule['access_to'])
            rule_state_map.update({rule['access_id']: {'state': 'active'}})
        if len(cifs_ips) > 0:
            cifs_ips.append('deny:ALL')
        return cifs_ips

    def _get_cifs_user_permissions(self, access_rules, rule_state_map):
        """Get CIFS user permissions."""
        cifs_user_permissions = []
        for rule in access_rules:
            access_level = const.ACCESS_LEVEL_RO
            smb_permission = powerscale_api.SmbPermission.ro
            if rule.get('access_level'):
                access_level = rule.get('access_level')
            if access_level == const.ACCESS_LEVEL_RW:
                smb_permission = powerscale_api.SmbPermission.rw
            elif access_level == const.ACCESS_LEVEL_RO:
                smb_permission = powerscale_api.SmbPermission.ro
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

    def manage_existing_snapshot(self, snapshot, driver_options):
        """Brings an existing snapshot under Manila management."""
        provider_location = snapshot.get('provider_location')
        snap = self._powerscale_api.get_snapshot_id(provider_location)
        if not snap:
            message = ("Could not find a snapshot in the backend with "
                       "ID: %s, please make sure "
                       "the snapshot exists in the backend."
                       % provider_location)
            LOG.error(message)
            raise exception.ManageInvalidShareSnapshot(reason=message)
        elif (snap['path'] !=
              self._get_container_path(snapshot['share'])):
            message = ("Snapshot does not belong to the given share %s."
                       % snapshot['share']['name'])
            LOG.error(message)
            raise exception.ManageInvalidShareSnapshot(reason=message)
        try:
            snapshot_size = int(driver_options.get("size", 0))
        except (ValueError, TypeError):
            msg = _("The size in driver options to manage snapshot "
                    "%(snap_id)s should be an integer, in format "
                    "driver-options size=<SIZE>. Value passed: "
                    "%(size)s.") % {'snap_id': snapshot['id'],
                                    'size': driver_options.get("size")}
            LOG.error(msg)
            raise exception.ManageInvalidShareSnapshot(reason=msg)

        if not snapshot_size:
            msg = _("Snapshot %(snap_id)s has no specified size. "
                    "Use default value to share size, "
                    "set size in driver options if you "
                    "want.") % {'snap_id': snapshot['id']}
            LOG.info(msg)
            snapshot_size = snapshot['share']['size']
        LOG.info("Snapshot %(provider_location)s in "
                 "PowerScale will be managed "
                 "with ID %(snapshot_id)s.",
                 {'provider_location': snapshot.get('provider_location'),
                  'snapshot_id': snapshot['id']})
        manage_snap_result = {"size": snapshot_size,
                              "provider_location": provider_location}
        if snapshot['share']['mount_snapshot_support']:
            snap_result = self._create_snap_export_path(
                snapshot=snapshot,
                snap_actual_name=snap['name']
            )
            manage_snap_result.update(snap_result)
        return manage_snap_result

    def _create_snap_export_path(self, snapshot, snap_actual_name=None):
        share_proto = snapshot['share']['share_proto']
        snap_export_path = self._get_snapshot_path(snapshot)
        snap_name = snapshot['name']
        if snap_actual_name:
            snap_name = snap_actual_name
            snap_export_path = os.path.join(self._snapshot_root_dir,
                                            snap_name)
        created = True
        export_path = None
        if share_proto == "NFS":
            share_export = (self._powerscale_api.
                            lookup_nfs_export(snap_export_path))
            if share_export is None:
                created = (self.
                           _powerscale_api.
                           create_snapshot_nfs_export(snap_export_path))
            export_path = self._format_nfs_path(snap_export_path)
        elif share_proto == "CIFS":
            smb_export = (self._powerscale_api.
                          lookup_smb_share(snap_name))
            if smb_export is None:
                created = (self._powerscale_api.
                           create_snapshot_smb_export(snap_name,
                                                      snap_export_path))
            export_path = self._format_smb_path(snap_name)
        if not created:
            msg = _('Failed to create snapshot export path '
                    '"%(snap)s".') % {'snap': snap_name}
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)
        return {'export_locations': self._get_location(export_path)}

    def _delete_export(self, proto, name, path=None):
        if proto == "NFS":
            share_id = self._powerscale_api.lookup_nfs_export(path)
            if share_id is None:
                LOG.warning('Attempted to delete NFS export "%s", '
                            'but it does not exist.', name)
                return
            if not self._powerscale_api.delete_nfs_share(share_id):
                msg = _('Error deleting NFS export: %s') % name
                LOG.error(msg)
                raise exception.ShareBackendException(msg=msg)
        elif proto == "CIFS":
            smb_share = self._powerscale_api.lookup_smb_share(name)
            if smb_share is None:
                LOG.warning('Attempted to delete CIFS export "%s", '
                            'but it does not exist.', name)
                return
            if not self._powerscale_api.delete_smb_share(name):
                msg = _('Error deleting CIFS export: %s') % name
                LOG.error(msg)
                raise exception.ShareBackendException(msg=msg)

    def snapshot_update_access(self, context, snapshot,
                               access_rules, add_rules=None,
                               delete_rules=None, share_server=None):
        """Update snapshot access."""
        snapshot_name = snapshot["name"]
        LOG.debug(f'Updating access for snapshot {snapshot_name}.')
        share_proto = snapshot['share']['share_proto']
        state_map = {}
        if share_proto == 'NFS':
            path = self._get_snapshot_path(snapshot)
            state_map = self._update_access_nfs(snapshot_name,
                                                path, access_rules)
        if share_proto == 'CIFS':
            state_map = self._update_access_cifs(snapshot_name,
                                                 access_rules,
                                                 read_only=True)
        return state_map
