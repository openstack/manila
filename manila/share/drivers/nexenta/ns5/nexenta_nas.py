# Copyright 2019 Nexenta by DDN, Inc.
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

import posixpath

from oslo_log import log
from oslo_utils import units

from manila.common import constants as common
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.nexenta.ns5 import jsonrpc
from manila.share.drivers.nexenta import options
from manila.share.drivers.nexenta import utils

VERSION = '1.1'
LOG = log.getLogger(__name__)
ZFS_MULTIPLIER = 1.1  # ZFS quotas do not take metadata into account.


class NexentaNasDriver(driver.ShareDriver):
    """Nexenta Share Driver.

    Executes commands relating to Shares.
    API version history:
        1.0 - Initial version.
        1.1 - Failover support.
            - Unshare filesystem completely after last securityContext
              is removed.
            - Moved all http/url code to jsonrpc.
            - Manage existing support.
            - Revert to snapshot support.
    """

    driver_prefix = 'nexenta'

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        LOG.debug('Initializing Nexenta driver.')
        super(NexentaNasDriver, self).__init__(False, *args, **kwargs)
        self.configuration = kwargs.get('configuration')
        if self.configuration:
            self.configuration.append_config_values(
                options.nexenta_connection_opts)
            self.configuration.append_config_values(
                options.nexenta_nfs_opts)
            self.configuration.append_config_values(
                options.nexenta_dataset_opts)
        else:
            raise exception.BadConfigurationException(
                reason=_('Nexenta configuration missing.'))

        self.nef = None
        self.verify_ssl = self.configuration.nexenta_ssl_cert_verify
        self.nas_host = self.configuration.nexenta_nas_host
        self.nef_port = self.configuration.nexenta_rest_port
        self.nef_user = self.configuration.nexenta_user
        self.nef_password = self.configuration.nexenta_password

        self.pool_name = self.configuration.nexenta_pool
        self.parent_fs = self.configuration.nexenta_folder

        self.nfs_mount_point_base = self.configuration.nexenta_mount_point_base
        self.dataset_compression = (
            self.configuration.nexenta_dataset_compression)
        self.provisioned_capacity = 0

    @property
    def storage_protocol(self):
        protocol = ''
        if self.configuration.nexenta_nfs:
            protocol = 'NFS'
        else:
            msg = _('At least 1 storage protocol must be enabled.')
            raise exception.NexentaException(msg)
        return protocol

    @property
    def root_path(self):
        return posixpath.join(self.pool_name, self.parent_fs)

    @property
    def share_backend_name(self):
        if not hasattr(self, '_share_backend_name'):
            self._share_backend_name = None
            if self.configuration:
                self._share_backend_name = self.configuration.safe_get(
                    'share_backend_name')
            if not self._share_backend_name:
                self._share_backend_name = 'NexentaStor5'
        return self._share_backend_name

    def do_setup(self, context):
        self.nef = jsonrpc.NefProxy(self.storage_protocol,
                                    self.root_path,
                                    self.configuration)

    def check_for_setup_error(self):
        """Check root filesystem, NFS service and NFS share."""
        filesystem = self.nef.filesystems.get(self.root_path)
        if filesystem['mountPoint'] == 'none':
            message = (_('NFS root filesystem %(path)s is not writable')
                       % {'path': filesystem['mountPoint']})
            raise jsonrpc.NefException(code='ENOENT', message=message)
        if not filesystem['isMounted']:
            message = (_('NFS root filesystem %(path)s is not mounted')
                       % {'path': filesystem['mountPoint']})
            raise jsonrpc.NefException(code='ENOTDIR', message=message)
        payload = {}
        if filesystem['nonBlockingMandatoryMode']:
            payload['nonBlockingMandatoryMode'] = False
        if filesystem['smartCompression']:
            payload['smartCompression'] = False
        if payload:
            self.nef.filesystems.set(self.root_path, payload)
        service = self.nef.services.get('nfs')
        if service['state'] != 'online':
            message = (_('NFS server service is not online: %(state)s')
                       % {'state': service['state']})
            raise jsonrpc.NefException(code='ESRCH', message=message)
        self._get_provisioned_capacity()

    def _get_provisioned_capacity(self):
        payload = {'fields': 'referencedQuotaSize'}
        self.provisioned_capacity += self.nef.filesystems.get(
            self.root_path, payload)['referencedQuotaSize']

    def ensure_share(self, context, share, share_server=None):
        pass

    def create_share(self, context, share, share_server=None):
        """Create a share."""
        LOG.debug('Creating share: %s.', self._get_share_name(share))
        dataset_path = self._get_dataset_path(share)
        size = int(share['size'] * units.Gi * ZFS_MULTIPLIER)
        payload = {
            'recordSize': self.configuration.nexenta_dataset_record_size,
            'compressionMode': self.dataset_compression,
            'path': dataset_path,
            'referencedQuotaSize': size,
            'nonBlockingMandatoryMode': False
        }
        if not self.configuration.nexenta_thin_provisioning:
            payload['referencedReservationSize'] = size
        self.nef.filesystems.create(payload)

        try:
            mount_path = self._mount_filesystem(share)
        except jsonrpc.NefException as create_error:
            try:
                payload = {'force': True}
                self.nef.filesystems.delete(dataset_path, payload)
            except jsonrpc.NefException as delete_error:
                LOG.debug('Failed to delete share %(path)s: %(error)s',
                          {'path': dataset_path, 'error': delete_error})
            raise create_error

        self.provisioned_capacity += share['size']
        location = {
            'path': mount_path,
            'id': self._get_share_name(share)
        }
        return [location]

    def _mount_filesystem(self, share):
        """Ensure that filesystem is activated and mounted on the host."""
        dataset_path = self._get_dataset_path(share)
        payload = {'fields': 'mountPoint,isMounted'}
        filesystem = self.nef.filesystems.get(dataset_path, payload)
        if filesystem['mountPoint'] == 'none':
            payload = {'datasetName': dataset_path}
            self.nef.hpr.activate(payload)
            filesystem = self.nef.filesystems.get(dataset_path, payload)
        elif not filesystem['isMounted']:
            self.nef.filesystems.mount(dataset_path)
        return '%s:%s' % (self.nas_host, filesystem['mountPoint'])

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Is called to create share from snapshot."""
        snapshot_path = self._get_snapshot_path(snapshot)
        LOG.debug('Creating share from snapshot %s.', snapshot_path)
        clone_path = self._get_dataset_path(share)
        size = int(share['size'] * units.Gi * ZFS_MULTIPLIER)
        payload = {
            'targetPath': clone_path,
            'referencedQuotaSize': size,
            'recordSize': self.configuration.nexenta_dataset_record_size,
            'compressionMode': self.dataset_compression,
            'nonBlockingMandatoryMode': False
        }
        if not self.configuration.nexenta_thin_provisioning:
            payload['referencedReservationSize'] = size
        self.nef.snapshots.clone(snapshot_path, payload)
        self._remount_filesystem(clone_path)
        self.provisioned_capacity += share['size']
        try:
            mount_path = self._mount_filesystem(share)
        except jsonrpc.NefException as create_error:
            try:
                payload = {'force': True}
                self.nef.filesystems.delete(clone_path, payload)
            except jsonrpc.NefException as delete_error:
                LOG.debug('Failed to delete share %(path)s: %(error)s',
                          {'path': clone_path, 'error': delete_error})
            raise create_error

        location = {
            'path': mount_path,
            'id': self._get_share_name(share)
        }
        return [location]

    def _remount_filesystem(self, clone_path):
        """Workaround for NEF bug: cloned share has offline NFS status"""
        self.nef.filesystems.unmount(clone_path)
        self.nef.filesystems.mount(clone_path)

    def _get_dataset_path(self, share):
        share_name = self._get_share_name(share)
        return posixpath.join(self.root_path, share_name)

    def _get_share_name(self, share):
        """Get share name with share name prefix."""
        return ('%(prefix)s%(share_id)s' % {
                'prefix': self.configuration.nexenta_share_name_prefix,
                'share_id': share['share_id']})

    def _get_snapshot_path(self, snapshot):
        """Return ZFS snapshot path for the snapshot."""
        snapshot_id = (
            snapshot['snapshot_id'] or snapshot['share_group_snapshot_id'])
        share = snapshot.get('share') or snapshot.get('share_instance')
        fs_path = self._get_dataset_path(share)
        return '%s@snapshot-%s' % (fs_path, snapshot_id)

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        LOG.debug('Deleting share: %s.', self._get_share_name(share))
        share_path = self._get_dataset_path(share)
        delete_payload = {'force': True, 'snapshots': True}
        try:
            self.nef.filesystems.delete(share_path, delete_payload)
        except jsonrpc.NefException as error:
            if error.code != 'EEXIST':
                raise error
            snapshots_tree = {}
            snapshots_payload = {'parent': share_path, 'fields': 'path'}
            snapshots = self.nef.snapshots.list(snapshots_payload)
            for snapshot in snapshots:
                clones_payload = {'fields': 'clones,creationTxg'}
                data = self.nef.snapshots.get(snapshot['path'], clones_payload)
                if data['clones']:
                    snapshots_tree[data['creationTxg']] = data['clones'][0]
            if snapshots_tree:
                clone_path = snapshots_tree[max(snapshots_tree)]
                self.nef.filesystems.promote(clone_path)
            self.nef.filesystems.delete(share_path, delete_payload)
        self.provisioned_capacity -= share['size']

    def extend_share(self, share, new_size, share_server=None):
        """Extends a share."""
        LOG.debug(
            'Extending share: %(name)s to %(size)sG.', (
                {'name': self._get_share_name(share), 'size': new_size}))
        self._set_quota(share, new_size)
        if not self.configuration.nexenta_thin_provisioning:
            self._set_reservation(share, new_size)
        self.provisioned_capacity += (new_size - share['size'])

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""
        LOG.debug(
            'Shrinking share: %(name)s to %(size)sG.', {
                'name': self._get_share_name(share), 'size': new_size})
        share_path = self._get_dataset_path(share)
        share_data = self.nef.filesystems.get(share_path)
        used = share_data['bytesUsedBySelf'] / units.Gi
        if used > new_size:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=self._get_share_name(share))
        if not self.configuration.nexenta_thin_provisioning:
            self._set_reservation(share, new_size)
        self._set_quota(share, new_size)
        self.provisioned_capacity += (share['size'] - new_size)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create a snapshot."""
        snapshot_path = self._get_snapshot_path(snapshot)
        LOG.debug('Creating snapshot: %s.', snapshot_path)
        payload = {'path': snapshot_path}
        self.nef.snapshots.create(payload)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot.

        :param snapshot: snapshot reference
        """
        snapshot_path = self._get_snapshot_path(snapshot)
        LOG.debug('Deleting snapshot: %s.', snapshot_path)
        payload = {'defer': True}
        self.nef.snapshots.delete(snapshot_path, payload)

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        """Reverts a share (in place) to the specified snapshot.

        Does not delete the share snapshot.  The share and snapshot must both
        be 'available' for the restore to be attempted.  The snapshot must be
        the most recent one taken by Manila; the API layer performs this check
        so the driver doesn't have to.

        The share must be reverted in place to the contents of the snapshot.
        Application admins should quiesce or otherwise prepare the application
        for the shared file system contents to change suddenly.

        :param context: Current context
        :param snapshot: The snapshot to be restored
        :param share_access_rules: List of all access rules for the affected
            share
        :param snapshot_access_rules: List of all access rules for the affected
            snapshot
        :param share_server: Optional -- Share server model or None
        """
        snapshot_path = self._get_snapshot_path(snapshot).split('@')[1]
        LOG.debug('Reverting to snapshot: %s.', snapshot_path)
        share_path = self._get_dataset_path(snapshot['share'])
        payload = {'snapshot': snapshot_path}
        self.nef.filesystems.rollback(share_path, payload)

    def manage_existing(self, share, driver_options):
        """Brings an existing share under Manila management.

        If the provided share is not valid, then raise a
        ManageInvalidShare exception, specifying a reason for the failure.

        If the provided share is not in a state that can be managed, such as
        being replicated on the backend, the driver *MUST* raise
        ManageInvalidShare exception with an appropriate message.

        The share has a share_type, and the driver can inspect that and
        compare against the properties of the referenced backend share.
        If they are incompatible, raise a
        ManageExistingShareTypeMismatch, specifying a reason for the failure.

        :param share: Share model
        :param driver_options: Driver-specific options provided by admin.
        :return: share_update dictionary with required key 'size',
                 which should contain size of the share.
        """
        LOG.debug('Manage share %s.', self._get_share_name(share))
        export_path = share['export_locations'][0]['path']

        # check that filesystem with provided export exists.
        fs_path = export_path.split(':/')[1]
        fs_data = self.nef.filesystems.get(fs_path)

        if not fs_data:
            # wrong export path, raise exception.
            msg = _('Share %s does not exist on Nexenta Store appliance, '
                    'cannot manage.') % export_path
            raise exception.NexentaException(msg)

        # get dataset properties.
        if fs_data['referencedQuotaSize']:
            size = (fs_data['referencedQuotaSize'] / units.Gi) + 1
        else:
            size = fs_data['bytesReferenced'] / units.Gi + 1
        # rename filesystem on appliance to correlate with manila ID.
        new_path = '%s/%s' % (self.root_path, self._get_share_name(share))
        self.nef.filesystems.rename(fs_path, {'newPath': new_path})
        # make sure quotas and reservations are correct.
        if not self.configuration.nexenta_thin_provisioning:
            self._set_reservation(share, size)
        self._set_quota(share, size)

        return {'size': size, 'export_locations': [{
            'path': '%s:/%s' % (self.nas_host, new_path)
        }]}

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share.

        Using access_rules list for both adding and deleting rules.
        :param context: The `context.RequestContext` object for the request
        :param share: Share that will have its access rules updated.
        :param access_rules: All access rules for given share. This list
        is enough to update the access rules for given share.
        :param add_rules: Empty List or List of access rules which should be
        added. access_rules already contains these rules. Not used by this
        driver.
        :param delete_rules: Empty List or List of access rules which should be
        removed. access_rules doesn't contain these rules. Not used by
        this driver.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """
        LOG.debug('Updating access to share %(id)s with following access '
                  'rules: %(rules)s', {
                      'id': self._get_share_name(share),
                      'rules': [(
                          rule.get('access_type'), rule.get('access_level'),
                          rule.get('access_to')) for rule in access_rules]})
        rw_list = []
        ro_list = []
        update_dict = {}
        if share['share_proto'] == 'NFS':
            for rule in access_rules:
                if rule['access_type'].lower() != 'ip':
                    msg = _(
                        'Only IP access control type is supported for NFS.')
                    LOG.warning(msg)
                    update_dict[rule['access_id']] = {
                        'state': 'error',
                    }
                else:
                    update_dict[rule['access_id']] = {
                        'state': 'active',
                    }
                if rule['access_level'] == common.ACCESS_LEVEL_RW:
                    rw_list.append(rule['access_to'])
                else:
                    ro_list.append(rule['access_to'])
            self._update_nfs_access(share, rw_list, ro_list)
        return update_dict

    def _update_nfs_access(self, share, rw_list, ro_list):
        # Define allowed security context types to be able to tell whether
        # the 'security_contexts' dict contains any rules at all
        context_types = {'none', 'root', 'readOnlyList', 'readWriteList'}

        security_contexts = {'securityModes': ['sys']}

        def add_sc(addr_list, sc_type):
            if sc_type not in context_types:
                return

            rule_list = []

            for addr in addr_list:
                address_mask = addr.strip().split('/', 1)
                address = address_mask[0]
                ls = {"allow": True, "etype": "fqdn", "entity": address}
                if len(address_mask) == 2:
                    mask = int(address_mask[1])
                    if 0 <= mask < 31:
                        ls['mask'] = mask
                        ls['etype'] = 'network'
                rule_list.append(ls)

            # Context type with no addresses will result in an API error
            if rule_list:
                security_contexts[sc_type] = rule_list

        add_sc(rw_list, 'readWriteList')
        add_sc(ro_list, 'readOnlyList')
        payload = {'securityContexts': [security_contexts]}
        share_path = self._get_dataset_path(share)
        if self.nef.nfs.list({'filesystem': share_path}):
            if not set(security_contexts.keys()) & context_types:
                self.nef.nfs.delete(share_path)
            else:
                self.nef.nfs.set(share_path, payload)
        else:
            payload['filesystem'] = share_path
            self.nef.nfs.create(payload)
        payload = {
            'flags': ['file_inherit', 'dir_inherit'],
            'permissions': ['full_set'],
            'principal': 'everyone@',
            'type': 'allow'
        }
        self.nef.filesystems.acl(share_path, payload)

    def _set_quota(self, share, new_size):
        quota = int(new_size * units.Gi * ZFS_MULTIPLIER)
        share_path = self._get_dataset_path(share)
        payload = {'referencedQuotaSize': quota}
        LOG.debug('Setting quota for dataset %s.', share_path)
        self.nef.filesystems.set(share_path, payload)

    def _set_reservation(self, share, new_size):
        res_size = int(new_size * units.Gi * ZFS_MULTIPLIER)
        share_path = self._get_dataset_path(share)
        payload = {'referencedReservationSize': res_size}
        self.nef.filesystems.set(share_path, payload)

    def _update_share_stats(self, data=None):
        super(NexentaNasDriver, self)._update_share_stats()
        total, free, allocated = self._get_capacity_info()
        compression = not self.dataset_compression == 'off'
        data = {
            'vendor_name': 'Nexenta',
            'storage_protocol': self.storage_protocol,
            'share_backend_name': self.share_backend_name,
            'nfs_mount_point_base': self.nfs_mount_point_base,
            'driver_version': VERSION,
            'snapshot_support': True,
            'create_share_from_snapshot_support': True,
            'revert_to_snapshot_support': True,
            'pools': [{
                'pool_name': self.pool_name,
                'compression': compression,
                'total_capacity_gb': total,
                'free_capacity_gb': free,
                'reserved_percentage': (
                    self.configuration.reserved_share_percentage),
                'reserved_snapshot_percentage':
                    (self.configuration.reserved_share_from_snapshot_percentage
                        or self.configuration.reserved_share_percentage),
                'reserved_share_extend_percentage':
                    (self.configuration.reserved_share_extend_percentage
                        or self.configuration.reserved_share_percentage),
                'max_over_subscription_ratio': (
                    self.configuration.safe_get(
                        'max_over_subscription_ratio')),
                'thin_provisioning':
                    self.configuration.nexenta_thin_provisioning,
                'provisioned_capacity_gb': self.provisioned_capacity,
            }],
        }
        self._stats.update(data)

    def _get_capacity_info(self):
        """Calculate available space on the NFS share."""
        data = self.nef.filesystems.get(self.root_path)
        free = int(utils.bytes_to_gb(data['bytesAvailable']))
        allocated = int(utils.bytes_to_gb(data['bytesUsed']))
        total = free + allocated
        return total, free, allocated
