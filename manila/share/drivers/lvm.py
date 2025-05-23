# Copyright 2012 NetApp
# Copyright 2016 Mirantis Inc.
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
LVM Driver for shares.

"""

import ipaddress
import math
import os
import re

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from oslo_utils import timeutils

from manila import exception
from manila.i18n import _
from manila.privsep import common as privsep_common
from manila.privsep import filesystem as privsep_filesystem
from manila.privsep import lvm as privsep_lvm
from manila.privsep import os as privsep_os
from manila.share import driver
from manila.share.drivers import generic
from manila.share import utils as share_utils
from manila import utils

LOG = log.getLogger(__name__)

share_opts = [
    cfg.StrOpt('lvm_share_export_root',
               default='$state_path/mnt',
               help='Base folder where exported shares are located.'),
    cfg.ListOpt('lvm_share_export_ips',
                help='List of IPs to export shares belonging to the LVM '
                     'storage driver.'),
    cfg.IntOpt('lvm_share_mirrors',
               default=0,
               help='If set, create LVMs with multiple mirrors. Note that '
                    'this requires lvm_mirrors + 2 PVs with available space.'),
    cfg.StrOpt('lvm_share_volume_group',
               default='lvm-shares',
               help='Name for the VG that will contain exported shares.'),
    cfg.ListOpt('lvm_share_helpers',
                default=[
                    'CIFS=manila.share.drivers.helpers.CIFSHelperUserAccess',
                    'NFS=manila.share.drivers.helpers.NFSHelper',
                ],
                help='Specify list of share export helpers.'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)
CONF.register_opts(generic.share_opts)


class LVMMixin(driver.ExecuteMixin):
    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        try:
            out, err = privsep_lvm.list_vgs_get_name()
        except processutils.ProcessExecutionError:
            msg = _("Failed to get LVM volume group names.")
            raise exception.ShareBackendException(msg=msg)
        volume_groups = out.split()
        if self.configuration.lvm_share_volume_group not in volume_groups:
            msg = (_("Share volume group %s doesn't exist.")
                   % self.configuration.lvm_share_volume_group)
            raise exception.InvalidParameterValue(err=msg)

        if not self.configuration.lvm_share_export_ips:
            msg = _("The option lvm_share_export_ips must be specified.")
            raise exception.InvalidParameterValue(err=msg)

    def _allocate_container(self, share):
        sizestr = '%sG' % share['size']
        mirrors = 0
        region_size = 0
        if self.configuration.lvm_share_mirrors:
            mirrors = self.configuration.lvm_share_mirrors
            terras = int(sizestr[:-1]) / 1024.0
            if terras >= 1.5:
                rsize = int(2 ** math.ceil(math.log(terras) / math.log(2)))
                # NOTE(vish): Next power of two for region size. See:
                #             http://red.ht/U2BPOD
                region_size = str(rsize)
        action_args = [
            share['size'],
            share['name'],
            self.configuration.lvm_share_volume_group,
            mirrors,
            region_size
        ]
        privsep_common.execute_with_retries(
            privsep_lvm.lvcreate, action_args,
            self.configuration.num_shell_tries)
        device_name = self._get_local_path(share)
        try:
            privsep_filesystem.make_filesystem(
                self.configuration.share_volume_fstype, device_name)
        except processutils.ProcessExecutionError:
            raise

    def _get_mount_point_name(self, share):
        return share.get('mount_point_name') or share.get('name')

    def _extend_container(self, share, device_name, size):
        privsep_common.execute_with_retries(
            privsep_lvm.lvextend, [device_name, size],
            self.configuration.num_shell_tries)

    def _deallocate_container(self, share_name):
        """Deletes a logical volume for share."""
        try:
            action_args = [
                self.configuration.lvm_share_volume_group, share_name]
            privsep_common.execute_with_retries(
                privsep_lvm.lvremove, action_args,
                self.configuration.num_shell_tries)
        except exception.ProcessExecutionError as exc:
            err_pattern = re.compile(".*failed to find.*|.*not found.*",
                                     re.IGNORECASE)
            if not err_pattern.match(exc.stderr):
                LOG.exception("Error deleting volume")
                raise
            LOG.warning("Volume not found: %s", exc.stderr)

    def _create_snapshot(self, context, snapshot):
        """Creates a snapshot."""
        orig_lv_name = "%s/%s" % (self.configuration.lvm_share_volume_group,
                                  snapshot['share_name'])
        action_args = [
            snapshot['share']['size'], snapshot['name'], orig_lv_name]
        privsep_common.execute_with_retries(
            privsep_lvm.lv_snapshot_create, action_args,
            self.configuration.num_shell_tries)

        self._set_random_uuid_to_device(snapshot)

    def _set_random_uuid_to_device(self, share_or_snapshot):
        # NOTE(vponomaryov): 'tune2fs' is required to make
        # filesystem of share created from snapshot have
        # unique ID, in case of LVM volumes, by default,
        # it will have the same UUID as source volume. Closes #1645751
        # NOTE(gouthamr): Executing tune2fs -U only works on
        # a recently checked filesystem.
        # See: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=857336
        device_path = self._get_local_path(share_or_snapshot)
        try:
            privsep_filesystem.e2fsck(device_path)
            privsep_filesystem.tune2fs(device_path)
        except processutils.ProcessExecutionError:
            msg = _("Failed to check or modify filesystems.")
            raise exception.ShareBackendException(msg=msg)

    def create_snapshot(self, context, snapshot, share_server=None):
        self._create_snapshot(context, snapshot)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""
        self._deallocate_container(snapshot['name'])


class LVMShareDriver(LVMMixin, driver.ShareDriver):
    """Executes commands relating to Shares."""

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        super(LVMShareDriver, self).__init__([False], *args, **kwargs)
        self.configuration.append_config_values(share_opts)
        self.configuration.append_config_values(generic.share_opts)
        self.configuration.share_mount_path = (
            self.configuration.lvm_share_export_root)
        self._helpers = None
        self.configured_ip_version = None
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'LVM'
        # Set of parameters used for compatibility with
        # Generic driver's helpers.
        self.share_server = {
            'instance_id': self.backend_name,
            'lock_name': 'manila_lvm',
        }
        self.share_server['public_addresses'] = (
            self.configuration.lvm_share_export_ips
        )
        self.ipv6_implemented = True

    def _ssh_exec_as_root(self, server, command, check_exit_code=True):
        kwargs = {}
        if 'sudo' in command:
            kwargs['run_as_root'] = True
            command.remove('sudo')
        kwargs['check_exit_code'] = check_exit_code
        return self._execute(*command, **kwargs)

    def do_setup(self, context):
        """Any initialization the volume driver does while starting."""
        super(LVMShareDriver, self).do_setup(context)
        self._setup_helpers()

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {}
        for helper_str in self.configuration.lvm_share_helpers:
            share_proto, _, import_str = helper_str.partition('=')
            helper = importutils.import_class(import_str)
            # TODO(rushiagr): better way to handle configuration
            #                 instead of just passing to the helper
            self._helpers[share_proto.upper()] = helper(
                self._execute, self._ssh_exec_as_root, self.configuration)

    def _get_local_path(self, share):
        # The escape characters are expected by the device mapper.
        escaped_group = (
            self.configuration.lvm_share_volume_group.replace('-', '--'))
        escaped_name = share['name'].replace('-', '--')
        return "/dev/mapper/%s-%s" % (escaped_group, escaped_name)

    def _update_share_stats(self):
        """Retrieve stats info from share volume group."""
        data = {
            'share_backend_name': self.backend_name,
            'storage_protocol': 'NFS_CIFS',
            'reserved_percentage':
                self.configuration.reserved_share_percentage,
            'reserved_snapshot_percentage':
                (self.configuration.reserved_share_from_snapshot_percentage
                    or self.configuration.reserved_share_percentage),
            'reserved_share_extend_percentage':
                (self.configuration.reserved_share_extend_percentage
                    or self.configuration.reserved_share_percentage),
            'snapshot_support': True,
            'create_share_from_snapshot_support': True,
            'revert_to_snapshot_support': True,
            'mount_snapshot_support': True,
            'driver_name': 'LVMShareDriver',
            'pools': self.get_share_server_pools(),
        }
        super(LVMShareDriver, self)._update_share_stats(data)

    def get_share_server_pools(self, share_server=None):
        try:
            out, err = privsep_lvm.get_vgs(
                self.configuration.lvm_share_volume_group)
        except processutils.ProcessExecutionError:
            msg = _("Failed to list LVM Volume Groups.")
            raise exception.ShareBackendException(msg=msg)
        total_size = re.findall(r"VSize\s[0-9.]+g", out)[0][6:-1]
        free_size = re.findall(r"VFree\s[0-9.]+g", out)[0][6:-1]
        return [{
            'pool_name': 'lvm-single-pool',
            'total_capacity_gb': float(total_size),
            'free_capacity_gb': float(free_size),
            'reserved_percentage': 0,
            'reserved_snapshot_percentage': 0,
            'reserved_share_extend_percentage': 0,
            'mount_point_name_support': True,
        }, ]

    def create_share(self, context, share, share_server=None):
        self._allocate_container(share)
        # create file system
        device_name = self._get_local_path(share)
        share_export_location = self._get_mount_point_name(share)
        location = self._get_helper(share).create_exports(
            self.share_server, share_export_location)
        self._mount_device(share, device_name)
        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Is called to create share from snapshot."""
        self._allocate_container(share)
        snapshot_device_name = self._get_local_path(snapshot)
        share_device_name = self._get_local_path(share)
        self._set_random_uuid_to_device(share)
        self._copy_volume(
            snapshot_device_name, share_device_name, share['size'])
        share_export_location = self._get_mount_point_name(share)
        location = self._get_helper(share).create_exports(
            self.share_server, share_export_location)
        self._mount_device(share, share_device_name)
        return location

    def delete_share(self, context, share, share_server=None):
        self._unmount_device(share, raise_if_missing=False,
                             retry_busy_device=True)
        self._delete_share(context, share)
        self._deallocate_container(share['name'])

    def _unmount_device(self, share_or_snapshot, raise_if_missing=True,
                        retry_busy_device=False):
        """Unmount the filesystem of a share or snapshot LV."""
        mount_path = self._get_mount_path(share_or_snapshot)
        if os.path.exists(mount_path):

            retries = 10 if retry_busy_device else 1

            @utils.retry(retry_param=exception.ShareBusyException,
                         retries=retries)
            def _unmount_device_with_retry():
                try:
                    privsep_os.umount(mount_path)
                except exception.ProcessExecutionError as exc:
                    if 'is busy' in exc.stderr.lower():
                        raise exception.ShareBusyException(
                            reason=share_or_snapshot['name'])
                    elif 'not mounted' in exc.stderr.lower():
                        if raise_if_missing:
                            LOG.error('Unable to find device: %s', exc)
                            raise
                    else:
                        LOG.error('Unable to umount: %s', exc)
                        raise

            _unmount_device_with_retry()
            # remove dir
            try:
                privsep_os.rmdir(mount_path)
            except exception.ProcessExecutionError:
                msg = _("Failed to remove the directory.")
                raise exception.ShareBackendException(msg=msg)

    def ensure_shares(self, context, shares):
        updates = {}
        for share in shares:
            updates[share['id']] = {
                'export_locations': self.ensure_share(context, share)}
        return updates

    def ensure_share(self, ctx, share, share_server=None):
        """Ensure that storage are mounted and exported."""
        device_name = self._get_local_path(share)
        self._mount_device(share, device_name)
        share_export_location = self._get_mount_point_name(share)
        return self._get_helper(share).create_exports(
            self.share_server,
            share_export_location,
            recreate=True
        )

    def _delete_share(self, ctx, share):
        share_export_location = self._get_mount_point_name(share)
        """Delete a share."""
        try:
            self._get_helper(share).remove_exports(
                self.share_server, share_export_location)
        except exception.ProcessExecutionError:
            LOG.warning("Can't remove share %r", share['id'])
        except exception.InvalidShare as exc:
            LOG.warning(exc)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, update_rules, share_server=None):
        """Update access rules for given share.

        This driver has two different behaviors according to parameters:
        1. Recovery after error - 'access_rules' contains all access_rules,
        'add_rules' and 'delete_rules' shall be empty. Previously existing
        access rules are cleared and then added back according
        to 'access_rules'.

        2. Adding/Deleting of several access rules - 'access_rules' contains
        all access_rules, 'add_rules' and 'delete_rules' contain rules which
        should be added/deleted. Rules in 'access_rules' are ignored and
        only rules from 'add_rules' and 'delete_rules' are applied.

        :param context: Current context
        :param share: Share model with share data.
        :param access_rules: All access rules for given share
        :param add_rules: Empty List or List of access rules which should be
               added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
               removed. access_rules doesn't contain these rules.
        :param update_rules: Empty List or List of access rules which should be
               updated. access_rules already contains these rules.
        :param share_server: None or Share server model
        """
        share_export_location = self._get_mount_point_name(share)
        self._get_helper(share).update_access(self.share_server,
                                              share_export_location,
                                              access_rules,
                                              add_rules=add_rules,
                                              delete_rules=delete_rules)

    def _get_helper(self, share):
        if share['share_proto'].lower().startswith('nfs'):
            return self._helpers['NFS']
        elif share['share_proto'].lower().startswith('cifs'):
            return self._helpers['CIFS']
        else:
            raise exception.InvalidShare(reason='Wrong share protocol')

    def _mount_device(self, share_or_snapshot, device_name):
        """Mount LV for share or snapshot and ignore if already mounted."""
        mount_path = self._get_mount_path(share_or_snapshot)
        self._execute('mkdir', '-p', mount_path)
        try:
            privsep_os.mount(device_name, mount_path)
            privsep_os.chmod('777', mount_path)
        except exception.ProcessExecutionError:
            out, err = privsep_os.list_mounts()
            if device_name in out:
                LOG.warning("%s is already mounted", device_name)
            else:
                raise
        return mount_path

    def _get_mount_path(self, share_or_snapshot):
        """Returns path where share or snapshot is mounted."""
        return os.path.join(self.configuration.share_mount_path,
                            share_or_snapshot['name'])

    def _copy_volume(self, srcstr, deststr, size_in_g):
        # Use O_DIRECT to avoid thrashing the system buffer cache
        # Check whether O_DIRECT is supported
        use_direct_io = (
            privsep_os.is_data_definition_direct_io_supported(srcstr, deststr))

        # Perform the copy
        try:
            privsep_os.data_definition(
                srcstr, deststr, (size_in_g * 1024),
                use_direct_io=use_direct_io)
        except exception.ProcessExecutionError:
            msg = _("Failed while copying from the snapshot to the share.")
            raise exception.ShareBackendException(msg=msg)

    def extend_share(self, share, new_size, share_server=None):
        device_name = self._get_local_path(share)
        self._extend_container(share, device_name, new_size)

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        share = snapshot['share']
        snapshot_export_location = self._get_mount_point_name(snapshot)
        share_export_location = self._get_mount_point_name(share)
        # Temporarily remove all access rules
        self._get_helper(share).update_access(self.share_server,
                                              snapshot_export_location,
                                              [], [], [])
        self._get_helper(share).update_access(self.share_server,
                                              share_export_location,
                                              [], [], [])
        # Unmount the snapshot filesystem
        self._unmount_device(snapshot)
        # Unmount the share filesystem
        self._unmount_device(share)
        # Merge the snapshot LV back into the share, reverting it
        try:
            privsep_lvm.lvconvert(self.configuration.lvm_share_volume_group,
                                  snapshot['name'])
        except exception.ProcessExecutionError:
            msg = _('Failed to revert the share to the given snapshot.')
            raise exception.ShareBackendException(msg=msg)

        # Now recreate the snapshot that was destroyed by the merge
        self._create_snapshot(context, snapshot)
        # At this point we can mount the share again
        device_name = self._get_local_path(share)
        self._mount_device(share, device_name)
        # Also remount the snapshot
        device_name = self._get_local_path(snapshot)
        self._mount_device(snapshot, device_name)
        share_export_location = self._get_mount_point_name(share)
        snapshot_export_location = self._get_mount_point_name(share)
        # Lastly we add all the access rules back
        self._get_helper(share).update_access(self.share_server,
                                              share_export_location,
                                              share_access_rules,
                                              [], [])
        snapshot_access_rules, __, __ = share_utils.change_rules_to_readonly(
            snapshot_access_rules, [], [])
        self._get_helper(share).update_access(self.share_server,
                                              snapshot_export_location,
                                              snapshot_access_rules,
                                              [], [])

    def create_snapshot(self, context, snapshot, share_server=None):
        self._create_snapshot(context, snapshot)

        device_name = self._get_local_path(snapshot)
        self._mount_device(snapshot, device_name)

        helper = self._get_helper(snapshot['share'])
        exports = helper.create_exports(self.share_server, snapshot['name'])

        return {'export_locations': exports}

    def delete_snapshot(self, context, snapshot, share_server=None):
        self._unmount_device(snapshot, raise_if_missing=False)

        super(LVMShareDriver, self).delete_snapshot(context, snapshot,
                                                    share_server)

    def get_configured_ip_versions(self):
        if self.configured_ip_version is None:
            try:
                self.configured_ip_version = []
                for ip in self.configuration.lvm_share_export_ips:
                    self.configured_ip_version.append(
                        ipaddress.ip_address(str(ip)).version)
            except Exception:
                message = (_("Invalid 'lvm_share_export_ips' option supplied "
                             "%s.") % self.configuration.lvm_share_export_ips)
                raise exception.InvalidInput(reason=message)
        return self.configured_ip_version

    def snapshot_update_access(self, context, snapshot, access_rules,
                               add_rules, delete_rules, share_server=None):
        """Update access rules for given snapshot.

        This driver has two different behaviors according to parameters:
        1. Recovery after error - 'access_rules' contains all access_rules,
        'add_rules' and 'delete_rules' shall be empty. Previously existing
        access rules are cleared and then added back according
        to 'access_rules'.

        2. Adding/Deleting of several access rules - 'access_rules' contains
        all access_rules, 'add_rules' and 'delete_rules' contain rules which
        should be added/deleted. Rules in 'access_rules' are ignored and
        only rules from 'add_rules' and 'delete_rules' are applied.

        :param context: Current context
        :param snapshot: Snapshot model with snapshot data.
        :param access_rules: All access rules for given snapshot
        :param add_rules: Empty List or List of access rules which should be
               added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
               removed. access_rules doesn't contain these rules.
        :param share_server: None or Share server model
        """
        helper = self._get_helper(snapshot['share'])
        access_rules, add_rules, delete_rules = (
            share_utils.change_rules_to_readonly(
                access_rules, add_rules, delete_rules)
        )

        helper.update_access(self.share_server,
                             snapshot['name'], access_rules,
                             add_rules=add_rules, delete_rules=delete_rules)

    def update_share_usage_size(self, context, shares):
        updated_shares = []
        out, err = self._execute(
            'df', '-l', '--output=target,used',
            '--block-size=g')
        gathered_at = timeutils.utcnow()

        for share in shares:
            try:
                mount_path = self._get_mount_path(share)
                if os.path.exists(mount_path):
                    used_size = (re.findall(
                        mount_path + r"\s*[0-9.]+G", out)[0].
                        split(' ')[-1][:-1])
                    updated_shares.append({'id': share['id'],
                                           'used_size': used_size,
                                           'gathered_at': gathered_at})
                else:
                    raise exception.NotFound(
                        _("Share mount path %s could not be "
                          "found.") % mount_path)
            except Exception:
                LOG.exception("Failed to gather 'used_size' for share %s.",
                              share['id'])

        return updated_shares

    def get_backend_info(self, context):
        return {
            'export_ips': ','.join(self.share_server['public_addresses']),
            'db_version': share_utils.get_recent_db_migration_id(),
        }
