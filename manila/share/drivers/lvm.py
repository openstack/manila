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

import math
import os
import re

from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LI
from manila.i18n import _LW
from manila.share import driver
from manila.share.drivers import generic


LOG = log.getLogger(__name__)

share_opts = [
    cfg.StrOpt('lvm_share_export_root',
               default='$state_path/mnt',
               help='Base folder where exported shares are located.'),
    cfg.StrOpt('lvm_share_export_ip',
               help='IP to be added to export string.'),
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
        out, err = self._execute('sudo', 'vgs', '--noheadings', '-o', 'name')
        volume_groups = out.split()
        if self.configuration.lvm_share_volume_group not in volume_groups:
            msg = (_("share volume group %s doesn't exist")
                   % self.configuration.lvm_share_volume_group)
            raise exception.InvalidParameterValue(err=msg)
        if not self.configuration.lvm_share_export_ip:
            msg = (_("share_export_ip isn't specified"))
            raise exception.InvalidParameterValue(err=msg)

    def _allocate_container(self, share):
        sizestr = '%sG' % share['size']
        cmd = ['lvcreate', '-L', sizestr, '-n', share['name'],
               self.configuration.lvm_share_volume_group]
        if self.configuration.lvm_share_mirrors:
            cmd += ['-m', self.configuration.lvm_share_mirrors, '--nosync']
            terras = int(sizestr[:-1]) / 1024.0
            if terras >= 1.5:
                rsize = int(2 ** math.ceil(math.log(terras) / math.log(2)))
                # NOTE(vish): Next power of two for region size. See:
                #             http://red.ht/U2BPOD
                cmd += ['-R', six.text_type(rsize)]

        self._try_execute(*cmd, run_as_root=True)
        device_name = self._get_local_path(share)
        self._execute('mkfs.%s' % self.configuration.share_volume_fstype,
                      device_name, run_as_root=True)

    def _extend_container(self, share, device_name, size):
        cmd = ['lvextend', '-L', '%sG' % size, '-n', device_name]
        self._try_execute(*cmd, run_as_root=True)

    def _deallocate_container(self, share_name):
        """Deletes a logical volume for share."""
        try:
            self._try_execute('lvremove', '-f', "%s/%s" %
                              (self.configuration.lvm_share_volume_group,
                               share_name), run_as_root=True)
        except exception.ProcessExecutionError as exc:
            if "not found" not in exc.stderr:
                LOG.exception(_LE("Error deleting volume"))
                raise
            LOG.warning(_LW("Volume not found: %s") % exc.stderr)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""
        orig_lv_name = "%s/%s" % (self.configuration.lvm_share_volume_group,
                                  snapshot['share_name'])
        self._try_execute(
            'lvcreate', '-L', '%sG' % snapshot['share']['size'],
            '--name', snapshot['name'],
            '--snapshot', orig_lv_name, run_as_root=True)

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
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'LVM'
        # Set of parameters used for compatibility with
        # Generic driver's helpers.
        self.share_server = {
            'public_address': self.configuration.lvm_share_export_ip,
            'instance_id': self.backend_name,
        }

    def _ssh_exec_as_root(self, server, command):
        kwargs = {}
        if 'sudo' in command:
            kwargs['run_as_root'] = True
            command.remove('sudo')
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
            'consistency_group_support': None,
            'snapshot_support': True,
            'driver_name': 'LVMShareDriver',
            'pools': self.get_share_server_pools()
        }
        super(LVMShareDriver, self)._update_share_stats(data)

    def get_share_server_pools(self, share_server=None):
        out, err = self._execute('sudo', 'vgs',
                                 self.configuration.lvm_share_volume_group,
                                 '--rows')
        total_size = re.findall("VSize\s[0-9.]+g", out)[0][6:-1]
        free_size = re.findall("VFree\s[0-9.]+g", out)[0][6:-1]
        return [{
            'pool_name': 'lvm-single-pool',
            'total_capacity_gb': float(total_size),
            'free_capacity_gb': float(free_size),
            'reserved_percentage': 0,
        }, ]

    def create_share(self, context, share, share_server=None):
        self._allocate_container(share)
        # create file system
        device_name = self._get_local_path(share)
        location = self._get_helper(share).create_export(self.share_server,
                                                         share['name'])
        self._mount_device(share, device_name)
        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        self._allocate_container(share)
        device_name = self._get_local_path(snapshot)
        self._copy_volume(device_name, self._get_local_path(share),
                          share['size'])
        location = self._get_helper(share).create_export(self.share_server,
                                                         share['name'])
        self._mount_device(share, device_name)
        return location

    def delete_share(self, context, share, share_server=None):
        self._remove_export(context, share)
        self._delete_share(context, share)
        self._deallocate_container(share['name'])

    def _remove_export(self, ctx, share):
        """Removes an access rules for a share."""
        mount_path = self._get_mount_path(share)
        if os.path.exists(mount_path):
            # umount, may be busy
            try:
                self._execute('umount', '-f', mount_path, run_as_root=True)
            except exception.ProcessExecutionError as exc:
                if 'device is busy' in six.text_type(exc):
                    raise exception.ShareBusyException(reason=share['name'])
                else:
                    LOG.info(_LI('Unable to umount: %s'), exc)
            # remove dir
            try:
                os.rmdir(mount_path)
            except OSError:
                LOG.warning(_LI('Unable to delete %s'), mount_path)

    def ensure_share(self, ctx, share, share_server=None):
        """Ensure that storage are mounted and exported."""
        device_name = self._get_local_path(share)
        self._mount_device(share, device_name)
        self._get_helper(share).create_export(self.share_server, share['name'],
                                              recreate=True)

    def _delete_share(self, ctx, share):
        """Delete a share."""
        try:
            self._get_helper(share).remove_export(self.share_server,
                                                  share['name'])
        except exception.ProcessExecutionError:
            LOG.warning(_LI("Can't remove share %r"), share['id'])
        except exception.InvalidShare as exc:
            LOG.warning(exc.message)

    def allow_access(self, ctx, share, access, share_server=None):
        """Allow access to the share."""
        self._get_helper(share).allow_access(self.share_server, share['name'],
                                             access['access_type'],
                                             access['access_level'],
                                             access['access_to'])

    def deny_access(self, ctx, share, access, share_server=None):
        """Deny access to the share."""
        self._get_helper(share).deny_access(self.share_server, share['name'],
                                            access)

    def _get_helper(self, share):
        if share['share_proto'].lower().startswith('nfs'):
            return self._helpers['NFS']
        elif share['share_proto'].lower().startswith('cifs'):
            return self._helpers['CIFS']
        else:
            raise exception.InvalidShare(reason='Wrong share protocol')

    def _mount_device(self, share, device_name):
        """Mount LVM share and ignore if already mounted."""
        mount_path = self._get_mount_path(share)
        self._execute('mkdir', '-p', mount_path)
        try:
            self._execute('mount', device_name, mount_path,
                          run_as_root=True, check_exit_code=True)
            self._execute('chmod', '777', mount_path,
                          run_as_root=True, check_exit_code=True)
        except exception.ProcessExecutionError:
            out, err = self._execute('mount', '-l', run_as_root=True)
            if device_name in out:
                LOG.warning(_LW("%s is already mounted"), device_name)
            else:
                raise
        return mount_path

    def _unmount_device(self, share):
        mount_path = self._get_mount_path(share)
        self._execute('umount', mount_path, run_as_root=True)
        self._execute('rmdir', mount_path, run_as_root=True)

    def _get_mount_path(self, share):
        """Returns path where share is mounted."""
        return os.path.join(self.configuration.share_mount_path,
                            share['name'])

    def _copy_volume(self, srcstr, deststr, size_in_g):
        # Use O_DIRECT to avoid thrashing the system buffer cache
        extra_flags = ['iflag=direct', 'oflag=direct']

        # Check whether O_DIRECT is supported
        try:
            self._execute('dd', 'count=0', 'if=%s' % srcstr, 'of=%s' % deststr,
                          *extra_flags, run_as_root=True)
        except exception.ProcessExecutionError:
            extra_flags = []

        # Perform the copy
        self._execute('dd', 'if=%s' % srcstr, 'of=%s' % deststr,
                      'count=%d' % (size_in_g * 1024), 'bs=1M',
                      *extra_flags, run_as_root=True)

    def extend_share(self, share, new_size, share_server=None):
        device_name = self._get_local_path(share)
        self._extend_container(share, device_name, new_size)
        self._execute('resize2fs', device_name, run_as_root=True)
