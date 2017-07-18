# Copyright 2014 IBM Corp.
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
GPFS Driver for shares.

Config Requirements:
  GPFS file system must have quotas enabled (`mmchfs -Q yes`).
Notes:
  GPFS independent fileset is used for each share.

TODO(nileshb): add support for share server creation/deletion/handling.

Limitation:
  While using remote GPFS node, with Ganesha NFS, 'gpfs_ssh_private_key'
  for remote login to the GPFS node must be specified and there must be
  a passwordless authentication already setup between the Manila share
  service and the remote GPFS node.

"""
import abc
import math
import os
import re
import socket

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import strutils
from oslo_utils import units
import six

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.helpers import NFSHelper
from manila.share import share_types
from manila import utils

LOG = log.getLogger(__name__)

# matches multiple comma separated avpairs on a line.  values with an embedded
# comma must be wrapped in quotation marks
AVPATTERN = re.compile(r'\s*(?P<attr>\w+)\s*=\s*(?P<val>'
                       '(["][a-zA-Z0-9_, ]+["])|(\w+))\s*[,]?')

ERR_FILE_NOT_FOUND = 2

gpfs_share_opts = [
    cfg.HostAddressOpt('gpfs_share_export_ip',
                       help='IP to be added to GPFS export string.'),
    cfg.StrOpt('gpfs_mount_point_base',
               default='$state_path/mnt',
               help='Base folder where exported shares are located.'),
    cfg.StrOpt('gpfs_nfs_server_type',
               default='CES',
               help=('NFS Server type. Valid choices are "CES" (Ganesha NFS) '
                     'or "KNFS" (Kernel NFS).')),
    cfg.ListOpt('gpfs_nfs_server_list',
                help=('A list of the fully qualified NFS server names that '
                      'make up the OpenStack Manila configuration.')),
    cfg.BoolOpt('is_gpfs_node',
                default=False,
                help=('True:when Manila services are running on one of the '
                      'Spectrum Scale node. '
                      'False:when Manila services are not running on any of '
                      'the Spectrum Scale node.')),
    cfg.PortOpt('gpfs_ssh_port',
                default=22,
                help='GPFS server SSH port.'),
    cfg.StrOpt('gpfs_ssh_login',
               help='GPFS server SSH login name.'),
    cfg.StrOpt('gpfs_ssh_password',
               secret=True,
               help='GPFS server SSH login password. '
                    'The password is not needed, if \'gpfs_ssh_private_key\' '
                    'is configured.'),
    cfg.StrOpt('gpfs_ssh_private_key',
               help='Path to GPFS server SSH private key for login.'),
    cfg.ListOpt('gpfs_share_helpers',
                default=[
                    'KNFS=manila.share.drivers.ibm.gpfs.KNFSHelper',
                    'CES=manila.share.drivers.ibm.gpfs.CESHelper',
                ],
                help='Specify list of share export helpers.'),
    cfg.StrOpt('knfs_export_options',
               default=('rw,sync,no_root_squash,insecure,no_wdelay,'
                        'no_subtree_check'),
               help=('Options to use when exporting a share using kernel '
                     'NFS server. Note that these defaults can be overridden '
                     'when a share is created by passing metadata with key '
                     'name export_options.'),
               deprecated_for_removal=True,
               deprecated_reason="This option isn't used any longer. Please "
                                 "use share-type extra specs for export "
                                 "options."),
]


CONF = cfg.CONF
CONF.register_opts(gpfs_share_opts)


class GPFSShareDriver(driver.ExecuteMixin, driver.GaneshaMixin,
                      driver.ShareDriver):

    """GPFS Share Driver.

    Executes commands relating to Shares.
    Supports creation of shares on a GPFS cluster.

    API version history:

        1.0 - Initial version.
        1.1 - Added extend_share functionality
        2.0 - Added CES support for NFS Ganesha
    """

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        super(GPFSShareDriver, self).__init__(False, *args, **kwargs)
        self._helpers = {}
        self.configuration.append_config_values(gpfs_share_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or "IBM Storage System"
        self.sshpool = None
        self.ssh_connections = {}
        self._gpfs_execute = None
        if self.configuration.is_gpfs_node:
            self.GPFS_PATH = ''
        else:
            self.GPFS_PATH = '/usr/lpp/mmfs/bin/'

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""
        super(GPFSShareDriver, self).do_setup(context)
        if self.configuration.is_gpfs_node:
            self._gpfs_execute = self._gpfs_local_execute
        else:
            self._gpfs_execute = self._gpfs_remote_execute
        self._setup_helpers()

    def _gpfs_local_execute(self, *cmd, **kwargs):
        if 'run_as_root' not in kwargs:
            kwargs.update({'run_as_root': True})
        if 'ignore_exit_code' in kwargs:
            check_exit_code = kwargs.pop('ignore_exit_code')
            check_exit_code.append(0)
            kwargs.update({'check_exit_code': check_exit_code})

        return utils.execute(*cmd, **kwargs)

    def _gpfs_remote_execute(self, *cmd, **kwargs):
        host = self.configuration.gpfs_share_export_ip
        check_exit_code = kwargs.pop('check_exit_code', True)
        ignore_exit_code = kwargs.pop('ignore_exit_code', None)

        return self._run_ssh(host, cmd, ignore_exit_code, check_exit_code)

    def _run_ssh(self, host, cmd_list, ignore_exit_code=None,
                 check_exit_code=True):
        command = ' '.join(six.moves.shlex_quote(cmd_arg)
                           for cmd_arg in cmd_list)
        if not self.sshpool:
            gpfs_ssh_login = self.configuration.gpfs_ssh_login
            password = self.configuration.gpfs_ssh_password
            privatekey = self.configuration.gpfs_ssh_private_key
            gpfs_ssh_port = self.configuration.gpfs_ssh_port
            ssh_conn_timeout = self.configuration.ssh_conn_timeout
            min_size = self.configuration.ssh_min_pool_conn
            max_size = self.configuration.ssh_max_pool_conn

            self.sshpool = utils.SSHPool(host,
                                         gpfs_ssh_port,
                                         ssh_conn_timeout,
                                         gpfs_ssh_login,
                                         password=password,
                                         privatekey=privatekey,
                                         min_size=min_size,
                                         max_size=max_size)
        try:
            with self.sshpool.item() as ssh:
                return self._gpfs_ssh_execute(
                    ssh,
                    command,
                    ignore_exit_code=ignore_exit_code,
                    check_exit_code=check_exit_code)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                msg = (_('Error running SSH command: %(cmd)s. '
                         'Error: %(excmsg)s.') %
                       {'cmd': command, 'excmsg': e})
                LOG.error(msg)
                raise exception.GPFSException(msg)

    def _gpfs_ssh_execute(self, ssh, cmd, ignore_exit_code=None,
                          check_exit_code=True):
        sanitized_cmd = strutils.mask_password(cmd)
        LOG.debug('Running cmd (SSH): %s', sanitized_cmd)

        stdin_stream, stdout_stream, stderr_stream = ssh.exec_command(cmd)
        channel = stdout_stream.channel

        stdout = stdout_stream.read()
        sanitized_stdout = strutils.mask_password(stdout)
        stderr = stderr_stream.read()
        sanitized_stderr = strutils.mask_password(stderr)

        stdin_stream.close()

        exit_status = channel.recv_exit_status()

        # exit_status == -1 if no exit code was returned
        if exit_status != -1:
            LOG.debug('Result was %s', exit_status)
            if ((check_exit_code and exit_status != 0)
                and
                (ignore_exit_code is None or
                 exit_status not in ignore_exit_code)):
                raise exception.ProcessExecutionError(exit_code=exit_status,
                                                      stdout=sanitized_stdout,
                                                      stderr=sanitized_stderr,
                                                      cmd=sanitized_cmd)

        return (sanitized_stdout, sanitized_stderr)

    def _check_gpfs_state(self):
        try:
            out, __ = self._gpfs_execute(self.GPFS_PATH + 'mmgetstate', '-Y')
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to check GPFS state. Error: %(excmsg)s.') %
                   {'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)
        lines = out.splitlines()
        try:
            state_token = lines[0].split(':').index('state')
            gpfs_state = lines[1].split(':')[state_token]
        except (IndexError, ValueError) as e:
            msg = (_('Failed to check GPFS state. Error: %(excmsg)s.') %
                   {'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)
        if gpfs_state != 'active':
            return False
        return True

    def _is_dir(self, path):
        try:
            output, __ = self._gpfs_execute('stat', '--format=%F', path,
                                            run_as_root=False)
        except exception.ProcessExecutionError as e:
            msg = (_('%(path)s is not a directory. Error: %(excmsg)s') %
                   {'path': path, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        return output.strip() == 'directory'

    def _is_gpfs_path(self, directory):
        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmlsattr', directory)
        except exception.ProcessExecutionError as e:
            msg = (_('%(dir)s is not on GPFS filesystem. Error: %(excmsg)s.') %
                   {'dir': directory, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        return True

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {}
        for helper_str in self.configuration.gpfs_share_helpers:
            share_proto, _, import_str = helper_str.partition('=')
            helper = importutils.import_class(import_str)
            self._helpers[share_proto.upper()] = helper(self._gpfs_execute,
                                                        self.configuration)

    def _local_path(self, sharename):
        """Get local path for a share or share snapshot by name."""
        return os.path.join(self.configuration.gpfs_mount_point_base,
                            sharename)

    def _get_gpfs_device(self):
        fspath = self.configuration.gpfs_mount_point_base
        try:
            (out, __) = self._gpfs_execute('df', fspath)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to get GPFS device for %(fspath)s.'
                   'Error: %(excmsg)s') %
                   {'fspath': fspath, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        lines = out.splitlines()
        fs = lines[1].split()[0]
        return fs

    def _create_share(self, shareobj):
        """Create a linked fileset file in GPFS.

        Note:  GPFS file system must have quotas enabled
        (mmchfs -Q yes).
        """
        sharename = shareobj['name']
        sizestr = '%sG' % shareobj['size']
        sharepath = self._local_path(sharename)
        fsdev = self._get_gpfs_device()

        # create fileset for the share, link it to root path and set max size
        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmcrfileset', fsdev,
                               sharename, '--inode-space', 'new')
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to create fileset on %(fsdev)s for '
                     'the share %(sharename)s. Error: %(excmsg)s.') %
                   {'fsdev': fsdev, 'sharename': sharename,
                    'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmlinkfileset', fsdev,
                               sharename, '-J', sharepath)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to link fileset for the share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmsetquota', fsdev + ':' +
                               sharename, '--block', '0:' + sizestr)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to set quota for the share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        try:
            self._gpfs_execute('chmod', '777', sharepath)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to set permissions for share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

    def _delete_share(self, shareobj):
        """Remove container by removing GPFS fileset."""
        sharename = shareobj['name']
        fsdev = self._get_gpfs_device()
        # ignore error, when the fileset does not exist
        # it may happen, when the share creation failed, the share is in
        # 'error' state, and the fileset was never created
        # we want to ignore that error condition while deleting the fileset,
        # i.e. 'Fileset name share-xyz not found', with error code '2'
        # and mark the deletion successful
        ignore_exit_code = [ERR_FILE_NOT_FOUND]

        # unlink and delete the share's fileset
        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmunlinkfileset', fsdev,
                               sharename, '-f',
                               ignore_exit_code=ignore_exit_code)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed unlink fileset for share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmdelfileset', fsdev,
                               sharename, '-f',
                               ignore_exit_code=ignore_exit_code)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed delete fileset for share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

    def _get_available_capacity(self, path):
        """Calculate available space on path."""
        try:
            out, __ = self._gpfs_execute('df', '-P', '-B', '1', path)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to check available capacity for %(path)s.'
                     'Error: %(excmsg)s.') %
                   {'path': path, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        out = out.splitlines()[1]
        size = int(out.split()[1])
        available = int(out.split()[3])
        return available, size

    def _create_share_snapshot(self, snapshot):
        """Create a snapshot of the share."""
        sharename = snapshot['share_name']
        snapshotname = snapshot['name']
        fsdev = self._get_gpfs_device()
        LOG.debug(
            'Attempting to create a snapshot %(snap)s from share %(share)s '
            'on device %(dev)s.',
            {'share': sharename, 'snap': snapshotname, 'dev': fsdev}
        )

        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmcrsnapshot', fsdev,
                               snapshot['name'], '-j', sharename)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to create snapshot %(snapshot)s. '
                     'Error: %(excmsg)s.') %
                   {'snapshot': snapshot['name'], 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

    def _delete_share_snapshot(self, snapshot):
        """Delete a snapshot of the share."""
        sharename = snapshot['share_name']
        fsdev = self._get_gpfs_device()

        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmdelsnapshot', fsdev,
                               snapshot['name'], '-j', sharename)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to delete snapshot %(snapshot)s. '
                     'Error: %(excmsg)s.') %
                   {'snapshot': snapshot['name'], 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

    def _create_share_from_snapshot(self, share, snapshot, share_path):
        """Create share from a share snapshot."""
        self._create_share(share)
        snapshot_path = self._get_snapshot_path(snapshot)
        snapshot_path = snapshot_path + "/"
        try:
            self._gpfs_execute('rsync', '-rp', snapshot_path, share_path)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to create share %(share)s from '
                     'snapshot %(snapshot)s. Error: %(excmsg)s.') %
                   {'share': share['name'], 'snapshot': snapshot['name'],
                    'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

    def _extend_share(self, shareobj, new_size):
        sharename = shareobj['name']
        sizestr = '%sG' % new_size
        fsdev = self._get_gpfs_device()
        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmsetquota', fsdev + ':' +
                               sharename, '--block', '0:' + sizestr)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to set quota for the share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

    def get_network_allocations_number(self):
        return 0

    def create_share(self, ctx, share, share_server=None):
        """Create GPFS directory that will be represented as share."""
        self._create_share(share)
        share_path = self._get_share_path(share)
        location = self._get_helper(share).create_export(share_path)
        return location

    def create_share_from_snapshot(self, ctx, share, snapshot,
                                   share_server=None):
        """Is called to create share from a snapshot."""
        share_path = self._get_share_path(share)
        self._create_share_from_snapshot(share, snapshot, share_path)
        location = self._get_helper(share).create_export(share_path)
        return location

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""
        self._create_share_snapshot(snapshot)

    def delete_share(self, ctx, share, share_server=None):
        """Remove and cleanup share storage."""
        location = self._get_share_path(share)
        self._get_helper(share).remove_export(location, share)
        self._delete_share(share)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""
        self._delete_share_snapshot(snapshot)

    def extend_share(self, share, new_size, share_server=None):
        """Extends the quota on the share fileset."""
        self._extend_share(share, new_size)

    def ensure_share(self, ctx, share, share_server=None):
        """Ensure that storage are mounted and exported."""

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share."""
        helper = self._get_helper(share)
        location = self._get_share_path(share)

        for access in delete_rules:
            helper.deny_access(location, share, access)

        for access in add_rules:
            helper.allow_access(location, share, access)

        if not (add_rules or delete_rules):
            helper.resync_access(location, share, access_rules)

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        if not self._check_gpfs_state():
            msg = (_('GPFS is not active.'))
            LOG.error(msg)
            raise exception.GPFSException(msg)

        if not self.configuration.gpfs_share_export_ip:
            msg = (_('gpfs_share_export_ip must be specified.'))
            LOG.error(msg)
            raise exception.InvalidParameterValue(err=msg)

        gpfs_base_dir = self.configuration.gpfs_mount_point_base
        if not gpfs_base_dir.startswith('/'):
            msg = (_('%s must be an absolute path.') % gpfs_base_dir)
            LOG.error(msg)
            raise exception.GPFSException(msg)

        if not self._is_dir(gpfs_base_dir):
            msg = (_('%s is not a directory.') % gpfs_base_dir)
            LOG.error(msg)
            raise exception.GPFSException(msg)

        if not self._is_gpfs_path(gpfs_base_dir):
            msg = (_('%s is not on GPFS. Perhaps GPFS not mounted.')
                   % gpfs_base_dir)
            LOG.error(msg)
            raise exception.GPFSException(msg)

        if self.configuration.gpfs_nfs_server_type not in ("KNFS", "CES"):
            msg = (_('Invalid gpfs_nfs_server_type value: %s. '
                     'Valid values are: "KNFS", "CES".')
                   % self.configuration.gpfs_nfs_server_type)
            LOG.error(msg)
            raise exception.InvalidParameterValue(err=msg)

        if ((not self.configuration.gpfs_nfs_server_list) and
                (self.configuration.gpfs_nfs_server_type != 'CES')):
            msg = (_('Missing value for gpfs_nfs_server_list.'))
            LOG.error(msg)
            raise exception.InvalidParameterValue(err=msg)

    def _is_share_valid(self, fsdev, location):
        try:
            out, __ = self._gpfs_execute(self.GPFS_PATH + 'mmlsfileset', fsdev,
                                         '-J', location, '-L', '-Y')
        except exception.ProcessExecutionError:
            msg = (_('Given share path %(share_path)s does not exist at '
                     'mount point %(mount_point)s.')
                   % {'share_path': location, 'mount_point': fsdev})
            LOG.exception(msg)
            raise exception.ManageInvalidShare(reason=msg)

        lines = out.splitlines()
        try:
            validation_token = lines[0].split(':').index('allocInodes')
            alloc_inodes = lines[1].split(':')[validation_token]
        except (IndexError, ValueError):
            msg = (_('Failed to check share at %s.') % location)
            LOG.exception(msg)
            raise exception.GPFSException(msg)

        return alloc_inodes != '0'

    def _get_share_name(self, fsdev, location):
        try:
            out, __ = self._gpfs_execute(self.GPFS_PATH + 'mmlsfileset', fsdev,
                                         '-J', location, '-L', '-Y')
        except exception.ProcessExecutionError:
            msg = (_('Given share path %(share_path)s does not exist at '
                     'mount point %(mount_point)s.')
                   % {'share_path': location, 'mount_point': fsdev})
            LOG.exception(msg)
            raise exception.ManageInvalidShare(reason=msg)

        lines = out.splitlines()
        try:
            validation_token = lines[0].split(':').index('filesetName')
            share_name = lines[1].split(':')[validation_token]
        except (IndexError, ValueError):
            msg = (_('Failed to check share at %s.') % location)
            LOG.exception(msg)
            raise exception.GPFSException(msg)

        return share_name

    def _manage_existing(self, fsdev, share, old_share_name):
        new_share_name = share['name']
        new_export_location = self._local_path(new_share_name)
        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmunlinkfileset', fsdev,
                               old_share_name, '-f')
        except exception.ProcessExecutionError:
            msg = _('Failed to unlink fileset for share %s.') % new_share_name
            LOG.exception(msg)
            raise exception.GPFSException(msg)
        LOG.debug('Unlinked the fileset of share %s.', old_share_name)

        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmchfileset', fsdev,
                               old_share_name, '-j', new_share_name)
        except exception.ProcessExecutionError:
            msg = _('Failed to rename fileset for share %s.') % new_share_name
            LOG.exception(msg)
            raise exception.GPFSException(msg)
        LOG.debug('Renamed the fileset from %(old_share)s to %(new_share)s.',
                  {'old_share': old_share_name, 'new_share': new_share_name})

        try:
            self._gpfs_execute(self.GPFS_PATH + 'mmlinkfileset', fsdev,
                               new_share_name, '-J', new_export_location)
        except exception.ProcessExecutionError:
            msg = _('Failed to link fileset for the share %s.'
                    ) % new_share_name
            LOG.exception(msg)
            raise exception.GPFSException(msg)
        LOG.debug('Linked the fileset of share %(share_name)s at location '
                  '%(export_location)s.',
                  {'share_name': new_share_name,
                   'export_location': new_export_location})

        try:
            self._gpfs_execute('chmod', '777', new_export_location)
        except exception.ProcessExecutionError:
            msg = _('Failed to set permissions for share %s.') % new_share_name
            LOG.exception(msg)
            raise exception.GPFSException(msg)
        LOG.debug('Changed the permission of share %s.', new_share_name)

        try:
            out, __ = self._gpfs_execute(self.GPFS_PATH + 'mmlsquota', '-j',
                                         new_share_name, '-Y', fsdev)
        except exception.ProcessExecutionError:
            msg = _('Failed to check size for share %s.') % new_share_name
            LOG.exception(msg)
            raise exception.GPFSException(msg)

        lines = out.splitlines()
        try:
            quota_limit = lines[0].split(':').index('blockLimit')
            quota_status = lines[1].split(':')[quota_limit]
        except (IndexError, ValueError):
            msg = _('Failed to check quota for share %s.') % new_share_name
            LOG.exception(msg)
            raise exception.GPFSException(msg)

        share_size = int(quota_status)
        # Note: since share_size returns integer value in KB,
        # we are checking whether share is less than 1GiB.
        # (units.Mi * KB = 1GB)
        if share_size < units.Mi:
            try:
                self._gpfs_execute(self.GPFS_PATH + 'mmsetquota', fsdev + ':' +
                                   new_share_name, '--block', '0:1G')
            except exception.ProcessExecutionError:
                msg = _('Failed to set quota for share %s.') % new_share_name
                LOG.exception(msg)
                raise exception.GPFSException(msg)
            LOG.info('Existing share %(shr)s has size %(size)s KB '
                     'which is below 1GiB, so extended it to 1GiB.',
                     {'shr': new_share_name, 'size': share_size})
            share_size = 1
        else:
            orig_share_size = share_size
            share_size = int(math.ceil(float(share_size) / units.Mi))
            if orig_share_size != share_size * units.Mi:
                try:
                    self._gpfs_execute(self.GPFS_PATH + 'mmsetquota', fsdev +
                                       ':' + new_share_name, '--block', '0:' +
                                       str(share_size) + 'G')
                except exception.ProcessExecutionError:
                    msg = _('Failed to set quota for share %s.'
                            ) % new_share_name
                    LOG.exception(msg)
                    raise exception.GPFSException(msg)

        new_export_location = self._get_helper(share).create_export(
            new_export_location)
        return share_size, new_export_location

    def manage_existing(self, share, driver_options):

        old_export = share['export_location'].split(':')
        try:
            ces_ip = old_export[0]
            old_export_location = old_export[1]
        except IndexError:
            msg = _('Incorrect export path. Expected format: '
                    'IP:/gpfs_mount_point_base/share_id.')
            LOG.exception(msg)
            raise exception.ShareBackendException(msg=msg)

        if ces_ip not in self.configuration.gpfs_nfs_server_list:
            msg = _('The CES IP %s is not present in the '
                    'configuration option "gpfs_nfs_server_list".') % ces_ip
            raise exception.ShareBackendException(msg=msg)

        fsdev = self._get_gpfs_device()
        if not self._is_share_valid(fsdev, old_export_location):
            err_msg = _('Given share path %s does not have a valid '
                        'share.') % old_export_location
            raise exception.ManageInvalidShare(reason=err_msg)

        share_name = self._get_share_name(fsdev, old_export_location)

        out = self._get_helper(share)._has_client_access(old_export_location)
        if out:
            err_msg = _('Clients have access to %s share currently. Evict any '
                        'clients before trying again.') % share_name
            raise exception.ManageInvalidShare(reason=err_msg)

        share_size, new_export_location = self._manage_existing(
            fsdev, share, share_name)
        return {"size": share_size, "export_locations": new_export_location}

    def _update_share_stats(self):
        """Retrieve stats info from share volume group."""

        data = dict(
            share_backend_name=self.backend_name,
            vendor_name='IBM',
            storage_protocol='NFS',
            reserved_percentage=self.configuration.reserved_share_percentage)

        free, capacity = self._get_available_capacity(
            self.configuration.gpfs_mount_point_base)

        data['total_capacity_gb'] = math.ceil(capacity / units.Gi)
        data['free_capacity_gb'] = math.ceil(free / units.Gi)

        super(GPFSShareDriver, self)._update_share_stats(data)

    def _get_helper(self, share):
        if share['share_proto'] == 'NFS':
            return self._helpers[self.configuration.gpfs_nfs_server_type]
        else:
            msg = (_('Share protocol %s not supported by GPFS driver.')
                   % share['share_proto'])
            LOG.error(msg)
            raise exception.InvalidShare(reason=msg)

    def _get_share_path(self, share):
        """Returns share path on storage provider."""
        return os.path.join(self.configuration.gpfs_mount_point_base,
                            share['name'])

    def _get_snapshot_path(self, snapshot):
        """Returns share path on storage provider."""
        snapshot_dir = ".snapshots"
        return os.path.join(self.configuration.gpfs_mount_point_base,
                            snapshot["share_name"], snapshot_dir,
                            snapshot["name"])


@six.add_metaclass(abc.ABCMeta)
class NASHelperBase(object):
    """Interface to work with share."""

    def __init__(self, execute, config_object):
        self.configuration = config_object
        self._execute = execute

    def create_export(self, local_path):
        """Construct location of new export."""
        return ':'.join([self.configuration.gpfs_share_export_ip, local_path])

    def get_export_options(self, share, access, helper):
        """Get the export options."""
        extra_specs = share_types.get_extra_specs_from_share(share)
        if helper == 'KNFS':
            export_options = extra_specs.get('knfs:export_options')
        elif helper == 'CES':
            export_options = extra_specs.get('ces:export_options')
        else:
            export_options = None

        options = self._get_validated_opt_list(export_options)
        options.append(self.get_access_option(access))
        return ','.join(options)

    def _validate_export_options(self, options):
        """Validate the export options."""
        options_not_allowed = self._get_options_not_allowed()
        invalid_options = [
            option for option in options if option in options_not_allowed
        ]

        if invalid_options:
            raise exception.InvalidInput(reason='Invalid export_option %s as '
                                                'it is set by access_type.'
                                                % invalid_options)

    def _get_validated_opt_list(self, export_options):
        """Validate the export options and return an option list."""
        if export_options:
            options = export_options.lower().split(',')
            self._validate_export_options(options)
        else:
            options = []
        return options

    @abc.abstractmethod
    def get_access_option(self, access):
        """Get access option string based on access level."""

    @abc.abstractmethod
    def _get_options_not_allowed(self):
        """Get access options that are not allowed in extra-specs."""

    @abc.abstractmethod
    def remove_export(self, local_path, share):
        """Remove export."""

    @abc.abstractmethod
    def allow_access(self, local_path, share, access):
        """Allow access to the host."""

    @abc.abstractmethod
    def deny_access(self, local_path, share, access):
        """Deny access to the host."""

    @abc.abstractmethod
    def resync_access(self, local_path, share, access_rules):
        """Re-sync all access rules for given share."""


class KNFSHelper(NASHelperBase):
    """Wrapper for Kernel NFS Commands."""

    def __init__(self, execute, config_object):
        super(KNFSHelper, self).__init__(execute, config_object)
        self._execute = execute
        try:
            self._execute('exportfs', check_exit_code=True, run_as_root=True)
        except exception.ProcessExecutionError as e:
            msg = (_('NFS server not found. Error: %s.') % e)
            LOG.error(msg)
            raise exception.GPFSException(msg)

    def _has_client_access(self, local_path, access_to=None):
        try:
            out, __ = self._execute('exportfs', run_as_root=True)
        except exception.ProcessExecutionError:
            msg = _('Failed to check exports on the systems.')
            LOG.exception(msg)
            raise exception.GPFSException(msg)

        if access_to:
            if (re.search(re.escape(local_path) + '[\s\n]*'
                          + re.escape(access_to), out)):
                return True
        else:
            if re.findall(local_path + '\\b', ''.join(out)):
                return True
        return False

    def _publish_access(self, *cmd, **kwargs):
        check_exit_code = kwargs.get('check_exit_code', True)

        outs = []
        localserver_iplist = socket.gethostbyname_ex(socket.gethostname())[2]
        for server in self.configuration.gpfs_nfs_server_list:
            if server in localserver_iplist:
                run_command = cmd
                run_local = True
            else:
                sshlogin = self.configuration.gpfs_ssh_login
                remote_login = sshlogin + '@' + server
                run_command = ['ssh', remote_login] + list(cmd)
                run_local = False
            try:
                out = utils.execute(*run_command,
                                    run_as_root=run_local,
                                    check_exit_code=check_exit_code)
            except exception.ProcessExecutionError:
                raise
            outs.append(out)
        return outs

    def _verify_denied_access(self, local_path, share, ip):
        try:
            cmd = ['exportfs']
            outs = self._publish_access(*cmd)
        except exception.ProcessExecutionError:
            msg = _('Failed to verify denied access for '
                    'share %s.') % share['name']
            LOG.exception(msg)
            raise exception.GPFSException(msg)

        for stdout, stderr in outs:
            if stderr and stderr.strip():
                msg = ('Log/ignore stderr during _validate_denied_access for '
                       'share %(sharename)s. Return code OK. '
                       'Stderr: %(stderr)s' % {'sharename': share['name'],
                                               'stderr': stderr})
                LOG.debug(msg)

            gpfs_ips = NFSHelper.get_host_list(stdout, local_path)
            if ip in gpfs_ips:
                msg = (_('Failed to deny access for share %(sharename)s. '
                         'IP %(ip)s still has access.') %
                       {'sharename': share['name'],
                        'ip': ip})
                LOG.error(msg)
                raise exception.GPFSException(msg)

    def remove_export(self, local_path, share):
        """Remove export."""

    def get_access_option(self, access):
        """Get access option string based on access level."""
        return access['access_level']

    def _get_options_not_allowed(self):
        """Get access options that are not allowed in extra-specs."""
        return list(constants.ACCESS_LEVELS)

    def _get_exports(self):
        """Get exportfs output."""
        try:
            out, __ = self._execute('exportfs', run_as_root=True)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to check exports on the systems. '
                     ' Error: %s.') % e)
            LOG.error(msg)
            raise exception.GPFSException(msg)
        return out

    def allow_access(self, local_path, share, access, error_on_exists=True):
        """Allow access to one or more vm instances."""

        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess(reason='Only ip access type '
                                                      'supported.')

        if error_on_exists:
            # check if present in export
            out = re.search(
                re.escape(local_path) + '[\s\n]*'
                + re.escape(access['access_to']), self._get_exports())

            if out is not None:
                access_type = access['access_type']
                access_to = access['access_to']
                raise exception.ShareAccessExists(access_type=access_type,
                                                  access=access_to)

        export_opts = self.get_export_options(share, access, 'KNFS')
        cmd = ['exportfs', '-o', export_opts,
               ':'.join([access['access_to'], local_path])]
        try:
            self._publish_access(*cmd)
        except exception.ProcessExecutionError:
            msg = _('Failed to allow access for share %s.') % share['name']
            LOG.exception(msg)
            raise exception.GPFSException(msg)

    def _deny_ip(self, local_path, share, ip):
        """Remove access for one or more vm instances."""
        cmd = ['exportfs', '-u', ':'.join([ip, local_path])]
        try:
            # Can get exit code 0 for success or 1 for already gone (also
            # potentially get 1 due to exportfs bug). So allow
            # _publish_access to continue with [0, 1] and then verify after
            # it is done.
            self._publish_access(*cmd, check_exit_code=[0, 1])
        except exception.ProcessExecutionError:
            msg = _('Failed to deny access for share %s.') % share['name']
            LOG.exception(msg)
            raise exception.GPFSException(msg)

        # Error code (0 or 1) makes deny IP success indeterminate.
        # So, verify that the IP access was completely removed.
        self._verify_denied_access(local_path, share, ip)

    def deny_access(self, local_path, share, access):
        """Remove access for one or more vm instances."""
        self._deny_ip(local_path, share, access['access_to'])

    def _remove_other_access(self, local_path, share, access_rules):
        """Remove any client access that is not in access_rules."""
        exports = self._get_exports()
        gpfs_ips = set(NFSHelper.get_host_list(exports, local_path))
        manila_ips = set([x['access_to'] for x in access_rules])
        remove_ips = gpfs_ips - manila_ips
        for ip in remove_ips:
            self._deny_ip(local_path, share, ip)

    def resync_access(self, local_path, share, access_rules):
        """Re-sync all access rules for given share."""
        for access in access_rules:
            self.allow_access(local_path, share, access, error_on_exists=False)
        self._remove_other_access(local_path, share, access_rules)


class CESHelper(NASHelperBase):
    """Wrapper for NFS by Spectrum Scale CES"""

    def __init__(self, execute, config_object):
        super(CESHelper, self).__init__(execute, config_object)
        self._execute = execute
        if self.configuration.is_gpfs_node:
            self.GPFS_PATH = ''
        else:
            self.GPFS_PATH = '/usr/lpp/mmfs/bin/'

    def _execute_mmnfs_command(self, cmd, err_msg):
        try:
            out, __ = self._execute(self.GPFS_PATH + 'mmnfs', 'export', *cmd)
        except exception.ProcessExecutionError as e:
            msg = (_('%(err_msg)s Error: %(e)s.')
                   % {'err_msg': err_msg, 'e': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)
        return out

    @staticmethod
    def _fix_export_data(data, headers):
        """Export data split by ':' may need fixing if client had colons."""

        # If an IPv6 client shows up then ':' delimiters don't work.
        # So use header positions to get data before/after Clients.
        # Then what is left in between can be joined back into a client IP.
        client_index = headers.index('Clients')
        # reverse_client_index is distance from end.
        reverse_client_index = len(headers) - (client_index + 1)
        after_client_index = len(data) - reverse_client_index

        before_client = data[:client_index]
        client = data[client_index: after_client_index]
        after_client = data[after_client_index:]

        result_data = before_client
        result_data.append(':'.join(client))  # Fixes colons in client IP
        result_data.extend(after_client)
        return result_data

    def _get_nfs_client_exports(self, local_path):
        """Get the current NFS client export details from GPFS."""

        out = self._execute_mmnfs_command(
            ('list', '-n', local_path, '-Y'),
            'Failed to get exports from the system.')

        # Remove the header line and use the headers to describe the data
        lines = out.splitlines()
        for line in lines:
            data = line.split(':')
            if "HEADER" in data:
                headers = data
                lines.remove(line)
                break
        else:
            msg = _('Failed to parse exports for path %s. '
                    'No HEADER found.') % local_path
            LOG.error(msg)
            raise exception.GPFSException(msg)

        exports = []
        for line in lines:
            data = line.split(':')
            if len(data) < 3:
                continue  # Skip empty lines (and anything less than minimal).

            result_data = self._fix_export_data(data, headers)
            exports.append(dict(zip(headers, result_data)))

        return exports

    def _has_client_access(self, local_path, access_to=None):
        """Check path for any export or for one with a specific IP address."""
        gpfs_clients = self._get_nfs_client_exports(local_path)
        return gpfs_clients and (access_to is None or access_to in [
            x['Clients'] for x in gpfs_clients])

    def remove_export(self, local_path, share):
        """Remove export."""
        if self._has_client_access(local_path):
            err_msg = ('Failed to remove export for share %s.'
                       % share['name'])
            self._execute_mmnfs_command(('remove', local_path), err_msg)

    def _get_options_not_allowed(self):
        """Get access options that are not allowed in extra-specs."""
        return ['access_type=ro', 'access_type=rw']

    def get_access_option(self, access):
        """Get access option string based on access level."""
        if access['access_level'] == constants.ACCESS_LEVEL_RO:
            return 'access_type=ro'
        else:
            return 'access_type=rw'

    def allow_access(self, local_path, share, access):
        """Allow access to the host."""

        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess(reason='Only ip access type '
                                                      'supported.')
        has_exports = self._has_client_access(local_path)

        export_opts = self.get_export_options(share, access, 'CES')

        if not has_exports:
            cmd = ['add', local_path, '-c',
                   access['access_to'] +
                   '(' + export_opts + ')']
        else:
            cmd = ['change', local_path, '--nfsadd',
                   access['access_to'] +
                   '(' + export_opts + ')']

        err_msg = ('Failed to allow access for share %s.'
                   % share['name'])
        self._execute_mmnfs_command(cmd, err_msg)

    def deny_access(self, local_path, share, access, force=False):
        """Deny access to the host."""
        has_export = self._has_client_access(local_path, access['access_to'])

        if has_export:
            err_msg = ('Failed to remove access for share %s.'
                       % share['name'])
            self._execute_mmnfs_command(('change', local_path,
                                         '--nfsremove', access['access_to']),
                                        err_msg)

    def _get_client_opts(self, access, opts_list):
        """Get client options string for access rule and NFS options."""
        nfs_opts = ','.join([self.get_access_option(access)] + opts_list)

        return '%(ip)s(%(nfs_opts)s)' % {'ip': access['access_to'],
                                         'nfs_opts': nfs_opts}

    def _get_share_opts(self, share):
        """Get a list of NFS options from the share's share type."""
        extra_specs = share_types.get_extra_specs_from_share(share)
        opts_list = self._get_validated_opt_list(
            extra_specs.get('ces:export_options'))
        return opts_list

    def _nfs_change(self, local_path, share, access_rules, gpfs_clients):
        """Bulk add/update/remove of access rules for share."""
        opts_list = self._get_share_opts(share)

        # Create a map of existing client access rules from GPFS.
        # Key from 'Clients' is an IP address or
        # Value from 'Access_Type' is RW|RO (case varies)
        gpfs_map = {
            x['Clients']: x['Access_Type'].lower() for x in gpfs_clients}
        gpfs_ips = set(gpfs_map.keys())

        manila_ips = set([x['access_to'] for x in access_rules])
        add_ips = manila_ips - gpfs_ips
        update_ips = gpfs_ips.intersection(manila_ips)
        remove_ips = gpfs_ips - manila_ips

        adds = []
        updates = []
        if add_ips or update_ips:
            for access in access_rules:
                ip = access['access_to']
                if ip in add_ips:
                    adds.append(self._get_client_opts(access, opts_list))
                elif (ip in update_ips
                      and access['access_level'] != gpfs_map[ip]):
                    updates.append(self._get_client_opts(access, opts_list))

        if remove_ips or adds or updates:
            cmd = ['change', local_path]
            if remove_ips:
                cmd.append('--nfsremove')
                cmd.append(','.join(remove_ips))
            if adds:
                cmd.append('--nfsadd')
                cmd.append(';'.join(adds))
            if updates:
                cmd.append('--nfschange')
                cmd.append(';'.join(updates))
            err_msg = ('Failed to resync access for share %s.' % share['name'])
            self._execute_mmnfs_command(cmd, err_msg)

    def _nfs_add(self, access_rules, local_path, share):
        """Bulk add of access rules to share."""
        if not access_rules:
            return

        opts_list = self._get_share_opts(share)
        client_options = []
        for access in access_rules:
            client_options.append(self._get_client_opts(access, opts_list))

        cmd = ['add', local_path, '-c', ';'.join(client_options)]
        err_msg = ('Failed to resync access for share %s.' % share['name'])
        self._execute_mmnfs_command(cmd, err_msg)

    def resync_access(self, local_path, share, access_rules):
        """Re-sync all access rules for given share."""
        gpfs_clients = self._get_nfs_client_exports(local_path)
        if not gpfs_clients:
            self._nfs_add(access_rules, local_path, share)
        else:
            self._nfs_change(local_path, share, access_rules, gpfs_clients)
