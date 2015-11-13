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
import copy
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

from manila import exception
from manila.i18n import _, _LE, _LI
from manila.share import driver
from manila.share.drivers.ibm import ganesha_utils
from manila import utils

LOG = log.getLogger(__name__)

# matches multiple comma separated avpairs on a line.  values with an embedded
# comma must be wrapped in quotation marks
AVPATTERN = re.compile(r'\s*(?P<attr>\w+)\s*=\s*(?P<val>'
                       '(["][a-zA-Z0-9_, ]+["])|(\w+))\s*[,]?')

ERR_FILE_NOT_FOUND = 2

gpfs_share_opts = [
    cfg.StrOpt('gpfs_share_export_ip',
               help='IP to be added to GPFS export string.'),
    cfg.StrOpt('gpfs_mount_point_base',
               default='$state_path/mnt',
               help='Base folder where exported shares are located.'),
    cfg.StrOpt('gpfs_nfs_server_type',
               default='KNFS',
               help=('NFS Server type. Valid choices are "KNFS" (kernel NFS) '
                     'or "GNFS" (Ganesha NFS).')),
    cfg.ListOpt('gpfs_nfs_server_list',
                help=('A list of the fully qualified NFS server names that '
                      'make up the OpenStack Manila configuration.')),
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
                    'GNFS=manila.share.drivers.ibm.gpfs.GNFSHelper',
                ],
                help='Specify list of share export helpers.'),
    cfg.StrOpt('knfs_export_options',
               default=('rw,sync,no_root_squash,insecure,no_wdelay,'
                        'no_subtree_check'),
               help=('Options to use when exporting a share using kernel '
                     'NFS server. Note that these defaults can be overridden '
                     'when a share is created by passing metadata with key '
                     'name export_options.')),
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

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""
        super(GPFSShareDriver, self).do_setup(context)
        host = self.configuration.gpfs_share_export_ip
        localserver_iplist = socket.gethostbyname_ex(socket.gethostname())[2]
        if host in localserver_iplist:  # run locally
            self._gpfs_execute = self._gpfs_local_execute
        else:
            self._gpfs_execute = self._gpfs_remote_execute
        self._setup_helpers()

    def _gpfs_local_execute(self, *cmd, **kwargs):
        if 'run_as_root' not in kwargs:
            kwargs.update({'run_as_root': True})

        return utils.execute(*cmd, **kwargs)

    def _gpfs_remote_execute(self, *cmd, **kwargs):
        host = self.configuration.gpfs_share_export_ip
        check_exit_code = kwargs.pop('check_exit_code', True)

        return self._run_ssh(host, cmd, check_exit_code)

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
            LOG.debug('Result was %s' % exit_status)
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
            out, __ = self._gpfs_execute('mmgetstate', '-Y')
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
            self._gpfs_execute('mmlsattr', directory)
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
            self._gpfs_execute('mmcrfileset', fsdev, sharename,
                               '--inode-space', 'new')
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to create fileset on %(fsdev)s for '
                     'the share %(sharename)s. Error: %(excmsg)s.') %
                   {'fsdev': fsdev, 'sharename': sharename,
                    'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        try:
            self._gpfs_execute('mmlinkfileset', fsdev, sharename, '-J',
                               sharepath)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to link fileset for the share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        try:
            self._gpfs_execute('mmsetquota', '-j', sharename, '-h',
                               sizestr, fsdev)
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
        # ignore_exit_code = [ERR_FILE_NOT_FOUND]

        # unlink and delete the share's fileset
        try:
            self._gpfs_execute('mmunlinkfileset', fsdev, sharename, '-f')
        except exception.ProcessExecutionError as e:
            msg = (_('Failed unlink fileset for share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': sharename, 'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

        try:
            self._gpfs_execute('mmdelfileset', fsdev, sharename, '-f')
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
        LOG.debug("sharename = %s, snapshotname = %s, fsdev = %s",
                  (sharename, snapshotname, fsdev))

        try:
            self._gpfs_execute('mmcrsnapshot', fsdev, snapshot['name'],
                               '-j', sharename)
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
            self._gpfs_execute('mmdelsnapshot', fsdev, snapshot['name'],
                               '-j', sharename)
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
            self._gpfs_execute('mmsetquota', '-j', sharename, '-h',
                               sizestr, fsdev)
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

    def allow_access(self, ctx, share, access, share_server=None):
        """Allow access to the share."""
        location = self._get_share_path(share)
        self._get_helper(share).allow_access(location, share,
                                             access['access_type'],
                                             access['access_to'])

    def deny_access(self, ctx, share, access, share_server=None):
        """Deny access to the share."""
        location = self._get_share_path(share)
        self._get_helper(share).deny_access(location, share,
                                            access['access_type'],
                                            access['access_to'])

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

        if self.configuration.gpfs_nfs_server_type not in ['KNFS', 'GNFS']:
            msg = (_('Invalid gpfs_nfs_server_type value: %s. '
                     'Valid values are: "KNFS", "GNFS".')
                   % self.configuration.gpfs_nfs_server_type)
            LOG.error(msg)
            raise exception.InvalidParameterValue(err=msg)

        if self.configuration.gpfs_nfs_server_list is None:
            msg = (_('Missing value for gpfs_nfs_server_list.'))
            LOG.error(msg)
            raise exception.InvalidParameterValue(err=msg)

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

    @abc.abstractmethod
    def remove_export(self, local_path, share):
        """Remove export."""

    @abc.abstractmethod
    def allow_access(self, local_path, share, access_type, access):
        """Allow access to the host."""

    @abc.abstractmethod
    def deny_access(self, local_path, share, access_type, access,
                    force=False):
        """Deny access to the host."""


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

    def _publish_access(self, *cmd):
        for server in self.configuration.gpfs_nfs_server_list:
            localserver_iplist = socket.gethostbyname_ex(
                socket.gethostname())[2]
            run_local = True
            if server not in localserver_iplist:
                sshlogin = self.configuration.gpfs_ssh_login
                remote_login = sshlogin + '@' + server
                cmd = ['ssh', remote_login] + list(cmd)
                run_local = False
            try:
                utils.execute(*cmd,
                              run_as_root=run_local,
                              check_exit_code=True)
            except exception.ProcessExecutionError:
                raise

    def _get_export_options(self, share):
        """Set various export attributes for share."""

        metadata = share.get('share_metadata')
        options = None
        if metadata:
            for item in metadata:
                if item['key'] == 'export_options':
                    options = item['value']
                else:
                    msg = (_('Unknown metadata key %s.') % item['key'])
                    LOG.error(msg)
                    raise exception.InvalidInput(reason=msg)
        if not options:
            options = self.configuration.knfs_export_options

        return options

    def remove_export(self, local_path, share):
        """Remove export."""

    def allow_access(self, local_path, share, access_type, access):
        """Allow access to one or more vm instances."""

        if access_type != 'ip':
            raise exception.InvalidShareAccess('Only ip access type '
                                               'supported.')

        # check if present in export
        try:
            out, __ = self._execute('exportfs', run_as_root=True)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to check exports on the systems. '
                     ' Error: %s.') % e)
            LOG.error(msg)
            raise exception.GPFSException(msg)

        out = re.search(re.escape(local_path) + '[\s\n]*' + re.escape(access),
                        out)
        if out is not None:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)

        export_opts = self._get_export_options(share)

        cmd = ['exportfs', '-o', export_opts,
               ':'.join([access, local_path])]
        try:
            self._publish_access(*cmd)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to allow access for share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)

    def deny_access(self, local_path, share, access_type, access,
                    force=False):
        """Remove access for one or more vm instances."""
        cmd = ['exportfs', '-u', ':'.join([access, local_path])]
        try:
            self._publish_access(*cmd)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to deny access for share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'excmsg': e})
            LOG.error(msg)
            raise exception.GPFSException(msg)


class GNFSHelper(NASHelperBase):
    """Wrapper for Ganesha NFS Commands."""

    def __init__(self, execute, config_object):
        super(GNFSHelper, self).__init__(execute, config_object)
        self.default_export_options = dict()
        for m in AVPATTERN.finditer(
            self.configuration.ganesha_nfs_export_options
        ):
            self.default_export_options[m.group('attr')] = m.group('val')

    def _get_export_options(self, share):
        """Set various export attributes for share."""

        # load default options first - any options passed as share metadata
        # will take precedence
        options = copy.copy(self.default_export_options)

        metadata = share.get('share_metadata')
        for item in metadata:
            attr = item['key']
            if attr in ganesha_utils.valid_flags():
                options[attr] = item['value']
            else:
                LOG.error(_LE('Invalid metadata %(attr)s for share '
                              '%(share)s.'),
                          {'attr': attr, 'share': share['name']})

        return options

    @utils.synchronized("ganesha-process-req", external=True)
    def _ganesha_process_request(self, req_type, local_path,
                                 share, access_type=None,
                                 access=None, force=False):
        cfgpath = self.configuration.ganesha_config_path
        gservice = self.configuration.ganesha_service_name
        gservers = self.configuration.gpfs_nfs_server_list
        sshlogin = self.configuration.gpfs_ssh_login
        sshkey = self.configuration.gpfs_ssh_private_key
        pre_lines, exports = ganesha_utils.parse_ganesha_config(cfgpath)
        reload_needed = True

        if (req_type == "allow_access"):
            export_opts = self._get_export_options(share)
            # add the new share if it's not already defined
            if not ganesha_utils.export_exists(exports, local_path):
                # Add a brand new export definition
                new_id = ganesha_utils.get_next_id(exports)
                export = ganesha_utils.get_export_template()
                export['fsal'] = '"GPFS"'
                export['export_id'] = new_id
                export['tag'] = '"fs%s"' % new_id
                export['path'] = '"%s"' % local_path
                export['pseudo'] = '"%s"' % local_path
                export['rw_access'] = (
                    '"%s"' % ganesha_utils.format_access_list(access)
                )
                for key in export_opts:
                    export[key] = export_opts[key]

                exports[new_id] = export
                LOG.info(_LI('Add %(share)s with access from %(access)s'),
                         {'share': share['name'], 'access': access})
            else:
                # Update existing access with new/extended access information
                export = ganesha_utils.get_export_by_path(exports, local_path)
                initial_access = export['rw_access'].strip('"')
                merged_access = ','.join([access, initial_access])
                updated_access = ganesha_utils.format_access_list(
                    merged_access
                )
                if initial_access != updated_access:
                    LOG.info(_LI('Update %(share)s with access from '
                                 '%(access)s'),
                             {'share': share['name'], 'access': access})
                    export['rw_access'] = '"%s"' % updated_access
                else:
                    LOG.info(_LI('Do not update %(share)s, access from '
                                 '%(access)s already defined'),
                             {'share': share['name'], 'access': access})
                    reload_needed = False

        elif (req_type == "deny_access"):
            export = ganesha_utils.get_export_by_path(exports, local_path)
            initial_access = export['rw_access'].strip('"')
            updated_access = ganesha_utils.format_access_list(
                initial_access,
                deny_access=access
            )

            if initial_access != updated_access:
                LOG.info(_LI('Update %(share)s removing access from '
                             '%(access)s'),
                         {'share': share['name'], 'access': access})
                export['rw_access'] = '"%s"' % updated_access
            else:
                LOG.info(_LI('Do not update %(share)s, access from %(access)s '
                             'already removed'), {'share': share['name'],
                                                  'access': access})
                reload_needed = False

        elif (req_type == "remove_export"):
            export = ganesha_utils.get_export_by_path(exports, local_path)
            if export:
                exports.pop(export['export_id'])
                LOG.info(_LI('Remove export for %s'), share['name'])
            else:
                LOG.info(_LI('Export for %s is not defined in Ganesha '
                             'config.'),
                         share['name'])
                reload_needed = False

        if reload_needed:
            # publish config to all servers and reload or restart
            ganesha_utils.publish_ganesha_config(gservers, sshlogin, sshkey,
                                                 cfgpath, pre_lines, exports)
            ganesha_utils.reload_ganesha_config(gservers, sshlogin, gservice)

    def remove_export(self, local_path, share):
        """Remove export."""
        self._ganesha_process_request("remove_export", local_path, share)

    def allow_access(self, local_path, share, access_type, access):
        """Allow access to the host."""
        # TODO(nileshb):  add support for read only, metadata, and other
        # access types
        if access_type != 'ip':
            raise exception.InvalidShareAccess('Only ip access type '
                                               'supported.')

        self._ganesha_process_request("allow_access", local_path,
                                      share, access_type, access)

    def deny_access(self, local_path, share, access_type, access,
                    force=False):
        """Deny access to the host."""
        self._ganesha_process_request("deny_access", local_path,
                                      share, access_type, access, force)
