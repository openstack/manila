# Copyright (c) 2015 Intel, Corp.
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

"""HDFS native protocol (hdfs) driver for manila shares.

Manila share is a directory in HDFS. And this share does not use
service VM instance (share server). The instance directly talks
to the the HDFS cluster.

The initial version only supports single namenode and flat network.

Configuration Requirements:
    To enable access control, HDFS file system must have ACLs enabled.
"""

import math
import os
import pipes
import socket

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import units
import six

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila import utils

LOG = log.getLogger(__name__)

hdfs_native_share_opts = [
    cfg.StrOpt('hdfs_namenode_ip',
               help='The IP of the HDFS namenode.'),
    cfg.PortOpt('hdfs_namenode_port',
                default=9000,
                help='The port of HDFS namenode service.'),
    cfg.PortOpt('hdfs_ssh_port',
                default=22,
                help='HDFS namenode SSH port.'),
    cfg.StrOpt('hdfs_ssh_name',
               help='HDFS namenode ssh login name.'),
    cfg.StrOpt('hdfs_ssh_pw',
               help='HDFS namenode SSH login password, '
                    'This parameter is not necessary, if '
                    '\'hdfs_ssh_private_key\' is configured.'),
    cfg.StrOpt('hdfs_ssh_private_key',
               help='Path to HDFS namenode SSH private '
                    'key for login.'),
]

CONF = cfg.CONF
CONF.register_opts(hdfs_native_share_opts)


class HDFSNativeShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """HDFS Share Driver.

    Executes commands relating to shares.
    API version history:

        1.0 - Initial Version
    """

    def __init__(self, *args, **kwargs):
        super(HDFSNativeShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(hdfs_native_share_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'HDFS-Native'
        self.ssh_connections = {}
        self._hdfs_execute = None
        self._hdfs_bin = None
        self._hdfs_base_path = None

    def do_setup(self, context):
        """Do initialization while the share driver starts."""
        super(HDFSNativeShareDriver, self).do_setup(context)
        host = self.configuration.hdfs_namenode_ip
        local_hosts = socket.gethostbyname_ex(socket.gethostname())[2]
        if host in local_hosts:
            self._hdfs_execute = self._hdfs_local_execute
        else:
            self._hdfs_execute = self._hdfs_remote_execute

        self._hdfs_bin = 'hdfs'
        self._hdfs_base_path = (
            'hdfs://' + self.configuration.hdfs_namenode_ip + ':'
            + six.text_type(self.configuration.hdfs_namenode_port))

    def _hdfs_local_execute(self, *cmd, **kwargs):
        if 'run_as_root' not in kwargs:
            kwargs.update({'run_as_root': False})

        return utils.execute(*cmd, **kwargs)

    def _hdfs_remote_execute(self, *cmd, **kwargs):
        host = self.configuration.hdfs_namenode_ip
        check_exit_code = kwargs.pop('check_exit_code', False)

        return self._run_ssh(host, cmd, check_exit_code)

    def _run_ssh(self, host, cmd_list, check_exit_code=False):
        command = ' '.join(pipes.quote(cmd_arg) for cmd_arg in cmd_list)
        connection = self.ssh_connections.get(host)
        if not connection:
            hdfs_ssh_name = self.configuration.hdfs_ssh_name
            password = self.configuration.hdfs_ssh_pw
            privatekey = self.configuration.hdfs_ssh_private_key
            hdfs_ssh_port = self.configuration.hdfs_ssh_port
            ssh_conn_timeout = self.configuration.ssh_conn_timeout
            min_size = self.configuration.ssh_min_pool_conn
            max_size = self.configuration.ssh_max_pool_conn

            ssh_pool = utils.SSHPool(host,
                                     hdfs_ssh_port,
                                     ssh_conn_timeout,
                                     hdfs_ssh_name,
                                     password=password,
                                     privatekey=privatekey,
                                     min_size=min_size,
                                     max_size=max_size)
            ssh = ssh_pool.create()
            self.ssh_connections[host] = (ssh_pool, ssh)
        else:
            ssh_pool, ssh = connection

        if not ssh.get_transport().is_active():
            ssh_pool.remove(ssh)
            ssh = ssh_pool.create()
            self.ssh_connections[host] = (ssh_pool, ssh)

        try:
            return processutils.ssh_execute(
                ssh,
                command,
                check_exit_code=check_exit_code)
        except Exception as e:
            msg = (_('Error running SSH command: %(cmd)s. '
                     'Error: %(excmsg)s.') %
                   {'cmd': command, 'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

    def _set_share_size(self, share, size=None):
        share_dir = '/' + share['name']

        if not size:
            sizestr = six.text_type(share['size']) + 'g'
        else:
            sizestr = six.text_type(size) + 'g'

        try:
            self._hdfs_execute(self._hdfs_bin, 'dfsadmin',
                               '-setSpaceQuota', sizestr, share_dir)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to set space quota for the '
                     'share %(sharename)s. Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

    def _create_share(self, share):
        """Creates a share."""
        if share['share_proto'].lower() != 'hdfs':
            msg = _('Only HDFS protocol supported!')
            LOG.error(msg)
            raise exception.HDFSException(msg)

        share_dir = '/' + share['name']

        try:
            self._hdfs_execute(self._hdfs_bin, 'dfs',
                               '-mkdir', share_dir)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to create directory in hdfs for the '
                     'share %(sharename)s. Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

        # set share size
        self._set_share_size(share)

        try:
            self._hdfs_execute(self._hdfs_bin, 'dfsadmin',
                               '-allowSnapshot', share_dir)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to allow snapshot for the '
                     'share %(sharename)s. Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

    def _get_share_path(self, share):
        """Return share path on storage provider."""
        return os.path.join(self._hdfs_base_path, share['name'])

    def _get_snapshot_path(self, snapshot):
        """Return snapshot path on storage provider."""
        snapshot_dir = '.snapshot'
        return os.path.join('/', snapshot['share_name'],
                            snapshot_dir, snapshot['name'])

    def get_network_allocations_number(self):
        return 0

    def create_share(self, context, share, share_server=None):
        """Create a HDFS directory which acted as a share."""
        self._create_share(share)
        return self._get_share_path(share)

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Creates a snapshot."""
        self._create_share(share)
        share_path = '/' + share['name']
        snapshot_path = self._get_snapshot_path(snapshot)

        try:
            # check if the directory is empty
            (out, __) = self._hdfs_execute(
                self._hdfs_bin, 'dfs', '-ls', snapshot_path)
            # only copy files when the snapshot directory is not empty
            if out:
                copy_path = snapshot_path + "/*"

                cmd = [self._hdfs_bin, 'dfs', '-cp',
                       copy_path, share_path]

                self._hdfs_execute(*cmd)

        except exception.ProcessExecutionError as e:
            msg = (_('Failed to create share %(sharename)s from '
                     'snapshot %(snapshotname)s. Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'snapshotname': snapshot['name'],
                    'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

        return self._get_share_path(share)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""
        share_dir = '/' + snapshot['share_name']
        snapshot_name = snapshot['name']

        cmd = [self._hdfs_bin, 'dfs', '-createSnapshot',
               share_dir, snapshot_name]
        try:
            self._hdfs_execute(*cmd)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to create snapshot %(snapshotname)s for '
                     'the share %(sharename)s. Error: %(excmsg)s.') %
                   {'snapshotname': snapshot_name,
                    'sharename': snapshot['share_name'],
                    'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

    def delete_share(self, context, share, share_server=None):
        """Deletes share storage."""
        share_dir = '/' + share['name']

        cmd = [self._hdfs_bin, 'dfs', '-rm', '-r', share_dir]
        try:
            self._hdfs_execute(*cmd)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to delete share %(sharename)s. '
                     'Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""
        share_dir = '/' + snapshot['share_name']

        cmd = [self._hdfs_bin, 'dfs', '-deleteSnapshot',
               share_dir, snapshot['name']]
        try:
            self._hdfs_execute(*cmd)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to delete snapshot %(snapshotname)s. '
                     'Error: %(excmsg)s.') %
                   {'snapshotname': snapshot['name'],
                    'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

    def ensure_share(self, context, share, share_server=None):
        """Ensure the storage are exported."""

    def allow_access(self, context, share, access, share_server=None):
        """Allows access to the share for a given user."""
        if access['access_type'] != 'user':
            msg = _("Only 'user' access type allowed!")
            LOG.error(msg)
            raise exception.InvalidShareAccess(msg)

        # Note(jun): For directories in HDFS, the x permission is
        # required to access a child of the directory.
        if access['access_level'] == 'rw':
            access_level = 'rwx'
        elif access['access_level'] == 'ro':
            access_level = 'r-x'
        else:
            msg = (_('The access level %(accesslevel)s was unsupported.') %
                   {'accesslevel': access['access_level']})
            LOG.error(msg)
            raise exception.InvalidShareAccess(msg)

        share_dir = '/' + share['name']
        user_access = ':'.join([access['access_type'],
                                access['access_to'],
                                access_level])

        cmd = [self._hdfs_bin, 'dfs', '-setfacl', '-m', '-R',
               user_access, share_dir]
        try:
            (__, out) = self._hdfs_execute(*cmd, check_exit_code=True)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to set ACL of share %(sharename)s for '
                     'user: %(username)s'
                     'Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'username': access['access_to'],
                    'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

    def deny_access(self, context, share, access, share_server=None):
        """Denies the access to the share for a given user."""
        share_dir = '/' + share['name']
        access_name = ':'.join([access['access_type'], access['access_to']])

        cmd = [self._hdfs_bin, 'dfs', '-setfacl', '-x', '-R',
               access_name, share_dir]
        try:
            (__, out) = self._hdfs_execute(*cmd, check_exit_code=True)
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to deny ACL of share %(sharename)s for '
                     'user: %(username)s'
                     'Error: %(excmsg)s.') %
                   {'sharename': share['name'],
                    'username': access['access_to'],
                    'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

    def extend_share(self, share, new_size, share_server=None):
        """Extend share storage."""
        self._set_share_size(share, new_size)

    def _check_hdfs_state(self):
        try:
            (out, __) = self._hdfs_execute(self._hdfs_bin, 'fsck', '/')
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to check hdfs state. Error: %(excmsg)s.') %
                   {'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)
        if 'HEALTHY' in out:
            return True
        else:
            return False

    def check_for_setup_error(self):
        """Return an error if the prerequisites are met."""
        if not self.configuration.hdfs_namenode_ip:
            msg = _('Not specify the hdfs cluster yet! '
                    'Add the ip of hdfs namenode in the '
                    'hdfs_namenode_ip configuration parameter.')
            LOG.error(msg)
            raise exception.HDFSException(msg)

        if not self._check_hdfs_state():
            msg = _('HDFS is not in healthy state.')
            LOG.error(msg)
            raise exception.HDFSException(msg)

    def _get_available_capacity(self):
        """Calculate available space on path."""
        try:
            (out, __) = self._hdfs_execute(self._hdfs_bin, 'dfsadmin',
                                           '-report')
        except exception.ProcessExecutionError as e:
            msg = (_('Failed to check available capacity for hdfs.'
                     'Error: %(excmsg)s.') %
                   {'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)

        lines = out.splitlines()
        try:
            total = int(lines[1].split()[2])
            free = int(lines[2].split()[2])
        except (IndexError, ValueError) as e:
            msg = (_('Failed to get hdfs capacity info. '
                     'Error: %(excmsg)s.') %
                   {'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.HDFSException(msg)
        return total, free

    def _update_share_stats(self):
        """Retrieves stats info of share directories group."""

        data = dict(share_backend_name=self.backend_name,
                    storage_protocol='HDFS',
                    reserved_percentage=self.configuration.
                    reserved_share_percentage)

        total, free = self._get_available_capacity()

        data['total_capacity_gb'] = math.ceil(total / units.Gi)
        data['free_capacity_gb'] = math.ceil(free / units.Gi)

        super(HDFSNativeShareDriver, self)._update_share_stats(data)
