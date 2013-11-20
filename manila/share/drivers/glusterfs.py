# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 Red Hat, Inc.
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
GlusterFS Driver for shares.

"""
import errno
import os
import pdb
from pipes import quote as shellquote
import re
import xml.etree.cElementTree as etree

from manila import exception
from manila.openstack.common import log as logging
from manila.share import driver
from manila import utils

from oslo.config import cfg

LOG = logging.getLogger(__name__)

GlusterfsManilaShare_opts = [
    cfg.StrOpt('glusterfs_volumes_config',
               default='/etc/manila/glusterfs_volumes',
               help='File with the list of Gluster volumes that can'
                    'be used to create shares'),
    cfg.StrOpt('glusterfs_mount_point_base',
               default='$state_path/mnt',
               help='Base dir containing mount points for Gluster volumes.'),
]

CONF = cfg.CONF
CONF.register_opts(GlusterfsManilaShare_opts)

_nfs_export_dir = 'nfs.export-dir'


class GlusterAddress(object):

    scheme = re.compile('\A(?:(?P<user>[^:@/]+)@)?'
                        '(?P<host>[^:@/]+):'
                        '/(?P<vol>.+)')

    def __init__(self, address):
        m = self.scheme.search(address)
        if not m:
            raise exception.GlusterfsException('invalid gluster address ' +
                                               address)
        self.remote_user = m.group('user')
        self.host = m.group('host')
        self.volume = m.group('vol')
        self.qualified = address
        self.export = ':/'.join([self.host, self.volume])

    def make_gluster_args(self, *args):
        args = ('gluster',) + args
        kw = {}
        if self.remote_user:
            args = ('ssh', '@'.join([self.remote_user, self.host]),
                    ' '.join(shellquote(a) for a in args))
        else:
            kw['run_as_root'] = True
        return args, kw


class GlusterfsShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """
    Glusterfs Specific driver
    """

    def __init__(self, db, *args, **kwargs):
        super(GlusterfsShareDriver, self).__init__(*args, **kwargs)
        self.db = db
        self._helpers = None
        self.gluster_address = None
        self.configuration.append_config_values(GlusterfsManilaShare_opts)

    def do_setup(self, context):
        """Native mount the Gluster volume."""
        super(GlusterfsShareDriver, self).do_setup(context)
        self.gluster_address = GlusterAddress(
                                   self._read_gluster_vol_from_config()
                               )
        try:
            self._execute('mount.glusterfs', check_exit_code=False)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise exception.GlusterfsException(
                    _('mount.glusterfs is not installed'))
            else:
                raise

        self._ensure_gluster_vol_mounted()

    def check_for_setup_error(self):
        """Is called after do_setup method. Nothing to do."""
        pass

    def _get_mount_point_for_gluster_vol(self):
        """Return mount point for gluster volume."""
        return os.path.join(self.configuration.glusterfs_mount_point_base,
                            self.gluster_address.volume)

    def _do_mount(self, cmd, ensure):
        """Finalize mount command.

        :param cmd: command to do the actual mount
        :param ensure: boolean to allow remounting a volume with a warning
        :param glusterfs_export: gluster volume that is mounted
        """
        try:
            self._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError as exc:
            if ensure and 'already mounted' in exc.stderr:
                LOG.warn(_("%s is already mounted"),
                         self.gluster_address.export)
            else:
                raise exception.GlusterfsException(
                     'Unable to mount Gluster volume'
                )

    def _mount_gluster_vol(self, mount_path, ensure=False):
        """Mount Gluster volume at the specified mount path."""
        self._execute('mkdir', '-p', mount_path)
        command = ['mount', '-t', 'glusterfs', self.gluster_address.export,
                   mount_path]
        self._do_mount(command, ensure)

    def _read_gluster_vol_from_config(self):
        config_file = self.configuration.glusterfs_volumes_config
        if not os.access(config_file, os.R_OK):
            msg = (_("Gluster config file at %(config)s doesn't exist") %
                   {'config': config})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        with open(config_file) as f:
            return f.readline().strip()

    def _get_export_dir_list(self):
        try:
            args, kw = self.gluster_address.make_gluster_args(
                           '--xml',
                           'volume',
                           'info',
                           self.gluster_address.volume
            )
            out, err = self._execute(*args, **kw)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error retrieving volume info: %s") % exc.stderr)
            raise

        if not out:
            raise exception.GlusterfsException(
                      'Empty answer from gluster command'
                  )

        vix = etree.fromstring(out)
        if int(vix.find('./volInfo/volumes/count').text) != 1:
            raise exception.InvalidShare('Volume name ambiguity')
        export_dir = None
        for o, v in \
            ((e.find(a).text for a in ('name', 'value'))
             for e in vix.findall(".//option")):
            if o == _nfs_export_dir:
                export_dir = v
                break
        if export_dir:
            return export_dir.split(',')
        else:
            return []

    def _ensure_gluster_vol_mounted(self):
        """Ensure that a Gluster volume is native-mounted on Manila host.
        """
        mount_path = self._get_mount_point_for_gluster_vol()
        try:
            self._mount_gluster_vol(mount_path, ensure=True)
        except exception.GlusterfsException:
            LOG.error('Could not mount the Gluster volume %s',
                      self.gluster_address.volume)
            raise

    def _get_local_share_path(self, share):
        """Determine the locally mounted path of the share
        (in Manila host).
        """
        local_vol_path = self._get_mount_point_for_gluster_vol()
        if not os.access(local_vol_path, os.R_OK):
            raise exception.GlusterfsException('share path %s does not exist' %
                                               local_vol_path)
        return os.path.join(local_vol_path, share['name'])

    def create_share(self, ctx, share):
        """Create a directory that'd serve as a share in a Gluster volume."""
        local_share_path = self._get_local_share_path(share)
        cmd = ['mkdir', local_share_path]
        try:
            self._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError:
            LOG.error('Unable to create share %s', share['name'])
            raise

        export_location = os.path.join(self.gluster_address.qualified,
                                       share['name'])
        return export_location

    def delete_share(self, context, share):
        """Remove a directory that served as a share in a Gluster volume."""
        local_share_path = self._get_local_share_path(share)
        cmd = ['rm', '-rf', local_share_path]
        try:
            self._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError:
            LOG.error('Unable to delete share %s', share['name'])
            raise

    def create_snapshot(self, context, snapshot):
        """TBD: Is called to create snapshot."""
        raise NotImplementedError()

    def create_share_from_snapshot(self, context, share, snapshot):
        """Is called to create share from snapshot."""
        raise NotImplementedError()

    def delete_snapshot(self, context, snapshot):
        """TBD: Is called to remove snapshot."""
        raise NotImplementedError()

    def ensure_share(self, context, share):
        """Might not be needed?"""
        pass

    def _manage_access(self, context, share, access, cbk):
        """Manage share access by adjusting the export list with cbk

        cbk is a callable of args (dl, acc), where dl is a list of strings
        and acc is a string. It should return True (or a value of Boolean
        reduct True) if it leaves dl intact, and False (or a value of Boolean
        reduct False) if it makes a change on dl

        cbk will be called with dl being  list of currently exported dirs and
        acc being a textual specification derived from access.
        """

        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess('only ip access type allowed')
        export_dir_list = self._get_export_dir_list()
        access_spec = "/%s(%s)" % (share['name'], access['access_to'])
        if cbk(export_dir_list, access_spec):
            return

        export_dir_new = ",".join(export_dir_list)
        try:
            args, kw = self.gluster_address.make_gluster_args(
                         'volume', 'set', self.gluster_address.volume,
                          _nfs_export_dir, export_dir_new)
            self._execute(*args, **kw)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error in gluster volume set: %s") % exc.stderr)
            raise

    def allow_access(self, context, share, access):
        """NFS export a dir to a volume"""
        self._manage_access(context, share, access,
                            lambda dl, acc:
                                True if acc in dl else dl.append(acc))

    def deny_access(self, context, share, access):
        """Deny access to the share."""
        self._manage_access(context, share, access,
                            lambda dl, acc:
                                True if acc not in dl else dl.remove(acc))
