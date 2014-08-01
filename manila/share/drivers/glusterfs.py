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

"""Single tenant GlusterFS Driver for shares.

Manila shares are subdirectories within a GlusterFS volume. The access to the
shares is currently mediated by the Gluster-NFS server running in the GlusterFS
backend storage pool. The Gluster-NFS server supports only NFSv3 protocol so
it's the only protocol that can be used to access the shares.

TODO(rraja): support SMB protocol.
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

NFS_EXPORT_DIR = 'nfs.export-dir'
NFS_EXPORT_VOL = 'nfs.export-volumes'


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
    """Execute commands relating to Shares."""

    def __init__(self, db, *args, **kwargs):
        super(GlusterfsShareDriver, self).__init__(*args, **kwargs)
        self.db = db
        self._helpers = None
        self.gluster_address = None
        self.configuration.append_config_values(GlusterfsManilaShare_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'GlusterFS'

    def do_setup(self, context):
        """Native mount the GlusterFS volume and tune it."""
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

        # exporting the whole volume must be prohibited
        # to not to defeat access control
        args, kw = self.gluster_address.make_gluster_args(
                    'volume', 'set', self.gluster_address.volume,
                    NFS_EXPORT_VOL, 'off')
        try:
            self._execute(*args, **kw)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error in gluster volume set: %s") % exc.stderr)
            raise

    def check_for_setup_error(self):
        pass

    def _get_mount_point_for_gluster_vol(self):
        """Return mount point for the GlusterFS volume."""
        return os.path.join(self.configuration.glusterfs_mount_point_base,
                            self.gluster_address.volume)

    def _do_mount(self, cmd, ensure):
        """Execute the mount command based on 'ensure' parameter.

        :param cmd: command to do the actual mount
        :param ensure: boolean to allow remounting a volume with a warning
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
        """Mount GlusterFS volume at the specified mount path."""
        self._execute('mkdir', '-p', mount_path)
        command = ['mount', '-t', 'glusterfs', self.gluster_address.export,
                   mount_path]
        self._do_mount(command, ensure)

    def _read_gluster_vol_from_config(self):
        config_file = self.configuration.glusterfs_volumes_config
        if not os.access(config_file, os.R_OK):
            msg = (_("Gluster config file %(config)s doesn't exist") %
                   {'config': config_file})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        with open(config_file) as f:
            return f.readline().strip()

    def _get_export_dir_dict(self):
        """Get the export entries of shares in the GlusterFS volume."""
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
            if o == NFS_EXPORT_DIR:
                export_dir = v
                break
        edh = {}
        if export_dir:
            # see
            # https://github.com/gluster/glusterfs
            #  /blob/aa19909/xlators/nfs/server/src/nfs.c#L1582
            # regarding the format of nfs.export-dir
            edl = export_dir.split(',')
            # parsing export_dir into a dict of {dir: [hostpec,..]..}
            # format
            r = re.compile('\A/(.*)\((.*)\)\Z')
            for ed in edl:
                d, e = r.match(ed).groups()
                edh[d] = e.split('|')
        return edh

    def _ensure_gluster_vol_mounted(self):
        """Ensure GlusterFS volume is native-mounted on Manila host."""
        mount_path = self._get_mount_point_for_gluster_vol()
        try:
            self._mount_gluster_vol(mount_path, ensure=True)
        except exception.GlusterfsException:
            LOG.error('Could not mount the Gluster volume %s',
                      self.gluster_address.volume)
            raise

    def _get_local_share_path(self, share):
        """Determine mount path of the GlusterFS volume in the Manila host."""
        local_vol_path = self._get_mount_point_for_gluster_vol()
        if not os.access(local_vol_path, os.R_OK):
            raise exception.GlusterfsException('share path %s does not exist' %
                                               local_vol_path)
        return os.path.join(local_vol_path, share['name'])

    def get_share_stats(self, refresh=False):
        """Get share stats.

        If 'refresh' is True, run update the stats first.
        """
        if refresh:
            self._update_share_stats()

        return self._stats

    def _update_share_stats(self):
        """Retrieve stats info from the GlusterFS volume."""

        # sanity check for gluster ctl mount
        smpb = os.stat(self.configuration.glusterfs_mount_point_base)
        smp = os.stat(self._get_mount_point_for_gluster_vol())
        if smpb.st_dev == smp.st_dev:
            raise exception.GlusterfsException(
                     _("GlusterFS control mount is not available")
                  )
        smpv = os.statvfs(self._get_mount_point_for_gluster_vol())

        LOG.debug("Updating share stats")

        data = {}

        data["share_backend_name"] = self.backend_name
        data["vendor_name"] = 'Red Hat'
        data["driver_version"] = '1.0'
        data["storage_protocol"] = 'NFS'

        data['reserved_percentage'] = \
            self.configuration.reserved_share_percentage
        data['QoS_support'] = False

        data['total_capacity_gb'] = (smpv.f_blocks * smpv.f_frsize) >> 30
        data['free_capacity_gb'] = (smpv.f_bavail * smpv.f_frsize) >> 30
        self._stats = data

    def create_share(self, ctx, share, share_server=None):
        """Create a sub-directory/share in the GlusterFS volume."""
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

    def delete_share(self, context, share, share_server=None):
        """Remove a sub-directory/share from the GlusterFS volume."""
        local_share_path = self._get_local_share_path(share)
        cmd = ['rm', '-rf', local_share_path]
        try:
            self._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError:
            LOG.error('Unable to delete share %s', share['name'])
            raise

    def create_snapshot(self, context, snapshot, share_server=None):
        """TBD: Is called to create snapshot."""
        raise NotImplementedError()

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        raise NotImplementedError()

    def delete_snapshot(self, context, snapshot, share_server=None):
        """TBD: Is called to remove snapshot."""
        raise NotImplementedError()

    def ensure_share(self, context, share, share_server=None):
        """Might not be needed?"""
        pass

    def _manage_access(self, context, share, access, cbk):
        """Manage share access with cbk.

        Adjust the exports of the Gluster-NFS server using cbk.

        :param share: share object
        :param access: access object
        :param cbk: callback to adjust the exports of NFS server

        Following is the description of cbk(ddict, edir, host).

        :param ddict: association of shares with ips that have access to them
        :type ddict: dict
        :param edir: name of share i.e. export directory
        :type edir: string
        :param host: ip address derived from the access object
        :type host: string
        :returns: bool (cbk leaves ddict intact) or None (cbk modifies ddict)
        """

        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess('only ip access type allowed')
        export_dir_dict = self._get_export_dir_dict()
        if cbk(export_dir_dict, share['name'], access['access_to']):
            return

        if export_dir_dict:
            export_dir_new = ",".join("/%s(%s)" % (d, "|".join(v))
                                      for d, v in export_dir_dict.items())
            args, kw = self.gluster_address.make_gluster_args(
                        'volume', 'set', self.gluster_address.volume,
                        NFS_EXPORT_DIR, export_dir_new)
        else:
            args, kw = self.gluster_address.make_gluster_args(
                        'volume', 'reset', self.gluster_address.volume,
                        NFS_EXPORT_DIR)
        try:
            self._execute(*args, **kw)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error in gluster volume set: %s") % exc.stderr)
            raise

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share."""
        def cbk(ddict, edir, host):
            if edir not in ddict:
                ddict[edir] = []
            if host in ddict[edir]:
                return True
            ddict[edir].append(host)
        self._manage_access(context, share, access, cbk)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to a share."""
        def cbk(ddict, edir, host):
            if edir not in ddict or host not in ddict[edir]:
                return True
            ddict[edir].remove(host)
            if not ddict[edir]:
                ddict.pop(edir)
        self._manage_access(context, share, access, cbk)
