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

"""Flat network GlusterFS Driver.

Manila shares are subdirectories within a GlusterFS volume. The backend,
a GlusterFS cluster, uses one of the two NFS servers, Gluster-NFS or
NFS-Ganesha, based on a configuration option, to mediate access to the shares.
NFS-Ganesha server supports NFSv3 and v4 protocols, while Gluster-NFS
server supports only NFSv3 protocol.

TODO(rraja): support SMB protocol.
"""

import errno
import os
import re
import sys
import xml.etree.cElementTree as etree

from oslo_config import cfg
from oslo_log import log
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW
from manila.share import driver
from manila.share.drivers import ganesha
from manila.share.drivers.ganesha import utils as ganesha_utils

LOG = log.getLogger(__name__)

GlusterfsManilaShare_opts = [
    cfg.StrOpt('glusterfs_target',
               help='Specifies the GlusterFS volume to be mounted on the '
                    'Manila host. It is of the form '
                    '[remoteuser@]<volserver>:<volid>.'),
    cfg.StrOpt('glusterfs_mount_point_base',
               default='$state_path/mnt',
               help='Base directory containing mount points for Gluster '
                    'volumes.'),
    cfg.StrOpt('glusterfs_nfs_server_type',
               default='Gluster',
               help='Type of NFS server that mediate access to the Gluster '
                    'volumes (Gluster or Ganesha).'),
    cfg.StrOpt('glusterfs_server_password',
               default=None,
               secret=True,
               help="Remote GlusterFS server node's login password. "
                    "This is not required if 'glusterfs_path_to_private_key'"
                    ' is configured.'),
    cfg.StrOpt('glusterfs_path_to_private_key',
               default=None,
               help='Path of Manila host\'s private SSH key file.'),
    cfg.StrOpt('glusterfs_ganesha_server_ip',
               default=None,
               help="Remote Ganesha server node's IP address."),
    cfg.StrOpt('glusterfs_ganesha_server_username',
               default='root',
               help="Remote Ganesha server node's username."),
    cfg.StrOpt('glusterfs_ganesha_server_password',
               default=None,
               secret=True,
               help="Remote Ganesha server node's login password. "
                    "This is not required if 'glusterfs_path_to_private_key'"
                    ' is configured.'),
]

CONF = cfg.CONF
CONF.register_opts(GlusterfsManilaShare_opts)

NFS_EXPORT_DIR = 'nfs.export-dir'
NFS_EXPORT_VOL = 'nfs.export-volumes'

GLUSTERFS_VERSION_MIN = (3, 5)


class GlusterManager(object):
    """Interface with a GlusterFS volume."""

    scheme = re.compile('\A(?:(?P<user>[^:@/]+)@)?'
                        '(?P<host>[^:@/]+)'
                        '(?::/(?P<vol>.+))?')

    def __init__(self, address, execf, path_to_private_key=None,
                 remote_server_password=None, has_volume=True):
        """Initialize a GlusterManager instance.

        :param address: the Gluster URI (in [<user>@]<host>:/<vol> format).
        :param execf: executor function for management commands.
        :param path_to_private_key: path to private ssh key of remote server.
        :param remote_server_password: ssh password for remote server.
        :param has_volume: instruction to uri parser regarding how to deal
                           with the optional volume part (True: require its
                           presence, False: require its absence, None: don't
                           require anything about volume).
        """
        m = self.scheme.search(address)
        if m:
            self.volume = m.group('vol')
            if (has_volume is True and not self.volume) or (
               has_volume is False and self.volume):
                m = None
        if not m:
            raise exception.GlusterfsException(
                _('Invalid gluster address %s.') % address)
        self.remote_user = m.group('user')
        self.host = m.group('host')
        self.management_address = '@'.join(
            filter(None, (self.remote_user, self.host)))
        self.qualified = address
        if self.volume:
            self.export = ':/'.join([self.host, self.volume])
        else:
            self.export = None
        self.path_to_private_key = path_to_private_key
        self.remote_server_password = remote_server_password
        self.gluster_call = self.make_gluster_call(execf)

    def make_gluster_call(self, execf):
        """Execute a Gluster command locally or remotely."""
        if self.remote_user:
            gluster_execf = ganesha_utils.SSHExecutor(
                self.host, 22, None, self.remote_user,
                password=self.remote_server_password,
                privatekey=self.path_to_private_key)
        else:
            gluster_execf = ganesha_utils.RootExecutor(execf)
        return lambda *args, **kwargs: gluster_execf(*(('gluster',) + args),
                                                     **kwargs)

    def get_gluster_vol_option(self, option):
        """Get the value of an option set on a GlusterFS volume."""
        args = ('--xml', 'volume', 'info', self.volume)
        try:
            out, err = self.gluster_call(*args)
        except exception.ProcessExecutionError as exc:
            LOG.error(_LE("Error retrieving volume info: %s"), exc.stderr)
            raise exception.GlusterfsException("gluster %s failed" %
                                               ' '.join(args))

        if not out:
            raise exception.GlusterfsException(
                'gluster volume info %s: no data received' %
                self.volume
            )

        vix = etree.fromstring(out)
        if int(vix.find('./volInfo/volumes/count').text) != 1:
            raise exception.InvalidShare('Volume name ambiguity')
        for e in vix.findall(".//option"):
            o, v = (e.find(a).text for a in ('name', 'value'))
            if o == option:
                return v

    def get_gluster_version(self):
        """Retrieve GlusterFS version.

        :returns: version (as tuple of strings, example: ('3', '6', '0beta2'))
        """
        try:
            out, err = self.gluster_call('--version')
        except exception.ProcessExecutionError as exc:
            raise exception.GlusterfsException(
                _("'gluster version' failed on server "
                  "%(server)s: %(message)s") %
                {'server': self.host, 'message': six.text_type(exc)})
        try:
            owords = out.split()
            if owords[0] != 'glusterfs':
                raise RuntimeError
            vers = owords[1].split('.')
            # provoke an exception if vers does not start with two numerals
            int(vers[0])
            int(vers[1])
        except Exception:
            raise exception.GlusterfsException(
                _("Cannot parse version info obtained from server "
                  "%(server)s, version info: %(info)s") %
                {'server': self.host, 'info': out})
        return vers

    def check_gluster_version(self, minvers):
        """Retrieve and check GlusterFS version.

        :param minvers: minimum version to require
                        (given as tuple of integers, example: (3, 6))
        """
        vers = self.get_gluster_version()
        if self.numreduct(vers) < minvers:
            raise exception.GlusterfsException(_(
                "Unsupported GlusterFS version %(version)s on server "
                "%(server)s, minimum requirement: %(minvers)s") % {
                'server': self.host,
                'version': '.'.join(vers),
                'minvers': '.'.join(six.text_type(c) for c in minvers)})

    @staticmethod
    def numreduct(vers):
        """The numeric reduct of a tuple of strings.

        That is, applying an integer conversion map on the longest
        initial segment of vers which consists of numerals.
        """
        numvers = []
        for c in vers:
            try:
                numvers.append(int(c))
            except ValueError:
                break
        return tuple(numvers)


class GlusterfsShareDriver(driver.ExecuteMixin, driver.GaneshaMixin,
                           driver.ShareDriver,):
    """Execute commands relating to Shares."""

    def __init__(self, *args, **kwargs):
        super(GlusterfsShareDriver, self).__init__(False, *args, **kwargs)
        self._helpers = {}
        self.gluster_manager = None
        self.configuration.append_config_values(GlusterfsManilaShare_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'GlusterFS'

    def do_setup(self, context):
        """Prepares the backend and appropriate NAS helpers."""
        super(GlusterfsShareDriver, self).do_setup(context)
        if not self.configuration.glusterfs_target:
            raise exception.GlusterfsException(
                _('glusterfs_target configuration that specifies the GlusterFS'
                  ' volume to be mounted on the Manila host is not set.'))
        self.gluster_manager = GlusterManager(
            self.configuration.glusterfs_target,
            self._execute,
            self.configuration.glusterfs_path_to_private_key,
            self.configuration.glusterfs_server_password,
        )
        self.gluster_manager.check_gluster_version(GLUSTERFS_VERSION_MIN)
        try:
            self._execute('mount.glusterfs', check_exit_code=False)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise exception.GlusterfsException(
                    _('mount.glusterfs is not installed.'))
            else:
                raise

        # enable quota options of a GlusteFS volume to allow
        # creation of shares of specific size
        args = ('volume', 'quota', self.gluster_manager.volume, 'enable')
        try:
            self.gluster_manager.gluster_call(*args)
        except exception.ProcessExecutionError as exc:
            if (self.gluster_manager.
                    get_gluster_vol_option('features.quota')) != 'on':
                LOG.error(_LE("Error in tuning GlusterFS volume to enable "
                              "creation of shares of specific size: %s"),
                          exc.stderr)
                raise exception.GlusterfsException(exc)

        self._setup_helpers()
        self._ensure_gluster_vol_mounted()

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        # TODO(rraja): The below seems crude. Accommodate CIFS helper as well?
        nfs_helper = getattr(
            sys.modules[__name__],
            self.configuration.glusterfs_nfs_server_type + 'NFSHelper')
        self._helpers['NFS'] = nfs_helper(self._execute,
                                          self.configuration,
                                          gluster_manager=self.gluster_manager)
        for helper in self._helpers.values():
            helper.init_helper()

    def check_for_setup_error(self):
        pass

    def _get_mount_point_for_gluster_vol(self):
        """Return mount point for the GlusterFS volume."""
        return os.path.join(self.configuration.glusterfs_mount_point_base,
                            self.gluster_manager.volume)

    def _do_mount(self, cmd, ensure):
        """Execute the mount command based on 'ensure' parameter.

        :param cmd: command to do the actual mount
        :param ensure: boolean to allow remounting a volume with a warning
        """
        try:
            self._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError as exc:
            if ensure and 'already mounted' in exc.stderr:
                LOG.warn(_LW("%s is already mounted"),
                         self.gluster_manager.export)
            else:
                raise exception.GlusterfsException(
                    'Unable to mount Gluster volume'
                )

    def _mount_gluster_vol(self, mount_path, ensure=False):
        """Mount GlusterFS volume at the specified mount path."""
        self._execute('mkdir', '-p', mount_path)
        command = ['mount', '-t', 'glusterfs', self.gluster_manager.export,
                   mount_path]
        self._do_mount(command, ensure)

    def _ensure_gluster_vol_mounted(self):
        """Ensure GlusterFS volume is native-mounted on Manila host."""
        mount_path = self._get_mount_point_for_gluster_vol()
        try:
            self._mount_gluster_vol(mount_path, ensure=True)
        except exception.GlusterfsException:
            LOG.error(_LE('Could not mount the Gluster volume %s'),
                      self.gluster_manager.volume)
            raise

    def _get_local_share_path(self, share):
        """Determine mount path of the GlusterFS volume in the Manila host."""
        local_vol_path = self._get_mount_point_for_gluster_vol()
        if not os.access(local_vol_path, os.R_OK):
            raise exception.GlusterfsException('share path %s does not exist' %
                                               local_vol_path)
        return os.path.join(local_vol_path, share['name'])

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

        data = dict(
            storage_protocol='NFS',
            vendor_name='Red Hat',
            share_backend_name=self.backend_name,
            reserved_percentage=self.configuration.reserved_share_percentage,
            total_capacity_gb=(smpv.f_blocks * smpv.f_frsize) >> 30,
            free_capacity_gb=(smpv.f_bavail * smpv.f_frsize) >> 30)
        super(GlusterfsShareDriver, self)._update_share_stats(data)

    def get_network_allocations_number(self):
        return 0

    def create_share(self, ctx, share, share_server=None):
        """Create a sub-directory/share in the GlusterFS volume."""
        # probe into getting a NAS protocol helper for the share in order
        # to facilitate early detection of unsupported protocol type
        self._get_helper(share)
        sizestr = six.text_type(share['size']) + 'GB'
        share_dir = '/' + share['name']
        local_share_path = self._get_local_share_path(share)
        cmd = ['mkdir', local_share_path]
        # set hard limit quota on the sub-directory/share
        args = ('volume', 'quota', self.gluster_manager.volume,
                'limit-usage', share_dir, sizestr)
        try:
            self._execute(*cmd, run_as_root=True)
            self.gluster_manager.gluster_call(*args)
        except exception.ProcessExecutionError as exc:
            self._cleanup_create_share(local_share_path, share['name'])
            LOG.error(_LE('Unable to create share %s'), share['name'])
            raise exception.GlusterfsException(exc)

        export_location = os.path.join(self.gluster_manager.qualified,
                                       share['name'])
        return export_location

    def _cleanup_create_share(self, share_path, share_name):
        """Cleanup share that errored out during its creation."""
        if os.path.exists(share_path):
            cmd = ['rm', '-rf', share_path]
            try:
                self._execute(*cmd, run_as_root=True)
            except exception.ProcessExecutionError as exc:
                LOG.error(_LE('Cannot cleanup share, %s, that errored out '
                              'during its creation, but exists in GlusterFS '
                              'volume.'), share_name)
                raise exception.GlusterfsException(exc)

    def delete_share(self, context, share, share_server=None):
        """Remove a sub-directory/share from the GlusterFS volume."""
        local_share_path = self._get_local_share_path(share)
        cmd = ['rm', '-rf', local_share_path]
        try:
            self._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError:
            LOG.error(_LE('Unable to delete share %s'), share['name'])
            raise

    def ensure_share(self, context, share, share_server=None):
        """Might not be needed?"""
        pass

    def _get_helper(self, share):
        """Choose a protocol specific helper class."""
        if share['share_proto'] == 'NFS':
            return self._helpers['NFS']
        else:
            raise exception.InvalidShare(
                reason=(_('Unsupported share type, %s.')
                        % share['share_proto']))

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        self._get_helper(share).allow_access('/', share, access)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        self._get_helper(share).deny_access('/', share, access)


class GlusterNFSHelper(ganesha.NASHelperBase):
    """Manage shares with Gluster-NFS server."""

    def __init__(self, execute, config_object, **kwargs):
        self.gluster_manager = kwargs.pop('gluster_manager')
        super(GlusterNFSHelper, self).__init__(execute, config_object,
                                               **kwargs)

    def init_helper(self):
        # exporting the whole volume must be prohibited
        # to not to defeat access control
        args = ('volume', 'set', self.gluster_manager.volume, NFS_EXPORT_VOL,
                'off')
        try:
            self.gluster_manager.gluster_call(*args)
        except exception.ProcessExecutionError as exc:
            LOG.error(_LE("Error in tuning GlusterFS volume to prevent "
                          "exporting the entire volume: %s"), exc.stderr)
            raise exception.GlusterfsException("gluster %s failed" %
                                               ' '.join(args))

    def _get_export_dir_dict(self):
        """Get the export entries of shares in the GlusterFS volume."""
        export_dir = self.gluster_manager.get_gluster_vol_option(
            NFS_EXPORT_DIR)
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

    def _manage_access(self, share_name, access_type, access_to, cbk):
        """Manage share access with cbk.

        Adjust the exports of the Gluster-NFS server using cbk.

        :param share_name: name of the share
        :type share_name: string
        :param access_type: type of access allowed in Manila
        :type access_type: string
        :param access_to: ip of the guest whose share access is managed
        :type access_to: string
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

        if access_type != 'ip':
            raise exception.InvalidShareAccess('only ip access type allowed')
        export_dir_dict = self._get_export_dir_dict()
        if cbk(export_dir_dict, share_name, access_to):
            return

        if export_dir_dict:
            export_dir_new = (",".join("/%s(%s)" % (d, "|".join(v))
                              for d, v in sorted(export_dir_dict.items())))
            args = ('volume', 'set', self.gluster_manager.volume,
                    NFS_EXPORT_DIR, export_dir_new)
        else:
            args = ('volume', 'reset', self.gluster_manager.volume,
                    NFS_EXPORT_DIR)
        try:
            self.gluster_manager.gluster_call(*args)
        except exception.ProcessExecutionError as exc:
            LOG.error(_LE("Error in gluster volume set: %s"), exc.stderr)
            raise

    def allow_access(self, base, share, access):
        """Allow access to a share."""
        def cbk(ddict, edir, host):
            if edir not in ddict:
                ddict[edir] = []
            if host in ddict[edir]:
                return True
            ddict[edir].append(host)
        self._manage_access(share['name'], access['access_type'],
                            access['access_to'], cbk)

    def deny_access(self, base, share, access):
        """Deny access to a share."""
        def cbk(ddict, edir, host):
            if edir not in ddict or host not in ddict[edir]:
                return True
            ddict[edir].remove(host)
            if not ddict[edir]:
                ddict.pop(edir)
        self._manage_access(share['name'], access['access_type'],
                            access['access_to'], cbk)


class GaneshaNFSHelper(ganesha.GaneshaNASHelper):

    def __init__(self, execute, config_object, **kwargs):
        self.gluster_manager = kwargs.pop('gluster_manager')
        if config_object.glusterfs_ganesha_server_ip:
            execute = ganesha_utils.SSHExecutor(
                config_object.glusterfs_ganesha_server_ip, 22, None,
                config_object.glusterfs_ganesha_server_username,
                password=config_object.glusterfs_ganesha_server_password,
                privatekey=config_object.glusterfs_path_to_private_key)
        else:
            execute = ganesha_utils.RootExecutor(execute)
        super(GaneshaNFSHelper, self).__init__(execute, config_object,
                                               **kwargs)

    def _default_config_hook(self):
        """Callback to provide default export block."""
        dconf = super(GaneshaNFSHelper, self)._default_config_hook()
        conf_dir = ganesha_utils.path_from(__file__, "glusterfs", "conf")
        ganesha_utils.patch(dconf, self._load_conf_dir(conf_dir))
        return dconf

    def _fsal_hook(self, base, share, access):
        """Callback to create FSAL subblock."""
        return {"Hostname": self.gluster_manager.host,
                "Volume": self.gluster_manager.volume,
                "Volpath": "/" + share['name']}
