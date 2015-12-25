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

import re
import socket
import sys

from oslo_config import cfg
from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.share import driver
from manila.share.drivers import ganesha
from manila.share.drivers.ganesha import utils as ganesha_utils
from manila.share.drivers.glusterfs import layout
from manila import utils

LOG = log.getLogger(__name__)

GlusterfsManilaShare_opts = [
    cfg.StrOpt('glusterfs_nfs_server_type',
               default='Gluster',
               help='Type of NFS server that mediate access to the Gluster '
                    'volumes (Gluster or Ganesha).'),
    cfg.StrOpt('glusterfs_ganesha_server_ip',
               help="Remote Ganesha server node's IP address."),
    cfg.StrOpt('glusterfs_ganesha_server_username',
               default='root',
               help="Remote Ganesha server node's username."),
    cfg.StrOpt('glusterfs_ganesha_server_password',
               secret=True,
               help="Remote Ganesha server node's login password. "
                    "This is not required if 'glusterfs_path_to_private_key'"
                    ' is configured.'),
]

CONF = cfg.CONF
CONF.register_opts(GlusterfsManilaShare_opts)

NFS_EXPORT_DIR = 'nfs.export-dir'
NFS_EXPORT_VOL = 'nfs.export-volumes'
NFS_RPC_AUTH_ALLOW = 'nfs.rpc-auth-allow'
NFS_RPC_AUTH_REJECT = 'nfs.rpc-auth-reject'


class GlusterfsShareDriver(driver.ExecuteMixin, driver.GaneshaMixin,
                           layout.GlusterfsShareDriverBase):
    """Execute commands relating to Shares."""

    GLUSTERFS_VERSION_MIN = (3, 5)

    supported_layouts = ('layout_directory.GlusterfsDirectoryMappedLayout',
                         'layout_volume.GlusterfsVolumeMappedLayout')
    supported_protocols = ('NFS',)

    def __init__(self, *args, **kwargs):
        super(GlusterfsShareDriver, self).__init__(False, *args, **kwargs)
        self._helpers = {}
        self.configuration.append_config_values(GlusterfsManilaShare_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'GlusterFS'
        self.nfs_helper = getattr(
            sys.modules[__name__],
            self.configuration.glusterfs_nfs_server_type + 'NFSHelper')

    def do_setup(self, context):
        # in order to do an initial instantialization of the helper
        self._get_helper()
        super(GlusterfsShareDriver, self).do_setup(context)

    def _setup_via_manager(self, share_manager, share_manager_parent=None):
        gluster_manager = share_manager['manager']
        # TODO(csaba): This should be refactored into proper dispatch to helper
        if self.nfs_helper == GlusterNFSHelper and not gluster_manager.path:
            # default is 'on'
            export_vol = gluster_manager.get_gluster_vol_option(
                NFS_EXPORT_VOL) or 'on'
            if export_vol.lower() not in ('on', '1', 'true', 'yes', 'enable'):
                raise exception.GlusterfsException(
                    _("Gluster-NFS with volume layout should be used "
                      "with `nfs.export-volumes = on`"))
            setting = [NFS_RPC_AUTH_REJECT, '*']
        else:
            # gluster-nfs export of the whole volume must be prohibited
            # to not to defeat access control
            setting = [NFS_EXPORT_VOL, 'off']
        args = ['volume', 'set', gluster_manager.volume] + setting
        gluster_manager.gluster_call(
            *args,
            log=_LE("Tuning the GlusterFS volume to prevent exporting the "
                    "entire volume"))
        return self.nfs_helper(self._execute, self.configuration,
                               gluster_manager=gluster_manager).get_export(
            share_manager['share'])

    def check_for_setup_error(self):
        pass

    def _update_share_stats(self):
        """Retrieve stats info from the GlusterFS volume."""

        data = dict(
            storage_protocol='NFS',
            vendor_name='Red Hat',
            share_backend_name=self.backend_name,
            reserved_percentage=self.configuration.reserved_share_percentage)
        super(GlusterfsShareDriver, self)._update_share_stats(data)

    def get_network_allocations_number(self):
        return 0

    def _get_helper(self, gluster_mgr=None):
        """Choose a protocol specific helper class."""
        helper_class = self.nfs_helper
        if (self.nfs_helper == GlusterNFSHelper and gluster_mgr and
                not gluster_mgr.path):
            helper_class = GlusterNFSVolHelper
        helper = helper_class(self._execute, self.configuration,
                              gluster_manager=gluster_mgr)
        helper.init_helper()
        return helper

    def _allow_access_via_manager(self, gluster_mgr, context, share, access,
                                  share_server=None):
        """Allow access to the share."""
        self._get_helper(gluster_mgr).allow_access('/', share, access)

    def _deny_access_via_manager(self, gluster_mgr, context, share, access,
                                 share_server=None):
        """Allow access to the share."""
        self._get_helper(gluster_mgr).deny_access('/', share, access)


class GlusterNFSHelper(ganesha.NASHelperBase):
    """Manage shares with Gluster-NFS server."""

    def __init__(self, execute, config_object, **kwargs):
        self.gluster_manager = kwargs.pop('gluster_manager')
        super(GlusterNFSHelper, self).__init__(execute, config_object,
                                               **kwargs)

    def get_export(self, share):
        return self.gluster_manager.export

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
        self.gluster_manager.gluster_call(
            *args,
            log=_LE("Tuning GlusterFS volume options"))

    def allow_access(self, base, share, access):
        """Allow access to a share."""
        def cbk(ddict, edir, host):
            if edir not in ddict:
                ddict[edir] = []
            if host in ddict[edir]:
                return True
            ddict[edir].append(host)
        path = self.gluster_manager.path
        self._manage_access(path[1:], access['access_type'],
                            access['access_to'], cbk)

    def deny_access(self, base, share, access):
        """Deny access to a share."""
        def cbk(ddict, edir, host):
            if edir not in ddict or host not in ddict[edir]:
                return True
            ddict[edir].remove(host)
            if not ddict[edir]:
                ddict.pop(edir)
        path = self.gluster_manager.path
        self._manage_access(path[1:], access['access_type'],
                            access['access_to'], cbk)


class GlusterNFSVolHelper(GlusterNFSHelper):
    """Manage shares with Gluster-NFS server, volume mapped variant."""

    def __init__(self, execute, config_object, **kwargs):
        self.gluster_manager = kwargs.pop('gluster_manager')
        super(GlusterNFSHelper, self).__init__(execute, config_object,
                                               **kwargs)

    def _get_vol_exports(self):
        export_vol = self.gluster_manager.get_gluster_vol_option(
            NFS_RPC_AUTH_ALLOW)
        return export_vol.split(',') if export_vol else []

    def _manage_access(self, access_type, access_to, cbk):
        """Manage share access with cbk.

        Adjust the exports of the Gluster-NFS server using cbk.

        :param access_type: type of access allowed in Manila
        :type access_type: string
        :param access_to: ip of the guest whose share access is managed
        :type access_to: string
        :param cbk: callback to adjust the exports of NFS server

        Following is the description of cbk(explist, host).

        :param explist: list of hosts that have access to the share
        :type explist: list
        :param host: ip address derived from the access object
        :type host: string
        :returns: bool (cbk leaves ddict intact) or None (cbk modifies ddict)
        """

        if access_type != 'ip':
            raise exception.InvalidShareAccess('only ip access type allowed')
        export_vol_list = self._get_vol_exports()
        if cbk(export_vol_list, access_to):
            return

        if export_vol_list:
            argseq = (('volume', 'set', self.gluster_manager.volume,
                       NFS_RPC_AUTH_ALLOW, ','.join(export_vol_list)),
                      ('volume', 'reset', self.gluster_manager.volume,
                       NFS_RPC_AUTH_REJECT))
        else:
            argseq = (('volume', 'reset', self.gluster_manager.volume,
                       NFS_RPC_AUTH_ALLOW),
                      ('volume', 'set', self.gluster_manager.volume,
                       NFS_RPC_AUTH_REJECT, '*'))
        for args in argseq:
            self.gluster_manager.gluster_call(
                *args,
                log=_LE("Tuning GlusterFS volume options"))

    def allow_access(self, base, share, access):
        """Allow access to a share."""
        def cbk(explist, host):
            if host in explist:
                return True
            explist.append(host)
        self._manage_access(access['access_type'], access['access_to'], cbk)

    def deny_access(self, base, share, access):
        """Deny access to a share."""
        def cbk(explist, host):
            if host not in explist:
                return True
            explist.remove(host)
        self._manage_access(access['access_type'], access['access_to'], cbk)


class GaneshaNFSHelper(ganesha.GaneshaNASHelper):

    shared_data = {}

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
        self.ganesha_host = config_object.glusterfs_ganesha_server_ip
        if not self.ganesha_host:
            self.ganesha_host = socket.gethostname()
        kwargs['tag'] = '-'.join(('GLUSTER', 'Ganesha', self.ganesha_host))
        super(GaneshaNFSHelper, self).__init__(execute, config_object,
                                               **kwargs)

    def get_export(self, share):
        return ':/'.join((self.ganesha_host, share['name']))

    def init_helper(self):
        @utils.synchronized(self.tag)
        def _init_helper():
            if self.tag in self.shared_data:
                return True
            super(GaneshaNFSHelper, self).init_helper()
            self.shared_data[self.tag] = {
                'ganesha': self.ganesha,
                'export_template': self.export_template}
            return False

        if _init_helper():
            tagdata = self.shared_data[self.tag]
            self.ganesha = tagdata['ganesha']
            self.export_template = tagdata['export_template']

    def _default_config_hook(self):
        """Callback to provide default export block."""
        dconf = super(GaneshaNFSHelper, self)._default_config_hook()
        conf_dir = ganesha_utils.path_from(__file__, "conf")
        ganesha_utils.patch(dconf, self._load_conf_dir(conf_dir))
        return dconf

    def _fsal_hook(self, base, share, access):
        """Callback to create FSAL subblock."""
        return {"Hostname": self.gluster_manager.host,
                "Volume": self.gluster_manager.volume,
                "Volpath": self.gluster_manager.path}
