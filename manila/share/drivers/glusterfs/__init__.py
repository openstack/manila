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

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers import ganesha
from manila.share.drivers.ganesha import utils as ganesha_utils
from manila.share.drivers.glusterfs import layout
from manila import utils


GlusterfsManilaShare_opts = [
    cfg.StrOpt('glusterfs_nfs_server_type',
               default='Gluster',
               help='Type of NFS server that mediate access to the Gluster '
                    'volumes (Gluster or Ganesha).'),
    cfg.HostAddressOpt('glusterfs_ganesha_server_ip',
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
            # default behavior of NFS_EXPORT_VOL is as if it were 'on'
            export_vol = gluster_manager.get_vol_option(
                NFS_EXPORT_VOL, boolean=True)
            if export_vol is False:
                raise exception.GlusterfsException(
                    _("Gluster-NFS with volume layout should be used "
                      "with `nfs.export-volumes = on`"))
            setting = [NFS_RPC_AUTH_REJECT, '*']
        else:
            # gluster-nfs export of the whole volume must be prohibited
            # to not to defeat access control
            setting = [NFS_EXPORT_VOL, False]
        gluster_manager.set_vol_option(*setting)
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

    @property
    def supported_access_types(self):
        return self.nfs_helper.supported_access_types

    @property
    def supported_access_levels(self):
        return self.nfs_helper.supported_access_levels

    def _update_access_via_manager(self, gluster_mgr, context, share,
                                   add_rules, delete_rules, recovery=False,
                                   share_server=None):
        """Update access to the share."""
        self._get_helper(gluster_mgr).update_access(
            '/', share, add_rules, delete_rules, recovery=recovery)


class GlusterNFSHelper(ganesha.NASHelperBase):
    """Manage shares with Gluster-NFS server."""

    supported_access_types = ('ip', )
    supported_access_levels = (constants.ACCESS_LEVEL_RW, )

    def __init__(self, execute, config_object, **kwargs):
        self.gluster_manager = kwargs.pop('gluster_manager')
        super(GlusterNFSHelper, self).__init__(execute, config_object,
                                               **kwargs)

    def get_export(self, share):
        return self.gluster_manager.export

    def _get_export_dir_dict(self):
        """Get the export entries of shares in the GlusterFS volume."""
        export_dir = self.gluster_manager.get_vol_option(
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

    def update_access(self, base_path, share, add_rules, delete_rules,
                      recovery=False):
        """Update access rules."""

        existing_rules_set = set()

        # The name of the directory, which is exported as the share.
        export_dir = self.gluster_manager.path[1:]

        # Fetch the existing export entries as an export dictionary with the
        # exported directories and the list of client IP addresses authorized
        # to access them as key-value pairs.
        export_dir_dict = self._get_export_dir_dict()

        if export_dir in export_dir_dict:
            existing_rules_set = set(export_dir_dict[export_dir])
        add_rules_set = {rule['access_to'] for rule in add_rules}
        delete_rules_set = {rule['access_to'] for rule in delete_rules}
        new_rules_set = (
            (existing_rules_set | add_rules_set) - delete_rules_set)

        if new_rules_set:
            export_dir_dict[export_dir] = new_rules_set
        elif export_dir not in export_dir_dict:
            return
        else:
            export_dir_dict.pop(export_dir)

        # Reconstruct the export entries.
        if export_dir_dict:
            export_dirs_new = (",".join("/%s(%s)" % (d, "|".join(sorted(v)))
                               for d, v in sorted(export_dir_dict.items())))
        else:
            export_dirs_new = None
        self.gluster_manager.set_vol_option(NFS_EXPORT_DIR, export_dirs_new)


class GlusterNFSVolHelper(GlusterNFSHelper):
    """Manage shares with Gluster-NFS server, volume mapped variant."""

    def _get_vol_exports(self):
        export_vol = self.gluster_manager.get_vol_option(
            NFS_RPC_AUTH_ALLOW)
        return export_vol.split(',') if export_vol else []

    def update_access(self, base_path, share, add_rules, delete_rules,
                      recovery=False):
        """Update access rules."""

        existing_rules_set = set(self._get_vol_exports())
        add_rules_set = {rule['access_to'] for rule in add_rules}
        delete_rules_set = {rule['access_to'] for rule in delete_rules}
        new_rules_set = (
            (existing_rules_set | add_rules_set) - delete_rules_set)

        if new_rules_set:
            argseq = ((NFS_RPC_AUTH_ALLOW, ','.join(sorted(new_rules_set))),
                      (NFS_RPC_AUTH_REJECT, None))
        else:
            argseq = ((NFS_RPC_AUTH_ALLOW, None),
                      (NFS_RPC_AUTH_REJECT, '*'))

        for args in argseq:
            self.gluster_manager.set_vol_option(*args)


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
        return ':/'.join((self.ganesha_host, share['name'] + "--<access-id>"))

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
