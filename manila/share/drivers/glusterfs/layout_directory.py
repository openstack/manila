# Copyright (c) 2015 Red Hat, Inc.
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

"""GlusterFS directory mapped share layout."""

import os

from oslo_config import cfg
from oslo_log import log
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.share.drivers.glusterfs import common
from manila.share.drivers.glusterfs import layout

LOG = log.getLogger(__name__)

glusterfs_directory_mapped_opts = [
    cfg.StrOpt('glusterfs_target',
               help='Specifies the GlusterFS volume to be mounted on the '
                    'Manila host. It is of the form '
                    '[remoteuser@]<volserver>:<volid>.'),
    cfg.StrOpt('glusterfs_mount_point_base',
               default='$state_path/mnt',
               help='Base directory containing mount points for Gluster '
                    'volumes.'),
]

CONF = cfg.CONF
CONF.register_opts(glusterfs_directory_mapped_opts)


class GlusterfsDirectoryMappedLayout(layout.GlusterfsShareLayoutBase):

    def __init__(self, driver, *args, **kwargs):
        super(GlusterfsDirectoryMappedLayout, self).__init__(
            driver, *args, **kwargs)
        self.configuration.append_config_values(
            common.glusterfs_common_opts)
        self.configuration.append_config_values(
            glusterfs_directory_mapped_opts)

    def _glustermanager(self, gluster_address):
        """Create GlusterManager object for gluster_address."""

        return common.GlusterManager(
            gluster_address, self.driver._execute,
            self.configuration.glusterfs_path_to_private_key,
            self.configuration.glusterfs_server_password,
            requires={'volume': True})

    def do_setup(self, context):
        """Prepares the backend and appropriate NAS helpers."""
        if not self.configuration.glusterfs_target:
            raise exception.GlusterfsException(
                _('glusterfs_target configuration that specifies the GlusterFS'
                  ' volume to be mounted on the Manila host is not set.'))
        self.gluster_manager = self._glustermanager(
            self.configuration.glusterfs_target)
        self.gluster_manager.check_gluster_version(
            self.driver.GLUSTERFS_VERSION_MIN)
        self._check_mount_glusterfs()

        # enable quota options of a GlusteFS volume to allow
        # creation of shares of specific size
        args = ('volume', 'quota', self.gluster_manager.volume, 'enable')
        try:
            self.gluster_manager.gluster_call(*args)
        except exception.GlusterfsException:
            if (self.gluster_manager.
                    get_vol_option('features.quota')) != 'on':
                LOG.error(_LE("Error in tuning GlusterFS volume to enable "
                              "creation of shares of specific size."))
                raise

        self._ensure_gluster_vol_mounted()

    def _share_manager(self, share):
        comp_path = self.gluster_manager.components.copy()
        comp_path.update({'path': '/' + share['name']})
        return self._glustermanager(comp_path)

    def _get_mount_point_for_gluster_vol(self):
        """Return mount point for the GlusterFS volume."""
        return os.path.join(self.configuration.glusterfs_mount_point_base,
                            self.gluster_manager.volume)

    def _ensure_gluster_vol_mounted(self):
        """Ensure GlusterFS volume is native-mounted on Manila host."""
        mount_path = self._get_mount_point_for_gluster_vol()
        try:
            common._mount_gluster_vol(self.driver._execute,
                                      self.gluster_manager.export, mount_path,
                                      ensure=True)
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

        return {'total_capacity_gb': (smpv.f_blocks * smpv.f_frsize) >> 30,
                'free_capacity_gb': (smpv.f_bavail * smpv.f_frsize) >> 30}

    def create_share(self, ctx, share, share_server=None):
        """Create a sub-directory/share in the GlusterFS volume."""
        # probe into getting a NAS protocol helper for the share in order
        # to facilitate early detection of unsupported protocol type
        sizestr = six.text_type(share['size']) + 'GB'
        share_dir = '/' + share['name']
        local_share_path = self._get_local_share_path(share)
        cmd = ['mkdir', local_share_path]
        # set hard limit quota on the sub-directory/share
        args = ('volume', 'quota', self.gluster_manager.volume,
                'limit-usage', share_dir, sizestr)
        try:
            self.driver._execute(*cmd, run_as_root=True)
            self.gluster_manager.gluster_call(*args)
        except Exception as exc:
            if isinstance(exc, exception.ProcessExecutionError):
                exc = exception.GlusterfsException(exc)
            if isinstance(exc, exception.GlusterfsException):
                self._cleanup_create_share(local_share_path, share['name'])
                LOG.error(_LE('Unable to create share %s'), share['name'])
            raise exc

        comp_share = self.gluster_manager.components.copy()
        comp_share['path'] = '/' + share['name']
        export_location = self.driver._setup_via_manager(
            {'share': share,
             'manager': self._glustermanager(comp_share)})

        return export_location

    def _cleanup_create_share(self, share_path, share_name):
        """Cleanup share that errored out during its creation."""
        if os.path.exists(share_path):
            cmd = ['rm', '-rf', share_path]
            try:
                self.driver._execute(*cmd, run_as_root=True)
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
            self.driver._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError:
            LOG.error(_LE('Unable to delete share %s'), share['name'])
            raise

    def ensure_share(self, context, share, share_server=None):
        pass

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        raise NotImplementedError

    def create_snapshot(self, context, snapshot, share_server=None):
        raise NotImplementedError

    def delete_snapshot(self, context, snapshot, share_server=None):
        raise NotImplementedError

    def manage_existing(self, share, driver_options):
        raise NotImplementedError

    def unmanage(self, share):
        raise NotImplementedError

    def extend_share(self, share, new_size, share_server=None):
        raise NotImplementedError

    def shrink_share(self, share, new_size, share_server=None):
        raise NotImplementedError
