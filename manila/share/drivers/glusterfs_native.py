# Copyright (c) 2014 Red Hat, Inc.
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

""" GlusterFS native protocol (glusterfs) driver for shares.

Manila share is a GlusterFS volume. Unlike the generic driver, this
does not use service VM approach. Instances directly talk with the
GlusterFS backend storage pool. Instance use the 'glusterfs' protocol
to mount the GlusterFS share. Access to the share is allowed via
SSL Certificates. Only the instance which has the SSL trust established
with the GlusterFS backend can mount and hence use the share.

Supports working with multiple glusterfs volumes.
"""

import errno
import pipes
import shutil
import tempfile

from oslo.config import cfg
import six

from manila import exception
from manila.openstack.common import log as logging
from manila.share import driver
from manila.share.drivers import glusterfs
from manila import utils


LOG = logging.getLogger(__name__)

glusterfs_native_manila_share_opts = [
    cfg.ListOpt('glusterfs_targets',
                default=[],
                help='List of GlusterFS volumes that can be used to create '
                     'shares. Each GlusterFS volume should be of the form '
                     '[remoteuser@]<volserver>:/<volid>'),
]

CONF = cfg.CONF
CONF.register_opts(glusterfs_native_manila_share_opts)

ACCESS_TYPE_CERT = 'cert'
AUTH_SSL_ALLOW = 'auth.ssl-allow'
CLIENT_SSL = 'client.ssl'
NFS_EXPORT_VOL = 'nfs.export-volumes'
SERVER_SSL = 'server.ssl'


class GlusterfsNativeShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """GlusterFS native protocol (glusterfs) share driver.

    Executes commands relating to Shares.
    Supports working with multiple glusterfs volumes.

    API version history:

        1.0 - Initial version.
        1.1 - Support for working with multiple gluster volumes.
    """

    def __init__(self, db, *args, **kwargs):
        super(GlusterfsNativeShareDriver, self).__init__(*args, **kwargs)
        self.db = db
        self._helpers = None
        self.gluster_unused_vols_dict = {}
        self.gluster_used_vols_dict = {}
        self.configuration.append_config_values(
            glusterfs_native_manila_share_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'GlusterFS-Native'

    def do_setup(self, context):
        """Setup the GlusterFS volumes."""
        super(GlusterfsNativeShareDriver, self).do_setup(context)

        # We don't use a service mount as its not necessary for us.
        # Do some sanity checks.
        if len(self.configuration.glusterfs_targets) == 0:
            # No volumes specified in the config file. Raise exception.
            msg = (_("glusterfs_targets list seems to be empty! "
                     "Add one or more gluster volumes to work "
                     "with in the glusterfs_targets configuration "
                     "parameter."))
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        LOG.info(_("Number of gluster volumes read from config: "
                   "%(numvols)s"),
                 {'numvols': len(self.configuration.glusterfs_targets)})

        try:
            self._execute('mount.glusterfs', check_exit_code=False)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                msg = (_("mount.glusterfs is not installed."))
                LOG.error(msg)
                raise exception.GlusterfsException(msg)
            else:
                msg = (_("Error running mount.glusterfs."))
                LOG.error(msg)
                raise

        # Update gluster_unused_vols_dict, gluster_used_vols_dict by walking
        # through the DB.
        self._update_gluster_vols_dict(context)
        if len(self.gluster_unused_vols_dict) == 0:
            # No volumes available for use as share. Warn user.
            msg = (_("No unused gluster volumes available for use as share! "
                     "Create share won't be supported unless existing shares "
                     "are deleted or add one or more gluster volumes to work "
                     "with in the glusterfs_targets configuration parameter."))
            LOG.warn(msg)
        else:
            LOG.info(_("Number of gluster volumes in use: %(inuse-numvols)s. "
                       "Number of gluster volumes available for use as share: "
                       "%(unused-numvols)s"),
                     {'inuse-numvols': len(self.gluster_used_vols_dict),
                     'unused-numvols': len(self.gluster_unused_vols_dict)})

        self._setup_gluster_vols()

    @utils.synchronized("glusterfs_native", external=False)
    def _update_gluster_vols_dict(self, context):
        """Update dict of gluster vols that are used/unused."""

        shares = self.db.share_get_all(context)

        # Store the gluster volumes in dict thats helpful to track
        # (push and pop) in future. {gluster_export: gluster_addr, ...}
        # gluster_export is of form hostname:/volname which is unique
        # enough to be used as a key.
        self.gluster_unused_vols_dict = {}
        self.gluster_used_vols_dict = {}

        for gv in self.configuration.glusterfs_targets:
            gaddr = glusterfs.GlusterAddress(gv)
            exp_locn_gv = gaddr.export

            # Assume its unused to begin with.
            self.gluster_unused_vols_dict.update({exp_locn_gv: gaddr})

            for s in shares:
                exp_locn_share = s.get('export_location', None)
                if exp_locn_share == exp_locn_gv:
                    # gluster volume is in use, move it to used list.
                    self.gluster_used_vols_dict.update({exp_locn_gv: gaddr})
                    self.gluster_unused_vols_dict.pop(exp_locn_gv)
                    break

    @utils.synchronized("glusterfs_native", external=False)
    def _setup_gluster_vols(self):
        # Enable gluster volumes for SSL access only.

        for gluster_addr in six.itervalues(self.gluster_unused_vols_dict):

            gargs, gkw = gluster_addr.make_gluster_args(
                'volume', 'set', gluster_addr.volume,
                NFS_EXPORT_VOL, 'off')
            try:
                self._execute(*gargs, **gkw)
            except exception.ProcessExecutionError as exc:
                msg = (_("Error in gluster volume set during volume setup. "
                         "Volume: %(volname)s, Option: %(option)s, "
                         "Error: %(error)s"),
                       {'volname': gluster_addr.volume,
                        'option': NFS_EXPORT_VOL, 'error': exc.stderr})
                LOG.error(msg)
                raise exception.GlusterfsException(msg)

            gargs, gkw = gluster_addr.make_gluster_args(
                'volume', 'set', gluster_addr.volume,
                CLIENT_SSL, 'on')
            try:
                self._execute(*gargs, **gkw)
            except exception.ProcessExecutionError as exc:
                msg = (_("Error in gluster volume set during volume setup. "
                         "Volume: %(volname)s, Option: %(option)s, "
                         "Error: %(error)s"),
                       {'volname': gluster_addr.volume,
                        'option': CLIENT_SSL, 'error': exc.stderr})
                LOG.error(msg)
                raise exception.GlusterfsException(msg)

            gargs, gkw = gluster_addr.make_gluster_args(
                'volume', 'set', gluster_addr.volume,
                SERVER_SSL, 'on')
            try:
                self._execute(*gargs, **gkw)
            except exception.ProcessExecutionError as exc:
                msg = (_("Error in gluster volume set during volume setup. "
                         "Volume: %(volname)s, Option: %(option)s, "
                         "Error: %(error)s"),
                       {'volname': gluster_addr.volume,
                        'option': SERVER_SSL, 'error': exc.stderr})
                LOG.error(msg)
                raise exception.GlusterfsException(msg)

            # TODO(deepakcs) Remove this once ssl options can be
            # set dynamically.
            self._restart_gluster_vol(gluster_addr)

    def _restart_gluster_vol(self, gluster_addr):
        gargs, gkw = gluster_addr.make_gluster_args(
            'volume', 'stop', gluster_addr.volume, '--mode=script')
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error stopping gluster volume. "
                     "Volume: %(volname)s, Error: %(error)s"),
                   {'volname': gluster_addr.volume, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        gargs, gkw = gluster_addr.make_gluster_args(
            'volume', 'start', gluster_addr.volume)
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error starting gluster volume. "
                     "Volume: %(volname)s, Error: %(error)s"),
                   {'volname': gluster_addr.volume, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

    @utils.synchronized("glusterfs_native", external=False)
    def _pop_gluster_vol(self):
        try:
            exp_locn, gaddr = self.gluster_unused_vols_dict.popitem()
        except KeyError:
            msg = (_("Couldn't find a free gluster volume to use."))
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        self.gluster_used_vols_dict.update({exp_locn: gaddr})
        return exp_locn

    @utils.synchronized("glusterfs_native", external=False)
    def _push_gluster_vol(self, exp_locn):
        try:
            gaddr = self.gluster_used_vols_dict.pop(exp_locn)
        except KeyError:
            msg = (_("Couldn't find the share in used list."))
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        self.gluster_unused_vols_dict.update({exp_locn: gaddr})

    def _do_mount(self, gluster_export, mntdir):

        cmd = ['mount', '-t', 'glusterfs', gluster_export, mntdir]
        try:
            self._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError as exc:
            msg = (_("Unable to mount gluster volume. "
                     "gluster_export: %(export)s, Error: %(error)s"),
                   {'export': gluster_export, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

    def _do_umount(self, mntdir):

        cmd = ['umount', mntdir]
        try:
            self._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError as exc:
            msg = (_("Unable to unmount gluster volume. "
                     "mount_dir: %(mntdir)s, Error: %(error)s"),
                   {'mntdir': mntdir, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

    def _wipe_gluster_vol(self, gluster_addr):

        # Reset the SSL options.
        gargs, gkw = gluster_addr.make_gluster_args(
            'volume', 'set', gluster_addr.volume,
            CLIENT_SSL, 'off')
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during _wipe_gluster_vol. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "Error: %(error)s"),
                   {'volname': gluster_addr.volume,
                    'option': CLIENT_SSL, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        gargs, gkw = gluster_addr.make_gluster_args(
            'volume', 'set', gluster_addr.volume,
            SERVER_SSL, 'off')
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during _wipe_gluster_vol. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "Error: %(error)s"),
                   {'volname': gluster_addr.volume,
                    'option': SERVER_SSL, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        self._restart_gluster_vol(gluster_addr)

        # Create a temporary mount.
        gluster_export = gluster_addr.export
        tmpdir = tempfile.mkdtemp()
        try:
            self._do_mount(gluster_export, tmpdir)
        except exception.GlusterfsException:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise

        # Delete only the contents, not the directory.
        cmd = ['find', pipes.quote(tmpdir), '-mindepth', '1', '-delete']
        try:
            self._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error trying to wipe gluster volume. "
                     "gluster_export: %(export)s, Error: %(error)s"),
                   {'export': gluster_export, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)
        finally:
            # Unmount.
            self._do_umount(tmpdir)
            shutil.rmtree(tmpdir, ignore_errors=True)

        # Set the SSL options.
        gargs, gkw = gluster_addr.make_gluster_args(
            'volume', 'set', gluster_addr.volume,
            CLIENT_SSL, 'on')
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during _wipe_gluster_vol. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "Error: %(error)s"),
                   {'volname': gluster_addr.volume,
                    'option': CLIENT_SSL, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        gargs, gkw = gluster_addr.make_gluster_args(
            'volume', 'set', gluster_addr.volume,
            SERVER_SSL, 'on')
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during _wipe_gluster_vol. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "Error: %(error)s"),
                   {'volname': gluster_addr.volume,
                    'option': SERVER_SSL, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        self._restart_gluster_vol(gluster_addr)

    def create_share(self, context, share, share_server=None):
        """Create a share using GlusterFS volume.

        1 Manila share = 1 GlusterFS volume. Pick an unused
        GlusterFS volume for use as a share.
        """
        try:
            export_location = self._pop_gluster_vol()
        except exception.GlusterfsException:
            msg = (_("Error creating share %(share_id)s"),
                   {'share_id': share['id']})
            LOG.error(msg)
            raise

        # TODO(deepakcs): Enable quota and set it to the share size.

        # For native protocol, the export_location should be of the form:
        # server:/volname
        LOG.info(_("export_location sent back from create_share: %s"),
                  (export_location,))
        return export_location

    def delete_share(self, context, share, share_server=None):
        """Delete a share on the GlusterFS volume.

        1 Manila share = 1 GlusterFS volume. Put the gluster
        volume back in the available list.
        """
        exp_locn = share.get('export_location', None)
        try:
            # Get the gluster address associated with the export.
            gaddr = self.gluster_used_vols_dict[exp_locn]
        except KeyError:
            msg = (_("Invalid request. Ignoring delete_share request for "
                     "share %(share_id)s"), {'share_id': share['id']},)
            LOG.warn(msg)
            return

        try:
            self._wipe_gluster_vol(gaddr)
            self._push_gluster_vol(exp_locn)
        except exception.GlusterfsException:
            msg = (_("Error during delete_share request for "
                     "share %(share_id)s"), {'share_id': share['id']},)
            LOG.error(msg)
            raise

        # TODO(deepakcs): Disable quota.

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share using certs.

        Add the SSL CN (Common Name) that's allowed to access the server.
        """

        if access['access_type'] != ACCESS_TYPE_CERT:
            raise exception.InvalidShareAccess(_("Only 'cert' access type "
                                                 "allowed"))
        exp_locn = share.get('export_location', None)
        gluster_addr = self.gluster_used_vols_dict.get(exp_locn)

        gargs, gkw = gluster_addr.make_gluster_args(
            'volume', 'set', gluster_addr.volume,
            AUTH_SSL_ALLOW, access['access_to'])
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during allow access. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "access_to: %(access_to)s, Error: %(error)s"),
                   {'volname': gluster_addr.volume,
                    'option': AUTH_SSL_ALLOW,
                    'access_to': access['access_to'], 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        # TODO(deepakcs) Remove this once ssl options can be
        # set dynamically.
        self._restart_gluster_vol(gluster_addr)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to a share that's using cert based auth.

        Remove the SSL CN (Common Name) that's allowed to access the server.
        """

        if access['access_type'] != ACCESS_TYPE_CERT:
            raise exception.InvalidShareAccess(_("Only 'cert' access type "
                                                 "allowed for access "
                                                 "removal."))
        exp_locn = share.get('export_location', None)
        gluster_addr = self.gluster_used_vols_dict.get(exp_locn)

        gargs, gkw = gluster_addr.make_gluster_args(
            'volume', 'reset', gluster_addr.volume,
            AUTH_SSL_ALLOW)
        try:
            self._execute(*gargs, **gkw)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume reset during deny access. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "Error: %(error)s"),
                   {'volname': gluster_addr.volume,
                    'option': AUTH_SSL_ALLOW, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        # TODO(deepakcs) Remove this once ssl options can be
        # set dynamically.
        self._restart_gluster_vol(gluster_addr)

    def get_share_stats(self, refresh=False):
        """Get share stats.

        If 'refresh' is True, update the stats first.
        """
        if refresh:
            self._update_share_stats()

        return self._stats

    def _update_share_stats(self):
        """Send stats info for the GlusterFS volume."""

        LOG.debug("Updating share stats")

        data = {}

        data["share_backend_name"] = self.backend_name
        data["vendor_name"] = 'Red Hat'
        data["driver_version"] = '1.1'
        data["storage_protocol"] = 'glusterfs'

        data['reserved_percentage'] = (
            self.configuration.reserved_share_percentage)
        data['QoS_support'] = False

        # We don't use a service mount to get stats data.
        # Instead we use glusterfs quota feature and use that to limit
        # the share to its expected share['size'].

        # TODO(deepakcs): Change below once glusterfs supports volume
        # specific stats via the gluster cli.
        data['total_capacity_gb'] = 'infinite'
        data['free_capacity_gb'] = 'infinite'
        self._stats = data

    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported."""
        pass
