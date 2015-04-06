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
import random
import re
import shutil
import string
import tempfile
import xml.etree.cElementTree as etree

from oslo_config import cfg
from oslo_log import log
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LI
from manila.i18n import _LW
from manila.share import driver
from manila.share.drivers import glusterfs
from manila import utils

LOG = log.getLogger(__name__)

glusterfs_native_manila_share_opts = [
    cfg.ListOpt('glusterfs_servers',
                default=[],
                deprecated_name='glusterfs_targets',
                help='List of GlusterFS servers that can be used to create '
                     'shares. Each GlusterFS server should be of the form '
                     '[remoteuser@]<volserver>, and they are assumed to '
                     'belong to distinct Gluster clusters.'),
    cfg.StrOpt('glusterfs_native_server_password',
               default=None,
               secret=True,
               help='Remote GlusterFS server node\'s login password. '
                    'This is not required if '
                    '\'glusterfs_native_path_to_private_key\' is '
                    'configured.'),
    cfg.StrOpt('glusterfs_native_path_to_private_key',
               default=None,
               help='Path of Manila host\'s private SSH key file.'),
    cfg.StrOpt('glusterfs_volume_pattern',
               default=None,
               help='Regular expression template used to filter '
                    'GlusterFS volumes for share creation. '
                    'The regex template can optionally (ie. with support '
                    'of the GlusterFS backend) contain the #{size} '
                    'parameter which matches an integer (sequence of '
                    'digits) in which case the value shall be intepreted as '
                    'size of the volume in GB. Examples: '
                    '"manila-share-volume-\d+$", '
                    '"manila-share-volume-#{size}G-\d+$"; '
                    'with matching volume names, respectively: '
                    '"manila-share-volume-12", "manila-share-volume-3G-13". '
                    'In latter example, the number that matches "#{size}", '
                    'that is, 3, is an indication that the size of volume '
                    'is 3G.'),
]

CONF = cfg.CONF
CONF.register_opts(glusterfs_native_manila_share_opts)

ACCESS_TYPE_CERT = 'cert'
AUTH_SSL_ALLOW = 'auth.ssl-allow'
CLIENT_SSL = 'client.ssl'
NFS_EXPORT_VOL = 'nfs.export-volumes'
SERVER_SSL = 'server.ssl'
# The dict specifying named parameters
# that can be used with glusterfs_volume_pattern
# in #{<param>} format.
# For each of them we give regex pattern it matches
# and a transformer function ('trans') for the matched
# string value.
# Currently we handle only #{size}.
PATTERN_DICT = {'size': {'pattern': '(?P<size>\d+)', 'trans': int}}


class GlusterfsNativeShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """GlusterFS native protocol (glusterfs) share driver.

    Executes commands relating to Shares.
    Supports working with multiple glusterfs volumes.

    API version history:

        1.0 - Initial version.
        1.1 - Support for working with multiple gluster volumes.
    """

    def __init__(self, db, *args, **kwargs):
        super(GlusterfsNativeShareDriver, self).__init__(
            False, *args, **kwargs)
        self.db = db
        self._helpers = None
        self.gluster_used_vols_dict = {}
        self.configuration.append_config_values(
            glusterfs_native_manila_share_opts)
        self.gluster_nosnap_vols_dict = {}
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'GlusterFS-Native'
        self.volume_pattern = self._compile_volume_pattern()
        self.volume_pattern_keys = self.volume_pattern.groupindex.keys()
        glusterfs_servers = {}
        for srvaddr in self.configuration.glusterfs_servers:
            glusterfs_servers[srvaddr] = self._glustermanager(
                srvaddr, has_volume=False)
        self.glusterfs_servers = glusterfs_servers

    def _compile_volume_pattern(self):
        """Compile a RegexObject from the config specified regex template.

        (cfg.glusterfs_volume_pattern)
        """

        subdict = {}
        for key, val in six.iteritems(PATTERN_DICT):
            subdict[key] = val['pattern']

        # Using templates with placeholder syntax #{<var>}
        class CustomTemplate(string.Template):
            delimiter = '#'

        volume_pattern = CustomTemplate(
            self.configuration.glusterfs_volume_pattern).substitute(
            subdict)
        return re.compile(volume_pattern)

    def do_setup(self, context):
        """Setup the GlusterFS volumes."""
        super(GlusterfsNativeShareDriver, self).do_setup(context)

        # We don't use a service mount as its not necessary for us.
        # Do some sanity checks.
        gluster_volumes_initial = set(self._fetch_gluster_volumes())
        if not gluster_volumes_initial:
            # No suitable volumes are found on the Gluster end.
            # Raise exception.
            msg = (_("Gluster backend does not provide any volume "
                     "matching pattern %s"
                     ) % self.configuration.glusterfs_volume_pattern)
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        LOG.info(_LI("Found %d Gluster volumes allocated for Manila."
                     ), len(gluster_volumes_initial))

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

        # Update gluster_used_vols_dict by walking through the DB.
        self._update_gluster_vols_dict(context)
        unused_vols = gluster_volumes_initial - set(
            self.gluster_used_vols_dict)
        if not unused_vols:
            # No volumes available for use as share. Warn user.
            msg = (_("No unused gluster volumes available for use as share! "
                     "Create share won't be supported unless existing shares "
                     "are deleted or some gluster volumes are created with "
                     "names matching 'glusterfs_volume_pattern'."))
            LOG.warn(msg)
        else:
            LOG.info(_LI("Number of gluster volumes in use:  "
                         "%(inuse-numvols)s. Number of gluster volumes "
                         "available for use as share: %(unused-numvols)s"),
                     {'inuse-numvols': len(self.gluster_used_vols_dict),
                     'unused-numvols': len(unused_vols)})

    def _glustermanager(self, gluster_address, has_volume=True):
        """Create GlusterManager object for gluster_address."""

        return glusterfs.GlusterManager(
            gluster_address, self._execute,
            self.configuration.glusterfs_native_path_to_private_key,
            self.configuration.glusterfs_native_server_password,
            has_volume=has_volume)

    def _fetch_gluster_volumes(self):
        """Do a 'gluster volume list | grep <volume pattern>'.

        Aggregate the results from all servers.
        Extract the named groups from the matching volume names
        using the specs given in PATTERN_DICT.
        Return a dict with keys of the form <server>:/<volname>
        and values being dicts that map names of named groups
        to their extracted value.
        """

        volumes_dict = {}
        for gsrv, gluster_mgr in six.iteritems(self.glusterfs_servers):
            try:
                out, err = gluster_mgr.gluster_call('volume', 'list')
            except exception.ProcessExecutionError as exc:
                msgdict = {'err': exc.stderr, 'hostinfo': ''}
                if gluster_mgr.remote_user:
                    msgdict['hostinfo'] = ' on host %s' % gluster_mgr.host
                LOG.error(_LE("Error retrieving volume list%(hostinfo)s: "
                              "%(err)s") % msgdict)
                raise exception.GlusterfsException(
                    _('gluster volume list failed'))
            for volname in out.split("\n"):
                patmatch = self.volume_pattern.match(volname)
                if not patmatch:
                    continue
                pattern_dict = {}
                for key in self.volume_pattern_keys:
                    keymatch = patmatch.group(key)
                    if keymatch is None:
                        pattern_dict[key] = None
                    else:
                        trans = PATTERN_DICT[key].get('trans', lambda x: x)
                        pattern_dict[key] = trans(keymatch)
                volumes_dict[gsrv + ':/' + volname] = pattern_dict
        return volumes_dict

    @utils.synchronized("glusterfs_native", external=False)
    def _update_gluster_vols_dict(self, context):
        """Update dict of gluster vols that are used/unused."""

        shares = self.db.share_get_all(context)

        for s in shares:
            if (s['status'].lower() == 'available'):
                vol = s['export_location']
                gluster_mgr = self._glustermanager(vol)
                self.gluster_used_vols_dict[vol] = gluster_mgr

    def _setup_gluster_vol(self, vol):
        # Enable gluster volumes for SSL access only.

        gluster_mgr = self._glustermanager(vol)

        ssl_allow_opt = gluster_mgr.get_gluster_vol_option(AUTH_SSL_ALLOW)
        if not ssl_allow_opt:
            # Not having AUTH_SSL_ALLOW set is a problematic edge case.
            # - In GlusterFS 3.6, it implies that access is allowed to
            #   noone, including intra-service access, which causes
            #   problems internally in GlusterFS
            # - In GlusterFS 3.7, it implies that access control is
            #   disabled, which defeats the purpose of this driver --
            # so to avoid these possiblitiies, we throw an error in this case.
            msg = (_("Option %(option)s is not defined on gluster volume. "
                     "Volume: %(volname)s") %
                   {'volname': gluster_mgr.volume,
                    'option': AUTH_SSL_ALLOW})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        for option, value in six.iteritems(
            {NFS_EXPORT_VOL: 'off', CLIENT_SSL: 'on', SERVER_SSL: 'on'}
        ):
            try:
                gluster_mgr.gluster_call(
                    'volume', 'set', gluster_mgr.volume,
                    option, value)
            except exception.ProcessExecutionError as exc:
                msg = (_("Error in gluster volume set during volume setup. "
                         "volume: %(volname)s, option: %(option)s, "
                         "value: %(value)s, error: %(error)s") %
                       {'volname': gluster_mgr.volume,
                        'option': option, 'value': value, 'error': exc.stderr})
                LOG.error(msg)
                raise exception.GlusterfsException(msg)

        # TODO(deepakcs) Remove this once ssl options can be
        # set dynamically.
        self._restart_gluster_vol(gluster_mgr)
        return gluster_mgr

    @staticmethod
    def _restart_gluster_vol(gluster_mgr):
        try:
            # TODO(csaba): eradicate '--mode=script' as it's unnecessary.
            gluster_mgr.gluster_call(
                'volume', 'stop', gluster_mgr.volume, '--mode=script')
        except exception.ProcessExecutionError as exc:
            msg = (_("Error stopping gluster volume. "
                     "Volume: %(volname)s, Error: %(error)s"),
                   {'volname': gluster_mgr.volume, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        try:
            gluster_mgr.gluster_call(
                'volume', 'start', gluster_mgr.volume)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error starting gluster volume. "
                     "Volume: %(volname)s, Error: %(error)s"),
                   {'volname': gluster_mgr.volume, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

    @utils.synchronized("glusterfs_native", external=False)
    def _pop_gluster_vol(self, size=None):
        """Pick an unbound volume.

        Do a _fetch_gluster_volumes() first to get the complete
        list of usable volumes.
        Keep only the unbound ones (ones that are not yet used to
        back a share).
        If size is given, try to pick one which has a size specification
        (according to the 'size' named group of the volume pattern),
        and its size is greater-than-or-equal to the given size.
        Return the volume chosen (in <host>:/<volname> format).
        """

        voldict = self._fetch_gluster_volumes()
        # calculate the set of unused volumes
        set1, set2 = (
            set(d) for d in (voldict, self.gluster_used_vols_dict)
        )
        unused_vols = set1 - set2
        # volmap is the data structure used to categorize and sort
        # the unused volumes. It's a nested dictionary of structure
        # {<size>: <hostmap>}
        # where <size> is either an integer or None,
        # <hostmap> is a dictionary of structure {<host>: <vols>}
        # where <host> is a host name (IP address), <vols> is a list
        # of volumes (gluster addresses).
        volmap = {None: {}}
        # if both caller has specified size and 'size' occurs as
        # a parameter in the volume pattern...
        if size and 'size' in self.volume_pattern_keys:
            # then this function is used to extract the
            # size value for a given volume from the voldict...
            get_volsize = lambda vol: voldict[vol]['size']
        else:
            # else just use a stub.
            get_volsize = lambda vol: None
        for vol in unused_vols:
            # For each unused volume, we extract the <size>
            # and <host> values with which it can be inserted
            # into the volmap, and conditionally perform
            # the insertion (with the condition being: once
            # caller specified size and a size indication was
            # found in the volume name, we require that the
            # indicated size adheres to caller's spec).
            volsize = get_volsize(vol)
            if not volsize or volsize >= size:
                hostmap = volmap.get(volsize)
                if not hostmap:
                    hostmap = {}
                    volmap[volsize] = hostmap
                host = self._glustermanager(vol).host
                hostvols = hostmap.get(host)
                if not hostvols:
                    hostvols = []
                    hostmap[host] = hostvols
                hostvols.append(vol)
        if len(volmap) > 1:
            # volmap has keys apart from the default None,
            # ie. volumes with sensible and adherent size
            # indication have been found. Then pick the smallest
            # of the size values.
            chosen_size = sorted(n for n in volmap.keys() if n)[0]
        else:
            chosen_size = None
        chosen_hostmap = volmap[chosen_size]
        if not chosen_hostmap:
            msg = (_("Couldn't find a free gluster volume to use."))
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        # From the hosts we choose randomly to tend towards
        # even distribution of share backing volumes among
        # Gluster clusters.
        chosen_host = random.choice(list(chosen_hostmap.keys()))
        # Within a host's volumes, choose alphabetically first,
        # to make it predictable.
        vol = sorted(chosen_hostmap[chosen_host])[0]
        self.gluster_used_vols_dict[vol] = self._setup_gluster_vol(vol)
        return vol

    @utils.synchronized("glusterfs_native", external=False)
    def _push_gluster_vol(self, exp_locn):
        try:
            self.gluster_used_vols_dict.pop(exp_locn)
        except KeyError:
            msg = (_("Couldn't find the share in used list."))
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

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

    def _wipe_gluster_vol(self, gluster_mgr):

        # Reset the SSL options.
        try:
            gluster_mgr.gluster_call(
                'volume', 'set', gluster_mgr.volume,
                CLIENT_SSL, 'off')
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during _wipe_gluster_vol. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "Error: %(error)s"),
                   {'volname': gluster_mgr.volume,
                    'option': CLIENT_SSL, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        try:
            gluster_mgr.gluster_call(
                'volume', 'set', gluster_mgr.volume,
                SERVER_SSL, 'off')
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during _wipe_gluster_vol. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "Error: %(error)s"),
                   {'volname': gluster_mgr.volume,
                    'option': SERVER_SSL, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        self._restart_gluster_vol(gluster_mgr)

        # Create a temporary mount.
        gluster_export = gluster_mgr.export
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
        try:
            gluster_mgr.gluster_call(
                'volume', 'set', gluster_mgr.volume,
                CLIENT_SSL, 'on')
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during _wipe_gluster_vol. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "Error: %(error)s"),
                   {'volname': gluster_mgr.volume,
                    'option': CLIENT_SSL, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        try:
            gluster_mgr.gluster_call(
                'volume', 'set', gluster_mgr.volume,
                SERVER_SSL, 'on')
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during _wipe_gluster_vol. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "Error: %(error)s"),
                   {'volname': gluster_mgr.volume,
                    'option': SERVER_SSL, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        self._restart_gluster_vol(gluster_mgr)

    def get_network_allocations_number(self):
        return 0

    def create_share(self, context, share, share_server=None):
        """Create a share using GlusterFS volume.

        1 Manila share = 1 GlusterFS volume. Pick an unused
        GlusterFS volume for use as a share.
        """
        try:
            export_location = self._pop_gluster_vol(share['size'])
        except exception.GlusterfsException:
            msg = (_("Error creating share %(share_id)s"),
                   {'share_id': share['id']})
            LOG.error(msg)
            raise

        # TODO(deepakcs): Enable quota and set it to the share size.

        # For native protocol, the export_location should be of the form:
        # server:/volname
        LOG.info(_LI("export_location sent back from create_share: %s"),
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
            gmgr = self.gluster_used_vols_dict[exp_locn]
        except KeyError:
            msg = (_("Invalid request. Ignoring delete_share request for "
                     "share %(share_id)s"), {'share_id': share['id']},)
            LOG.warn(msg)
            return

        try:
            self._wipe_gluster_vol(gmgr)
            self._push_gluster_vol(exp_locn)
        except exception.GlusterfsException:
            msg = (_("Error during delete_share request for "
                     "share %(share_id)s"), {'share_id': share['id']},)
            LOG.error(msg)
            raise

        # TODO(deepakcs): Disable quota.

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""
        # FIXME: need to access db to retrieve share data
        vol = self.db.share_get(context,
                                snapshot['share_id'])['export_location']
        if vol in self.gluster_nosnap_vols_dict:
            opret, operrno = -1, 0
            operrstr = self.gluster_nosnap_vols_dict[vol]
        else:
            gluster_mgr = self.gluster_used_vols_dict[vol]
            args = ('--xml', 'snapshot', 'create', snapshot['id'],
                    gluster_mgr.volume)
            try:
                out, err = gluster_mgr.gluster_call(*args)
            except exception.ProcessExecutionError as exc:
                LOG.error(_LE("Error retrieving volume info: %s"), exc.stderr)
                raise exception.GlusterfsException("gluster %s failed" %
                                                   ' '.join(args))

            if not out:
                raise exception.GlusterfsException(
                    'gluster volume info %s: no data received' %
                    gluster_mgr.volume
                )

            outxml = etree.fromstring(out)
            opret = int(outxml.find('opRet').text)
            operrno = int(outxml.find('opErrno').text)
            operrstr = outxml.find('opErrstr').text

        if opret == -1 and operrno == 0:
            self.gluster_nosnap_vols_dict[vol] = operrstr
            msg = _("Share %(share_id)s does not support snapshots: "
                    "%(errstr)s.") % {'share_id': snapshot['share_id'],
                                      'errstr': operrstr}
            LOG.error(msg)
            raise exception.ShareSnapshotNotSupported(msg)
        elif operrno:
            raise exception.GlusterfsException(
                _("Creating snapshot for share %(share_id)s failed "
                  "with %(errno)d: %(errstr)s") % {
                      'share_id': snapshot['share_id'],
                      'errno': operrno,
                      'errstr': operrstr})

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""
        # FIXME: need to access db to retrieve share data
        vol = self.db.share_get(context,
                                snapshot['share_id'])['export_location']
        gluster_mgr = self.gluster_used_vols_dict[vol]
        args = ('--xml', 'snapshot', 'delete', snapshot['id'])
        try:
            out, err = gluster_mgr.gluster_call(*args)
        except exception.ProcessExecutionError as exc:
            LOG.error(_LE("Error retrieving volume info: %s"), exc.stderr)
            raise exception.GlusterfsException("gluster %s failed" %
                                               ' '.join(args))

        if not out:
            raise exception.GlusterfsException(
                'gluster volume info %s: no data received' %
                gluster_mgr.volume
            )

        outxml = etree.fromstring(out)
        opret = int(outxml.find('opRet').text)
        operrno = int(outxml.find('opErrno').text)
        operrstr = outxml.find('opErrstr').text

        if opret:
            raise exception.GlusterfsException(
                _("Deleting snapshot %(snap_id)s of share %(share_id)s failed "
                  "with %(errno)d: %(errstr)s") % {
                      'snap_id': snapshot['id'],
                      'share_id': snapshot['share_id'],
                      'errno': operrno,
                      'errstr': operrstr})

    @utils.synchronized("glusterfs_native_access", external=False)
    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share using certs.

        Add the SSL CN (Common Name) that's allowed to access the server.
        """

        if access['access_type'] != ACCESS_TYPE_CERT:
            raise exception.InvalidShareAccess(_("Only 'cert' access type "
                                                 "allowed"))
        exp_locn = share.get('export_location', None)
        gluster_mgr = self.gluster_used_vols_dict.get(exp_locn)

        ssl_allow_opt = gluster_mgr.get_gluster_vol_option(AUTH_SSL_ALLOW)
        # wrt. GlusterFS' parsing of auth.ssl-allow, please see code from
        # https://github.com/gluster/glusterfs/blob/v3.6.2/
        # xlators/protocol/auth/login/src/login.c#L80
        # until end of gf_auth() function
        ssl_allow = re.split('[ ,]', ssl_allow_opt)
        access_to = access['access_to']
        if access_to in ssl_allow:
            LOG.warn(_LW("Access to %(share)s at %(export)s is already "
                         "granted for %(access_to)s. GlusterFS volume "
                         "options might have been changed externally."),
                     {'share': share['id'], 'export': exp_locn,
                      'access_to': access_to})
            return

        ssl_allow.append(access_to)
        ssl_allow_opt = ','.join(ssl_allow)
        try:
            gluster_mgr.gluster_call(
                'volume', 'set', gluster_mgr.volume,
                AUTH_SSL_ALLOW, ssl_allow_opt)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during allow access. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "access_to: %(access_to)s, Error: %(error)s"),
                   {'volname': gluster_mgr.volume,
                    'option': AUTH_SSL_ALLOW, 'access_to': access_to,
                    'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        # TODO(deepakcs) Remove this once ssl options can be
        # set dynamically.
        self._restart_gluster_vol(gluster_mgr)

    @utils.synchronized("glusterfs_native_access", external=False)
    def deny_access(self, context, share, access, share_server=None):
        """Deny access to a share that's using cert based auth.

        Remove the SSL CN (Common Name) that's allowed to access the server.
        """

        if access['access_type'] != ACCESS_TYPE_CERT:
            raise exception.InvalidShareAccess(_("Only 'cert' access type "
                                                 "allowed for access "
                                                 "removal."))
        exp_locn = share.get('export_location', None)
        gluster_mgr = self.gluster_used_vols_dict.get(exp_locn)

        ssl_allow_opt = gluster_mgr.get_gluster_vol_option(AUTH_SSL_ALLOW)
        ssl_allow = re.split('[ ,]', ssl_allow_opt)
        access_to = access['access_to']
        if access_to not in ssl_allow:
            LOG.warn(_LW("Access to %(share)s at %(export)s is already "
                         "denied for %(access_to)s. GlusterFS volume "
                         "options might have been changed externally."),
                     {'share': share['id'], 'export': exp_locn,
                      'access_to': access_to})
            return

        ssl_allow.remove(access_to)
        ssl_allow_opt = ','.join(ssl_allow)
        try:
            gluster_mgr.gluster_call(
                'volume', 'set', gluster_mgr.volume,
                AUTH_SSL_ALLOW, ssl_allow_opt)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error in gluster volume set during deny access. "
                     "Volume: %(volname)s, Option: %(option)s, "
                     "access_to: %(access_to)s, Error: %(error)s"),
                   {'volname': gluster_mgr.volume,
                    'option': AUTH_SSL_ALLOW, 'access_to': access_to,
                    'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        # TODO(deepakcs) Remove this once ssl options can be
        # set dynamically.
        self._restart_gluster_vol(gluster_mgr)

    def _update_share_stats(self):
        """Send stats info for the GlusterFS volume."""

        data = dict(
            share_backend_name=self.backend_name,
            vendor_name='Red Hat',
            driver_version='1.1',
            storage_protocol='glusterfs',
            reserved_percentage=self.configuration.reserved_share_percentage)

        # We don't use a service mount to get stats data.
        # Instead we use glusterfs quota feature and use that to limit
        # the share to its expected share['size'].

        # TODO(deepakcs): Change below once glusterfs supports volume
        # specific stats via the gluster cli.
        data['total_capacity_gb'] = 'infinite'
        data['free_capacity_gb'] = 'infinite'

        super(GlusterfsNativeShareDriver, self)._update_share_stats(data)

    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported."""
        pass
