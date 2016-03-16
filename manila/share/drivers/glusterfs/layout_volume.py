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

"""GlusterFS volume mapped share layout."""

import os
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
from manila.share.drivers.glusterfs import common
from manila.share.drivers.glusterfs import layout
from manila import utils

LOG = log.getLogger(__name__)


glusterfs_volume_mapped_opts = [
    cfg.ListOpt('glusterfs_servers',
                default=[],
                deprecated_name='glusterfs_targets',
                help='List of GlusterFS servers that can be used to create '
                     'shares. Each GlusterFS server should be of the form '
                     '[remoteuser@]<volserver>, and they are assumed to '
                     'belong to distinct Gluster clusters.'),
    cfg.StrOpt('glusterfs_volume_pattern',
               help='Regular expression template used to filter '
                    'GlusterFS volumes for share creation. '
                    'The regex template can optionally (ie. with support '
                    'of the GlusterFS backend) contain the #{size} '
                    'parameter which matches an integer (sequence of '
                    'digits) in which case the value shall be interpreted as '
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
CONF.register_opts(glusterfs_volume_mapped_opts)

# The dict specifying named parameters
# that can be used with glusterfs_volume_pattern
# in #{<param>} format.
# For each of them we give regex pattern it matches
# and a transformer function ('trans') for the matched
# string value.
# Currently we handle only #{size}.
PATTERN_DICT = {'size': {'pattern': '(?P<size>\d+)', 'trans': int}}
USER_MANILA_SHARE = 'user.manila-share'
USER_CLONED_FROM = 'user.manila-cloned-from'
UUID_RE = re.compile('\A[\da-f]{8}-([\da-f]{4}-){3}[\da-f]{12}\Z', re.I)


class GlusterfsVolumeMappedLayout(layout.GlusterfsShareLayoutBase):

    _snapshots_are_supported = True

    def __init__(self, driver, *args, **kwargs):
        super(GlusterfsVolumeMappedLayout, self).__init__(
            driver, *args, **kwargs)
        self.gluster_used_vols = set()
        self.configuration.append_config_values(
            common.glusterfs_common_opts)
        self.configuration.append_config_values(
            glusterfs_volume_mapped_opts)
        self.gluster_nosnap_vols_dict = {}
        self.volume_pattern = self._compile_volume_pattern()
        self.volume_pattern_keys = self.volume_pattern.groupindex.keys()
        for srvaddr in self.configuration.glusterfs_servers:
            # format check for srvaddr
            self._glustermanager(srvaddr, False)
        self.glusterfs_versions = {}
        self.private_storage = kwargs.get('private_storage')

    def _compile_volume_pattern(self):
        """Compile a RegexObject from the config specified regex template.

        (cfg.glusterfs_volume_pattern)
        """

        subdict = {}
        for key, val in PATTERN_DICT.items():
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
        glusterfs_versions, exceptions = {}, {}
        for srvaddr in self.configuration.glusterfs_servers:
            try:
                glusterfs_versions[srvaddr] = self._glustermanager(
                    srvaddr, False).get_gluster_version()
            except exception.GlusterfsException as exc:
                exceptions[srvaddr] = six.text_type(exc)
        if exceptions:
            for srvaddr, excmsg in exceptions.items():
                LOG.error(_LE("'gluster version' failed on server "
                              "%(server)s with: %(message)s"),
                          {'server': srvaddr, 'message': excmsg})
            raise exception.GlusterfsException(_(
                "'gluster version' failed on servers %s") % (
                ','.join(exceptions.keys())))
        notsupp_servers = []
        for srvaddr, vers in glusterfs_versions.items():
            if common.numreduct(vers) < self.driver.GLUSTERFS_VERSION_MIN:
                notsupp_servers.append(srvaddr)
        if notsupp_servers:
            gluster_version_min_str = '.'.join(
                six.text_type(c) for c in self.driver.GLUSTERFS_VERSION_MIN)
            for srvaddr in notsupp_servers:
                LOG.error(_LE("GlusterFS version %(version)s on server "
                              "%(server)s is not supported, "
                              "minimum requirement: %(minvers)s"),
                          {'server': srvaddr,
                           'version': '.'.join(glusterfs_versions[srvaddr]),
                           'minvers': gluster_version_min_str})
            raise exception.GlusterfsException(_(
                "Unsupported GlusterFS version on servers %(servers)s, "
                "minimum requirement: %(minvers)s") % {
                'servers': ','.join(notsupp_servers),
                'minvers': gluster_version_min_str})
        self.glusterfs_versions = glusterfs_versions

        gluster_volumes_initial = set(
            self._fetch_gluster_volumes(filter_used=False))
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

        self._check_mount_glusterfs()

    def _glustermanager(self, gluster_address, req_volume=True):
        """Create GlusterManager object for gluster_address."""

        return common.GlusterManager(
            gluster_address, self.driver._execute,
            self.configuration.glusterfs_path_to_private_key,
            self.configuration.glusterfs_server_password,
            requires={'volume': req_volume})

    def _share_manager(self, share):
        """Return GlusterManager object representing share's backend."""
        gluster_address = self.private_storage.get(share['id'], 'volume')
        if gluster_address is None:
            return
        return self._glustermanager(gluster_address)

    def _fetch_gluster_volumes(self, filter_used=True):
        """Do a 'gluster volume list | grep <volume pattern>'.

        Aggregate the results from all servers.
        Extract the named groups from the matching volume names
        using the specs given in PATTERN_DICT.
        Return a dict with keys of the form <server>:/<volname>
        and values being dicts that map names of named groups
        to their extracted value.
        """

        volumes_dict = {}
        for srvaddr in self.configuration.glusterfs_servers:
            gluster_mgr = self._glustermanager(srvaddr, False)
            if gluster_mgr.user:
                logmsg = _LE("Retrieving volume list "
                             "on host %s") % gluster_mgr.host
            else:
                logmsg = _LE("Retrieving volume list")
            out, err = gluster_mgr.gluster_call('volume', 'list', log=logmsg)
            for volname in out.split("\n"):
                patmatch = self.volume_pattern.match(volname)
                if not patmatch:
                    continue
                comp_vol = gluster_mgr.components.copy()
                comp_vol.update({'volume': volname})
                gluster_mgr_vol = self._glustermanager(comp_vol)
                if filter_used:
                    vshr = gluster_mgr_vol.get_vol_option(
                        USER_MANILA_SHARE) or ''
                    if UUID_RE.search(vshr):
                        continue
                pattern_dict = {}
                for key in self.volume_pattern_keys:
                    keymatch = patmatch.group(key)
                    if keymatch is None:
                        pattern_dict[key] = None
                    else:
                        trans = PATTERN_DICT[key].get('trans', lambda x: x)
                        pattern_dict[key] = trans(keymatch)
                volumes_dict[gluster_mgr_vol.qualified] = pattern_dict
        return volumes_dict

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
        unused_vols = set(voldict) - self.gluster_used_vols

        if not unused_vols:
            # No volumes available for use as share. Warn user.
            LOG.warning(_LW("No unused gluster volumes available for use as "
                            "share! Create share won't be supported unless "
                            "existing shares are deleted or some gluster "
                            "volumes are created with names matching "
                            "'glusterfs_volume_pattern'."))
        else:
            LOG.info(_LI("Number of gluster volumes in use:  "
                         "%(inuse-numvols)s. Number of gluster volumes "
                         "available for use as share: %(unused-numvols)s"),
                     {'inuse-numvols': len(self.gluster_used_vols),
                     'unused-numvols': len(unused_vols)})

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
        self.gluster_used_vols.add(vol)
        return vol

    @utils.synchronized("glusterfs_native", external=False)
    def _push_gluster_vol(self, exp_locn):
        try:
            self.gluster_used_vols.remove(exp_locn)
        except KeyError:
            msg = (_("Couldn't find the share in used list."))
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

    def _wipe_gluster_vol(self, gluster_mgr):

        # Create a temporary mount.
        gluster_export = gluster_mgr.export
        tmpdir = tempfile.mkdtemp()
        try:
            common._mount_gluster_vol(self.driver._execute, gluster_export,
                                      tmpdir)
        except exception.GlusterfsException:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise

        # Delete the contents of a GlusterFS volume that is temporarily
        # mounted.
        # From GlusterFS version 3.7, two directories, '.trashcan' at the root
        # of the GlusterFS volume and 'internal_op' within the '.trashcan'
        # directory, are internally created when a GlusterFS volume is started.
        # GlusterFS does not allow unlink(2) of the two directories. So do not
        # delete the paths of the two directories, but delete their contents
        # along with the rest of the contents of the volume.
        srvaddr = gluster_mgr.host_access
        if common.numreduct(self.glusterfs_versions[srvaddr]) < (3, 7):
            cmd = ['find', tmpdir, '-mindepth', '1', '-delete']
        else:
            ignored_dirs = map(lambda x: os.path.join(tmpdir, *x),
                               [('.trashcan', ), ('.trashcan', 'internal_op')])
            ignored_dirs = list(ignored_dirs)
            cmd = ['find', tmpdir, '-mindepth', '1', '!', '-path',
                   ignored_dirs[0], '!', '-path', ignored_dirs[1], '-delete']

        try:
            self.driver._execute(*cmd, run_as_root=True)
        except exception.ProcessExecutionError as exc:
            msg = (_("Error trying to wipe gluster volume. "
                     "gluster_export: %(export)s, Error: %(error)s") %
                   {'export': gluster_export, 'error': exc.stderr})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)
        finally:
            # Unmount.
            common._umount_gluster_vol(self.driver._execute, tmpdir)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def create_share(self, context, share, share_server=None):
        """Create a share using GlusterFS volume.

        1 Manila share = 1 GlusterFS volume. Pick an unused
        GlusterFS volume for use as a share.
        """
        try:
            vol = self._pop_gluster_vol(share['size'])
        except exception.GlusterfsException:
            msg = (_LE("Error creating share %(share_id)s"),
                   {'share_id': share['id']})
            LOG.error(msg)
            raise

        gmgr = self._glustermanager(vol)
        export = self.driver._setup_via_manager(
            {'share': share, 'manager': gmgr})

        gmgr.set_vol_option(USER_MANILA_SHARE, share['id'])
        self.private_storage.update(share['id'], {'volume': vol})

        # TODO(deepakcs): Enable quota and set it to the share size.

        # For native protocol, the export_location should be of the form:
        # server:/volname
        LOG.info(_LI("export_location sent back from create_share: %s"),
                 export)
        return export

    def delete_share(self, context, share, share_server=None):
        """Delete a share on the GlusterFS volume.

        1 Manila share = 1 GlusterFS volume. Put the gluster
        volume back in the available list.
        """
        gmgr = self._share_manager(share)
        if not gmgr:
            # Share does not have a record in private storage.
            # It means create_share{,_from_snapshot} did not
            # succeed(*). In that case we should not obstruct
            # share deletion, so we just return doing nothing.
            #
            # (*) or we have a database corruption but then
            # basically does not matter what we do here
            return
        clone_of = gmgr.get_vol_option(USER_CLONED_FROM) or ''
        try:
            if UUID_RE.search(clone_of):
                # We take responsibility for the lifecycle
                # management of those volumes which were
                # created by us (as snapshot clones) ...
                gmgr.gluster_call('volume', 'delete', gmgr.volume)
            else:
                # ... for volumes that come from the pool, we return
                # them to the pool (after some purification rituals)
                self._wipe_gluster_vol(gmgr)
                gmgr.set_vol_option(USER_MANILA_SHARE, 'NONE')

            self._push_gluster_vol(gmgr.qualified)
        except exception.GlusterfsException:
            msg = (_LE("Error during delete_share request for "
                       "share %(share_id)s"), {'share_id': share['id']})
            LOG.error(msg)
            raise

        self.private_storage.delete(share['id'])
        # TODO(deepakcs): Disable quota.

    @staticmethod
    def _find_actual_backend_snapshot_name(gluster_mgr, snapshot):
        args = ('snapshot', 'list', gluster_mgr.volume, '--mode=script')
        out, err = gluster_mgr.gluster_call(
            *args,
            log=_LE("Retrieving snapshot list"))
        snapgrep = list(filter(lambda x: snapshot['id'] in x, out.split("\n")))
        if len(snapgrep) != 1:
            msg = (_("Failed to identify backing GlusterFS object "
                     "for snapshot %(snap_id)s of share %(share_id)s: "
                     "a single candidate was expected, %(found)d was found.") %
                   {'snap_id': snapshot['id'],
                    'share_id': snapshot['share_id'],
                    'found': len(snapgrep)})
            raise exception.GlusterfsException(msg)
        backend_snapshot_name = snapgrep[0]
        return backend_snapshot_name

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        old_gmgr = self._share_manager(snapshot['share_instance'])

        # Snapshot clone feature in GlusterFS server essential to support this
        # API is available in GlusterFS server versions 3.7 and higher. So do
        # a version check.
        vers = self.glusterfs_versions[old_gmgr.host_access]
        minvers = (3, 7)
        if common.numreduct(vers) < minvers:
            minvers_str = '.'.join(six.text_type(c) for c in minvers)
            vers_str = '.'.join(vers)
            msg = (_("GlusterFS version %(version)s on server %(server)s does "
                     "not support creation of shares from snapshot. "
                     "minimum requirement: %(minversion)s") %
                   {'version': vers_str, 'server': old_gmgr.host,
                    'minversion': minvers_str})
            LOG.error(msg)
            raise exception.GlusterfsException(msg)

        # Clone the snapshot. The snapshot clone, a new GlusterFS volume
        # would serve as a share.
        backend_snapshot_name = self._find_actual_backend_snapshot_name(
            old_gmgr, snapshot)
        volume = ''.join(['manila-', share['id']])
        args_tuple = (('snapshot', 'activate', backend_snapshot_name,
                      'force', '--mode=script'),
                      ('snapshot', 'clone', volume, backend_snapshot_name))
        for args in args_tuple:
            out, err = old_gmgr.gluster_call(
                *args,
                log=_LE("Creating share from snapshot"))

        # Get a manager for the the new volume/share.
        comp_vol = old_gmgr.components.copy()
        comp_vol.update({'volume': volume})
        gmgr = self._glustermanager(comp_vol)
        export = self.driver._setup_via_manager(
            {'share': share, 'manager': gmgr},
            {'share': snapshot['share_instance'], 'manager': old_gmgr})

        argseq = (('set',
                   [USER_CLONED_FROM, snapshot['share_id']]),
                  ('set', [USER_MANILA_SHARE, share['id']]),
                  ('start', []))
        for op, opargs in argseq:
            args = ['volume', op, gmgr.volume] + opargs
            gmgr.gluster_call(*args, log=_LE("Creating share from snapshot"))

        self.gluster_used_vols.add(gmgr.qualified)
        self.private_storage.update(share['id'], {'volume': gmgr.qualified})

        return export

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""

        gluster_mgr = self._share_manager(snapshot['share'])
        if gluster_mgr.qualified in self.gluster_nosnap_vols_dict:
            opret, operrno = -1, 0
            operrstr = self.gluster_nosnap_vols_dict[gluster_mgr.qualified]
        else:
            args = ('--xml', 'snapshot', 'create', 'manila-' + snapshot['id'],
                    gluster_mgr.volume)
            out, err = gluster_mgr.gluster_call(
                *args,
                log=_LE("Retrieving volume info"))

            if not out:
                raise exception.GlusterfsException(
                    'gluster volume info %s: no data received' %
                    gluster_mgr.volume
                )

            outxml = etree.fromstring(out)
            opret = int(common.volxml_get(outxml, 'opRet'))
            operrno = int(common.volxml_get(outxml, 'opErrno'))
            operrstr = common.volxml_get(outxml, 'opErrstr', None)

        if opret == -1:
            vers = self.glusterfs_versions[gluster_mgr.host_access]
            if common.numreduct(vers) > (3, 6):
                # This logic has not yet been implemented in GlusterFS 3.6
                if operrno == 0:
                    self.gluster_nosnap_vols_dict[
                        gluster_mgr.qualified] = operrstr
                    msg = _("Share %(share_id)s does not support snapshots: "
                            "%(errstr)s.") % {'share_id': snapshot['share_id'],
                                              'errstr': operrstr}
                    LOG.error(msg)
                    raise exception.ShareSnapshotNotSupported(msg)
            raise exception.GlusterfsException(
                _("Creating snapshot for share %(share_id)s failed "
                  "with %(errno)d: %(errstr)s") % {
                      'share_id': snapshot['share_id'],
                      'errno': operrno,
                      'errstr': operrstr})

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""

        gluster_mgr = self._share_manager(snapshot['share'])
        backend_snapshot_name = self._find_actual_backend_snapshot_name(
            gluster_mgr, snapshot)
        args = ('--xml', 'snapshot', 'delete', backend_snapshot_name,
                '--mode=script')
        out, err = gluster_mgr.gluster_call(
            *args,
            log=_LE("Error deleting snapshot"))

        if not out:
            raise exception.GlusterfsException(
                _('gluster snapshot delete %s: no data received') %
                gluster_mgr.volume
            )

        outxml = etree.fromstring(out)
        gluster_mgr.xml_response_check(outxml, args[1:])

    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported."""
        gmgr = self._share_manager(share)
        self.gluster_used_vols.add(gmgr.qualified)

        gmgr.set_vol_option(USER_MANILA_SHARE, share['id'])

    # Debt...

    def manage_existing(self, share, driver_options):
        raise NotImplementedError()

    def unmanage(self, share):
        raise NotImplementedError()

    def extend_share(self, share, new_size, share_server=None):
        raise NotImplementedError()

    def shrink_share(self, share, new_size, share_server=None):
        raise NotImplementedError()
