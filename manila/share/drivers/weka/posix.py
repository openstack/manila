# Copyright 2026 Weka.IO Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""WekaFS POSIX client mount helper for the Manila share driver.

Builds and runs ``mount -t wekafs [-o opts] <backends>/<fs_name> <dir>``
on the Manila host.  Filesystems created with auth_required take an
``auth_token_path=<file>`` option pointing at the JSON that ``weka user
login`` writes.  Why the POSIX client is preferred over NFS is covered
in doc/source/admin/weka_share_driver.rst.
"""

import os
import threading

from oslo_concurrency import processutils
from oslo_log import log as logging

from manila.privsep import weka as weka_privsep
from manila.share.drivers.weka import exceptions

LOG = logging.getLogger(__name__)

_SHARE_DIR_MODE = 0o777

_MOUNT_LOCKS = {}
_MOUNT_LOCKS_LOCK = threading.Lock()


def _get_mount_lock(mount_point):
    """Return a per-mount-point threading.Lock (created on first use)."""
    with _MOUNT_LOCKS_LOCK:
        if mount_point not in _MOUNT_LOCKS:
            _MOUNT_LOCKS[mount_point] = threading.Lock()
        return _MOUNT_LOCKS[mount_point]


class WekaMount(object):
    """Manages a single WekaFS POSIX mount on the Manila host.

    Usable as a context manager, which unmounts on exit.  A filesystem
    created with auth_required needs *auth_token_path*, the JSON file
    ``weka user login`` produces.
    """

    def __init__(self, backends, fs_name, mount_point,
                 auth_token_path=None,
                 num_cores=1,
                 net=None,
                 read_cache=True,
                 writecache=False,
                 sync_on_close=False,
                 max_io_size=None,
                 iops_limit=None):
        self.backends = backends
        self.fs_name = fs_name
        self.mount_point = mount_point
        self.auth_token_path = auth_token_path
        self.num_cores = num_cores
        self.net = net
        self.read_cache = read_cache
        self.writecache = writecache
        self.sync_on_close = sync_on_close
        self.max_io_size = max_io_size
        self.iops_limit = iops_limit
        self._lock = _get_mount_lock(mount_point)

    def __enter__(self):
        self.mount()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.unmount()
        except Exception as exc:
            LOG.warning("Failed to unmount %s on context exit: %s",
                        self.mount_point, exc)
        return False  # do not suppress exceptions

    def mount(self):
        """Mount at self.mount_point; idempotent if already mounted."""
        with self._lock:
            if self.is_mounted(self.mount_point):
                LOG.debug(
                    "WekaFS %s already mounted at %s — skipping",
                    self.fs_name, self.mount_point,
                )
                return

            self._ensure_mount_point_dir(self.mount_point)

            # A joined client mounts by bare filesystem name, reusing its
            # cluster attachment; only a stateless one needs the prefix.
            if self.backends:
                source = '{backends}/{fs_name}'.format(
                    backends=self.backends, fs_name=self.fs_name)
            else:
                source = self.fs_name
            mount_options = self._build_mount_options()

            LOG.info(
                "Mounting WekaFS filesystem '%s' at '%s'",
                self.fs_name, self.mount_point,
            )
            try:
                weka_privsep.wekafs_mount(
                    source,
                    self.mount_point,
                    ','.join(mount_options) if mount_options else None,
                )
            except processutils.ProcessExecutionError as exc:
                raise exceptions.WekaMountError(
                    reason='mount command failed: {}'.format(exc))

    def unmount(self, force=False):
        """Unmount the filesystem; *force* makes it a lazy umount."""
        with self._lock:
            if not self.is_mounted(self.mount_point):
                LOG.debug(
                    "WekaFS %s not mounted at %s — nothing to unmount",
                    self.fs_name, self.mount_point,
                )
                return

            LOG.info(
                "Unmounting WekaFS filesystem '%s' from '%s'",
                self.fs_name, self.mount_point,
            )
            try:
                weka_privsep.umount(self.mount_point, lazy=force)
            except processutils.ProcessExecutionError as exc:
                raise exceptions.WekaUnmountError(
                    reason='umount command failed: {}'.format(exc))

    @staticmethod
    def is_mounted(mount_point):
        """True if *mount_point* holds a WekaFS mount, per /proc/mounts."""
        try:
            with open('/proc/mounts', 'r') as fh:
                for line in fh:
                    parts = line.split()
                    # fields: device mount_point fstype options dump pass
                    if len(parts) >= 3:
                        if (parts[1] == mount_point
                                and parts[2] == 'wekafs'):
                            return True
        except IOError:
            pass
        return False

    def get_or_create_share_path(self, mount_point, sub_path,
                                 mode=_SHARE_DIR_MODE):
        """Return a share sub-directory path, creating it with *mode*."""
        sub_path = sub_path.lstrip('/')
        abs_path = os.path.join(mount_point, sub_path)

        if not os.path.isdir(abs_path):
            LOG.debug("Creating share directory: %s", abs_path)
            try:
                os.makedirs(abs_path, mode=mode)
            except OSError as exc:
                raise exceptions.WekaMountError(
                    reason='Failed to create share directory {}: {}'.format(
                        abs_path, exc))
        else:
            try:
                os.chmod(abs_path, mode)
            except OSError as exc:
                LOG.warning(
                    "Could not set permissions on %s: %s", abs_path, exc)

        return abs_path

    def remove_share_path(self, mount_point, sub_path, force=False):
        """Remove a share sub-directory; *force* allows a non-empty one."""
        sub_path = sub_path.lstrip('/')
        abs_path = os.path.join(mount_point, sub_path)

        if not os.path.exists(abs_path):
            LOG.debug("Share path %s does not exist — skipping removal",
                      abs_path)
            return

        try:
            if force:
                import shutil
                shutil.rmtree(abs_path)
            else:
                os.rmdir(abs_path)
        except OSError as exc:
            raise exceptions.WekaMountError(
                reason='Failed to remove share directory {}: {}'.format(
                    abs_path, exc))

    def get_directory_inode(self, path):
        """Return the inode of *path*, as Weka directory quotas need."""
        try:
            return os.stat(path).st_ino
        except OSError as exc:
            raise exceptions.WekaMountError(
                reason='Failed to stat {}: {}'.format(path, exc))

    def _build_mount_options(self):
        """Build the list of WekaFS mount options."""
        opts = []
        opts.append('num_cores={}'.format(self.num_cores))
        if self.auth_token_path:
            opts.append('auth_token_path={}'.format(self.auth_token_path))
        if self.net:
            opts.append('net={}'.format(self.net))
        if not self.read_cache:
            opts.append('readcache=off')
        if self.writecache:
            opts.append('writecache')
        if self.sync_on_close:
            opts.append('sync_on_close')
        if self.max_io_size is not None:
            opts.append('max_io_size={}'.format(self.max_io_size))
        if self.iops_limit is not None:
            opts.append('iops_limit={}'.format(self.iops_limit))
        return opts

    @staticmethod
    def _ensure_mount_point_dir(path):
        """Create the mount point directory if it does not exist."""
        if not os.path.isdir(path):
            try:
                os.makedirs(path, exist_ok=True)
            except OSError as exc:
                raise exceptions.WekaMountError(
                    reason='Cannot create mount point {}: {}'.format(
                        path, exc))
