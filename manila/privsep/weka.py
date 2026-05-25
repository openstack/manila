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

"""Privileged-execution helpers for the Weka Manila share driver.

All functions in this module run inside Manila's shared privsep daemon
(sys_admin_pctxt) and therefore execute with the capabilities granted to
that context (CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.).  Callers must NOT
pass run_as_root to processutils.execute — the daemon is already
privileged.

Usage::

    from manila.privsep import weka as weka_privsep
    weka_privsep.wekafs_mount(source, mount_point, options)
    weka_privsep.umount(mount_point)
    weka_privsep.nfs_mount(export, mount_point)
    weka_privsep.rsync(src, dst)
"""

from oslo_concurrency import processutils

import manila.privsep


@manila.privsep.sys_admin_pctxt.entrypoint
def nfs_mount(export, mount_path):
    """Mount an NFS export at mount_path."""
    processutils.execute('mount', '-t', 'nfs', export, mount_path)


@manila.privsep.sys_admin_pctxt.entrypoint
def wekafs_mount(source, mount_path, options=None):
    """Mount a WekaFS filesystem at mount_path."""
    cmd = ['mount', '-t', 'wekafs']
    if options:
        cmd += ['-o', options]
    cmd += [source, mount_path]
    processutils.execute(*cmd)


@manila.privsep.sys_admin_pctxt.entrypoint
def umount(mount_path, lazy=False):
    """Unmount the filesystem at mount_path; *lazy* passes ``-l``."""
    cmd = ['umount']
    if lazy:
        cmd.append('-l')
    cmd.append(mount_path)
    processutils.execute(*cmd)


@manila.privsep.sys_admin_pctxt.entrypoint
def rsync(src, dst):
    """Rsync src/ into dst/ in archive mode, minus directory times.

    Setting mtime on an NFS export root fails with EPERM and aborts the
    copy (exit 23); --omit-dir-times avoids that while still preserving
    contents, permissions, ownership and per-file timestamps.
    """
    processutils.execute('rsync', '-a', '--omit-dir-times', src, dst)
