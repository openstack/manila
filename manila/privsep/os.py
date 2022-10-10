# Copyright 2021 Red Hat, Inc
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

"""
Helpers for os basic commands
"""

from oslo_concurrency import processutils

from manila import exception

import manila.privsep


@manila.privsep.sys_admin_pctxt.entrypoint
def rmdir(dir_path):
    processutils.execute('rmdir', dir_path)


@manila.privsep.sys_admin_pctxt.entrypoint
def mkdir(dir_path):
    processutils.execute('mkdir', dir_path)


@manila.privsep.sys_admin_pctxt.entrypoint
def recursive_forced_rm(dir_path):
    processutils.execute('rm', '-rf', dir_path)


@manila.privsep.sys_admin_pctxt.entrypoint
def is_data_definition_direct_io_supported(src_str, dest_str):
    try:
        processutils.execute(
            'dd', 'count=0', f'if={src_str}', f'of={dest_str}',
            'iflag=direct', 'oflag=direct')
        is_direct_io_supported = True
    except exception.ProcessExecutionError:
        is_direct_io_supported = False

    return is_direct_io_supported


@manila.privsep.sys_admin_pctxt.entrypoint
def data_definition(src_str, dest_str, size_in_g, use_direct_io=False):
    extra_flags = []
    if use_direct_io:
        extra_flags += ['iflag=direct', 'oflag=direct']
    processutils.execute(
        'dd', 'if=%s' % src_str, 'of=%s' % dest_str, 'count=%d' % size_in_g,
        'bs=1M', *extra_flags)


@manila.privsep.sys_admin_pctxt.entrypoint
def umount(mount_path):
    processutils.execute('umount', '-f', mount_path)


@manila.privsep.sys_admin_pctxt.entrypoint
def mount(device_name, mount_path, mount_type=None):
    extra_args = ['-t', mount_type] if mount_type else []
    processutils.execute('mount', device_name, mount_path, *extra_args)


@manila.privsep.sys_admin_pctxt.entrypoint
def list_mounts():
    out, err = processutils.execute('mount', '-l')
    return out, err


@manila.privsep.sys_admin_pctxt.entrypoint
def chmod(permission_level_str, mount_path):
    processutils.execute('chmod', permission_level_str, mount_path)


@manila.privsep.sys_admin_pctxt.entrypoint
def find(directory_to_find, min_depth='1', dirs_to_ignore=[], delete=False):
    ignored_dirs = []
    extra_args = []
    for dir in dirs_to_ignore:
        ignored_dirs += '!', '-path', dir

    if delete:
        extra_args.append('-delete')

    processutils.execute(
        'find', directory_to_find, '-mindepth', min_depth, *ignored_dirs,
        *extra_args)
