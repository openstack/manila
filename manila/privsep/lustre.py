# Copyright 2026 Red Hat, Inc.
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

"""Privileged operations for the Lustre share driver."""

from oslo_concurrency import processutils

import manila.privsep


@manila.privsep.sys_admin_pctxt.entrypoint
def lfs_setquota(project_id, block_hardlimit, mount_point):
    processutils.execute(
        'lfs', 'setquota', '-p', str(project_id),
        '-B', block_hardlimit, mount_point)


@manila.privsep.sys_admin_pctxt.entrypoint
def lfs_quota(project_id, mount_point):
    out, err = processutils.execute(
        'lfs', 'quota', '-p', str(project_id), mount_point)
    return out, err


@manila.privsep.sys_admin_pctxt.entrypoint
def lfs_df(mount_point):
    out, err = processutils.execute('lfs', 'df', mount_point)
    return out, err


@manila.privsep.sys_admin_pctxt.entrypoint
def lfs_project(path, recursive=False):
    args = ['lfs', 'project', '-d']
    if recursive:
        args.append('-r')
    args.append(path)
    out, err = processutils.execute(*args)
    return out, err


@manila.privsep.sys_admin_pctxt.entrypoint
def lctl_get_param(param):
    out, err = processutils.execute(
        'lctl', 'get_param', '-n', param)
    return out, err


@manila.privsep.sys_admin_pctxt.entrypoint
def lctl_nodemap_add(name):
    processutils.execute('lctl', 'nodemap_add', name)


@manila.privsep.sys_admin_pctxt.entrypoint
def lctl_nodemap_del(name):
    processutils.execute('lctl', 'nodemap_del', name)


@manila.privsep.sys_admin_pctxt.entrypoint
def lctl_nodemap_add_range(name, nid_range):
    processutils.execute(
        'lctl', 'nodemap_add_range',
        '--name', name, '--range', nid_range)


@manila.privsep.sys_admin_pctxt.entrypoint
def lctl_nodemap_del_range(name, nid_range):
    processutils.execute(
        'lctl', 'nodemap_del_range',
        '--name', name, '--range', nid_range)


@manila.privsep.sys_admin_pctxt.entrypoint
def lctl_nodemap_modify(name, prop, value):
    processutils.execute(
        'lctl', 'nodemap_modify',
        '--name', name, '--property', prop, '--value', value)


@manila.privsep.sys_admin_pctxt.entrypoint
def chattr_project(project_id, path):
    processutils.execute(
        'chattr', '+P', '-p', str(project_id), path)


@manila.privsep.sys_admin_pctxt.entrypoint
def lfs_clear_quota(project_id, mount_point):
    processutils.execute(
        'lfs', 'setquota', '-p', str(project_id),
        '-b', '0', '-B', '0', mount_point)
