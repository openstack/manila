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
Helpers for lvm related routines
"""

from oslo_concurrency import processutils

import manila.privsep


@manila.privsep.sys_admin_pctxt.entrypoint
def lvremove(vg_name, lv_name):
    processutils.execute('lvremove', '-f', f'{vg_name}/{lv_name}')


@manila.privsep.sys_admin_pctxt.entrypoint
def lvcreate(lv_size, lv_name, vg_name, mirrors=0, region_size=0):
    extra_params = []

    if mirrors:
        extra_params += ['-m', mirrors, '--nosync']
    if region_size:
        extra_params += ['-R', region_size]

    processutils.execute(
        'lvcreate', '-Wy', '--yes', '-L', f'{lv_size}G', '-n', lv_name,
        vg_name, *extra_params)


@manila.privsep.sys_admin_pctxt.entrypoint
def lv_snapshot_create(snapshot_size, snap_name, orig_lv_name):
    size_str = '%sG' % snapshot_size
    processutils.execute(
        'lvcreate', '-L', size_str, '--name', snap_name,
        '--snapshot', orig_lv_name)


@manila.privsep.sys_admin_pctxt.entrypoint
def get_vgs(vg_name):
    out, err = processutils.execute(
        'vgs', vg_name, '--rows', '--units', 'g',)
    return out, err


@manila.privsep.sys_admin_pctxt.entrypoint
def list_vgs_get_name():
    out, err = processutils.execute('vgs', '--noheadings', '-o', 'name')
    return out, err


@manila.privsep.sys_admin_pctxt.entrypoint
def lvconvert(vg_name, snapshot_name):
    processutils.execute(
        'lvconvert', '--merge', f'{vg_name}/{snapshot_name}')


@manila.privsep.sys_admin_pctxt.entrypoint
def lvrename(vg_name, lv_name, new_name):
    processutils.execute(
        'lvrename', vg_name, lv_name, new_name)


@manila.privsep.sys_admin_pctxt.entrypoint
def lvextend(lv_name, new_size):
    processutils.execute('lvextend', '-L', '%sG' % new_size, '-r', lv_name)
