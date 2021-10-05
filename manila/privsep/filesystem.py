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
Helpers for filesystem commands
"""

from oslo_concurrency import processutils

import manila.privsep


@manila.privsep.sys_admin_pctxt.entrypoint
def e2fsck(device_path):
    return processutils.execute('e2fsck', '-y', '-f', device_path)


@manila.privsep.sys_admin_pctxt.entrypoint
def tune2fs(device_path):
    return processutils.execute('tune2fs', '-U', 'random', device_path)


@manila.privsep.sys_admin_pctxt.entrypoint
def make_filesystem(ext_version, device_name):
    return processutils.execute(f'mkfs.{ext_version}', device_name)
