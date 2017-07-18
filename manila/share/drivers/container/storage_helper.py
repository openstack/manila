# Copyright (c) 2016 Mirantis, Inc.
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

import os
import re

from oslo_config import cfg
from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.share import driver


CONF = cfg.CONF

lv_opts = [
    cfg.StrOpt("container_volume_group",
               default="manila_docker_volumes",
               help="LVM volume group to use for volumes. This volume group "
                    "must be created by the cloud administrator independently "
                    "from manila operations."),
]

CONF.register_opts(lv_opts)
LOG = log.getLogger(__name__)


class LVMHelper(driver.ExecuteMixin):

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration", None)
        if self.configuration is None:
            raise exception.ManilaException(_("LVMHelper called without "
                                              "supplying configuration."))
        self.configuration.append_config_values(lv_opts)
        super(LVMHelper, self).__init__(*args, **kwargs)
        self.init_execute_mixin()

    def get_share_server_pools(self, share_server=None):
        out, err = self._execute('vgs',
                                 self.configuration.container_volume_group,
                                 '--rows', run_as_root=True)
        total_size = re.findall("VSize\s[0-9.]+g", out)[0][6:-1]
        free_size = re.findall("VFree\s[0-9.]+g", out)[0][6:-1]
        return [{
            'pool_name': self.configuration.container_volume_group,
            'total_capacity_gb': float(total_size),
            'free_capacity_gb': float(free_size),
            'reserved_percentage': 0,
        }, ]

    def _get_lv_device(self, share):
        return os.path.join("/dev", self.configuration.container_volume_group,
                            share.share_id)

    def _get_lv_folder(self, share):
        # Provides folder name in hosts /tmp to which logical volume is
        # mounted prior to providing access to it from a container.
        return os.path.join("/tmp/shares", share.share_id)

    def provide_storage(self, share):
        share_name = share.share_id
        self._execute("lvcreate", "-p", "rw", "-L",
                      str(share.size) + "G", "-n", share_name,
                      self.configuration.container_volume_group,
                      run_as_root=True)
        self._execute("mkfs.ext4", self._get_lv_device(share),
                      run_as_root=True)

    def remove_storage(self, share):
        to_remove = self._get_lv_device(share)
        try:
            self._execute("umount", to_remove, run_as_root=True)
        except exception.ProcessExecutionError as e:
            LOG.warning("Failed to umount helper directory %s.",
                        to_remove)
            LOG.error(e)
        # (aovchinnikov): bug 1621784 manifests itself in jamming logical
        # volumes, so try removing once and issue warning until it is fixed.
        try:
            self._execute("lvremove", "-f", "--autobackup", "n",
                          to_remove, run_as_root=True)
        except exception.ProcessExecutionError as e:
            LOG.warning("Failed to remove logical volume %s.", to_remove)
            LOG.error(e)

    def extend_share(self, share, new_size, share_server=None):
        lv_device = self._get_lv_device(share)
        cmd = ('lvextend', '-L', '%sG' % new_size, '-n', lv_device)
        self._execute(*cmd, run_as_root=True)
        self._execute("e2fsck", "-f", "-y", lv_device, run_as_root=True)
        self._execute('resize2fs', lv_device, run_as_root=True)
