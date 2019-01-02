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
                                 '--options', 'vg_size,vg_free',
                                 '--noheadings',
                                 '--units', 'g',
                                 run_as_root=True)
        if err:
            msg = _("Unable to gather size of the volume group %(vg)s to be "
                    "used by the driver. Error: %(err)s")
            raise exception.ShareBackendException(
                msg % {'vg': self.configuration.container_volume_group,
                       'err': err})

        (free_size, total_size) = sorted(re.findall("\d+\.\d+|\d+", out),
                                         reverse=False)
        return [{
            'pool_name': self.configuration.container_volume_group,
            'total_capacity_gb': float(total_size),
            'free_capacity_gb': float(free_size),
            'reserved_percentage': 0,
        }, ]

    def _get_lv_device(self, share_name):
        return os.path.join("/dev", self.configuration.container_volume_group,
                            share_name)

    def _get_lv_folder(self, share_name):
        # Provides folder name in hosts /tmp to which logical volume is
        # mounted prior to providing access to it from a container.
        return os.path.join("/tmp/shares", share_name)

    def provide_storage(self, share_name, size):
        self._execute("lvcreate", "-p", "rw", "-L",
                      str(size) + "G", "-n", share_name,
                      self.configuration.container_volume_group,
                      run_as_root=True)
        self._execute("mkfs.ext4", self._get_lv_device(share_name),
                      run_as_root=True)

    def _try_to_unmount_device(self, device):
        # NOTE(ganso): We invoke this method to be sure volume was unmounted,
        # and we swallow the exception in case it fails to.
        try:
            self._execute("umount", device, run_as_root=True)
        except exception.ProcessExecutionError as e:
            LOG.warning("Failed to umount helper directory %(device)s due to "
                        "%(reason)s.", {'device': device, 'reason': e})

    def remove_storage(self, share_name):
        device = self._get_lv_device(share_name)
        self._try_to_unmount_device(device)

        # (aovchinnikov): bug 1621784 manifests itself in jamming logical
        # volumes, so try removing once and issue warning until it is fixed.
        try:
            self._execute("lvremove", "-f", "--autobackup", "n",
                          device, run_as_root=True)
        except exception.ProcessExecutionError as e:
            LOG.warning("Failed to remove logical volume %(device)s due to "
                        "%(reason)s.", {'device': device, 'reason': e})

    def rename_storage(self, share_name, new_share_name):
        old_device = self._get_lv_device(share_name)
        new_device = self._get_lv_device(new_share_name)

        self._try_to_unmount_device(old_device)

        try:
            self._execute("lvrename", "--autobackup", "n",
                          old_device, new_device, run_as_root=True)
        except exception.ProcessExecutionError as e:
            msg = ("Failed to rename logical volume %(device)s due to "
                   "%(reason)s." % {'device': old_device, 'reason': e})
            LOG.exception(msg)
            raise

    def extend_share(self, share_name, new_size, share_server=None):
        lv_device = self._get_lv_device(share_name)
        cmd = ('lvextend', '-L', '%sG' % new_size, '-n', lv_device)
        self._execute(*cmd, run_as_root=True)
        self._execute("e2fsck", "-f", "-y", lv_device, run_as_root=True)
        self._execute('resize2fs', lv_device, run_as_root=True)

    def get_size(self, share_name):
        device = self._get_lv_device(share_name)
        size = self._execute(
            "lvs", "-o", "lv_size", "--noheadings", "--nosuffix",
            "--units", "g", device, run_as_root=True)
        LOG.debug("Found size %(size)s for LVM device "
                  "%(lvm)s.", {'size': size[0], 'lvm': share_name})
        return size[0]
