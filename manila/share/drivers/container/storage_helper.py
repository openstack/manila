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
from manila.share import utils as share_utils

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

        (free_size, total_size) = sorted(re.findall(r"\d+\.\d+|\d+", out),
                                         reverse=False)
        return [{
            'pool_name': self.configuration.container_volume_group,
            'total_capacity_gb': float(total_size),
            'free_capacity_gb': float(free_size),
            'reserved_percentage': 0,
            'reserved_snapshot_percentage': 0,
            'reserved_share_extend_percentage': 0,
        }, ]

    def _get_lv_device(self, share_name):
        return os.path.join("/dev", self.configuration.container_volume_group,
                            share_name)

    def _get_lv_folder(self, share_name):
        return os.path.join(self.configuration.container_volume_mount_path,
                            share_name)

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

    def migration_check_compatibility(self, context, source_share,
                                      destination_share, share_server=None,
                                      destination_share_server=None):
        """Checks compatibility between self.host and destination host."""
        # They must be in same vg and host
        compatible = False
        destination_host = destination_share['host']
        source_host = source_share['host']
        destination_vg = share_utils.extract_host(
            destination_host, level='pool')
        source_vg = share_utils.extract_host(
            source_host, level='pool')

        if destination_vg != source_vg:
            msg = ("Cannot migrate share %(shr)s between "
                   "%(src)s and %(dest)s, they must be in the same volume "
                   "group.")
            msg_args = {
                'shr': source_share['id'],
                'src': source_share['host'],
                'dest': destination_host,
            }
            LOG.exception(msg, msg_args)
        else:
            compatible = True

        compatibility = {
            'compatible': compatible,
            'writable': True,
            'nondisruptive': False,
            'preserve_metadata': True,
            'preserve_snapshots': False,
        }

        return compatibility

    def migration_start(self, context, source_share, destination_share,
                        source_snapshots, snapshot_mappings,
                        share_server=None, destination_share_server=None):
        """Starts the migration of the share from one host to another."""

        # NOTE(felipe_rodrigues): Since they are in the same volume group,
        # there is no need to copy the data between the volumes.
        return

    def migration_continue(self, context, source_share, destination_share,
                           source_snapshots, snapshot_mappings,
                           share_server=None, destination_share_server=None):
        """Check the progress of the migration."""
        return True

    def migration_get_progress(self, context, source_share,
                               destination_share, source_snapshots,
                               snapshot_mappings, share_server=None,
                               destination_share_server=None):
        """Return detailed progress of the migration in progress."""
        return {
            'total_progress': 100,
        }

    def migration_cancel(self, context, source_share, destination_share,
                         source_snapshots, snapshot_mappings,
                         share_server=None, destination_share_server=None):
        """Abort an ongoing migration."""

        # NOTE(felipe_rodrigues): Since they are in the same volume group,
        # there is no need to cancel the copy of the data.
        return

    def migration_complete(self, context, source_share, destination_share,
                           source_snapshots, snapshot_mappings,
                           share_server=None, destination_share_server=None):
        """Completes by removing the source local volume."""

        # NOTE(felipe_rodrigues): Since they are in the same volume group,
        # there is no need to remove source lv.
        return

    def share_server_migration_check_compatibility(
            self, context, share_server, dest_host, old_share_network,
            new_share_network, shares_request_spec):
        """Is called to check migration compatibility for a share server."""
        not_compatible = {
            'compatible': False,
            'writable': None,
            'nondisruptive': None,
            'preserve_snapshots': None,
            'migration_cancel': None,
            'migration_get_progress': None,
        }

        dest_backend_name = share_utils.extract_host(dest_host,
                                                     level='backend_name')
        source_backend_name = share_utils.extract_host(share_server['host'],
                                                       level='backend_name')
        if dest_backend_name == source_backend_name:
            msg = _("Cannot perform server migration %(server)s within the "
                    "same backend. Please choose a destination host different "
                    "from the source.")
            msg_args = {
                'server': share_server['id'],
            }
            LOG.error(msg, msg_args)
            return not_compatible

        # The container backend has only one pool, gets its pool name from the
        # first instance.
        first_share = shares_request_spec['shares_req_spec'][0]
        source_host = first_share['share_instance_properties']['host']
        source_vg = share_utils.extract_host(
            source_host, level='pool')
        dest_vg = share_utils.extract_host(
            dest_host, level='pool')
        if dest_vg and dest_vg != source_vg:
            msg = ("Cannot migrate share server %(server)s between %(src)s "
                   "and %(dest)s. They must be in the same volume group.")
            msg_args = {
                'server': share_server['id'],
                'src': source_host,
                'dest': dest_host,
            }
            LOG.error(msg, msg_args)
            return not_compatible

        # NOTE(felipe_rodrigues): it is not required to check the capacity,
        # because it is migrating in the same volume group.

        return {
            'compatible': True,
            'writable': True,
            'nondisruptive': False,
            'preserve_snapshots': False,
            'migration_cancel': True,
            'migration_get_progress': True,
        }

    def share_server_migration_start(self, context, src_share_server,
                                     dest_share_server, shares, snapshots):
        """Is called to perform 1st phase of migration of a share server."""

        # NOTE(felipe_rodrigues): Since they are in the same volume group,
        # there is no need to copy the data between the volumes.
        return

    def share_server_migration_continue(self, context, src_share_server,
                                        dest_share_server, shares, snapshots):
        """Check the progress of the migration."""
        return True

    def share_server_migration_complete(self, context, source_share_server,
                                        dest_share_server, shares, snapshots,
                                        new_network_allocations):
        """Completes by removing the source local volume."""

        # NOTE(felipe_rodrigues): Since they are in the same volume group,
        # there is no need to remove source lv.
        return

    def share_server_migration_cancel(self, context, src_share_server,
                                      dest_share_server, shares, snapshots):
        """Abort an ongoing migration."""

        # NOTE(felipe_rodrigues): Since they are in the same volume group,
        # there is no need to cancel the copy of the data.
        return

    def share_server_migration_get_progress(self, context, src_share_server,
                                            dest_share_server, shares,
                                            snapshots):
        """Return detailed progress of the server migration in progress."""

        return {
            'total_progress': 100,
        }

    def get_share_pool_name(self, share_id):
        """Return the pool name where the share is allocated"""

        return self.configuration.container_volume_group
