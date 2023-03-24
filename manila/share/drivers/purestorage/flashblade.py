# Copyright 2021 Pure Storage Inc.
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
"""
Pure Storage FlashBlade Share Driver
"""

import functools
import platform

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units

from manila import exception
from manila.i18n import _
from manila.share import driver

HAS_PURITY_FB = True
try:
    import purity_fb
except ImportError:
    purity_fb = None

LOG = logging.getLogger(__name__)

flashblade_connection_opts = [
    cfg.HostAddressOpt(
        "flashblade_mgmt_vip",
        help="The name (or IP address) for the Pure Storage "
        "FlashBlade storage system management VIP.",
    ),
    cfg.HostAddressOpt(
        "flashblade_data_vip",
        help="The name (or IP address) for the Pure Storage "
        "FlashBlade storage system data VIP.",
    ),
]

flashblade_auth_opts = [
    cfg.StrOpt(
        "flashblade_api",
        help=("API token for an administrative user account"),
        secret=True,
    ),
]

flashblade_extra_opts = [
    cfg.BoolOpt(
        "flashblade_eradicate",
        default=True,
        help="When enabled, all FlashBlade file systems and snapshots "
        "will be eradicated at the time of deletion in Manila. "
        "Data will NOT be recoverable after a delete with this "
        "set to True! When disabled, file systems and snapshots "
        "will go into pending eradication state and can be "
        "recovered.)",
    ),
]

CONF = cfg.CONF
CONF.register_opts(flashblade_connection_opts)
CONF.register_opts(flashblade_auth_opts)
CONF.register_opts(flashblade_extra_opts)


def purity_fb_to_manila_exceptions(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except purity_fb.rest.ApiException as ex:
            msg = _("Caught exception from purity_fb: %s") % ex
            LOG.exception(msg)
            raise exception.ShareBackendException(msg=msg)

    return wrapper


class FlashBladeShareDriver(driver.ShareDriver):
    """Version hisotry:

       1.0.0 - Initial version
       2.0.0 - Xena release
       3.0.0 - Yoga release
       4.0.0 - Zed release
       5.0.0 - Antelope release
       6.0.0 - Bobcat release

    """

    VERSION = "6.0"  # driver version
    USER_AGENT_BASE = "OpenStack Manila"

    def __init__(self, *args, **kwargs):
        super(FlashBladeShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(flashblade_connection_opts)
        self.configuration.append_config_values(flashblade_auth_opts)
        self.configuration.append_config_values(flashblade_extra_opts)
        self._user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
            "base": self.USER_AGENT_BASE,
            "class": self.__class__.__name__,
            "version": self.VERSION,
            "platform": platform.platform(),
        }

    def do_setup(self, context):
        """Driver initialization"""
        if purity_fb is None:
            msg = _(
                "Missing 'purity_fb' python module, ensure the library"
                " is installed and available."
            )
            raise exception.ManilaException(message=msg)

        self.api = self._safe_get_from_config_or_fail("flashblade_api")
        self.management_address = self._safe_get_from_config_or_fail(
            "flashblade_mgmt_vip"
        )
        self.data_address = self._safe_get_from_config_or_fail(
            "flashblade_data_vip"
        )
        self._sys = purity_fb.PurityFb(self.management_address)
        self._sys.disable_verify_ssl()
        try:
            self._sys.login(self.api)
            self._sys._api_client.user_agent = self._user_agent
        except purity_fb.rest.ApiException as ex:
            msg = _("Exception when logging into the array: %s\n") % ex
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)

        backend_name = self.configuration.safe_get("share_backend_name")
        self._backend_name = backend_name or self.__class__.__name__

        LOG.debug("setup complete")

    def _update_share_stats(self, data=None):
        """Retrieve stats info from share group."""
        (
            free_capacity_bytes,
            physical_capacity_bytes,
            provisioned_cap_bytes,
            data_reduction,
        ) = self._get_available_capacity()

        reserved_share_percentage = self.configuration.safe_get(
            "reserved_share_percentage"
        )
        if reserved_share_percentage is None:
            reserved_share_percentage = 0

        reserved_share_from_snapshot_percentage = self.configuration.safe_get(
            "reserved_share_from_snapshot_percentage"
        )
        if reserved_share_from_snapshot_percentage is None:
            reserved_share_from_snapshot_percentage = reserved_share_percentage

        reserved_share_extend_percentage = self.configuration.safe_get(
            "reserved_share_extend_percentage"
        )
        if reserved_share_extend_percentage is None:
            reserved_share_extend_percentage = reserved_share_percentage

        data = dict(
            share_backend_name=self._backend_name,
            vendor_name="PURE STORAGE",
            driver_version=self.VERSION,
            storage_protocol="NFS",
            data_reduction=data_reduction,
            reserved_percentage=reserved_share_percentage,
            reserved_snapshot_percentage=(
                reserved_share_from_snapshot_percentage),
            reserved_share_extend_percentage=(
                reserved_share_extend_percentage),
            total_capacity_gb=float(physical_capacity_bytes) / units.Gi,
            free_capacity_gb=float(free_capacity_bytes) / units.Gi,
            provisioned_capacity_gb=float(provisioned_cap_bytes) / units.Gi,
            snapshot_support=True,
            create_share_from_snapshot_support=False,
            mount_snapshot_support=False,
            revert_to_snapshot_support=True,
            thin_provisioning=True,
        )

        super(FlashBladeShareDriver, self)._update_share_stats(data)

    def _get_available_capacity(self):
        space = self._sys.arrays.list_arrays_space()
        array_space = space.items[0]
        data_reduction = array_space.space.data_reduction
        physical_capacity_bytes = array_space.capacity
        used_capacity_bytes = array_space.space.total_physical
        free_capacity_bytes = physical_capacity_bytes - used_capacity_bytes
        provisioned_capacity_bytes = array_space.space.unique
        return (
            free_capacity_bytes,
            physical_capacity_bytes,
            provisioned_capacity_bytes,
            data_reduction,
        )

    def _safe_get_from_config_or_fail(self, config_parameter):
        config_value = self.configuration.safe_get(config_parameter)
        if not config_value:
            reason = _(
                "%(config_parameter)s configuration parameter "
                "must be specified"
            ) % {"config_parameter": config_parameter}
            LOG.exception(reason)
            raise exception.BadConfigurationException(reason=reason)
        return config_value

    def _make_source_name(self, snapshot):
        base_name = CONF.share_name_template + "-manila"
        return base_name % snapshot["share_id"]

    def _make_share_name(self, manila_share):
        base_name = CONF.share_name_template + "-manila"
        return base_name % manila_share["id"]

    def _get_full_nfs_export_path(self, export_path):
        subnet_ip = self.data_address
        return "{subnet_ip}:/{export_path}".format(
            subnet_ip=subnet_ip, export_path=export_path
        )

    def _get_flashblade_filesystem_by_name(self, name):
        filesys = []
        filesys.append(name)
        try:
            res = self._sys.file_systems.list_file_systems(names=filesys)
        except purity_fb.rest.ApiException as ex:
            msg = _("Share not found on FlashBlade: %s\n") % ex
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)
        message = "Filesystem %(share_name)s exists. Continuing..."
        LOG.debug(message, {"share_name": res.items[0].name})

    def _get_flashblade_snapshot_by_name(self, name):
        try:
            self._sys.file_system_snapshots.list_file_system_snapshots(
                filter=name
            )
        except purity_fb.rest.ApiException as ex:
            msg = _("Snapshot not found on FlashBlade: %s\n") % ex
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)

    @purity_fb_to_manila_exceptions
    def _create_filesystem_export(self, flashblade_filesystem):
        flashblade_export = flashblade_filesystem.add_export(permissions=[])
        return {
            "path": self._get_full_nfs_export_path(
                flashblade_export.get_export_path()
            ),
            "is_admin_only": False,
            "preferred": True,
            "metadata": {},
        }

    @purity_fb_to_manila_exceptions
    def _resize_share(self, share, new_size):
        dataset_name = self._make_share_name(share)
        self._get_flashblade_filesystem_by_name(dataset_name)
        consumed_size = (
            self._sys.file_systems.list_file_systems(names=[dataset_name])
            .items[0]
            .space.virtual
        )
        attr = {}
        if consumed_size >= new_size * units.Gi:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share["id"]
            )
        attr["provisioned"] = new_size * units.Gi
        n_attr = purity_fb.FileSystem(**attr)
        LOG.debug("Resizing filesystem...")
        self._sys.file_systems.update_file_systems(
            name=dataset_name, attributes=n_attr
        )

    def _update_nfs_access(self, share, access_rules):
        dataset_name = self._make_share_name(share)
        self._get_flashblade_filesystem_by_name(dataset_name)
        nfs_rules = ""
        rule_state = {}
        for access in access_rules:
            if access["access_type"] == "ip":
                line = (
                    access["access_to"]
                    + "("
                    + access["access_level"]
                    + ",no_root_squash) "
                )
                rule_state[access["access_id"]] = {"state": "active"}
                nfs_rules += line
            else:
                message = _(
                    'Only "ip" access type is allowed for NFS protocol.'
                )
                LOG.error(message)
                rule_state[access["access_id"]] = {"state": "error"}
        try:
            self._sys.file_systems.update_file_systems(
                name=dataset_name,
                attributes=purity_fb.FileSystem(
                    nfs=purity_fb.NfsRule(rules=nfs_rules)
                ),
            )
            message = "Set nfs rules %(nfs_rules)s for %(share_name)s"
            LOG.debug(
                message, {"nfs_rules": nfs_rules, "share_name": dataset_name}
            )
        except purity_fb.rest.ApiException as ex:
            msg = _("Failed to set NFS access rules: %s\n") % ex
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)
        return rule_state

    @purity_fb_to_manila_exceptions
    def create_share(self, context, share, share_server=None):
        """Create a share and export it based on protocol used."""
        size = share["size"] * units.Gi
        share_name = self._make_share_name(share)

        if share["share_proto"] == "NFS":
            flashblade_fs = purity_fb.FileSystem(
                name=share_name,
                provisioned=size,
                hard_limit_enabled=True,
                fast_remove_directory_enabled=True,
                snapshot_directory_enabled=True,
                nfs=purity_fb.NfsRule(
                    v3_enabled=True, rules="", v4_1_enabled=True
                ),
            )
            self._sys.file_systems.create_file_systems(flashblade_fs)
            location = self._get_full_nfs_export_path(share_name)
        else:
            message = _("Unsupported share protocol: %(proto)s.") % {
                "proto": share["share_proto"]
            }
            LOG.exception(message)
            raise exception.InvalidShare(reason=message)
        LOG.info("FlashBlade created share %(name)s", {"name": share_name})

        return location

    def create_snapshot(self, context, snapshot, share_server=None):
        """Called to create a snapshot"""
        source = []
        flashblade_filesystem = self._make_source_name(snapshot)
        source.append(flashblade_filesystem)
        try:
            self._sys.file_system_snapshots.create_file_system_snapshots(
                sources=source, suffix=purity_fb.SnapshotSuffix(snapshot["id"])
            )
        except purity_fb.rest.ApiException as ex:
            msg = (
                _("Snapshot failed. Share not found on FlashBlade: %s\n") % ex
            )
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)

    def delete_share(self, context, share, share_server=None):
        """Called to delete a share"""
        dataset_name = self._make_share_name(share)
        try:
            self._get_flashblade_filesystem_by_name(dataset_name)
        except purity_fb.rest.ApiException:
            message = (
                "share %(dataset_name)s not found on FlashBlade, skip "
                "delete"
            )
            LOG.warning(message, {"dataset_name": dataset_name})
            return
        self._sys.file_systems.update_file_systems(
            name=dataset_name,
            attributes=purity_fb.FileSystem(
                nfs=purity_fb.NfsRule(v3_enabled=False, v4_1_enabled=False),
                smb=purity_fb.ProtocolRule(enabled=False),
                destroyed=True,
            ),
        )
        if self.configuration.flashblade_eradicate:
            self._sys.file_systems.delete_file_systems(name=dataset_name)
            LOG.info(
                "FlashBlade eradicated share %(name)s", {"name": dataset_name}
            )

    @purity_fb_to_manila_exceptions
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Called to delete a snapshot"""
        dataset_name = self._make_source_name(snapshot)
        filt = "source_display_name='{0}' and suffix='{1}'".format(
            dataset_name, snapshot["id"]
        )
        name = "{0}.{1}".format(dataset_name, snapshot["id"])
        LOG.debug("FlashBlade filter %(name)s", {"name": filt})
        try:
            self._get_flashblade_snapshot_by_name(filt)
        except exception.ShareResourceNotFound:
            message = (
                "snapshot %(snapshot)s not found on FlashBlade, skip delete"
            )
            LOG.warning(
                message, {"snapshot": dataset_name + "." + snapshot["id"]}
            )
            return
        self._sys.file_system_snapshots.update_file_system_snapshots(
            name=name, attributes=purity_fb.FileSystemSnapshot(destroyed=True)
        )
        LOG.debug(
            "Snapshot %(name)s deleted successfully",
            {"name": dataset_name + "." + snapshot["id"]},
        )
        if self.configuration.flashblade_eradicate:
            self._sys.file_system_snapshots.delete_file_system_snapshots(
                name=name
            )
            LOG.debug(
                "Snapshot %(name)s eradicated successfully",
                {"name": dataset_name + "." + snapshot["id"]},
            )

    def ensure_share(self, context, share, share_server=None):
        """Dummy - called to ensure share is exported.

        All shares created on a FlashBlade are guaranteed to
        be exported so this check is redundant
        """

    def update_access(
        self,
        context,
        share,
        access_rules,
        add_rules,
        delete_rules,
        share_server=None,
    ):
        """Update access of share"""
        # We will use the access_rules list to bulk update access
        state_map = self._update_nfs_access(share, access_rules)
        return state_map

    def extend_share(self, share, new_size, share_server=None):
        """uses resize_share to extend a share"""
        self._resize_share(share, new_size)

    def shrink_share(self, share, new_size, share_server=None):
        """uses resize_share to shrink a share"""
        self._resize_share(share, new_size)

    @purity_fb_to_manila_exceptions
    def revert_to_snapshot(
        self,
        context,
        snapshot,
        share_access_rules,
        snapshot_access_rules,
        share_server=None,
    ):
        dataset_name = self._make_source_name(snapshot)
        filt = "source_display_name='{0}' and suffix='{1}'".format(
            dataset_name, snapshot["id"]
        )
        LOG.debug("FlashBlade filter %(name)s", {"name": filt})
        name = "{0}.{1}".format(dataset_name, snapshot["id"])
        self._get_flashblade_snapshot_by_name(filt)
        fs_attr = purity_fb.FileSystem(
            name=dataset_name, source=purity_fb.Reference(name=name)
        )
        try:
            self._sys.file_systems.create_file_systems(
                overwrite=True,
                discard_non_snapshotted_data=True,
                file_system=fs_attr,
            )
        except purity_fb.rest.ApiException as ex:
            msg = _("Failed to revert snapshot: %s\n") % ex
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)
