# Copyright 2024 VAST Data Inc.
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
VAST's Share Driver


Configuration:


[DEFAULT]
enabled_share_backends = vast

[vast]
share_driver = manila.share.drivers.vastdata.driver.VASTShareDriver
share_backend_name = vast
snapshot_support = true
driver_handles_share_servers = false
vast_mgmt_host = v11
vast_vippool_name = vippool-1
vast_root_export = manila
vast_mgmt_user = admin
vast_mgmt_password = 123456
"""

import collections

import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.vastdata import driver_util
import manila.share.drivers.vastdata.rest as vast_rest


LOG = logging.getLogger(__name__)

OPTS = [
    cfg.HostAddressOpt(
        "vast_mgmt_host",
        help="Hostname or IP address VAST storage system management VIP.",
    ),
    cfg.PortOpt(
        "vast_mgmt_port",
        help="Port for VAST management",
        default=443
    ),
    cfg.StrOpt(
        "vast_vippool_name",
        help="Name of Virtual IP pool"
    ),
    cfg.StrOpt(
        "vast_root_export",
        default="manila",
        help="Base path for shares"
    ),
    cfg.StrOpt(
        "vast_mgmt_user",
        help="Username for VAST management"
    ),
    cfg.StrOpt(
        "vast_mgmt_password",
        help="Password for VAST management",
        secret=True
    ),
]

CONF = cfg.CONF
CONF.register_opts(OPTS)

MANILA_TO_VAST_ACCESS_LEVEL = {
    constants.ACCESS_LEVEL_RW: "nfs_read_write",
    constants.ACCESS_LEVEL_RO: "nfs_read_only",
}


@driver_util.decorate_methods_with(
    driver_util.verbose_driver_trace
)
class VASTShareDriver(driver.ShareDriver):
    """Driver for the VastData Filesystem."""

    VERSION = "1.0"  # driver version

    def __init__(self, *args, **kwargs):
        super().__init__(False, *args, config_opts=[OPTS], **kwargs)

    def do_setup(self, context):
        """Driver initialization"""
        backend_name = self.configuration.safe_get("share_backend_name")
        root_export = self.configuration.vast_root_export
        vip_pool_name = self.configuration.safe_get("vast_vippool_name")
        if not vip_pool_name:
            raise exception.VastDriverException(
                reason="vast_vippool_name must be set"
            )
        self._backend_name = backend_name or self.__class__.__name__
        self._vippool_name = vip_pool_name
        self._root_export = "/" + root_export.strip("/")

        username = self.configuration.safe_get("vast_mgmt_user")
        password = self.configuration.safe_get("vast_mgmt_password")
        host = self.configuration.safe_get("vast_mgmt_host")
        port = self.configuration.safe_get("vast_mgmt_port")
        if not all((username, password, port)):
            raise exception.VastDriverException(
                reason="Not all required parameters are present."
                       " Make sure you specified `vast_mgmt_host`,"
                       " `vast_mgmt_port`, and `vast_mgmt_user` "
                       "in manila.conf."
            )
        if port:
            host = f"{host}:{port}"
        self.rest = vast_rest.RestApi(
            host, username, password, False, self.VERSION
        )
        LOG.debug("VAST Data driver setup is complete.")

    def _update_share_stats(self, data=None):
        """Retrieve stats info from share group."""
        metrics_list = [
            "Capacity,drr",
            "Capacity,logical_space",
            "Capacity,logical_space_in_use",
            "Capacity,physical_space",
            "Capacity,physical_space_in_use",
        ]
        metrics = self.rest.capacity_metrics.get(metrics_list)
        data = dict(
            share_backend_name=self._backend_name,
            vendor_name="VAST STORAGE",
            driver_version=self.VERSION,
            storage_protocol="NFS",
            data_reduction=metrics.drr,
            total_capacity_gb=float(metrics.logical_space) / units.Gi,
            free_capacity_gb=float(
                metrics.logical_space - metrics.logical_space_in_use
            )
            / units.Gi,
            provisioned_capacity_gb=float(
                metrics.logical_space_in_use) / units.Gi,
            snapshot_support=True,
            create_share_from_snapshot_support=False,
            mount_snapshot_support=False,
            revert_to_snapshot_support=False,
        )

        super()._update_share_stats(data)

    def _to_volume_path(self, share_id, root=None):
        if not root:
            root = self._root_export
        return f"{root}/manila-{share_id}"

    def create_share(self, context, share, share_server=None):
        return self._ensure_share(share)[0]

    def delete_share(self, context, share, share_server=None):
        """Called to delete a share"""
        share_id = share["id"]
        src = self._to_volume_path(share_id)
        LOG.debug(f"Deleting '{src}'.")
        self.rest.folders.delete(path=src)
        self.rest.views.delete(name=share_id)
        self.rest.quotas.delete(name=share_id)
        self.rest.view_policies.delete(name=share_id)

    def update_access(
        self, context, share, access_rules,
        add_rules, delete_rules, share_server=None
    ):
        """Update access rules for share."""
        rule_state_map = {}

        if not (add_rules or delete_rules):
            add_rules = access_rules

        if share["share_proto"] != "NFS":
            LOG.error("The share protocol flavor is invalid. Please use NFS.")
            return

        valid_add_rules = []
        for rule in (add_rules or []):
            try:
                validate_access_rule(rule)
            except (
                    exception.InvalidShareAccess,
                    exception.InvalidShareAccessLevel,
            ) as exc:
                rule_id = rule["access_id"]
                access_level = rule["access_level"]
                access_to = rule["access_to"]
                LOG.exception(
                    f"Failed to provide {access_level} access to "
                    f"{access_to} (Rule ID: {rule_id}, Reason: {exc}). "
                    "Setting rule to 'error' state."
                )
                rule_state_map[rule['id']] = {'state': 'error'}
            else:
                valid_add_rules.append(rule)

        share_id = share["id"]
        export = self._to_volume_path(share_id)

        LOG.debug(f"Changing access on {share_id}.")
        data = {
            "name": share_id,
            "nfs_no_squash": ["*"],
            "nfs_root_squash": ["*"]
        }
        policy = self.rest.view_policies.one(name=share_id)
        if not policy:
            raise exception.VastDriverException(
                reason=f"Policy not found for share {share_id}."
            )
        if valid_add_rules:
            policy_rules = policy_payload_from_rules(
                rules=valid_add_rules, policy=policy, action="update"
            )
            data.update(policy_rules)
            LOG.debug(f"Changing access on {export}. Rules: {policy_rules}.")
            self.rest.view_policies.update(policy.id, **data)

        if delete_rules:
            policy_rules = policy_payload_from_rules(
                rules=delete_rules, policy=policy, action="deny"
            )
            LOG.debug(f"Changing access on {export}. Rules: {policy_rules}.")
            data.update(policy_rules)
            self.rest.view_policies.update(policy.id, **data)

        return rule_state_map

    def extend_share(self, share, new_size, share_server=None):
        """uses resize_share to extend a share"""
        self._resize_share(share, new_size)

    def shrink_share(self, share, new_size, share_server=None):
        """uses resize_share to shrink a share"""
        self._resize_share(share, new_size)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create snapshot."""
        path = self._to_volume_path(snapshot["share_instance_id"])
        self.rest.snapshots.create(path=path, name=snapshot["name"])

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove share."""
        self.rest.snapshots.delete(name=snapshot["name"])

    def get_network_allocations_number(self):
        return 0

    def ensure_shares(self, context, shares):
        updates = {}
        for share in shares:
            export_locations = self._ensure_share(share)
            updates[share["id"]] = {
                'export_locations': export_locations
            }
        return updates

    def get_backend_info(self, context):
        backend_info = {
            "vast_vippool_name": self.configuration.vast_vippool_name,
            "vast_mgmt_host": self.configuration.vast_mgmt_host,
        }
        return backend_info

    def _resize_share(self, share, new_size):
        share_id = share["id"]
        quota = self.rest.quotas.one(name=share_id)
        if not quota:
            raise exception.ShareNotFound(
                reason="Share not found", share_id=share_id
            )
        requested_capacity = new_size * units.Gi
        if requested_capacity < quota.used_effective_capacity:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])
        self.rest.quotas.update(quota.id, hard_limit=requested_capacity)

    def _ensure_share(self, share):
        share_proto = share["share_proto"]
        if share_proto != "NFS":
            raise exception.InvalidShare(
                reason=_(
                    "Invalid NAS protocol supplied: {}.".format(share_proto)
                )
            )

        vips = self.rest.vip_pools.vips(pool_name=self._vippool_name)

        share_id = share["id"]
        requested_capacity = share["size"] * units.Gi
        path = self._to_volume_path(share_id)
        policy = self.rest.view_policies.ensure(name=share_id)
        quota = self.rest.quotas.ensure(
            name=share_id, path=path,
            create_dir=True, hard_limit=requested_capacity
        )
        if quota.hard_limit != requested_capacity:
            raise exception.VastDriverException(
                reason=f"Share already exists with different capacity"
                f" (requested={requested_capacity}, exists={quota.hard_limit})"
                )
        view = self.rest.views.ensure(
            name=share_id, path=path, policy_id=policy.id
        )
        if view.policy != share_id:
            self.rest.views.update(view.id, policy_id=policy.id)
        return [
            dict(path=f"{vip}:{path}", is_admin_only=False) for vip in vips
        ]


def policy_payload_from_rules(rules, policy, action):
    """Convert list of manila rules

    into vast compatible payload for updating/creating policy.
    """
    hosts = collections.defaultdict(set)
    for rule in rules:
        addr_list = map(
            str, netaddr.IPNetwork(rule["access_to"]).iter_hosts()
        )
        hosts[
            MANILA_TO_VAST_ACCESS_LEVEL[rule["access_level"]]
        ].update(addr_list)

    _default_rules = set()

    # Delete default_vast_policy on each update.
    # There is no sense to keep * in list of allowed/denied hosts
    # as user want to set particular ip/ips only.
    _default_vast_policy = {"*"}
    if action == "update":
        rw = set(policy.nfs_read_write).union(
            hosts.get("nfs_read_write", _default_rules)
        )
        ro = set(policy.nfs_read_only).union(
            hosts.get("nfs_read_only", _default_rules)
        )
    elif action == "deny":
        rw = set(policy.nfs_read_write).difference(
            hosts.get("nfs_read_write", _default_rules)
        )
        ro = set(policy.nfs_read_only).difference(
            hosts.get("nfs_read_only", _default_rules)
        )
    else:
        raise ValueError("Invalid action")

    # When policy created default access is
    # "*" for read-write and read-only operations.
    # After updating any of rules (rw or ro)
    # we need to delete "*" to prevent ambiguous state when
    # resource available for certain ip and for all range of ip addresses.
    if len(rw) > 1:
        rw -= _default_vast_policy

    if len(ro) > 1:
        ro -= _default_vast_policy

    return {"nfs_read_write": list(rw), "nfs_read_only": list(ro)}


def validate_access_rule(access_rule):
    allowed_types = {"ip"}
    allowed_levels = MANILA_TO_VAST_ACCESS_LEVEL.keys()

    access_type = access_rule["access_type"]
    access_level = access_rule["access_level"]
    if access_type not in allowed_types:
        reason = _("Only {} access type allowed.").format(
            ", ".join(tuple([f"'{x}'" for x in allowed_types]))
        )
        raise exception.InvalidShareAccess(reason=reason)
    if access_level not in allowed_levels:
        raise exception.InvalidShareAccessLevel(level=access_level)
    try:
        netaddr.IPNetwork(access_rule["access_to"])
    except (netaddr.core.AddrFormatError, OSError) as exc:
        raise exception.InvalidShareAccess(reason=str(exc))
