# Copyright 2016 Mirantis inc.
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
Dummy share driver for testing Manila APIs and other interfaces.

This driver simulates support of:
- Both available driver modes: DHSS=True/False
- NFS and CIFS protocols
- IP access for NFS shares and USER access for CIFS shares
- CIFS shares in DHSS=True driver mode
- Creation and deletion of share snapshots
- Share replication (readable)
- Share migration
- Consistency groups
- Resize of a share (extend/shrink)

"""

import functools
import time

from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import configuration
from manila.share import driver
from manila.share.manager import share_manager_opts  # noqa
from manila.share import utils as share_utils

LOG = log.getLogger(__name__)


dummy_opts = [
    cfg.FloatOpt(
        "dummy_driver_default_driver_method_delay",
        help="Defines default time delay in seconds for each dummy driver "
             "method. To redefine some specific method delay use other "
             "'dummy_driver_driver_methods_delays' config opt. Optional.",
        default=2.0,
        min=0,
    ),
    cfg.DictOpt(
        "dummy_driver_driver_methods_delays",
        help="It is dictionary-like config option, that consists of "
             "driver method names as keys and integer/float values that are "
             "time delay in seconds. Optional.",
        default={
            "ensure_share": "1.05",
            "create_share": "3.98",
            "get_pool": "0.5",
            "do_setup": "0.05",

            "_get_pools_info": "0.1",
            "_update_share_stats": "0.3",

            "create_replica": "3.99",
            "delete_replica": "2.98",
            "promote_replica": "0.75",
            "update_replica_state": "0.85",
            "create_replicated_snapshot": "4.15",
            "delete_replicated_snapshot": "3.16",
            "update_replicated_snapshot": "1.17",

            "migration_start": 1.01,
            "migration_continue": 1.02,  # it will be called 2 times
            "migration_complete": 1.03,
            "migration_cancel": 1.04,
            "migration_get_progress": 1.05,
            "migration_check_compatibility": 0.05,
        },
    ),
]

CONF = cfg.CONF


def slow_me_down(f):

    @functools.wraps(f)
    def wrapped_func(self, *args, **kwargs):
        sleep_time = self.configuration.safe_get(
            "dummy_driver_driver_methods_delays").get(
                f.__name__,
                self.configuration.safe_get(
                    "dummy_driver_default_driver_method_delay")
            )
        time.sleep(float(sleep_time))
        return f(self, *args, **kwargs)

    return wrapped_func


def get_backend_configuration(backend_name):
    config_stanzas = CONF.list_all_sections()
    if backend_name not in config_stanzas:
        msg = _("Could not find backend stanza %(backend_name)s in "
                "configuration which is required for share replication and "
                "migration. Available stanzas are %(stanzas)s")
        params = {
            "stanzas": config_stanzas,
            "backend_name": backend_name,
        }
        raise exception.BadConfigurationException(reason=msg % params)

    config = configuration.Configuration(
        driver.share_opts, config_group=backend_name)
    config.append_config_values(dummy_opts)
    config.append_config_values(share_manager_opts)
    config.append_config_values(driver.ssh_opts)

    return config


class DummyDriver(driver.ShareDriver):
    """Dummy share driver that implements all share driver interfaces."""

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        super(self.__class__, self).__init__(
            [False, True], *args, config_opts=[dummy_opts], **kwargs)
        self._verify_configuration()
        self.private_storage = kwargs.get('private_storage')
        self.backend_name = self.configuration.safe_get(
            "share_backend_name") or "DummyDriver"
        self.migration_progress = {}

    def _verify_configuration(self):
        allowed_driver_methods = [m for m in dir(self) if m[0] != '_']
        allowed_driver_methods.extend([
            "_setup_server",
            "_teardown_server",
            "_get_pools_info",
            "_update_share_stats",
        ])
        disallowed_driver_methods = (
            "get_admin_network_allocations_number",
            "get_network_allocations_number",
            "get_share_server_pools",
        )
        for k, v in self.configuration.safe_get(
                "dummy_driver_driver_methods_delays").items():
            if k not in allowed_driver_methods:
                raise exception.BadConfigurationException(reason=(
                    "Dummy driver does not have '%s' method." % k
                ))
            elif k in disallowed_driver_methods:
                raise exception.BadConfigurationException(reason=(
                    "Method '%s' does not support delaying." % k
                ))
            try:
                float(v)
            except (TypeError, ValueError):
                raise exception.BadConfigurationException(reason=(
                    "Wrong value (%(v)s) for '%(k)s' dummy driver method time "
                    "delay is set in 'dummy_driver_driver_methods_delays' "
                    "config option." % {"k": k, "v": v}
                ))

    def _get_share_name(self, share):
        return "share_%(s_id)s_%(si_id)s" % {
            "s_id": share["share_id"].replace("-", "_"),
            "si_id": share["id"].replace("-", "_")}

    def _get_snapshot_name(self, snapshot):
        return "snapshot_%(s_id)s_%(si_id)s" % {
            "s_id": snapshot["snapshot_id"].replace("-", "_"),
            "si_id": snapshot["id"].replace("-", "_")}

    def _generate_export_locations(self, mountpoint, share_server=None):
        details = share_server["backend_details"] if share_server else {
            "primary_public_ip": "10.0.0.10",
            "secondary_public_ip": "10.0.0.20",
            "service_ip": "11.0.0.11",
        }
        return [
            {
                "path": "%(ip)s:%(mp)s" % {"ip": ip, "mp": mountpoint},
                "metadata": {
                    "preferred": preferred,
                },
                "is_admin_only": is_admin_only,
            } for ip, is_admin_only, preferred in (
                (details["primary_public_ip"], False, True),
                (details["secondary_public_ip"], False, False),
                (details["service_ip"], True, False))
        ]

    def _create_share(self, share, share_server=None):
        share_proto = share["share_proto"]
        if share_proto not in ("NFS", "CIFS"):
            msg = _("Unsupported share protocol provided - %s.") % share_proto
            raise exception.InvalidShareAccess(reason=msg)

        share_name = self._get_share_name(share)
        mountpoint = "/path/to/fake/share/%s" % share_name
        self.private_storage.update(
            share["id"], {
                "fake_provider_share_name": share_name,
                "fake_provider_location": mountpoint,
            }
        )
        return self._generate_export_locations(
            mountpoint, share_server=share_server)

    @slow_me_down
    def create_share(self, context, share, share_server=None):
        """Is called to create share."""
        return self._create_share(share, share_server=share_server)

    @slow_me_down
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        return self._create_share(share, share_server=share_server)

    def _create_snapshot(self, snapshot, share_server=None):
        snapshot_name = self._get_snapshot_name(snapshot)
        mountpoint = "/path/to/fake/snapshot/%s" % snapshot_name
        self.private_storage.update(
            snapshot["id"], {
                "fake_provider_snapshot_name": snapshot_name,
                "fake_provider_location": mountpoint,
            }
        )
        return {
            'fake_key1': 'fake_value1',
            'fake_key2': 'fake_value2',
            'fake_key3': 'fake_value3',
            "provider_location": mountpoint,
            "export_locations": self._generate_export_locations(
                mountpoint, share_server=share_server)
        }

    @slow_me_down
    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create snapshot."""
        return self._create_snapshot(snapshot, share_server)

    @slow_me_down
    def delete_share(self, context, share, share_server=None):
        """Is called to remove share."""
        self.private_storage.delete(share["id"])

    @slow_me_down
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove snapshot."""
        LOG.debug('Deleting snapshot with following data: %s', snapshot)
        self.private_storage.delete(snapshot["id"])

    @slow_me_down
    def get_pool(self, share):
        """Return pool name where the share resides on."""
        pool_name = share_utils.extract_host(share["host"], level="pool")
        return pool_name

    @slow_me_down
    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported."""

    @slow_me_down
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share."""
        for rule in add_rules + access_rules:
            share_proto = share["share_proto"].lower()
            access_type = rule["access_type"].lower()
            if not (
                    (share_proto == "nfs" and access_type == "ip") or
                    (share_proto == "cifs" and access_type == "user")):
                msg = _("Unsupported '%(access_type)s' access type provided "
                        "for '%(share_proto)s' share protocol.") % {
                    "access_type": access_type, "share_proto": share_proto}
                raise exception.InvalidShareAccess(reason=msg)

    @slow_me_down
    def snapshot_update_access(self, context, snapshot, access_rules,
                               add_rules, delete_rules, share_server=None):
        """Update access rules for given snapshot."""
        self.update_access(context, snapshot['share'], access_rules,
                           add_rules, delete_rules, share_server)

    @slow_me_down
    def do_setup(self, context):
        """Any initialization the share driver does while starting."""

    @slow_me_down
    def manage_existing(self, share, driver_options):
        """Brings an existing share under Manila management."""
        new_export = share['export_location']
        old_share_id = self._get_share_id_from_export(new_export)
        old_export = self.private_storage.get(
            old_share_id, key='export_location')
        if old_export.split(":/")[-1] == new_export.split(":/")[-1]:
            result = {"size": 1, "export_locations": self._create_share(share)}
            self.private_storage.delete(old_share_id)
            return result
        else:
            msg = ("Invalid export specified, existing share %s"
                   " could not be found" % old_share_id)
            raise exception.ShareBackendException(msg=msg)

    def _get_share_id_from_export(self, export_location):
        values = export_location.split('share_')
        if len(values) > 1:
            return values[1][37:].replace("_", "-")
        else:
            return export_location

    @slow_me_down
    def unmanage(self, share):
        """Removes the specified share from Manila management."""
        self.private_storage.update(
            share['id'], {'export_location': share['export_location']})

    @slow_me_down
    def manage_existing_snapshot(self, snapshot, driver_options):
        """Brings an existing snapshot under Manila management."""
        old_snap_id = self._get_snap_id_from_provider_location(
            snapshot['provider_location'])
        old_provider_location = self.private_storage.get(
            old_snap_id, key='provider_location')
        if old_provider_location == snapshot['provider_location']:
            self._create_snapshot(snapshot)
            self.private_storage.delete(old_snap_id)
            return {"size": 1,
                    "provider_location": snapshot["provider_location"]}
        else:
            msg = ("Invalid provider location specified, existing snapshot %s"
                   " could not be found" % old_snap_id)
            raise exception.ShareBackendException(msg=msg)

    def _get_snap_id_from_provider_location(self, provider_location):
        values = provider_location.split('snapshot_')
        if len(values) > 1:
            return values[1][37:].replace("_", "-")
        else:
            return provider_location

    @slow_me_down
    def unmanage_snapshot(self, snapshot):
        """Removes the specified snapshot from Manila management."""
        self.private_storage.update(
            snapshot['id'],
            {'provider_location': snapshot['provider_location']})

    @slow_me_down
    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        """Reverts a share (in place) to the specified snapshot."""

    @slow_me_down
    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share."""

    @slow_me_down
    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return 2

    def get_admin_network_allocations_number(self):
        return 1

    @slow_me_down
    def _setup_server(self, network_info, metadata=None):
        """Sets up and configures share server with given network parameters.

        Redefine it within share driver when it is going to handle share
        servers.
        """
        server_details = {
            "primary_public_ip": network_info[
                "network_allocations"][0]["ip_address"],
            "secondary_public_ip": network_info[
                "network_allocations"][1]["ip_address"],
            "service_ip": network_info[
                "admin_network_allocations"][0]["ip_address"],
            "username": "fake_username",
        }
        return server_details

    @slow_me_down
    def _teardown_server(self, server_details, security_services=None):
        """Tears down share server."""

    @slow_me_down
    def _get_pools_info(self):
        pools = [{
            "pool_name": "fake_pool_for_%s" % self.backend_name,
            "total_capacity_gb": 1230.0,
            "free_capacity_gb": 1210.0,
            "reserved_percentage": self.configuration.reserved_share_percentage
        }]
        if self.configuration.replication_domain:
            pools[0]["replication_type"] = "readable"
        return pools

    @slow_me_down
    def _update_share_stats(self, data=None):
        """Retrieve stats info from share group."""
        data = {
            "share_backend_name": self.backend_name,
            "storage_protocol": "NFS_CIFS",
            "reserved_percentage":
                self.configuration.reserved_share_percentage,
            "snapshot_support": True,
            "create_share_from_snapshot_support": True,
            "revert_to_snapshot_support": True,
            "mount_snapshot_support": True,
            "driver_name": "Dummy",
            "pools": self._get_pools_info(),
            "share_group_stats": {
                "consistent_snapshot_support": "pool",
            }
        }
        if self.configuration.replication_domain:
            data["replication_type"] = "readable"
        super(self.__class__, self)._update_share_stats(data)

    def get_share_server_pools(self, share_server):
        """Return list of pools related to a particular share server."""
        return []

    @slow_me_down
    def create_consistency_group(self, context, cg_dict, share_server=None):
        """Create a consistency group."""
        LOG.debug(
            "Successfully created dummy Consistency Group with ID: %s.",
            cg_dict["id"])

    @slow_me_down
    def delete_consistency_group(self, context, cg_dict, share_server=None):
        """Delete a consistency group."""
        LOG.debug(
            "Successfully deleted dummy consistency group with ID %s.",
            cg_dict["id"])

    @slow_me_down
    def create_cgsnapshot(self, context, snap_dict, share_server=None):
        """Create a consistency group snapshot."""
        LOG.debug("Successfully created CG snapshot %s.", snap_dict["id"])
        return None, None

    @slow_me_down
    def delete_cgsnapshot(self, context, snap_dict, share_server=None):
        """Delete a consistency group snapshot."""
        LOG.debug("Successfully deleted CG snapshot %s.", snap_dict["id"])
        return None, None

    @slow_me_down
    def create_consistency_group_from_cgsnapshot(
            self, context, cg_dict, cgsnapshot_dict, share_server=None):
        """Create a consistency group from a cgsnapshot."""
        LOG.debug(
            ("Successfully created dummy Consistency Group (%(cg_id)s) "
             "from CG snapshot (%(cg_snap_id)s)."),
            {"cg_id": cg_dict["id"], "cg_snap_id": cgsnapshot_dict["id"]})
        return None, []

    @slow_me_down
    def create_replica(self, context, replica_list, new_replica,
                       access_rules, replica_snapshots, share_server=None):
        """Replicate the active replica to a new replica on this backend."""
        replica_name = self._get_share_name(new_replica)
        mountpoint = "/path/to/fake/share/%s" % replica_name
        self.private_storage.update(
            new_replica["id"], {
                "fake_provider_replica_name": replica_name,
                "fake_provider_location": mountpoint,
            }
        )
        return {
            "export_locations": self._generate_export_locations(
                mountpoint, share_server=share_server),
            "replica_state": constants.REPLICA_STATE_IN_SYNC,
            "access_rules_status": constants.STATUS_ACTIVE,
        }

    @slow_me_down
    def delete_replica(self, context, replica_list, replica_snapshots,
                       replica, share_server=None):
        """Delete a replica."""
        self.private_storage.delete(replica["id"])

    @slow_me_down
    def promote_replica(self, context, replica_list, replica, access_rules,
                        share_server=None):
        """Promote a replica to 'active' replica state."""
        return_replica_list = []
        for r in replica_list:
            if r["id"] == replica["id"]:
                replica_state = constants.REPLICA_STATE_ACTIVE
            else:
                replica_state = constants.REPLICA_STATE_IN_SYNC
            return_replica_list.append(
                {"id": r["id"], "replica_state": replica_state})
        return return_replica_list

    @slow_me_down
    def update_replica_state(self, context, replica_list, replica,
                             access_rules, replica_snapshots,
                             share_server=None):
        """Update the replica_state of a replica."""
        return constants.REPLICA_STATE_IN_SYNC

    @slow_me_down
    def create_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots, share_server=None):
        """Create a snapshot on active instance and update across the replicas.

        """
        return_replica_snapshots = []
        for r in replica_snapshots:
            return_replica_snapshots.append(
                {"id": r["id"], "status": constants.STATUS_AVAILABLE})
        return return_replica_snapshots

    @slow_me_down
    def revert_to_replicated_snapshot(self, context, active_replica,
                                      replica_list, active_replica_snapshot,
                                      replica_snapshots, share_access_rules,
                                      snapshot_access_rules,
                                      share_server=None):
        """Reverts a replicated share (in place) to the specified snapshot."""

    @slow_me_down
    def delete_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots, share_server=None):
        """Delete a snapshot by deleting its instances across the replicas."""
        return_replica_snapshots = []
        for r in replica_snapshots:
            return_replica_snapshots.append(
                {"id": r["id"], "status": constants.STATUS_DELETED})
        return return_replica_snapshots

    @slow_me_down
    def update_replicated_snapshot(self, context, replica_list,
                                   share_replica, replica_snapshots,
                                   replica_snapshot, share_server=None):
        """Update the status of a snapshot instance that lives on a replica."""
        return {
            "id": replica_snapshot["id"], "status": constants.STATUS_AVAILABLE}

    @slow_me_down
    def migration_check_compatibility(
            self, context, source_share, destination_share,
            share_server=None, destination_share_server=None):
        """Is called to test compatibility with destination backend."""
        backend_name = share_utils.extract_host(
            destination_share['host'], level='backend_name')
        config = get_backend_configuration(backend_name)
        compatible = 'Dummy' in config.share_driver
        return {
            'compatible': compatible,
            'writable': compatible,
            'preserve_metadata': compatible,
            'nondisruptive': False,
            'preserve_snapshots': compatible,
        }

    @slow_me_down
    def migration_start(
            self, context, source_share, destination_share, source_snapshots,
            snapshot_mappings, share_server=None,
            destination_share_server=None):
        """Is called to perform 1st phase of driver migration of a given share.

        """
        LOG.debug(
            "Migration of dummy share with ID '%s' has been started.",
            source_share["id"])
        self.migration_progress[source_share['share_id']] = 0

    @slow_me_down
    def migration_continue(
            self, context, source_share, destination_share, source_snapshots,
            snapshot_mappings, share_server=None,
            destination_share_server=None):

        if source_share["id"] not in self.migration_progress:
            self.migration_progress[source_share["id"]] = 0

        self.migration_progress[source_share["id"]] += 50

        LOG.debug(
            "Migration of dummy share with ID '%s' is continuing, %s.",
            source_share["id"],
            self.migration_progress[source_share["id"]])

        return self.migration_progress[source_share["id"]] == 100

    @slow_me_down
    def migration_complete(
            self, context, source_share, destination_share, source_snapshots,
            snapshot_mappings, share_server=None,
            destination_share_server=None):
        """Is called to perform 2nd phase of driver migration of a given share.

        """
        snapshot_updates = {}
        for src_snap_ins, dest_snap_ins in snapshot_mappings.items():
            snapshot_updates[dest_snap_ins['id']] = self._create_snapshot(
                dest_snap_ins)
        return {
            'snapshot_updates': snapshot_updates,
            'export_locations': self._do_migration(
                source_share, destination_share, share_server)
        }

    def _do_migration(self, source_share_ref, dest_share_ref, share_server):
        share_name = self._get_share_name(dest_share_ref)
        mountpoint = "/path/to/fake/share/%s" % share_name
        self.private_storage.delete(source_share_ref["id"])
        self.private_storage.update(
            dest_share_ref["id"], {
                "fake_provider_share_name": share_name,
                "fake_provider_location": mountpoint,
            }
        )
        LOG.debug(
            "Migration of dummy share with ID '%s' has been completed.",
            source_share_ref["id"])
        self.migration_progress.pop(source_share_ref["id"], None)

        return self._generate_export_locations(
            mountpoint, share_server=share_server)

    @slow_me_down
    def migration_cancel(
            self, context, source_share, destination_share, source_snapshots,
            snapshot_mappings, share_server=None,
            destination_share_server=None):
        """Is called to cancel driver migration."""
        LOG.debug(
            "Migration of dummy share with ID '%s' has been canceled.",
            source_share["id"])
        self.migration_progress.pop(source_share["id"], None)

    @slow_me_down
    def migration_get_progress(
            self, context, source_share, destination_share, source_snapshots,
            snapshot_mappings, share_server=None,
            destination_share_server=None):
        """Is called to get migration progress."""
        # Simulate migration progress.
        if source_share["id"] not in self.migration_progress:
            self.migration_progress[source_share["id"]] = 0
        total_progress = self.migration_progress[source_share["id"]]
        LOG.debug("Progress of current dummy share migration "
                  "with ID '%(id)s' is %(progress)s.", {
                      "id": source_share["id"],
                      "progress": total_progress
                  })
        return {"total_progress": total_progress}

    def update_share_usage_size(self, context, shares):
        share_updates = []
        gathered_at = timeutils.utcnow()
        for s in shares:
            share_updates.append({'id': s['id'],
                                  'used_size':  1,
                                  'gathered_at': gathered_at})
        return share_updates
