# Copyright (c) 2014 NetApp Inc.
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
"""NAS share manager managers creating shares and access rights.

**Related Flags**

:share_driver: Used by :class:`ShareManager`.
"""

import copy
import datetime
import functools
import hashlib
import json
from operator import xor

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_service import periodic_task
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import timeutils

from manila.common import constants
from manila import context
from manila import coordination
from manila.data import rpcapi as data_rpcapi
from manila import exception
from manila.i18n import _
from manila import manager
from manila.message import api as message_api
from manila.message import message_field
from manila import quota
from manila.share import access
from manila.share import api
from manila.share import configuration
from manila.share import drivers_private_data
from manila.share import migration
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types
from manila.share import snapshot_access
from manila.share import utils as share_utils
from manila.transfer import api as transfer_api
from manila import utils

profiler = importutils.try_import('osprofiler.profiler')

LOG = log.getLogger(__name__)

share_manager_opts = [
    cfg.StrOpt('share_driver',
               default='manila.share.drivers.generic.GenericShareDriver',
               help='Driver to use for share creation.'),
    cfg.ListOpt('hook_drivers',
                default=[],
                help='Driver(s) to perform some additional actions before and '
                     'after share driver actions and on a periodic basis. '
                     'Default is [].'),
    cfg.BoolOpt('delete_share_server_with_last_share',
                default=False,
                help='Whether share servers will '
                     'be deleted on deletion of the last share.'),
    cfg.BoolOpt('unmanage_remove_access_rules',
                default=False,
                help='If set to True, then manila will deny access and remove '
                     'all access rules on share unmanage.'
                     'If set to False - nothing will be changed.'),
    cfg.BoolOpt('automatic_share_server_cleanup',
                default=True,
                help='If set to True, then Manila will delete all share '
                     'servers which were unused more than specified time .'
                     'If set to False - automatic deletion of share servers '
                     'will be disabled.'),
    cfg.IntOpt('unused_share_server_cleanup_interval',
               default=10,
               help='Unallocated share servers reclamation time interval '
                    '(minutes). Minimum value is 10 minutes, maximum is 60 '
                    'minutes. The reclamation function is run every '
                    '10 minutes and delete share servers which were unused '
                    'more than unused_share_server_cleanup_interval option '
                    'defines. This value reflects the shortest time Manila '
                    'will wait for a share server to go unutilized before '
                    'deleting it.',
               min=10,
               max=60),
    cfg.IntOpt('replica_state_update_interval',
               default=300,
               help='This value, specified in seconds, determines how often '
                    'the share manager will poll for the health '
                    '(replica_state) of each replica instance.'),
    cfg.IntOpt('migration_driver_continue_update_interval',
               default=60,
               help='This value, specified in seconds, determines how often '
                    'the share manager will poll the driver to perform the '
                    'next step of migration in the storage backend, for a '
                    'migrating share.'),
    cfg.IntOpt('server_migration_driver_continue_update_interval',
               default=900,
               help='This value, specified in seconds, determines how often '
                    'the share manager will poll the driver to perform the '
                    'next step of migration in the storage backend, for a '
                    'migrating share server.'),
    cfg.IntOpt('share_usage_size_update_interval',
               default=300,
               help='This value, specified in seconds, determines how often '
                    'the share manager will poll the driver to update the '
                    'share usage size in the storage backend, for shares in '
                    'that backend.'),
    cfg.BoolOpt('enable_gathering_share_usage_size',
                default=False,
                help='If set to True, share usage size will be polled for in '
                     'the interval specified with '
                     '"share_usage_size_update_interval". Usage data can be '
                     'consumed by telemetry integration. If telemetry is not '
                     'configured, this option must be set to False. '
                     'If set to False - gathering share usage size will be'
                     ' disabled.'),
    cfg.BoolOpt('share_service_inithost_offload',
                default=False,
                help='Offload pending share ensure during '
                     'share service startup'),
    cfg.IntOpt('check_for_expired_shares_in_recycle_bin_interval',
               default=3600,
               help='This value, specified in seconds, determines how often '
                    'the share manager will check for expired shares and '
                    'delete them from the Recycle bin.'),
    cfg.IntOpt('check_for_expired_transfers',
               default=300,
               help='This value, specified in seconds, determines how often '
                    'the share manager will check for expired transfers and '
                    'destroy them and roll back share state.'),
    cfg.IntOpt('driver_backup_continue_update_interval',
               default=60,
               help='This value, specified in seconds, determines how often '
                    'the share manager will poll to perform the next steps '
                    'of backup such as fetch the progress of backup.'),
    cfg.IntOpt('driver_restore_continue_update_interval',
               default=60,
               help='This value, specified in seconds, determines how often '
                    'the share manager will poll to perform the next steps '
                    'of restore such as fetch the progress of restore.')
]

CONF = cfg.CONF
CONF.register_opts(share_manager_opts)
CONF.import_opt('periodic_hooks_interval', 'manila.share.hook')
CONF.import_opt('periodic_interval', 'manila.service')

# Drivers that need to change module paths or class names can add their
# old/new path here to maintain backward compatibility.
MAPPING = {
    'manila.share.drivers.netapp.cluster_mode.NetAppClusteredShareDriver':
    'manila.share.drivers.netapp.common.NetAppDriver',
    'manila.share.drivers.hp.hp_3par_driver.HP3ParShareDriver':
    'manila.share.drivers.hpe.hpe_3par_driver.HPE3ParShareDriver',
    'manila.share.drivers.hitachi.hds_hnas.HDSHNASDriver':
    'manila.share.drivers.hitachi.hnas.driver.HitachiHNASDriver',
    'manila.share.drivers.glusterfs_native.GlusterfsNativeShareDriver':
    'manila.share.drivers.glusterfs.glusterfs_native.'
    'GlusterfsNativeShareDriver',
    'manila.share.drivers.emc.driver.EMCShareDriver':
    'manila.share.drivers.dell_emc.driver.EMCShareDriver',
    'manila.share.drivers.cephfs.cephfs_native.CephFSNativeDriver':
    'manila.share.drivers.cephfs.driver.CephFSDriver',
}

QUOTAS = quota.QUOTAS


def locked_share_replica_operation(operation):
    """Lock decorator for share replica operations.

    Takes a named lock prior to executing the operation. The lock is named with
    the id of the share to which the replica belongs.

    Intended use:
    If a replica operation uses this decorator, it will block actions on
    all share replicas of the share until the named lock is free. This is
    used to protect concurrent operations on replicas of the same share e.g.
    promote ReplicaA while deleting ReplicaB, both belonging to the same share.
    """

    def wrapped(*args, **kwargs):
        share_id = kwargs.get('share_id')

        @coordination.synchronized(
            'locked-share-replica-operation-for-share-%s' % share_id)
        def locked_replica_operation(*_args, **_kwargs):
            return operation(*_args, **_kwargs)
        return locked_replica_operation(*args, **kwargs)

    return wrapped


def locked_share_network_operation(operation):
    """Lock decorator for share network operations.

    Takes a named lock prior to executing the operation. The lock is named with
    the id of the share network.
    """

    def wrapped(*args, **kwargs):
        share_network_id = kwargs.get('share_network_id')

        @coordination.synchronized(
            'locked-share-network-operation-%s' % share_network_id)
        def locked_network_operation(*_args, **_kwargs):
            return operation(*_args, **_kwargs)
        return locked_network_operation(*args, **kwargs)

    return wrapped


def add_hooks(f):
    """Hook decorator to perform action before and after a share method call

    The hook decorator can perform actions before some share driver methods
    calls and after a call with results of driver call and preceding hook call.
    """
    @functools.wraps(f)
    def wrapped(self, *args, **kwargs):
        if not self.hooks:
            return f(self, *args, **kwargs)

        pre_hook_results = []
        for hook in self.hooks:
            pre_hook_results.append(
                hook.execute_pre_hook(
                    func_name=f.__name__,
                    *args, **kwargs))

        wrapped_func_results = f(self, *args, **kwargs)

        for i, hook in enumerate(self.hooks):
            hook.execute_post_hook(
                func_name=f.__name__,
                driver_action_results=wrapped_func_results,
                pre_hook_data=pre_hook_results[i],
                *args, **kwargs)

        return wrapped_func_results

    return wrapped


class ShareManager(manager.SchedulerDependentManager):
    """Manages NAS storages."""

    RPC_API_VERSION = '1.26'

    def __init__(self, share_driver=None, service_name=None, *args, **kwargs):
        """Load the driver from args, or from flags."""
        self.configuration = configuration.Configuration(
            share_manager_opts,
            config_group=service_name)
        super(ShareManager, self).__init__(service_name='share',
                                           *args, **kwargs)

        if not share_driver:
            share_driver = self.configuration.share_driver
        if share_driver in MAPPING:
            msg_args = {'old': share_driver, 'new': MAPPING[share_driver]}
            LOG.warning("Driver path %(old)s is deprecated, update your "
                        "configuration to the new path %(new)s",
                        msg_args)
            share_driver = MAPPING[share_driver]

        ctxt = context.get_admin_context()
        private_storage = drivers_private_data.DriverPrivateData(
            context=ctxt, backend_host=self.host,
            config_group=self.configuration.config_group
        )
        self.driver = importutils.import_object(
            share_driver, private_storage=private_storage,
            configuration=self.configuration,
        )

        backend_availability_zone = self.driver.configuration.safe_get(
            'backend_availability_zone')
        self.availability_zone = (
            backend_availability_zone or CONF.storage_availability_zone
        )

        self.access_helper = access.ShareInstanceAccess(self.db, self.driver)
        self.snapshot_access_helper = (
            snapshot_access.ShareSnapshotInstanceAccess(self.db, self.driver))
        self.migration_wait_access_rules_timeout = (
            CONF.migration_wait_access_rules_timeout)

        self.message_api = message_api.API()
        self.share_api = api.API()
        self.transfer_api = transfer_api.API()
        if CONF.profiler.enabled and profiler is not None:
            self.driver = profiler.trace_cls("driver")(self.driver)
        self.hooks = []
        self._init_hook_drivers()
        self.service_id = None

    def _init_hook_drivers(self):
        # Try to initialize hook driver(s).
        hook_drivers = self.configuration.safe_get("hook_drivers")
        for hook_driver in hook_drivers:
            self.hooks.append(
                importutils.import_object(
                    hook_driver,
                    configuration=self.configuration,
                    host=self.host,
                )
            )

    def _ensure_share_instance_has_pool(self, ctxt, share_instance):
        pool = share_utils.extract_host(share_instance['host'], 'pool')
        if pool is None:
            # No pool name encoded in host, so this is a legacy
            # share created before pool is introduced, ask
            # driver to provide pool info if it has such
            # knowledge and update the DB.
            try:
                pool = self.driver.get_pool(share_instance)
            except Exception:
                LOG.exception("Failed to fetch pool name for share: "
                              "%(share)s.",
                              {'share': share_instance['id']})
                return

            if pool:
                new_host = share_utils.append_host(
                    share_instance['host'], pool)
                self.db.share_instance_update(
                    ctxt, share_instance['id'], {'host': new_host})

        return pool

    @add_hooks
    def init_host(self, service_id=None):
        """Initialization for a standalone service."""

        self.service_id = service_id
        ctxt = context.get_admin_context()
        driver_host_pair = "{}@{}".format(
            self.driver.__class__.__name__,
            self.host)

        # we want to retry to setup the driver. In case of a multi-backend
        # scenario, working backends are usable and the non-working ones (where
        # do_setup() or check_for_setup_error() fail) retry.
        @utils.retry(interval=2, backoff_rate=2,
                     infinite=True, backoff_sleep_max=600)
        def _driver_setup():
            self.driver.initialized = False
            LOG.debug("Start initialization of driver: '%s'", driver_host_pair)
            try:
                self.driver.do_setup(ctxt)
                self.driver.check_for_setup_error()
            except Exception:
                LOG.exception("Error encountered during initialization of "
                              "driver %s", driver_host_pair)
                raise
            else:
                self.driver.initialized = True

        _driver_setup()
        if (self.driver.driver_handles_share_servers and
                hasattr(self.driver, 'service_instance_manager')):
            (self.driver.service_instance_manager.network_helper.
             setup_connectivity_with_service_instances())

        self.ensure_driver_resources(ctxt)

        self.publish_service_capabilities(ctxt)
        LOG.info("Finished initialization of driver: '%(driver)s"
                 "@%(host)s'",
                 {"driver": self.driver.__class__.__name__,
                  "host": self.host})

    def is_service_ready(self):
        """Return if Manager is ready to accept requests.

        This is to inform Service class that in case of manila driver
        initialization failure the manager is actually down and not ready to
        accept any requests.

        """
        return self.driver.initialized

    def ensure_driver_resources(self, ctxt):
        old_backend_info = self.db.backend_info_get(ctxt, self.host)
        old_backend_info_hash = (old_backend_info.get('info_hash')
                                 if old_backend_info is not None else None)
        new_backend_info = None
        new_backend_info_hash = None
        backend_info_implemented = True
        update_share_instances = []
        try:
            new_backend_info = self.driver.get_backend_info(ctxt)
        except Exception as e:
            if not isinstance(e, NotImplementedError):
                LOG.exception(
                    "The backend %(host)s could not get backend info.",
                    {'host': self.host})
                raise
            else:
                backend_info_implemented = False
                LOG.debug(
                    ("The backend %(host)s does not support get backend"
                     " info method."),
                    {'host': self.host})

        if new_backend_info:
            new_backend_info_hash = hashlib.sha1(str(
                sorted(new_backend_info.items())).encode('utf-8')).hexdigest()
        if (old_backend_info_hash == new_backend_info_hash and
                backend_info_implemented):
            LOG.debug(
                ("Ensure shares is being skipped because the %(host)s's old "
                 "backend info is the same as its new backend info."),
                {'host': self.host})
            return

        share_instances = self.db.share_instances_get_all_by_host(
            ctxt, self.host)
        LOG.debug("Re-exporting %s shares", len(share_instances))

        for share_instance in share_instances:
            share_ref = self.db.share_get(ctxt, share_instance['share_id'])

            if share_ref.is_busy:
                LOG.info(
                    "Share instance %(id)s: skipping export, "
                    "because it is busy with an active task: %(task)s.",
                    {'id': share_instance['id'],
                     'task': share_ref['task_state']},
                )
                continue

            if share_instance['status'] != constants.STATUS_AVAILABLE:
                LOG.info(
                    "Share instance %(id)s: skipping export, "
                    "because it has '%(status)s' status.",
                    {'id': share_instance['id'],
                     'status': share_instance['status']},
                )
                continue

            self._ensure_share_instance_has_pool(ctxt, share_instance)
            share_instance = self.db.share_instance_get(
                ctxt, share_instance['id'], with_share_data=True)
            share_instance_dict = self._get_share_instance_dict(
                ctxt, share_instance)
            update_share_instances.append(share_instance_dict)

        if update_share_instances:
            try:
                update_share_instances = self.driver.ensure_shares(
                    ctxt, update_share_instances) or {}
            except Exception as e:
                if not isinstance(e, NotImplementedError):
                    LOG.exception("Caught exception trying ensure "
                                  "share instances.")
                else:
                    for share_instance in update_share_instances:
                        if CONF.share_service_inithost_offload:
                            self._add_to_threadpool(self._ensure_share,
                                                    ctxt, share_instance)
                        else:
                            self._ensure_share(ctxt, share_instance)

        if new_backend_info:
            self.db.backend_info_update(
                ctxt, self.host, new_backend_info_hash)

        for share_instance in share_instances:
            if share_instance['id'] not in update_share_instances:
                continue
            share_instance_update_dict = (
                update_share_instances[share_instance['id']]
            )
            if share_instance_update_dict.get('status'):
                self.db.share_instance_update(
                    ctxt, share_instance['id'],
                    {'status': share_instance_update_dict.get('status'),
                     'host': share_instance['host']}
                )

            update_export_locations = (
                share_instance_update_dict.get('export_locations')
            )
            if update_export_locations:
                self.db.share_export_locations_update(
                    ctxt, share_instance['id'], update_export_locations)

            share_server = self._get_share_server(ctxt, share_instance)
            driver_has_to_reapply_access_rules = (
                share_instance_update_dict.get('reapply_access_rules') is True
            )
            share_instance_has_pending_rules = (
                share_instance['access_rules_status'] !=
                constants.STATUS_ACTIVE
            )
            if (driver_has_to_reapply_access_rules or
                    share_instance_has_pending_rules):
                try:
                    # Cast any existing 'applying' rules to 'new'
                    self.access_helper.reset_rules_to_queueing_states(
                        ctxt, share_instance['id'],
                        reset_active=driver_has_to_reapply_access_rules)
                    self.access_helper.update_access_rules(
                        ctxt, share_instance['id'], share_server=share_server)
                except Exception:
                    LOG.exception(
                        ("Unexpected error occurred while updating access "
                         "rules for share instance %(s_id)s."),
                        {'s_id': share_instance['id']},
                    )

            snapshot_instances = (
                self.db.share_snapshot_instance_get_all_with_filters(
                    ctxt, {'share_instance_ids': share_instance['id']},
                    with_share_data=True))

            for snap_instance in snapshot_instances:

                rules = (
                    self.db.
                    share_snapshot_access_get_all_for_snapshot_instance(
                        ctxt, snap_instance['id']))

                # NOTE(ganso): We don't invoke update_access for snapshots if
                # we don't have invalid rules or pending updates
                if any(r['state'] in (constants.ACCESS_STATE_DENYING,
                                      constants.ACCESS_STATE_QUEUED_TO_DENY,
                                      constants.ACCESS_STATE_APPLYING,
                                      constants.ACCESS_STATE_QUEUED_TO_APPLY)
                       for r in rules):
                    try:
                        self.snapshot_access_helper.update_access_rules(
                            ctxt, snap_instance['id'], share_server)
                    except Exception:
                        LOG.exception(
                            "Unexpected error occurred while updating "
                            "access rules for snapshot instance %s.",
                            snap_instance['id'])

    def _ensure_share(self, ctxt, share_instance):
        export_locations = None
        try:
            export_locations = self.driver.ensure_share(
                ctxt, share_instance,
                share_server=share_instance['share_server'])
        except Exception:
            LOG.exception("Caught exception trying ensure "
                          "share '%(s_id)s'.",
                          {'s_id': share_instance['id']})
        if export_locations:
            self.db.share_export_locations_update(
                ctxt, share_instance['id'], export_locations)

    def _check_share_server_backend_limits(
            self, context, available_share_servers, share_instance=None):
        max_shares_limit = self.driver.max_shares_per_share_server
        max_server_size = self.driver.max_share_server_size

        if max_server_size == max_shares_limit == -1:
            return available_share_servers

        for ss in available_share_servers[:]:
            share_instances = self.db.share_instances_get_all_by_share_server(
                context, ss['id'], with_share_data=True)
            if not share_instances:
                continue
            share_instance_ids = [si['id'] for si in share_instances]
            share_snapshot_instances = (
                self.db.share_snapshot_instance_get_all_with_filters(
                    context, {"share_instance_ids": share_instance_ids},
                    with_share_data=True))

            server_instances_size_sum = 0
            num_instances = 0

            server_instances_size_sum += sum(
                instance['size'] for instance in share_instances)
            server_instances_size_sum += sum(
                instance['size'] for instance in share_snapshot_instances)
            num_instances += len(share_instances)

            # NOTE(carloss): If a share instance was not provided, means that
            # a share group is being requested and there aren't shares to
            # be added to to the sum yet.
            if share_instance:
                server_instances_size_sum += share_instance['size']
                num_instances += 1

            achieved_gigabytes_limit = (
                max_server_size != -1 and (
                    server_instances_size_sum > max_server_size))

            achieved_instances_limit = num_instances > max_shares_limit > -1

            providing_server_for_share_migration = (
                share_instance and share_instance['status'] ==
                constants.STATUS_MIGRATING_TO)

            src_server_id_equals_current_iteration = False

            if providing_server_for_share_migration:
                share = self.db.share_get(context, share_instance['share_id'])
                src_instance_id, dest_instance_id = (
                    self.share_api.get_migrating_instances(share))
                src_instance = self.db.share_instance_get(
                    context, src_instance_id)
                src_server_id_equals_current_iteration = (
                    src_instance['share_server_id'] == ss['id'])

            if (not src_server_id_equals_current_iteration and (
                    achieved_gigabytes_limit or achieved_instances_limit)):
                available_share_servers.remove(ss)

        return available_share_servers

    def _provide_share_server_for_share(self, context, share_network_id,
                                        share_instance, snapshot=None,
                                        share_group=None,
                                        create_on_backend=True):
        """Gets or creates share_server and updates share with its id.

        Active share_server can be deleted if there are no dependent shares
        on it.
        So we need avoid possibility to delete share_server in time gap
        between reaching active state for share_server and setting up
        share_server_id for share. It is possible, for example, with first
        share creation, which starts share_server creation.
        For this purpose used shared lock between this method and the one
        with deletion of share_server.

        :param context: Current context
        :param share_network_id: Share network where existing share server
                                 should be found or created. If
                                 share_network_id is None method use
                                 share_network_id from provided snapshot.
        :param share_instance: Share Instance model
        :param snapshot: Optional -- Snapshot model
        :param create_on_backend: Boolean. If True, driver will be asked to
                                  create the share server if no share server
                                  is available.

        :returns: dict, dict -- first value is share_server, that
                  has been chosen for share schedule. Second value is
                  share updated with share_server_id.
        """
        if not (share_network_id or snapshot):
            msg = _("'share_network_id' parameter or 'snapshot'"
                    " should be provided. ")
            raise ValueError(msg)

        def error(msg, *args):
            LOG.error(msg, *args)
            self.db.share_instance_update(context, share_instance['id'],
                                          {'status': constants.STATUS_ERROR})
        parent_share_server = None
        parent_share_same_dest = False
        if snapshot:
            parent_share_server_id = (
                snapshot['share']['instance']['share_server_id'])
            try:
                parent_share_server = self.db.share_server_get(
                    context, parent_share_server_id)
            except exception.ShareServerNotFound:
                with excutils.save_and_reraise_exception():
                    error("Parent share server %s does not exist.",
                          parent_share_server_id)

            if parent_share_server['status'] != constants.STATUS_ACTIVE:
                error_params = {
                    'id': parent_share_server_id,
                    'status': parent_share_server['status'],
                }
                msg = _("Parent share server %(id)s has invalid status "
                        "'%(status)s'.")
                error(msg, error_params)
                raise exception.InvalidShareServer(reason=msg % error_params)
            parent_share_same_dest = (snapshot['share']['instance']['host']
                                      == share_instance['host'])
        share_network_subnets = None
        if share_network_id:
            share_network_subnets = (
                self.db.share_network_subnets_get_all_by_availability_zone_id(
                    context, share_network_id,
                    availability_zone_id=share_instance.get(
                        'availability_zone_id')))
            if not share_network_subnets:
                raise exception.ShareNetworkSubnetNotFound(
                    share_network_subnet_id=None)
        elif parent_share_server:
            share_network_subnets = (
                parent_share_server['share_network_subnets'])

        # NOTE(felipe_rodrigues): it can retrieve the available share
        # servers using one single subnet_id from the availability zone
        # subnets, because if the share server has one, it will have
        # all subnets on that availability zone.
        share_network_subnet_id = share_network_subnets[0]['id']

        def get_available_share_servers():
            if parent_share_server and parent_share_same_dest:
                return [parent_share_server]
            else:
                return (
                    self.db
                        .share_server_get_all_by_host_and_share_subnet_valid(
                            context, self.host, share_network_subnet_id)
                )

        @utils.synchronized("share_manager_%s" % share_network_subnet_id,
                            external=True)
        def _wrapped_provide_share_server_for_share():
            try:
                available_share_servers = get_available_share_servers()
            except exception.ShareServerNotFound:
                available_share_servers = None

            # creating from snapshot in the same host must reuse the server,
            # so it ignores the server limits.
            if available_share_servers and not parent_share_same_dest:
                available_share_servers = (
                    self._check_share_server_backend_limits(
                        context, available_share_servers,
                        share_instance=share_instance))

            compatible_share_server = None
            if available_share_servers:
                try:
                    compatible_share_server = (
                        self.driver.choose_share_server_compatible_with_share(
                            context, available_share_servers, share_instance,
                            snapshot=snapshot.instance if snapshot else None,
                            share_group=share_group
                        )
                    )
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        error("Cannot choose compatible share server: %s",
                              e)

            if not compatible_share_server:
                compatible_share_server = self.db.share_server_create(
                    context,
                    {
                        'host': self.host,
                        'share_network_subnets': share_network_subnets,
                        'status': constants.STATUS_CREATING,
                        'security_service_update_support': (
                            self.driver.security_service_update_support),
                        'network_allocation_update_support': (
                            self.driver.network_allocation_update_support),
                    }
                )

            msg = ("Using share_server %(share_server)s for share instance"
                   " %(share_instance_id)s")
            LOG.debug(msg, {
                'share_server': compatible_share_server['id'],
                'share_instance_id': share_instance['id']
            })

            share_instance_ref = self.db.share_instance_update(
                context,
                share_instance['id'],
                {'share_server_id': compatible_share_server['id']},
                with_share_data=True
            )
            if create_on_backend:
                metadata = self._build_server_metadata(
                    share_instance['host'], share_instance['share_type_id'])
                compatible_share_server = (
                    self._create_share_server_in_backend(
                        context, compatible_share_server, metadata))

            return compatible_share_server, share_instance_ref

        return _wrapped_provide_share_server_for_share()

    def _build_server_metadata(self, host, share_type_id):
        return {
            'request_host': host,
            'share_type_id': share_type_id,
        }

    def _provide_share_server_for_migration(self, context,
                                            source_share_server,
                                            new_share_network_id,
                                            availability_zone_id,
                                            destination_host,
                                            create_on_backend=True,
                                            server_metadata=None):
        """Gets or creates share_server for a migration procedure.

        Active share_server can be deleted if there are no dependent shares
        on it.
        So we need avoid possibility to delete share_server in time gap
        between reaching active state for share_server and setting up
        share_server_id for share. It is possible, for example, with first
        share creation, which starts share_server creation.
        For this purpose used shared lock between this method and the one
        with deletion of share_server.

        :param context: Current context
        :param source_share_server: Share server model that will be migrated.
        :param new_share_network_id: Share network where existing share server
            should be found or created.
        :param availability_zone_id: Id of the availability zone where the
            new share server will be placed.
        :param destination_host: The destination host where the new share
            server will be created or retrieved.
        :param create_on_backend: Boolean. If True, driver will be asked to
            create the share server if no share server is available.
        :param server_metadata: dict. Holds some important information that
            can help drivers whether to create a new share server or not.
        :returns: Share server that  has been chosen for share server
            migration.
        """

        share_network_subnets = (
            self.db.share_network_subnets_get_all_by_availability_zone_id(
                context, new_share_network_id,
                availability_zone_id=availability_zone_id))
        if not share_network_subnets:
            raise exception.ShareNetworkSubnetNotFound(
                share_network_subnet_id=None)

        server_metadata = {} if not server_metadata else server_metadata

        @utils.synchronized(
            "share_manager_%s" % share_network_subnets[0]['id'], external=True)
        def _wrapped_provide_share_server_for_migration():
            destination_share_server = self.db.share_server_create(
                context,
                {
                    'host': self.host,
                    'share_network_subnets': share_network_subnets,
                    'status': constants.STATUS_CREATING,
                    'security_service_update_support': (
                        self.driver.security_service_update_support),
                    'network_allocation_update_support': (
                        self.driver.network_allocation_update_support),
                }
            )

            msg = ("Using share_server %(share_server)s as destination for "
                   "migration.")
            LOG.debug(msg, {
                'share_server': destination_share_server['id'],
            })

            if create_on_backend:
                # NOTE(carloss): adding some information about the request, so
                # backends that support share server migration and need to know
                # if the request share server is from a share server migration
                # request can use this metadata to take actions.
                server_metadata['migration_destination'] = True
                server_metadata['request_host'] = destination_host
                server_metadata['source_share_server'] = (
                    source_share_server)
                destination_share_server = (
                    self._create_share_server_in_backend(
                        context, destination_share_server,
                        metadata=server_metadata))

            return destination_share_server

        return _wrapped_provide_share_server_for_migration()

    def _create_share_server_in_backend(self, context, share_server,
                                        metadata):
        """Perform setup_server on backend

        :param metadata: A dictionary, to be passed to driver's setup_server()
        """

        if share_server['status'] == constants.STATUS_CREATING:
            # Create share server on backend with data from db.
            share_server = self._setup_server(context, share_server, metadata)
            LOG.info("Share server created successfully.")
        else:
            LOG.info("Using preexisting share server: "
                     "'%(share_server_id)s'",
                     {'share_server_id': share_server['id']})
        return share_server

    def create_share_server(
            self, context, share_server_id, share_instance_id):
        """Invoked to create a share server in this backend.

        This method is invoked to create the share server defined in the model
        obtained by the supplied id.

        :param context: The 'context.RequestContext' object for the request.
        :param share_server_id: The id of the server to be created.
        :param share_instance_id: The id of the share instance
        """
        share_server = self.db.share_server_get(context, share_server_id)
        share = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)
        metadata = self._build_server_metadata(share['host'],
                                               share['share_type_id'])

        self._create_share_server_in_backend(context, share_server, metadata)

    def provide_share_server(self, context, share_instance_id,
                             share_network_id, snapshot_id=None):
        """Invoked to provide a compatible share server.

        This method is invoked to find a compatible share server among the
        existing ones or create a share server database instance with the share
        server properties that will be used to create the share server later.

        :param context: The 'context.RequestContext' object for the request.
        :param share_instance_id: The id of the share instance whose model
            attributes will be used to provide the share server.
        :param share_network_id: The id of the share network the share server
            to be provided has to be related to.
        :param snapshot_id: The id of the snapshot to be used to obtain the
            share server if applicable.
        :return: The id of the share server that is being provided.
        """
        share_instance = self.db.share_instance_get(context, share_instance_id,
                                                    with_share_data=True)
        snapshot_ref = None
        if snapshot_id:
            snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)

        share_group_ref = None
        if share_instance.get('share_group_id'):
            share_group_ref = self.db.share_group_get(
                context, share_instance['share_group_id'])

        share_server, share_instance = self._provide_share_server_for_share(
            context, share_network_id, share_instance, snapshot_ref,
            share_group_ref, create_on_backend=False)

        return share_server['id']

    def _provide_share_server_for_share_group(self, context,
                                              share_network_id,
                                              share_network_subnets,
                                              share_group_ref,
                                              share_group_snapshot=None):
        """Gets or creates share_server and updates share group with its id.

        Active share_server can be deleted if there are no shares or share
        groups dependent on it.

        So we need avoid possibility to delete share_server in time gap
        between reaching active state for share_server and setting up
        share_server_id for share group. It is possible, for example, with
        first share group creation, which starts share_server creation.
        For this purpose used shared lock between this method and the one
        with deletion of share_server.

        :param context: Current context
        :param share_network_id: Share network where existing share server
                                 should be found or created.
        :param share_network_subnets: Share network subnets where existing
                                      share server should be found or created.
        :param share_group_ref: Share Group model
        :param share_group_snapshot: Optional -- ShareGroupSnapshot model.  If
                                     supplied, driver will use it to choose
                                     the appropriate share server.

        :returns: dict, dict -- first value is share_server, that
                  has been chosen for share group schedule.
                  Second value is share group updated with
                  share_server_id.
        """
        if not share_network_id:
            msg = _("'share_network_id' parameter should be provided. ")
            raise exception.InvalidInput(reason=msg)

        def error(msg, *args):
            LOG.error(msg, *args)
            self.db.share_group_update(
                context, share_group_ref['id'],
                {'status': constants.STATUS_ERROR})

        @utils.synchronized("share_manager_%s" % share_network_id,
                            external=True)
        def _wrapped_provide_share_server_for_share_group():
            # NOTE(felipe_rodrigues): it can retrieve the available share
            # servers using one single subnet_id from the availability zone
            # subnets, because if the share server has one, it will have
            # all subnets on that availability zone.
            share_network_subnet_id = share_network_subnets[0]['id']
            try:
                available_share_servers = (
                    self.db
                        .share_server_get_all_by_host_and_share_subnet_valid(
                            context, self.host, share_network_subnet_id))
            except exception.ShareServerNotFound:
                available_share_servers = None

            compatible_share_server = None

            if available_share_servers:
                available_share_servers = (
                    self._check_share_server_backend_limits(
                        context, available_share_servers))

            choose_share_server = (
                self.driver.choose_share_server_compatible_with_share_group)

            if available_share_servers:
                try:
                    compatible_share_server = choose_share_server(
                        context, available_share_servers, share_group_ref,
                        share_group_snapshot=share_group_snapshot,
                    )
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        error("Cannot choose compatible share-server: %s",
                              e)

            if not compatible_share_server:
                compatible_share_server = self.db.share_server_create(
                    context,
                    {
                        'host': self.host,
                        'share_network_subnets': share_network_subnets,
                        'status': constants.STATUS_CREATING,
                        'security_service_update_support': (
                            self.driver.security_service_update_support),
                        'network_allocation_update_support': (
                            self.driver.network_allocation_update_support),
                    }
                )

            msg = ("Using share_server %(share_server)s for share "
                   "group %(group_id)s")
            LOG.debug(msg, {
                'share_server': compatible_share_server['id'],
                'group_id': share_group_ref['id']
            })

            updated_share_group = self.db.share_group_update(
                context,
                share_group_ref['id'],
                {'share_server_id': compatible_share_server['id']},
            )

            if compatible_share_server['status'] == constants.STATUS_CREATING:
                # Create share server on backend with data from db.
                metadata = self._build_server_metadata(
                    share_group_ref['host'],
                    share_group_ref['share_types'][0]['share_type_id'])
                compatible_share_server = self._setup_server(
                    context, compatible_share_server, metadata)
                LOG.info("Share server created successfully.")
            else:
                LOG.info("Used preexisting share server "
                         "'%(share_server_id)s'",
                         {'share_server_id': compatible_share_server['id']})
            return compatible_share_server, updated_share_group

        return _wrapped_provide_share_server_for_share_group()

    def _get_share_server(self, context, share_instance):
        if share_instance['share_server_id']:
            return self.db.share_server_get(
                context, share_instance['share_server_id'])
        else:
            return None

    @utils.require_driver_initialized
    def connection_get_info(self, context, share_instance_id):
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        share_server = None
        if share_instance.get('share_server_id'):
            share_server = self.db.share_server_get(
                context, share_instance['share_server_id'])

        return self.driver.connection_get_info(context, share_instance,
                                               share_server)

    def _migration_start_driver(
            self, context, share_ref, src_share_instance, dest_host, writable,
            preserve_metadata, nondisruptive, preserve_snapshots,
            new_share_network_id, new_az_id, new_share_type_id):

        share_server = self._get_share_server(context, src_share_instance)

        request_spec, dest_share_instance = (
            self.share_api.create_share_instance_and_get_request_spec(
                context, share_ref, new_az_id, None, dest_host,
                new_share_network_id, new_share_type_id))

        self.db.share_instance_update(
            context, dest_share_instance['id'],
            {'status': constants.STATUS_MIGRATING_TO})

        # refresh and obtain proxified properties
        dest_share_instance = self.db.share_instance_get(
            context, dest_share_instance['id'], with_share_data=True)

        helper = migration.ShareMigrationHelper(
            context, self.db, self.access_helper)

        try:
            if dest_share_instance['share_network_id']:
                # NOTE(carloss): For a nondisruptive migration request, we must
                # not change the share server, otherwise the share's export
                # location will change, disconnecting the user. Disruptive
                # migration requests the share server from the driver.
                if nondisruptive:
                    dest_share_server = self._get_share_server_dict(
                        context, share_server)
                    dest_share_instance = self.db.share_instance_update(
                        context,
                        dest_share_instance['id'],
                        {'share_server_id': dest_share_server['id']},
                        with_share_data=True
                    )
                else:
                    rpcapi = share_rpcapi.ShareAPI()

                    # NOTE(ganso): Obtaining the share_server_id asynchronously
                    # so we can wait for it to be ready.
                    dest_share_server_id = rpcapi.provide_share_server(
                        context, dest_share_instance,
                        dest_share_instance['share_network_id'])

                    rpcapi.create_share_server(
                        context, dest_share_instance, dest_share_server_id)

                    dest_share_server = helper.wait_for_share_server(
                        dest_share_server_id)

            else:
                dest_share_server = None

            compatibility = self.driver.migration_check_compatibility(
                context, src_share_instance, dest_share_instance,
                share_server, dest_share_server)

            if not compatibility.get('compatible'):
                msg = _("Destination host %(host)s is not compatible with "
                        "share %(share)s's source backend for driver-assisted "
                        "migration.") % {
                    'host': dest_host,
                    'share': share_ref['id'],
                }
                raise exception.ShareMigrationFailed(reason=msg)

            if (not compatibility.get('nondisruptive') and
                    nondisruptive):
                msg = _("Driver cannot perform a non-disruptive migration of "
                        "share %s.") % share_ref['id']
                raise exception.ShareMigrationFailed(reason=msg)

            if (not compatibility.get('preserve_metadata') and
                    preserve_metadata):
                msg = _("Driver cannot perform migration of share %s while "
                        "preserving all metadata.") % share_ref['id']
                raise exception.ShareMigrationFailed(reason=msg)

            if not compatibility.get('writable') and writable:
                msg = _("Driver cannot perform migration of share %s while "
                        "remaining writable.") % share_ref['id']
                raise exception.ShareMigrationFailed(reason=msg)

            if (not compatibility.get('preserve_snapshots') and
                    preserve_snapshots):
                msg = _("Driver cannot perform migration of share %s while "
                        "preserving snapshots.") % share_ref['id']
                raise exception.ShareMigrationFailed(reason=msg)

            snapshot_mapping = {}
            src_snap_instances = []
            src_snapshots = self.db.share_snapshot_get_all_for_share(
                context, share_ref['id'])

            if compatibility.get('preserve_snapshots'):

                # Make sure all snapshots are 'available'
                if any(x['status'] != constants.STATUS_AVAILABLE
                       for x in src_snapshots):
                    msg = _(
                        "All snapshots must have '%(status)s' status to be "
                        "migrated by the driver along with share "
                        "%(share)s.") % {
                        'share': share_ref['id'],
                        'status': constants.STATUS_AVAILABLE
                    }
                    raise exception.ShareMigrationFailed(reason=msg)

                src_snap_instances = [x.instance for x in src_snapshots]

                dest_snap_instance_data = {
                    'status': constants.STATUS_MIGRATING_TO,
                    'progress': '0%',
                    'share_instance_id': dest_share_instance['id'],
                }

                for snap_instance in src_snap_instances:
                    snapshot_mapping[snap_instance['id']] = (
                        self.db.share_snapshot_instance_create(
                            context, snap_instance['snapshot_id'],
                            dest_snap_instance_data))
                    self.db.share_snapshot_instance_update(
                        context, snap_instance['id'],
                        {'status': constants.STATUS_MIGRATING})

            else:
                if src_snapshots:
                    msg = _("Driver does not support preserving snapshots, "
                            "driver-assisted migration cannot proceed while "
                            "share %s has snapshots.") % share_ref['id']
                    raise exception.ShareMigrationFailed(reason=msg)

            if not compatibility.get('writable'):
                self._cast_access_rules_to_readonly(
                    context, src_share_instance, share_server)

            LOG.debug("Initiating driver migration for share %s.",
                      share_ref['id'])

            self.db.share_update(
                context, share_ref['id'],
                {'task_state': (
                    constants.TASK_STATE_MIGRATION_DRIVER_STARTING)})

            self.driver.migration_start(
                context, src_share_instance, dest_share_instance,
                src_snap_instances, snapshot_mapping, share_server,
                dest_share_server)

            self.db.share_update(
                context, share_ref['id'],
                {'task_state': (
                    constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)})

        except Exception:
            # NOTE(ganso): Cleaning up error'ed destination share instance from
            # database. It is assumed that driver cleans up leftovers in
            # backend when migration fails.
            share_types.revert_allocated_share_type_quotas_during_migration(
                context, src_share_instance,
                src_share_instance['share_type_id'])
            self._migration_delete_instance(context, dest_share_instance['id'])
            self._restore_migrating_snapshots_status(
                context, src_share_instance['id'])

            # NOTE(ganso): Read only access rules and share instance status
            # will be restored in migration_start's except block.

            # NOTE(ganso): For now source share instance should remain in
            # migrating status for host-assisted migration.
            msg = _("Driver-assisted migration of share %s "
                    "failed.") % share_ref['id']
            LOG.exception(msg)
            raise exception.ShareMigrationFailed(reason=msg)

        return True

    def _cast_access_rules_to_readonly(self, context, src_share_instance,
                                       share_server, dest_host=None):
        self._cast_access_rules_to_readonly_for_server(
            context, [src_share_instance], share_server, dest_host=dest_host)

    def _cast_access_rules_to_readonly_for_server(
            self, context, src_share_instances, share_server, dest_host=None):
        for src_share_instance in src_share_instances:
            self.db.share_instance_update(
                context, src_share_instance['id'],
                {'cast_rules_to_readonly': True})

            # Set all 'applying' or 'active' rules to 'queued_to_apply'. Since
            # the share instance has its cast_rules_to_readonly attribute set
            # to True, existing rules will be cast to read/only.
            acceptable_past_states = (constants.ACCESS_STATE_APPLYING,
                                      constants.ACCESS_STATE_ACTIVE)
            new_state = constants.ACCESS_STATE_QUEUED_TO_APPLY
            conditionally_change = {k: new_state
                                    for k in acceptable_past_states}
            self.access_helper.get_and_update_share_instance_access_rules(
                context, share_instance_id=src_share_instance['id'],
                conditionally_change=conditionally_change)

        src_share_instance_ids = [x.id for x in src_share_instances]
        share_server_id = share_server['id'] if share_server else None
        if dest_host:
            rpcapi = share_rpcapi.ShareAPI()
            rpcapi.update_access_for_instances(context,
                                               dest_host,
                                               src_share_instance_ids,
                                               share_server_id)
        else:
            self.update_access_for_instances(context, src_share_instance_ids,
                                             share_server_id=share_server_id)

        for src_share_instance in src_share_instances:
            utils.wait_for_access_update(
                context, self.db, src_share_instance,
                self.migration_wait_access_rules_timeout)

    def _reset_read_only_access_rules(
            self, context, share_instance_id, supress_errors=True,
            helper=None):
        instance = self.db.share_instance_get(context, share_instance_id,
                                              with_share_data=True)
        share_server = self._get_share_server(context, instance)
        self._reset_read_only_access_rules_for_server(
            context, [instance], share_server, supress_errors, helper)

    def _reset_read_only_access_rules_for_server(
            self, context, share_instances, share_server,
            supress_errors=True, helper=None, dest_host=None):
        if helper is None:
            helper = migration.ShareMigrationHelper(
                context, self.db, self.access_helper)

        instances_to_update = []
        for share_instance in share_instances:
            instance = self.db.share_instance_get(context,
                                                  share_instance['id'],
                                                  with_share_data=True)
            if instance['cast_rules_to_readonly']:
                update = {'cast_rules_to_readonly': False}
                instances_to_update.append(share_instance)

                self.db.share_instance_update(
                    context, share_instance['id'], update)

        if instances_to_update:
            if supress_errors:
                helper.cleanup_access_rules(instances_to_update,
                                            share_server,
                                            dest_host)
            else:
                helper.revert_access_rules(instances_to_update,
                                           share_server,
                                           dest_host)

    @periodic_task.periodic_task(
        spacing=CONF.migration_driver_continue_update_interval)
    @utils.require_driver_initialized
    def migration_driver_continue(self, context):
        """Invokes driver to continue migration of shares."""

        instances = self.db.share_instances_get_all_by_host(
            context, self.host, with_share_data=True)

        for instance in instances:

            if instance['status'] != constants.STATUS_MIGRATING:
                continue

            share = self.db.share_get(context, instance['share_id'])

            if share['task_state'] == (
                    constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):

                src_share_instance_id, dest_share_instance_id = (
                    self.share_api.get_migrating_instances(share))

                src_share_instance = instance

                dest_share_instance = self.db.share_instance_get(
                    context, dest_share_instance_id, with_share_data=True)

                src_share_server = self._get_share_server(
                    context, src_share_instance)

                dest_share_server = self._get_share_server(
                    context, dest_share_instance)

                src_snap_instances, snapshot_mappings = (
                    self._get_migrating_snapshots(context, src_share_instance,
                                                  dest_share_instance))

                try:

                    finished = self.driver.migration_continue(
                        context, src_share_instance, dest_share_instance,
                        src_snap_instances, snapshot_mappings,
                        src_share_server, dest_share_server)

                    if finished:
                        self.db.share_update(
                            context, instance['share_id'],
                            {'task_state':
                                (constants.
                                 TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)})

                        LOG.info("Share Migration for share %s completed "
                                 "first phase successfully.",
                                 share['id'])
                    else:
                        share = self.db.share_get(
                            context, instance['share_id'])

                        if (share['task_state'] ==
                                constants.TASK_STATE_MIGRATION_CANCELLED):
                            LOG.warning(
                                "Share Migration for share %s was cancelled.",
                                share['id'])

                except Exception:

                    (share_types.
                        revert_allocated_share_type_quotas_during_migration(
                            context, src_share_instance,
                            dest_share_instance['share_type_id']))
                    # NOTE(ganso): Cleaning up error'ed destination share
                    # instance from database. It is assumed that driver cleans
                    # up leftovers in backend when migration fails.
                    self._migration_delete_instance(
                        context, dest_share_instance['id'])
                    self._restore_migrating_snapshots_status(
                        context, src_share_instance['id'])
                    self._reset_read_only_access_rules(
                        context, src_share_instance_id)
                    self.db.share_instance_update(
                        context, src_share_instance_id,
                        {'status': constants.STATUS_AVAILABLE})

                    self.db.share_update(
                        context, instance['share_id'],
                        {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
                    msg = _("Driver-assisted migration of share %s "
                            "failed.") % share['id']
                    LOG.exception(msg)

    def _get_migrating_snapshots(
            self, context, src_share_instance, dest_share_instance):

        dest_snap_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context,
                {'share_instance_ids': [dest_share_instance['id']]}))

        snapshot_mappings = {}
        src_snap_instances = []
        if len(dest_snap_instances) > 0:
            src_snap_instances = (
                self.db.share_snapshot_instance_get_all_with_filters(
                    context,
                    {'share_instance_ids': [src_share_instance['id']]}))
            for snap in src_snap_instances:
                dest_snap_instance = next(
                    x for x in dest_snap_instances
                    if snap['snapshot_id'] == x['snapshot_id'])
                snapshot_mappings[snap['id']] = dest_snap_instance

        return src_snap_instances, snapshot_mappings

    def _restore_migrating_snapshots_status(
            self, context, src_share_instance_id,
            errored_dest_instance_id=None):
        filters = {'share_instance_ids': [src_share_instance_id]}
        status = constants.STATUS_AVAILABLE
        if errored_dest_instance_id:
            filters['share_instance_ids'].append(errored_dest_instance_id)
            status = constants.STATUS_ERROR
        snap_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, filters)
        )
        for instance in snap_instances:
            if instance['status'] == constants.STATUS_MIGRATING:
                self.db.share_snapshot_instance_update(
                    context, instance['id'], {'status': status})
            elif (errored_dest_instance_id and
                  instance['status'] == constants.STATUS_MIGRATING_TO):
                self.db.share_snapshot_instance_update(
                    context, instance['id'], {'status': status})

    @utils.require_driver_initialized
    def migration_start(
            self, context, share_id, dest_host, force_host_assisted_migration,
            preserve_metadata, writable, nondisruptive, preserve_snapshots,
            new_share_network_id=None, new_share_type_id=None):
        """Migrates a share from current host to another host."""
        LOG.debug("Entered migration_start method for share %s.", share_id)

        self.db.share_update(
            context, share_id,
            {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS})

        share_ref = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share_ref)
        success = False

        host_value = share_utils.extract_host(dest_host)
        service = self.db.service_get_by_args(
            context, host_value, 'manila-share')
        new_az_id = service['availability_zone_id']

        if not force_host_assisted_migration:

            try:
                success = self._migration_start_driver(
                    context, share_ref, share_instance, dest_host, writable,
                    preserve_metadata, nondisruptive, preserve_snapshots,
                    new_share_network_id, new_az_id, new_share_type_id)

            except Exception as e:
                if not isinstance(e, NotImplementedError):
                    LOG.exception(
                        ("The driver could not migrate the share %(shr)s"),
                        {'shr': share_id})

        try:

            if not success:
                if (writable or preserve_metadata or nondisruptive or
                        preserve_snapshots):
                    msg = _("Migration for share %s could not be "
                            "performed because host-assisted migration is not "
                            "allowed when share must remain writable, "
                            "preserve snapshots and/or file metadata or be "
                            "performed nondisruptively.") % share_id

                    raise exception.ShareMigrationFailed(reason=msg)

                # We only handle shares without snapshots for now
                snaps = self.db.share_snapshot_get_all_for_share(
                    context, share_id)
                if snaps:
                    msg = _("Share %s must not have snapshots in order to "
                            "perform a host-assisted migration.") % share_id
                    raise exception.ShareMigrationFailed(reason=msg)

                LOG.debug("Starting host-assisted migration "
                          "for share %s.", share_id)

                self.db.share_update(
                    context, share_id,
                    {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS})

                self._migration_start_host_assisted(
                    context, share_ref, share_instance, dest_host,
                    new_share_network_id, new_az_id, new_share_type_id)

        except Exception:
            msg = _("Host-assisted migration failed for share %s.") % share_id
            LOG.exception(msg)
            self.db.share_update(
                context, share_id,
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
            self._reset_read_only_access_rules(
                context, share_instance['id'])
            self.db.share_instance_update(
                context, share_instance['id'],
                {'status': constants.STATUS_AVAILABLE})

            raise exception.ShareMigrationFailed(reason=msg)

    def _migration_start_host_assisted(
            self, context, share, src_share_instance, dest_host,
            new_share_network_id, new_az_id, new_share_type_id):

        rpcapi = share_rpcapi.ShareAPI()

        helper = migration.ShareMigrationHelper(
            context, self.db, self.access_helper)

        share_server = self._get_share_server(context.elevated(),
                                              src_share_instance)

        self._cast_access_rules_to_readonly(
            context, src_share_instance, share_server)

        try:
            dest_share_instance = helper.create_instance_and_wait(
                share, dest_host, new_share_network_id, new_az_id,
                new_share_type_id)

            self.db.share_instance_update(
                context, dest_share_instance['id'],
                {'status': constants.STATUS_MIGRATING_TO})

        except Exception:
            msg = _("Failed to create instance on destination "
                    "backend during migration of share %s.") % share['id']
            LOG.exception(msg)
            raise exception.ShareMigrationFailed(reason=msg)

        ignore_list = self.driver.configuration.safe_get(
            'migration_ignore_files')

        data_rpc = data_rpcapi.DataAPI()

        try:
            src_connection_info = self.driver.connection_get_info(
                context, src_share_instance, share_server)

            dest_connection_info = rpcapi.connection_get_info(
                context, dest_share_instance)

            LOG.debug("Time to start copying in migration"
                      " for share %s.", share['id'])

            data_rpc.migration_start(
                context, share['id'], ignore_list, src_share_instance['id'],
                dest_share_instance['id'], src_connection_info,
                dest_connection_info)

        except Exception:
            msg = _("Failed to obtain migration info from backends or"
                    " invoking Data Service for migration of "
                    "share %s.") % share['id']
            LOG.exception(msg)
            helper.cleanup_new_instance(dest_share_instance)
            raise exception.ShareMigrationFailed(reason=msg)

    def _migration_complete_driver(
            self, context, share_ref, src_share_instance, dest_share_instance):

        share_server = self._get_share_server(context, src_share_instance)
        dest_share_server = self._get_share_server(
            context, dest_share_instance)

        self.db.share_update(
            context, share_ref['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING})

        src_snap_instances, snapshot_mappings = (
            self._get_migrating_snapshots(context, src_share_instance,
                                          dest_share_instance))

        data_updates = self.driver.migration_complete(
            context, src_share_instance, dest_share_instance,
            src_snap_instances, snapshot_mappings, share_server,
            dest_share_server) or {}

        if data_updates.get('export_locations'):
            self.db.share_export_locations_update(
                context, dest_share_instance['id'],
                data_updates['export_locations'])

        snapshot_updates = data_updates.get('snapshot_updates') or {}

        dest_extra_specs = self._get_extra_specs_from_share_type(
            context, dest_share_instance['share_type_id'])

        for src_snap_ins, dest_snap_ins in snapshot_mappings.items():
            model_update = snapshot_updates.get(dest_snap_ins['id']) or {}
            snapshot_export_locations = model_update.pop(
                'export_locations', [])

            model_update['status'] = constants.STATUS_AVAILABLE
            model_update['progress'] = '100%'
            self.db.share_snapshot_instance_update(
                context, dest_snap_ins['id'], model_update)

            if dest_extra_specs['mount_snapshot_support']:

                for el in snapshot_export_locations:
                    values = {
                        'share_snapshot_instance_id': dest_snap_ins['id'],
                        'path': el['path'],
                        'is_admin_only': el['is_admin_only'],
                    }
                    self.db.share_snapshot_instance_export_location_create(
                        context, values)

        helper = migration.ShareMigrationHelper(
            context, self.db, self.access_helper)

        helper.apply_new_access_rules(dest_share_instance, share_ref['id'])

        self._migration_complete_instance(context, share_ref,
                                          src_share_instance['id'],
                                          dest_share_instance['id'])

        share_types.revert_allocated_share_type_quotas_during_migration(
            context, dest_share_instance, src_share_instance['share_type_id'],
            allow_deallocate_from_current_type=True)

        self._migration_delete_instance(context, src_share_instance['id'])

    def _migration_complete_instance(self, context, share_ref,
                                     src_instance_id, dest_instance_id):
        dest_updates = {
            'status': constants.STATUS_AVAILABLE,
            'progress': '100%'
        }
        if share_ref.get('replication_type'):
            dest_updates['replica_state'] = constants.REPLICA_STATE_ACTIVE

        self.db.share_instance_update(context, dest_instance_id, dest_updates)

        self.db.share_instance_update(context, src_instance_id,
                                      {'status': constants.STATUS_INACTIVE})

    def _migration_delete_instance(self, context, instance_id):

        # refresh the share instance model
        share_instance = self.db.share_instance_get(
            context, instance_id, with_share_data=True)

        rules = self.access_helper.get_and_update_share_instance_access_rules(
            context, share_instance_id=instance_id)

        self.access_helper.delete_share_instance_access_rules(
            context, rules, instance_id)

        snap_instances = self.db.share_snapshot_instance_get_all_with_filters(
            context, {'share_instance_ids': [instance_id]})

        for instance in snap_instances:
            self.db.share_snapshot_instance_delete(context, instance['id'])

        self.db.share_instance_delete(context, instance_id)
        LOG.info("Share instance %s: deleted successfully.",
                 instance_id)

        self._check_delete_share_server(context, share_instance=share_instance)

    @utils.require_driver_initialized
    def migration_complete(self, context, src_instance_id, dest_instance_id):

        src_share_instance = self.db.share_instance_get(
            context, src_instance_id, with_share_data=True)
        dest_share_instance = self.db.share_instance_get(
            context, dest_instance_id, with_share_data=True)

        share_ref = self.db.share_get(context, src_share_instance['share_id'])

        LOG.info("Received request to finish Share Migration for "
                 "share %s.", share_ref['id'])

        if share_ref['task_state'] == (
                constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE):

            try:
                self._migration_complete_driver(
                    context, share_ref, src_share_instance,
                    dest_share_instance)

            except Exception:
                msg = _("Driver migration completion failed for"
                        " share %s.") % share_ref['id']
                LOG.exception(msg)

                # NOTE(ganso): If driver fails during migration-complete,
                # all instances are set to error and it is up to the admin
                # to fix the problem to either complete migration
                # manually or clean it up. At this moment, data
                # preservation at the source backend cannot be
                # guaranteed.

                self._restore_migrating_snapshots_status(
                    context, src_share_instance['id'],
                    errored_dest_instance_id=dest_share_instance['id'])
                self.db.share_instance_update(
                    context, src_instance_id,
                    {'status': constants.STATUS_ERROR})
                self.db.share_instance_update(
                    context, dest_instance_id,
                    {'status': constants.STATUS_ERROR})
                self.db.share_update(
                    context, share_ref['id'],
                    {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
                # NOTE(carloss): No need to deallocate quotas allocated during
                # the migration request, since both share instances still exist
                # even they are set to an error state.
                raise exception.ShareMigrationFailed(reason=msg)
        else:
            try:
                self._migration_complete_host_assisted(
                    context, share_ref, src_instance_id,
                    dest_instance_id)
            except Exception:
                msg = _("Host-assisted migration completion failed for"
                        " share %s.") % share_ref['id']
                LOG.exception(msg)
                # NOTE(carloss): No need to deallocate quotas allocated during
                # the migration request, since both source and destination
                # instances will still exist
                self.db.share_update(
                    context, share_ref['id'],
                    {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
                self.db.share_instance_update(
                    context, src_instance_id,
                    {'status': constants.STATUS_AVAILABLE})
                raise exception.ShareMigrationFailed(reason=msg)

        model_update = self._get_extra_specs_from_share_type(
            context, dest_share_instance['share_type_id'])

        model_update['task_state'] = constants.TASK_STATE_MIGRATION_SUCCESS

        self.db.share_update(
            context, dest_share_instance['share_id'], model_update)

        LOG.info("Share Migration for share %s"
                 " completed successfully.", share_ref['id'])

    def _get_extra_specs_from_share_type(self, context, share_type_id):

        share_type = share_types.get_share_type(context, share_type_id)

        return self.share_api.get_share_attributes_from_share_type(share_type)

    def _migration_complete_host_assisted(self, context, share_ref,
                                          src_instance_id, dest_instance_id):

        src_share_instance = self.db.share_instance_get(
            context, src_instance_id, with_share_data=True)
        dest_share_instance = self.db.share_instance_get(
            context, dest_instance_id, with_share_data=True)

        helper = migration.ShareMigrationHelper(
            context, self.db, self.access_helper)

        task_state = share_ref['task_state']
        if task_state in (constants.TASK_STATE_DATA_COPYING_ERROR,
                          constants.TASK_STATE_DATA_COPYING_CANCELLED):
            msg = _("Data copy of host assisted migration for share %s has not"
                    " completed successfully.") % share_ref['id']
            LOG.warning(msg)
            helper.cleanup_new_instance(dest_share_instance)
            cancelled = (
                task_state == constants.TASK_STATE_DATA_COPYING_CANCELLED)
            suppress_errors = True
            if cancelled:
                suppress_errors = False
            self._reset_read_only_access_rules(
                context, src_instance_id,
                supress_errors=suppress_errors, helper=helper)
            self.db.share_instance_update(
                context, src_instance_id,
                {'status': constants.STATUS_AVAILABLE})
            if cancelled:
                self.db.share_update(
                    context, share_ref['id'],
                    {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED})

                LOG.info("Share Migration for share %s"
                         " was cancelled.", share_ref['id'])
                return
            else:
                raise exception.ShareMigrationFailed(reason=msg)

        elif task_state != constants.TASK_STATE_DATA_COPYING_COMPLETED:
            msg = _("Data copy for migration of share %s has not completed"
                    " yet.") % share_ref['id']
            LOG.error(msg)
            raise exception.ShareMigrationFailed(reason=msg)

        self.db.share_update(
            context, share_ref['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING})

        try:
            helper.apply_new_access_rules(dest_share_instance, share_ref['id'])
        except Exception:
            msg = _("Failed to apply new access rules during migration "
                    "of share %s.") % share_ref['id']
            LOG.exception(msg)
            helper.cleanup_new_instance(dest_share_instance)
            self._reset_read_only_access_rules(
                context, src_instance_id, helper=helper,
                supress_errors=True)
            self.db.share_instance_update(
                context, src_instance_id,
                {'status': constants.STATUS_AVAILABLE})

            raise exception.ShareMigrationFailed(reason=msg)

        self._migration_complete_instance(context, share_ref,
                                          src_share_instance['id'],
                                          dest_share_instance['id'])

        # NOTE(carloss): Won't revert allocated quotas for the share type here
        # because the delete_instance_and_wait method will end up calling the
        # delete_share_instance method here in the share manager. When the
        # share instance deletion is requested in the share manager, Manila
        # itself will take care of deallocating the existing quotas for the
        # share instance
        helper.delete_instance_and_wait(src_share_instance)

    @utils.require_driver_initialized
    def migration_cancel(self, context, src_instance_id, dest_instance_id):

        src_share_instance = self.db.share_instance_get(
            context, src_instance_id, with_share_data=True)
        dest_share_instance = self.db.share_instance_get(
            context, dest_instance_id, with_share_data=True)

        share_ref = self.db.share_get(context, src_share_instance['share_id'])

        if share_ref['task_state'] not in (
                constants.TASK_STATE_DATA_COPYING_COMPLETED,
                constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):
            msg = _("Migration of share %s cannot be cancelled at this "
                    "moment.") % share_ref['id']
            raise exception.InvalidShare(reason=msg)

        share_server = self._get_share_server(context, src_share_instance)

        dest_share_server = self._get_share_server(
            context, dest_share_instance)

        helper = migration.ShareMigrationHelper(
            context, self.db, self.access_helper)

        if share_ref['task_state'] == (
                constants.TASK_STATE_DATA_COPYING_COMPLETED):

            self.db.share_instance_update(
                context, dest_share_instance['id'],
                {'status': constants.STATUS_INACTIVE})

            helper.cleanup_new_instance(dest_share_instance)

        else:

            src_snap_instances, snapshot_mappings = (
                self._get_migrating_snapshots(context, src_share_instance,
                                              dest_share_instance))

            self.driver.migration_cancel(
                context, src_share_instance, dest_share_instance,
                src_snap_instances, snapshot_mappings, share_server,
                dest_share_server)

            self._migration_delete_instance(context, dest_share_instance['id'])
            self._restore_migrating_snapshots_status(
                context, src_share_instance['id'])

        self._reset_read_only_access_rules(
            context, src_instance_id, supress_errors=False,
            helper=helper)

        self.db.share_instance_update(
            context, src_instance_id,
            {'status': constants.STATUS_AVAILABLE})

        self.db.share_update(
            context, share_ref['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED})

        share_types.revert_allocated_share_type_quotas_during_migration(
            context, src_share_instance, dest_share_instance['share_type_id'])

        LOG.info("Share Migration for share %s"
                 " was cancelled.", share_ref['id'])

    @utils.require_driver_initialized
    def migration_get_progress(self, context, src_instance_id,
                               dest_instance_id):

        src_share_instance = self.db.share_instance_get(
            context, src_instance_id, with_share_data=True)
        dest_share_instance = self.db.share_instance_get(
            context, dest_instance_id, with_share_data=True)

        share_ref = self.db.share_get(context, src_share_instance['share_id'])

        # Confirm that it is driver migration scenario
        if share_ref['task_state'] != (
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):
            msg = _("Driver is not performing migration for"
                    " share %s at this moment.") % share_ref['id']
            raise exception.InvalidShare(reason=msg)

        share_server = None
        if share_ref.instance.get('share_server_id'):
            share_server = self.db.share_server_get(
                context, src_share_instance['share_server_id'])

        dest_share_server = None
        if dest_share_instance.get('share_server_id'):
            dest_share_server = self.db.share_server_get(
                context, dest_share_instance['share_server_id'])

        src_snap_instances, snapshot_mappings = (
            self._get_migrating_snapshots(context, src_share_instance,
                                          dest_share_instance))

        return self.driver.migration_get_progress(
            context, src_share_instance, dest_share_instance,
            src_snap_instances, snapshot_mappings, share_server,
            dest_share_server)

    def _get_share_instance(self, context, share):
        if isinstance(share, str):
            id = share
        else:
            id = share.instance['id']
        return self.db.share_instance_get(context, id, with_share_data=True)

    @add_hooks
    @utils.require_driver_initialized
    def create_share_instance(self, context, share_instance_id,
                              request_spec=None, filter_properties=None,
                              snapshot_id=None):
        """Creates a share instance."""
        context = context.elevated()

        share_instance = self._get_share_instance(context, share_instance_id)
        share_id = share_instance.get('share_id')
        share_network_id = share_instance.get('share_network_id')
        share = self.db.share_get(context, share_id)

        self._notify_about_share_usage(context, share,
                                       share_instance, "create.start")

        if not share_instance['availability_zone']:
            share_instance = self.db.share_instance_update(
                context, share_instance_id,
                {'availability_zone': self.availability_zone},
                with_share_data=True
            )

        if share_network_id and not self.driver.driver_handles_share_servers:
            self.db.share_instance_update(
                context, share_instance_id, {'status': constants.STATUS_ERROR})
            self.message_api.create(
                context,
                message_field.Action.CREATE,
                share['project_id'],
                resource_type=message_field.Resource.SHARE,
                resource_id=share_id,
                detail=message_field.Detail.UNEXPECTED_NETWORK)
            raise exception.ManilaException(_(
                "Creation of share instance %s failed: driver does not expect "
                "share-network to be provided with current "
                "configuration.") % share_instance_id)

        if snapshot_id is not None:
            snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
            parent_share_server_id = (
                snapshot_ref['share']['instance']['share_server_id'])
        else:
            snapshot_ref = None
            parent_share_server_id = None

        share_group_ref = None
        if share_instance.get('share_group_id'):
            share_group_ref = self.db.share_group_get(
                context, share_instance['share_group_id'])

        if share_network_id or parent_share_server_id:
            try:
                share_server, share_instance = (
                    self._provide_share_server_for_share(
                        context, share_network_id, share_instance,
                        snapshot=snapshot_ref,
                        share_group=share_group_ref,
                    )
                )
            except exception.PortLimitExceeded:
                with excutils.save_and_reraise_exception():
                    error = ("Creation of share instance %s failed: "
                             "failed to allocate network")
                    LOG.error(error, share_instance_id)
                    self.db.share_instance_update(
                        context, share_instance_id,
                        {'status': constants.STATUS_ERROR}
                    )
                    self.message_api.create(
                        context,
                        message_field.Action.CREATE,
                        share['project_id'],
                        resource_type=message_field.Resource.SHARE,
                        resource_id=share_id,
                        detail=(message_field.Detail
                                .SHARE_NETWORK_PORT_QUOTA_LIMIT_EXCEEDED))
            except exception.SecurityServiceFailedAuth:
                with excutils.save_and_reraise_exception():
                    error = ("Provision of share server failed: "
                             "failed to authenticate user "
                             "against security server.")
                    LOG.error(error)
                    self.db.share_instance_update(
                        context, share_instance_id,
                        {'status': constants.STATUS_ERROR}
                    )
                    self.message_api.create(
                        context,
                        message_field.Action.CREATE,
                        share['project_id'],
                        resource_type=message_field.Resource.SHARE,
                        resource_id=share_id,
                        detail=(message_field.Detail
                                .SECURITY_SERVICE_FAILED_AUTH))
            except Exception:
                with excutils.save_and_reraise_exception():
                    error = ("Creation of share instance %s failed: "
                             "failed to get share server.")
                    LOG.error(error, share_instance_id)
                    self.db.share_instance_update(
                        context, share_instance_id,
                        {'status': constants.STATUS_ERROR}
                    )
                    self.message_api.create(
                        context,
                        message_field.Action.CREATE,
                        share['project_id'],
                        resource_type=message_field.Resource.SHARE,
                        resource_id=share_id,
                        detail=message_field.Detail.NO_SHARE_SERVER)

        else:
            share_server = None

        if share_network_id and self.driver.driver_handles_share_servers:
            proto = share_instance.get('share_proto').lower()
            ret_types = (
                self.driver.dhss_mandatory_security_service_association.get(
                    proto))
            if ret_types:
                share_network = self.db.share_network_get(context,
                                                          share_network_id)
                share_network_ss = []
                for security_service in share_network['security_services']:
                    share_network_ss.append(security_service['type'].lower())
                for types in ret_types:
                    if types not in share_network_ss:
                        self.db.share_instance_update(
                            context, share_instance_id,
                            {'status': constants.STATUS_ERROR}
                        )
                        self.message_api.create(
                            context,
                            message_field.Action.CREATE,
                            share['project_id'],
                            resource_type=message_field.Resource.SHARE,
                            resource_id=share_id,
                            detail=(message_field.Detail
                                    .MISSING_SECURITY_SERVICE))
                        raise exception.InvalidRequest(_(
                            "Share network security service association is "
                            "mandatory for protocol %s.") %
                            share_instance.get('share_proto'))

        status = constants.STATUS_AVAILABLE
        try:
            if snapshot_ref:
                # NOTE(dviroel): we need to provide the parent share info to
                # assist drivers that create shares from snapshot in different
                # pools or back ends
                parent_share_instance = self.db.share_instance_get(
                    context, snapshot_ref['share']['instance']['id'],
                    with_share_data=True)
                parent_share_dict = self._get_share_instance_dict(
                    context, parent_share_instance)
                model_update = self.driver.create_share_from_snapshot(
                    context, share_instance, snapshot_ref.instance,
                    share_server=share_server, parent_share=parent_share_dict)
                if isinstance(model_update, list):
                    # NOTE(dviroel): the driver that doesn't implement the new
                    # model_update will return only the export locations
                    export_locations = model_update
                else:
                    # NOTE(dviroel): share status is mandatory when answering
                    # a model update. If not provided, won't be possible to
                    # determine if was successfully created.
                    status = model_update.get('status')
                    if status is None:
                        msg = _("Driver didn't provide a share status.")
                        raise exception.InvalidShareInstance(reason=msg)
                    export_locations = model_update.get('export_locations')
            else:
                export_locations = self.driver.create_share(
                    context, share_instance, share_server=share_server)
            if status not in [constants.STATUS_AVAILABLE,
                              constants.STATUS_CREATING_FROM_SNAPSHOT]:
                msg = _('Driver returned an invalid status: %s') % status
                raise exception.InvalidShareInstance(reason=msg)

            if export_locations:
                self.db.share_export_locations_update(
                    context, share_instance['id'], export_locations)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error("Share instance %s failed on creation.",
                          share_instance_id)
                detail_data = getattr(e, 'detail_data', {})

                def get_export_location(details):
                    if not isinstance(details, dict):
                        return None
                    return details.get('export_locations',
                                       details.get('export_location'))

                export_locations = get_export_location(detail_data)

                if export_locations:
                    self.db.share_export_locations_update(
                        context, share_instance['id'], export_locations)
                else:
                    LOG.warning('Share instance information in exception '
                                'can not be written to db because it '
                                'contains %s and it is not a dictionary.',
                                detail_data)
                self.db.share_instance_update(
                    context, share_instance_id,
                    {'status': constants.STATUS_ERROR}
                )
                self.message_api.create(
                    context,
                    message_field.Action.CREATE,
                    share['project_id'],
                    resource_type=message_field.Resource.SHARE,
                    resource_id=share_id,
                    exception=e)
        else:
            LOG.info("Share instance %s created successfully.",
                     share_instance_id)
            progress = '100%' if status == constants.STATUS_AVAILABLE else '0%'
            updates = {
                'status': status,
                'launched_at': timeutils.utcnow(),
                'progress': progress
            }
            if share.get('replication_type'):
                updates['replica_state'] = constants.REPLICA_STATE_ACTIVE

            self.db.share_instance_update(context, share_instance_id, updates)

            self._notify_about_share_usage(context, share,
                                           share_instance, "create.end")

    def _update_share_instance_access_rules_state(self, context,
                                                  share_instance_id, state):
        """Update the access_rules_status for the share instance."""
        self.access_helper.get_and_update_share_instance_access_rules_status(
            context, status=state, share_instance_id=share_instance_id)

    def _get_replica_snapshots_for_snapshot(self, context, snapshot_id,
                                            active_replica_id,
                                            share_replica_id,
                                            with_share_data=True):
        """Return dict of snapshot instances of active and replica instances.

        This method returns a dict of snapshot instances for snapshot
        referred to by snapshot_id. The dict contains the snapshot instance
        pertaining to the 'active' replica and the snapshot instance
        pertaining to the replica referred to by share_replica_id.
        """
        filters = {
            'snapshot_ids': snapshot_id,
            'share_instance_ids': (share_replica_id, active_replica_id),
        }
        instance_list = self.db.share_snapshot_instance_get_all_with_filters(
            context, filters, with_share_data=with_share_data)

        snapshots = {
            'active_replica_snapshot': self._get_snapshot_instance_dict(
                context,
                list(filter(lambda x:
                            x['share_instance_id'] == active_replica_id,
                            instance_list))[0]),
            'share_replica_snapshot': self._get_snapshot_instance_dict(
                context,
                list(filter(lambda x:
                            x['share_instance_id'] == share_replica_id,
                            instance_list))[0]),
        }

        return snapshots

    @add_hooks
    @utils.require_driver_initialized
    @locked_share_replica_operation
    def create_share_replica(self, context, share_replica_id, share_id=None,
                             request_spec=None, filter_properties=None):
        """Create a share replica."""
        context = context.elevated()
        share_replica = self.db.share_replica_get(
            context, share_replica_id, with_share_data=True,
            with_share_server=True)

        if not share_replica['availability_zone']:
            share_replica = self.db.share_replica_update(
                context, share_replica['id'],
                {'availability_zone': self.availability_zone},
                with_share_data=True
            )

        _active_replica = (
            self.db.share_replicas_get_available_active_replica(
                context, share_replica['share_id'], with_share_data=True,
                with_share_server=True))
        if not _active_replica:
            self.db.share_replica_update(
                context, share_replica['id'],
                {'status': constants.STATUS_ERROR,
                 'replica_state': constants.STATUS_ERROR})
            self.message_api.create(
                context,
                message_field.Action.CREATE,
                share_replica['project_id'],
                resource_type=message_field.Resource.SHARE_REPLICA,
                resource_id=share_replica['id'],
                detail=message_field.Detail.NO_ACTIVE_REPLICA)
            msg = _("An 'active' replica must exist in 'available' "
                    "state to create a new replica for share %s.")
            raise exception.ReplicationException(
                reason=msg % share_replica['share_id'])

        # We need the share_network_id in case of
        # driver_handles_share_server=True
        share_network_id = share_replica.get('share_network_id', None)
        if xor(bool(share_network_id),
               self.driver.driver_handles_share_servers):
            self.db.share_replica_update(
                context, share_replica['id'],
                {'status': constants.STATUS_ERROR,
                 'replica_state': constants.STATUS_ERROR})
            self.message_api.create(
                context,
                message_field.Action.CREATE,
                share_replica['project_id'],
                resource_type=message_field.Resource.SHARE_REPLICA,
                resource_id=share_replica['id'],
                detail=message_field.Detail.UNEXPECTED_NETWORK)
            raise exception.InvalidDriverMode(
                "The share-network value provided does not match with the "
                "current driver configuration.")

        if share_network_id:
            try:
                share_server, share_replica = (
                    self._provide_share_server_for_share(
                        context, share_network_id, share_replica)
                )
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error("Failed to get share server "
                              "for share replica creation.")
                    self.db.share_replica_update(
                        context, share_replica['id'],
                        {'status': constants.STATUS_ERROR,
                         'replica_state': constants.STATUS_ERROR})
                    self.message_api.create(
                        context,
                        message_field.Action.CREATE,
                        share_replica['project_id'],
                        resource_type=message_field.Resource.SHARE_REPLICA,
                        resource_id=share_replica['id'],
                        detail=message_field.Detail.NO_SHARE_SERVER)
        else:
            share_server = None

        # Map the existing access rules for the share to
        # the replica in the DB.
        share_access_rules = self.db.share_instance_access_copy(
            context, share_replica['share_id'], share_replica['id'])

        # Get snapshots for the share.
        share_snapshots = self.db.share_snapshot_get_all_for_share(
            context, share_id)
        # Get the required data for snapshots that have 'aggregate_status'
        # set to 'available'.
        available_share_snapshots = [
            self._get_replica_snapshots_for_snapshot(
                context, x['id'], _active_replica['id'], share_replica_id)
            for x in share_snapshots
            if x['aggregate_status'] == constants.STATUS_AVAILABLE]

        replica_list = (
            self.db.share_replicas_get_all_by_share(
                context, share_replica['share_id'],
                with_share_data=True, with_share_server=True)
        )

        replica_list = [self._get_share_instance_dict(context, r)
                        for r in replica_list]
        share_replica = self._get_share_instance_dict(context, share_replica)

        try:
            replica_ref = self.driver.create_replica(
                context, replica_list, share_replica,
                share_access_rules, available_share_snapshots,
                share_server=share_server) or {}

        except Exception as excep:
            with excutils.save_and_reraise_exception():
                LOG.error("Share replica %s failed on creation.",
                          share_replica['id'])
                self.db.share_replica_update(
                    context, share_replica['id'],
                    {'status': constants.STATUS_ERROR,
                     'replica_state': constants.STATUS_ERROR})
                self._update_share_instance_access_rules_state(
                    context, share_replica['id'], constants.STATUS_ERROR)
                self.message_api.create(
                    context,
                    message_field.Action.CREATE,
                    share_replica['project_id'],
                    resource_type=message_field.Resource.SHARE_REPLICA,
                    resource_id=share_replica['id'],
                    exception=excep)

        if replica_ref.get('export_locations'):
            if isinstance(replica_ref.get('export_locations'), list):
                self.db.share_export_locations_update(
                    context, share_replica['id'],
                    replica_ref.get('export_locations'))
            else:
                msg = ('Invalid export locations passed to the share '
                       'manager.')
                LOG.warning(msg)

        if replica_ref.get('replica_state'):
            self.db.share_replica_update(
                context, share_replica['id'],
                {'status': constants.STATUS_AVAILABLE,
                 'replica_state': replica_ref.get('replica_state'),
                 'progress': '100%'})

        reported_access_rules_status = replica_ref.get('access_rules_status')
        if reported_access_rules_status in (None, "active"):
            # update all rules to "active"
            conditionally_change = {'queued_to_apply': 'active'}
            self.access_helper.get_and_update_share_instance_access_rules(
                context, share_instance_id=share_replica['id'],
                conditionally_change=conditionally_change)
            # update "access_rules_status" on the replica
            self._update_share_instance_access_rules_state(
                context, share_replica['id'],
                constants.STATUS_ACTIVE)
        elif replica_ref.get('share_access_rules'):
            # driver would like to update individual access rules
            share_access_rules_dict = {
                rule['id']: rule for rule in share_access_rules}
            for rule_update in replica_ref.get('share_access_rules'):
                self.access_helper.get_and_update_share_instance_access_rule(
                    context,
                    rule_update['id'],
                    {'state': rule_update['state']},
                    share_instance_id=share_replica['id'])
                share_access_rules_dict.pop(rule_update['id'])
            for rule_id in share_access_rules_dict:
                self.access_helper.get_and_update_share_instance_access_rule(
                    context,
                    rule_id,
                    {'state': 'active'},
                    share_instance_id=share_replica['id'])
            self._update_share_instance_access_rules_state(
                context, share_replica['id'],
                replica_ref.get('access_rules_status'))

        LOG.info("Share replica %s created successfully.",
                 share_replica['id'])

    @add_hooks
    @utils.require_driver_initialized
    @locked_share_replica_operation
    def delete_share_replica(self, context, share_replica_id, share_id=None,
                             force=False):
        """Delete a share replica."""
        context = context.elevated()
        share_replica = self.db.share_replica_get(
            context, share_replica_id, with_share_data=True,
            with_share_server=True)

        # Grab all the snapshot instances that belong to this replica.
        replica_snapshots = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, {'share_instance_ids': share_replica_id},
                with_share_data=True)
        )

        replica_list = (
            self.db.share_replicas_get_all_by_share(
                context, share_replica['share_id'],
                with_share_data=True, with_share_server=True)
        )

        replica_list = [self._get_share_instance_dict(context, r)
                        for r in replica_list]
        replica_snapshots = [self._get_snapshot_instance_dict(context, s)
                             for s in replica_snapshots]
        share_server = self._get_share_server(context, share_replica)
        share_replica = self._get_share_instance_dict(context, share_replica)

        try:
            self.access_helper.update_access_rules(
                context,
                share_replica_id,
                delete_all_rules=True,
                share_server=share_server
            )
        except Exception as excep:
            with excutils.save_and_reraise_exception() as exc_context:
                # Set status to 'error' from 'deleting' since
                # access_rules_status has been set to 'error'.
                self.db.share_replica_update(
                    context, share_replica['id'],
                    {'status': constants.STATUS_ERROR})
                self.message_api.create(
                    context,
                    message_field.Action.DELETE_ACCESS_RULES,
                    share_replica['project_id'],
                    resource_type=message_field.Resource.SHARE_REPLICA,
                    resource_id=share_replica['id'],
                    exception=excep)
                if force:
                    msg = _("The driver was unable to delete access rules "
                            "for the replica: %s. Will attempt to delete "
                            "the replica anyway.")
                    LOG.exception(msg, share_replica['id'])
                    exc_context.reraise = False

        try:
            self.driver.delete_replica(
                context, replica_list, replica_snapshots, share_replica,
                share_server=share_server)
        except Exception as excep:
            with excutils.save_and_reraise_exception() as exc_context:
                if force:
                    msg = _("The driver was unable to delete the share "
                            "replica: %s on the backend. Since "
                            "this operation is forced, the replica will be "
                            "deleted from Manila's database. A cleanup on "
                            "the backend may be necessary.")
                    LOG.exception(msg, share_replica['id'])
                    exc_context.reraise = False
                else:
                    self.db.share_replica_update(
                        context, share_replica['id'],
                        {'status': constants.STATUS_ERROR_DELETING,
                         'replica_state': constants.STATUS_ERROR})
                self.message_api.create(
                    context,
                    message_field.Action.DELETE,
                    share_replica['project_id'],
                    resource_type=message_field.Resource.SHARE_REPLICA,
                    resource_id=share_replica['id'],
                    exception=excep)

        for replica_snapshot in replica_snapshots:
            self.db.share_snapshot_instance_delete(
                context, replica_snapshot['id'])

        self.db.share_replica_delete(context, share_replica['id'])
        LOG.info("Share replica %s deleted successfully.",
                 share_replica['id'])

    @add_hooks
    @utils.require_driver_initialized
    @locked_share_replica_operation
    def promote_share_replica(self, context, share_replica_id, share_id=None,
                              quiesce_wait_time=None):
        """Promote a share replica to active state."""
        context = context.elevated()
        share_replica = self.db.share_replica_get(
            context, share_replica_id, with_share_data=True,
            with_share_server=True)
        replication_type = share_replica['replication_type']
        if replication_type == constants.REPLICATION_TYPE_READABLE:
            ensure_old_active_replica_to_readonly = True
        else:
            ensure_old_active_replica_to_readonly = False
        share_server = self._get_share_server(context, share_replica)

        # Get list of all replicas for share
        replica_list = (
            self.db.share_replicas_get_all_by_share(
                context, share_replica['share_id'],
                with_share_data=True, with_share_server=True)
        )

        try:
            old_active_replica = list(filter(
                lambda r: (
                    r['replica_state'] == constants.REPLICA_STATE_ACTIVE),
                replica_list))[0]
        except IndexError:
            self.db.share_replica_update(
                context, share_replica['id'],
                {'status': constants.STATUS_AVAILABLE})
            msg = _("Share %(share)s has no replica with 'replica_state' "
                    "set to %(state)s. Promoting %(replica)s is not "
                    "possible.")
            self.message_api.create(
                context,
                message_field.Action.PROMOTE,
                share_replica['project_id'],
                resource_type=message_field.Resource.SHARE_REPLICA,
                resource_id=share_replica['id'],
                detail=message_field.Detail.NO_ACTIVE_REPLICA)
            raise exception.ReplicationException(
                reason=msg % {'share': share_replica['share_id'],
                              'state': constants.REPLICA_STATE_ACTIVE,
                              'replica': share_replica['id']})

        access_rules = self.db.share_access_get_all_for_share(
            context, share_replica['share_id'])

        replica_list = [self._get_share_instance_dict(context, r)
                        for r in replica_list]
        share_replica = self._get_share_instance_dict(context, share_replica)

        try:
            updated_replica_list = (
                self.driver.promote_replica(
                    context, replica_list, share_replica, access_rules,
                    share_server=share_server,
                    quiesce_wait_time=quiesce_wait_time)
            )
        except Exception as excep:
            with excutils.save_and_reraise_exception():
                # (NOTE) gouthamr: If the driver throws an exception at
                # this stage, there is a good chance that the replicas are
                # somehow altered on the backend. We loop through the
                # replicas and set their 'status's to 'error' and
                # leave the 'replica_state' unchanged. This also changes the
                # 'status' of the replica that failed to promote to 'error' as
                # before this operation. The backend may choose to update
                # the actual replica_state during the replica_monitoring
                # stage.
                updates = {'status': constants.STATUS_ERROR}
                for replica_ref in replica_list:
                    self.db.share_replica_update(
                        context, replica_ref['id'], updates)
                    self.message_api.create(
                        context,
                        message_field.Action.PROMOTE,
                        replica_ref['project_id'],
                        resource_type=message_field.Resource.SHARE_REPLICA,
                        resource_id=replica_ref['id'],
                        exception=excep)

        # Set any 'creating' snapshots on the currently active replica to
        # 'error' since we cannot guarantee they will finish 'creating'.
        active_replica_snapshot_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, {'share_instance_ids': share_replica['id']})
        )
        for instance in active_replica_snapshot_instances:
            if instance['status'] in (constants.STATUS_CREATING,
                                      constants.STATUS_DELETING):
                msg = ("The replica snapshot instance %(instance)s was "
                       "in %(state)s. Since it was not in %(available)s "
                       "state when the replica was promoted, it will be "
                       "set to %(error)s.")
                payload = {
                    'instance': instance['id'],
                    'state': instance['status'],
                    'available': constants.STATUS_AVAILABLE,
                    'error': constants.STATUS_ERROR,
                }
                LOG.info(msg, payload)
                self.db.share_snapshot_instance_update(
                    context, instance['id'],
                    {'status': constants.STATUS_ERROR})

        if not updated_replica_list:
            self.db.share_replica_update(
                context, old_active_replica['id'],
                {'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC,
                 'cast_rules_to_readonly':
                     ensure_old_active_replica_to_readonly})
            self.db.share_replica_update(
                context, share_replica['id'],
                {'status': constants.STATUS_AVAILABLE,
                 'replica_state': constants.REPLICA_STATE_ACTIVE,
                 'cast_rules_to_readonly': False})
        else:
            while updated_replica_list:
                # NOTE(vponomaryov): update 'active' replica last.
                for updated_replica in updated_replica_list:
                    if (updated_replica['id'] == share_replica['id'] and
                            len(updated_replica_list) > 1):
                        continue
                    updated_replica_list.remove(updated_replica)
                    break

                updated_export_locs = updated_replica.get(
                    'export_locations')
                if(updated_export_locs is not None
                   and isinstance(updated_export_locs, list)):
                    self.db.share_export_locations_update(
                        context, updated_replica['id'],
                        updated_export_locs)

                updated_replica_state = updated_replica.get(
                    'replica_state')
                updates = {}
                # Change the promoted replica's status from 'available' to
                # 'replication_change' and unset cast_rules_to_readonly
                if updated_replica['id'] == share_replica['id']:
                    updates['cast_rules_to_readonly'] = False
                    updates['status'] = constants.STATUS_AVAILABLE
                elif updated_replica['id'] == old_active_replica['id']:
                    updates['cast_rules_to_readonly'] = (
                        ensure_old_active_replica_to_readonly)
                if updated_replica_state == constants.STATUS_ERROR:
                    updates['status'] = constants.STATUS_ERROR
                if updated_replica_state is not None:
                    updates['replica_state'] = updated_replica_state
                if updates:
                    self.db.share_replica_update(
                        context, updated_replica['id'], updates)

                if updated_replica.get('access_rules_status'):
                    self._update_share_instance_access_rules_state(
                        context, share_replica['id'],
                        updated_replica.get('access_rules_status'))

        LOG.info("Share replica %s: promoted to active state "
                 "successfully.", share_replica['id'])

    @periodic_task.periodic_task(spacing=CONF.replica_state_update_interval)
    @utils.require_driver_initialized
    def periodic_share_replica_update(self, context):
        LOG.debug("Updating status of share replica instances.")
        replicas = self.db.share_replicas_get_all(context,
                                                  with_share_data=True)

        # Filter only non-active replicas belonging to this backend
        def qualified_replica(r):
            return (share_utils.extract_host(r['host']) ==
                    share_utils.extract_host(self.host) and
                    r['replica_state'] != constants.REPLICA_STATE_ACTIVE)

        replicas = list(filter(lambda x: qualified_replica(x), replicas))
        for replica in replicas:
            self._share_replica_update(
                context, replica, share_id=replica['share_id'])

    @add_hooks
    @utils.require_driver_initialized
    def update_share_replica(self, context, share_replica_id, share_id=None):
        """Initiated by the force_update API."""
        share_replica = self.db.share_replica_get(
            context, share_replica_id, with_share_data=True,
            with_share_server=True)
        self._share_replica_update(context, share_replica, share_id=share_id)

    @locked_share_replica_operation
    def _share_replica_update(self, context, share_replica, share_id=None):
        # Re-grab the replica:
        try:
            share_replica = self.db.share_replica_get(
                context, share_replica['id'], with_share_data=True,
                with_share_server=True)
        except exception.ShareReplicaNotFound:
            # Replica may have been deleted, nothing to do here
            return

        # We don't poll for replicas that are busy in some operation,
        # or if they are the 'active' instance.
        if (share_replica['status'] in constants.TRANSITIONAL_STATUSES
            or share_replica['status'] == constants.STATUS_ERROR_DELETING
            or share_replica['replica_state'] ==
                constants.REPLICA_STATE_ACTIVE):
            return

        share_server = self._get_share_server(context, share_replica)

        access_rules = self.db.share_access_get_all_for_share(
            context, share_replica['share_id'])

        LOG.debug("Updating status of share share_replica %s: ",
                  share_replica['id'])

        replica_list = (
            self.db.share_replicas_get_all_by_share(
                context, share_replica['share_id'],
                with_share_data=True, with_share_server=True)
        )

        _active_replica = next((x for x in replica_list
                                if x['replica_state'] ==
                                constants.REPLICA_STATE_ACTIVE), None)

        if _active_replica is None:
            if share_replica['replica_state'] != constants.STATUS_ERROR:
                # only log warning if replica_state was not already in error
                msg = (("Replica parent share %(id)s has no active "
                        "replica.") % {'id': share_replica['share_id']})
                LOG.warning(msg)
                self.db.share_replica_update(context, share_replica['id'],
                                             {'replica_state':
                                              constants.STATUS_ERROR})
            # without a related active replica, we cannot act on any
            # non-active replica
            return

        # Get snapshots for the share.
        share_snapshots = self.db.share_snapshot_get_all_for_share(
            context, share_id)

        # Get the required data for snapshots that have 'aggregate_status'
        # set to 'available'.
        available_share_snapshots = [
            self._get_replica_snapshots_for_snapshot(
                context, x['id'], _active_replica['id'], share_replica['id'])
            for x in share_snapshots
            if x['aggregate_status'] == constants.STATUS_AVAILABLE]

        replica_list = [self._get_share_instance_dict(context, r)
                        for r in replica_list]

        share_replica = self._get_share_instance_dict(context, share_replica)

        try:
            replica_state = self.driver.update_replica_state(
                context, replica_list, share_replica, access_rules,
                available_share_snapshots, share_server=share_server)
        except Exception as excep:
            msg = ("Driver error when updating replica "
                   "state for replica %s.")
            LOG.exception(msg, share_replica['id'])
            self.db.share_replica_update(
                context, share_replica['id'],
                {'replica_state': constants.STATUS_ERROR,
                 'status': constants.STATUS_ERROR})
            self.message_api.create(
                context,
                message_field.Action.UPDATE,
                share_replica['project_id'],
                resource_type=message_field.Resource.SHARE_REPLICA,
                resource_id=share_replica['id'],
                exception=excep)
            return

        if replica_state in (constants.REPLICA_STATE_IN_SYNC,
                             constants.REPLICA_STATE_OUT_OF_SYNC,
                             constants.STATUS_ERROR):
            self.db.share_replica_update(context, share_replica['id'],
                                         {'replica_state': replica_state})
        elif replica_state:
            msg = (("Replica %(id)s cannot be set to %(state)s "
                    "through update call.") %
                   {'id': share_replica['id'], 'state': replica_state})
            LOG.warning(msg)

    def _validate_share_and_driver_mode(self, share_instance):
        driver_dhss = self.driver.driver_handles_share_servers

        share_dhss = share_types.parse_boolean_extra_spec(
            'driver_handles_share_servers',
            share_types.get_share_type_extra_specs(
                share_instance['share_type_id'],
                constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS))

        if driver_dhss != share_dhss:
            msg = _("Driver mode of share %(share)s being managed is "
                    "incompatible with mode DHSS=%(dhss)s configured for"
                    " this backend.") % {'share': share_instance['share_id'],
                                         'dhss': driver_dhss}
            raise exception.InvalidShare(reason=msg)

        return driver_dhss

    @add_hooks
    @utils.require_driver_initialized
    def manage_share(self, context, share_id, driver_options):
        context = context.elevated()
        share_ref = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share_ref)
        share_type = share_types.get_share_type(
            context, share_instance['share_type_id'])
        share_type_extra_specs = self._get_extra_specs_from_share_type(
            context, share_instance['share_type_id'])
        share_type_supports_replication = share_type_extra_specs.get(
            'replication_type', None)

        project_id = share_ref['project_id']

        try:

            driver_dhss = self._validate_share_and_driver_mode(share_instance)

            if driver_dhss is True:
                share_server = self._get_share_server(context, share_instance)

                share_update = (
                    self.driver.manage_existing_with_server(
                        share_instance, driver_options, share_server)
                    or {}
                )
            else:
                share_update = (
                    self.driver.manage_existing(
                        share_instance, driver_options)
                    or {}
                )

            if not share_update.get('size'):
                # NOTE(haixin)if failed to get real size of share, will not
                # commit quota usages.
                msg = _("Driver cannot calculate share size.")
                raise exception.InvalidShare(reason=msg)
            else:
                share_types.provision_filter_on_size(context,
                                                     share_type,
                                                     share_update.get('size'))
                try:
                    values = {'per_share_gigabytes': share_update.get('size')}
                    QUOTAS.limit_check(context, project_id=context.project_id,
                                       **values)
                except exception.OverQuota as e:
                    quotas = e.kwargs['quotas']
                    LOG.warning("Requested share size %(size)d is larger than "
                                "maximum allowed limit %(limit)d.",
                                {'size': share_update.get('size'),
                                 'limit': quotas['per_share_gigabytes']})

            deltas = {
                'project_id': project_id,
                'user_id': context.user_id,
                'shares': 1,
                'gigabytes': share_update['size'],
                'share_type_id': share_instance['share_type_id'],
            }

            if share_type_supports_replication:
                deltas.update({'share_replicas': 1,
                               'replica_gigabytes': share_update['size']})

            # NOTE(carloss): Allowing OverQuota to do not compromise this
            # operation. If this hit OverQuota error while managing a share,
            # the admin would need to reset the state of the share and
            # delete or force delete the share (bug 1863298). Allowing
            # OverQuota makes this operation work properly and the admin will
            # need to adjust quotas afterwards.
            reservations = QUOTAS.reserve(context, overquota_allowed=True,
                                          **deltas)
            QUOTAS.commit(
                context, reservations, project_id=project_id,
                share_type_id=share_instance['share_type_id'],
            )

            share_update.update({
                'status': constants.STATUS_AVAILABLE,
                'launched_at': timeutils.utcnow(),
                'availability_zone': self.availability_zone,
            })

            # If the share was managed with `replication_type` extra-spec, the
            # instance becomes an `active` replica.
            if share_ref.get('replication_type'):
                share_update['replica_state'] = constants.REPLICA_STATE_ACTIVE

            # NOTE(vponomaryov): we should keep only those export locations
            # that driver has calculated to avoid incompatibilities with one
            # provided by user.
            if 'export_locations' in share_update:
                self.db.share_export_locations_update(
                    context, share_instance['id'],
                    share_update.pop('export_locations'),
                    delete=True)

            self.db.share_update(context, share_id, share_update)
        except Exception:
            # NOTE(haixin) we should set size 0 because we don't know the real
            # size of the size, and we will skip quota cuts when
            # delete/unmanage share.
            self.db.share_update(
                context, share_id,
                {'status': constants.STATUS_MANAGE_ERROR, 'size': 0})
            raise

    @add_hooks
    @utils.require_driver_initialized
    def manage_snapshot(self, context, snapshot_id, driver_options):

        context = context.elevated()
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)

        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_ref.instance['id'], with_share_data=True
        )
        project_id = snapshot_ref['project_id']

        driver_dhss = self.driver.driver_handles_share_servers

        try:
            if driver_dhss is True:

                share_server = self._get_share_server(context,
                                                      snapshot_ref['share'])

                snapshot_update = (
                    self.driver.manage_existing_snapshot_with_server(
                        snapshot_instance, driver_options, share_server)
                    or {}
                )
            else:
                snapshot_update = (
                    self.driver.manage_existing_snapshot(
                        snapshot_instance, driver_options)
                    or {}
                )

            if not snapshot_update.get('size'):
                snapshot_update['size'] = snapshot_ref['share']['size']
                LOG.warning("Cannot get the size of the snapshot "
                            "%(snapshot_id)s. Using the size of "
                            "the share instead.",
                            {'snapshot_id': snapshot_id})

            self._update_quota_usages(context, project_id, {
                "snapshots": 1,
                "snapshot_gigabytes": snapshot_update['size'],
            })

            snapshot_export_locations = snapshot_update.pop(
                'export_locations', [])

            if snapshot_instance['share']['mount_snapshot_support']:

                for el in snapshot_export_locations:
                    values = {
                        'share_snapshot_instance_id': snapshot_instance['id'],
                        'path': el['path'],
                        'is_admin_only': el['is_admin_only'],
                    }

                    self.db.share_snapshot_instance_export_location_create(
                        context, values)

            snapshot_update.update({
                'status': constants.STATUS_AVAILABLE,
                'progress': '100%',
            })
            snapshot_update.pop('id', None)
            self.db.share_snapshot_update(context, snapshot_id,
                                          snapshot_update)
        except Exception:
            # NOTE(vponomaryov): set size as 1 because design expects size
            # to be set, it also will allow us to handle delete/unmanage
            # operations properly with this errored snapshot according to
            # quotas.
            self.db.share_snapshot_update(
                context, snapshot_id,
                {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})
            raise

    def _update_quota_usages(self, context, project_id, usages):
        user_id = context.user_id
        for resource, usage in usages.items():
            try:
                current_usage = self.db.quota_usage_get(
                    context, project_id, resource, user_id)
                self.db.quota_usage_update(
                    context, project_id, user_id, resource,
                    in_use=current_usage['in_use'] + usage)
            except exception.QuotaUsageNotFound:
                self.db.quota_usage_create(context, project_id,
                                           user_id, resource, usage)

    @add_hooks
    @utils.require_driver_initialized
    def unmanage_share(self, context, share_id):
        context = context.elevated()
        share_ref = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share_ref)
        share_server = None
        project_id = share_ref['project_id']
        replicas = self.db.share_replicas_get_all_by_share(
            context, share_id)
        supports_replication = len(replicas) > 0

        def share_manage_set_error_status(msg, exception):
            status = {'status': constants.STATUS_UNMANAGE_ERROR}
            self.db.share_update(context, share_id, status)
            LOG.error(msg, exception)

        dhss = self.driver.driver_handles_share_servers

        try:
            if dhss is True:
                share_server = self._get_share_server(context, share_instance)
                self.driver.unmanage_with_server(share_instance, share_server)
            else:
                self.driver.unmanage(share_instance)

        except exception.InvalidShare as e:
            share_manage_set_error_status(
                ("Share can not be unmanaged: %s."), e)
            return

        # NOTE(haixin) we will skip quota cuts when unmanag share with
        # 'error_manage' status, because we have not commit quota usages when
        # we failed to manage the share.
        if share_ref['status'] != constants.STATUS_MANAGE_ERROR_UNMANAGING:
            deltas = {
                'project_id': project_id,
                'shares': -1,
                'gigabytes': -share_ref['size'],
                'share_type_id': share_instance['share_type_id'],
            }
            # NOTE(carloss): while unmanaging a share, a share will not
            # contain replicas other than the active one. So there is no need
            # to recalculate the amount of share replicas to be deallocated.
            if supports_replication:
                deltas.update({'share_replicas': -1,
                               'replica_gigabytes': -share_ref['size']})
            try:
                reservations = QUOTAS.reserve(context, **deltas)
                QUOTAS.commit(
                    context, reservations, project_id=project_id,
                    share_type_id=share_instance['share_type_id'],
                )
            except Exception as e:
                # Note(imalinovskiy):
                # Quota reservation errors here are not fatal, because
                # unmanage is administrator API and he/she could update user
                # quota usages later if it's required.
                LOG.warning("Failed to update quota usages: %s.", e)

        if self.configuration.safe_get('unmanage_remove_access_rules'):
            try:
                self.access_helper.update_access_rules(
                    context,
                    share_instance['id'],
                    delete_all_rules=True,
                    share_server=share_server
                )
            except Exception as e:
                share_manage_set_error_status(
                    ("Can not remove access rules of share: %s."), e)
                return

        self.db.share_instance_delete(context, share_instance['id'])

        # NOTE(ganso): Since we are unmanaging a share that is still within a
        # share server, we need to prevent the share server from being
        # auto-deleted.
        if share_server and share_server['is_auto_deletable']:
            self.db.share_server_update(context, share_server['id'],
                                        {'is_auto_deletable': False})
            msg = ("Since share %(share)s has been un-managed from share "
                   "server %(server)s. This share server must be removed "
                   "manually, either by un-managing or by deleting it. The "
                   "share network subnets %(subnets)s and share network "
                   "%(network)s cannot be deleted unless this share server "
                   "has been removed.")
            msg_args = {
                'share': share_id,
                'server': share_server['id'],
                'subnets': share_server['share_network_subnet_ids'],
                'network': share_instance['share_network_id']
            }
            LOG.warning(msg, msg_args)

        LOG.info("Share %s: unmanaged successfully.", share_id)

    @add_hooks
    @utils.require_driver_initialized
    def unmanage_snapshot(self, context, snapshot_id):
        status = {'status': constants.STATUS_UNMANAGE_ERROR}

        context = context.elevated()
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
        share_server = self._get_share_server(context,
                                              snapshot_ref['share'])

        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_ref.instance['id'], with_share_data=True
        )

        project_id = snapshot_ref['project_id']

        if self.configuration.safe_get('unmanage_remove_access_rules'):
            try:
                self.snapshot_access_helper.update_access_rules(
                    context,
                    snapshot_instance['id'],
                    delete_all_rules=True,
                    share_server=share_server)
            except Exception:
                LOG.exception(
                    ("Cannot remove access rules of snapshot %s."),
                    snapshot_id)
                self.db.share_snapshot_update(context, snapshot_id, status)
                return

        dhss = self.driver.driver_handles_share_servers

        try:
            if dhss:
                self.driver.unmanage_snapshot_with_server(
                    snapshot_instance, share_server)
            else:
                self.driver.unmanage_snapshot(snapshot_instance)
        except exception.UnmanageInvalidShareSnapshot as e:
            self.db.share_snapshot_update(context, snapshot_id, status)
            LOG.error("Share snapshot cannot be unmanaged: %s.", e)
            return

        try:
            share_type_id = snapshot_ref['share']['instance']['share_type_id']
            reservations = QUOTAS.reserve(
                context,
                project_id=project_id,
                snapshots=-1,
                snapshot_gigabytes=-snapshot_ref['size'],
                share_type_id=share_type_id,
            )
            QUOTAS.commit(
                context, reservations, project_id=project_id,
                share_type_id=share_type_id,
            )
        except Exception as e:
            # Note(imalinovskiy):
            # Quota reservation errors here are not fatal, because
            # unmanage is administrator API and he/she could update user
            # quota usages later if it's required.
            LOG.warning("Failed to update quota usages: %s.", e)

        self.db.share_snapshot_instance_delete(
            context, snapshot_instance['id'])

    @add_hooks
    @utils.require_driver_initialized
    def manage_share_server(self, context, share_server_id, identifier,
                            driver_opts):

        if self.driver.driver_handles_share_servers is False:
            msg = _("Cannot manage share server %s in a "
                    "backend configured with driver_handles_share_servers"
                    " set to False.") % share_server_id
            raise exception.ManageShareServerError(reason=msg)

        server = self.db.share_server_get(context, share_server_id)

        try:
            # NOTE(felipe_rodrigues): Manila does not support manage share
            # server with multiple allocations, so it can get the first
            # subnet_id element.
            share_network_subnet = self.db.share_network_subnet_get(
                context, server['share_network_subnet_ids'][0])
            share_network = self.db.share_network_get(
                context, share_network_subnet['share_network_id'])

            number_allocations = (
                self.driver.get_network_allocations_number())

            if self.driver.admin_network_api:
                number_allocations += (
                    self.driver.get_admin_network_allocations_number())

            if number_allocations > 0:

                # allocations obtained from the driver that still need to
                # be validated
                remaining_allocations = (
                    self.driver.get_share_server_network_info(
                        context, server, identifier, driver_opts))

                if len(remaining_allocations) > 0:

                    if self.driver.admin_network_api:
                        remaining_allocations = (
                            self.driver.admin_network_api.
                            manage_network_allocations(
                                context, remaining_allocations, server))

                    # allocations that are managed are removed from
                    # remaining_allocations

                    remaining_allocations = (
                        self.driver.network_api.
                        manage_network_allocations(
                            context, remaining_allocations, server,
                            share_network, share_network_subnet))

                    # We require that all allocations are managed, else we
                    # may have problems deleting this share server
                    if len(remaining_allocations) > 0:
                        msg = ("Failed to manage all allocations. "
                               "Allocations %s were not "
                               "managed." % remaining_allocations)
                        raise exception.ManageShareServerError(reason=msg)

                else:
                    # if there should be allocations, but the driver
                    # doesn't return any something is wrong

                    msg = ("Driver did not return required network "
                           "allocations to be managed. Required number "
                           "of allocations is %s." % number_allocations)
                    raise exception.ManageShareServerError(reason=msg)

            new_identifier, backend_details = self.driver.manage_server(
                context, server, identifier, driver_opts)

            if not new_identifier:
                new_identifier = server['id']

            if backend_details is None or not isinstance(
                    backend_details, dict):
                backend_details = {}

            for security_service in share_network['security_services']:
                ss_type = security_service['type']
                data = {
                    'name': security_service['name'],
                    'ou': security_service['ou'],
                    'default_ad_site': security_service['default_ad_site'],
                    'domain': security_service['domain'],
                    'server': security_service['server'],
                    'dns_ip': security_service['dns_ip'],
                    'user': security_service['user'],
                    'type': ss_type,
                    'password': security_service['password'],
                }
                backend_details.update({
                    'security_service_' + ss_type: jsonutils.dumps(data)
                })

            if backend_details:
                self.db.share_server_backend_details_set(
                    context, server['id'], backend_details)

            self.db.share_server_update(
                context, share_server_id,
                {'status': constants.STATUS_ACTIVE,
                 'identifier': new_identifier,
                 'network_allocation_update_support': (
                     self.driver.network_allocation_update_support)})

        except Exception:
            msg = "Error managing share server %s"
            LOG.exception(msg, share_server_id)
            self.db.share_server_update(
                context, share_server_id,
                {'status': constants.STATUS_MANAGE_ERROR})
            raise

        LOG.info("Share server %s managed successfully.", share_server_id)

    @add_hooks
    @utils.require_driver_initialized
    def unmanage_share_server(self, context, share_server_id, force=False):

        server = self.db.share_server_get(
            context, share_server_id)
        server_details = server['backend_details']

        security_services = []
        for ss_name in constants.SECURITY_SERVICES_ALLOWED_TYPES:
            ss = server_details.get('security_service_' + ss_name)
            if ss:
                security_services.append(jsonutils.loads(ss))

        try:
            self.driver.unmanage_server(server_details, security_services)
        except NotImplementedError:
            if not force:
                LOG.error("Did not unmanage share server %s since the driver "
                          "does not support managing share servers and no "
                          "``force`` option was supplied.",
                          share_server_id)
                self.db.share_server_update(
                    context, share_server_id,
                    {'status': constants.STATUS_UNMANAGE_ERROR})
                return

        try:

            if self.driver.get_network_allocations_number() > 0:
                # NOTE(ganso): This will already remove admin allocations.
                self.driver.network_api.unmanage_network_allocations(
                    context, share_server_id)
            elif (self.driver.get_admin_network_allocations_number() > 0
                  and self.driver.admin_network_api):
                # NOTE(ganso): This is here in case there are only admin
                # allocations.
                self.driver.admin_network_api.unmanage_network_allocations(
                    context, share_server_id)
            self.db.share_server_delete(context, share_server_id)
        except Exception:
            msg = "Error unmanaging share server %s"
            LOG.exception(msg, share_server_id)
            self.db.share_server_update(
                context, share_server_id,
                {'status': constants.STATUS_UNMANAGE_ERROR})
            raise

        LOG.info("Share server %s unmanaged successfully.", share_server_id)

    @add_hooks
    @utils.require_driver_initialized
    def revert_to_snapshot(self, context, snapshot_id,
                           reservations):
        context = context.elevated()
        snapshot = self.db.share_snapshot_get(context, snapshot_id)
        share = snapshot['share']
        share_id = share['id']
        share_instance_id = snapshot.instance.share_instance_id
        share_access_rules = (
            self.access_helper.get_share_instance_access_rules(
                context, filters={'state': constants.STATUS_ACTIVE},
                share_instance_id=share_instance_id))
        snapshot_access_rules = (
            self.snapshot_access_helper.get_snapshot_instance_access_rules(
                context, snapshot.instance['id']))

        if share.get('has_replicas'):
            self._revert_to_replicated_snapshot(
                context, share, snapshot, reservations, share_access_rules,
                snapshot_access_rules, share_id=share_id)
        else:
            self._revert_to_snapshot(context, share, snapshot, reservations,
                                     share_access_rules, snapshot_access_rules)

    def _revert_to_snapshot(self, context, share, snapshot, reservations,
                            share_access_rules, snapshot_access_rules):

        share_server = self._get_share_server(context, share)
        share_id = share['id']
        snapshot_id = snapshot['id']
        project_id = share['project_id']
        user_id = share['user_id']

        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot.instance['id'], with_share_data=True)
        share_type_id = snapshot_instance["share_instance"]["share_type_id"]

        # Make primitive to pass the information to the driver
        snapshot_instance_dict = self._get_snapshot_instance_dict(
            context, snapshot_instance, snapshot=snapshot)

        try:
            self.driver.revert_to_snapshot(context,
                                           snapshot_instance_dict,
                                           share_access_rules,
                                           snapshot_access_rules,
                                           share_server=share_server)
        except Exception as excep:
            with excutils.save_and_reraise_exception():

                msg = ('Share %(share)s could not be reverted '
                       'to snapshot %(snap)s.')
                msg_args = {'share': share_id, 'snap': snapshot_id}
                LOG.exception(msg, msg_args)

                if reservations:
                    QUOTAS.rollback(
                        context, reservations, project_id=project_id,
                        user_id=user_id, share_type_id=share_type_id,
                    )

                self.db.share_update(
                    context, share_id,
                    {'status': constants.STATUS_REVERTING_ERROR})
                self.db.share_snapshot_update(
                    context, snapshot_id,
                    {'status': constants.STATUS_AVAILABLE})
                self.message_api.create(
                    context,
                    message_field.Action.REVERT_TO_SNAPSHOT,
                    share['project_id'],
                    resource_type=message_field.Resource.SHARE,
                    resource_id=share_id,
                    exception=excep)

        if reservations:
            QUOTAS.commit(
                context, reservations, project_id=project_id, user_id=user_id,
                share_type_id=share_type_id,
            )

        self.db.share_update(
            context, share_id,
            {'status': constants.STATUS_AVAILABLE, 'size': snapshot['size']})
        self.db.share_snapshot_update(
            context, snapshot_id, {'status': constants.STATUS_AVAILABLE})

        msg = ('Share %(share)s reverted to snapshot %(snap)s '
               'successfully.')
        msg_args = {'share': share_id, 'snap': snapshot_id}
        LOG.info(msg, msg_args)

    @add_hooks
    @utils.require_driver_initialized
    def delete_share_instance(self, context, share_instance_id, force=False):
        """Delete a share instance."""
        context = context.elevated()
        share_instance = self._get_share_instance(context, share_instance_id)
        share_id = share_instance.get('share_id')
        share_server = self._get_share_server(context, share_instance)
        share = self.db.share_get(context, share_id)

        self._notify_about_share_usage(context, share,
                                       share_instance, "delete.start")

        try:
            self.access_helper.update_access_rules(
                context,
                share_instance_id,
                delete_all_rules=True,
                share_server=share_server
            )
        except exception.ShareResourceNotFound:
            LOG.warning("Share instance %s does not exist in the "
                        "backend.", share_instance_id)
        except Exception as excep:
            with excutils.save_and_reraise_exception() as exc_context:
                if force:
                    msg = ("The driver was unable to delete access rules "
                           "for the instance: %s. Will attempt to delete "
                           "the instance anyway.")
                    LOG.error(msg, share_instance_id)
                    exc_context.reraise = False
                else:
                    self.db.share_instance_update(
                        context,
                        share_instance_id,
                        {'status': constants.STATUS_ERROR_DELETING})
                self.message_api.create(
                    context,
                    message_field.Action.DELETE_ACCESS_RULES,
                    share_instance['project_id'],
                    resource_type=message_field.Resource.SHARE,
                    resource_id=share_instance_id,
                    exception=excep)

        try:
            self.driver.delete_share(context, share_instance,
                                     share_server=share_server)
        except exception.ShareResourceNotFound:
            LOG.warning("Share instance %s does not exist in the "
                        "backend.", share_instance_id)
        except Exception as excep:
            with excutils.save_and_reraise_exception() as exc_context:
                if force:
                    msg = ("The driver was unable to delete the share "
                           "instance: %s on the backend. Since this "
                           "operation is forced, the instance will be "
                           "deleted from Manila's database. A cleanup on "
                           "the backend may be necessary.")
                    LOG.error(msg, share_instance_id)
                    exc_context.reraise = False
                else:
                    self.db.share_instance_update(
                        context,
                        share_instance_id,
                        {'status': constants.STATUS_ERROR_DELETING})
                self.message_api.create(
                    context,
                    message_field.Action.DELETE,
                    share_instance['project_id'],
                    resource_type=message_field.Resource.SHARE,
                    resource_id=share_instance_id,
                    exception=excep)

        self.db.share_instance_delete(
            context, share_instance_id, need_to_update_usages=True)

        LOG.info("Share instance %s: deleted successfully.",
                 share_instance_id)

        self._check_delete_share_server(context, share_instance=share_instance)

        self._notify_about_share_usage(context, share,
                                       share_instance, "delete.end")

    def _check_delete_share_server(self, context, share_instance=None,
                                   share_server=None, remote_host=False):

        if CONF.delete_share_server_with_last_share:
            if share_instance and not share_server:
                share_server = self._get_share_server(context, share_instance)
            if (share_server and len(share_server.share_instances) == 0
                    and share_server.is_auto_deletable is True):
                LOG.debug("Scheduled deletion of share-server "
                          "with id '%s' automatically by "
                          "deletion of last share.", share_server['id'])
                if remote_host:
                    rpcapi = share_rpcapi.ShareAPI()
                    rpcapi.delete_share_server(context, share_server)
                else:
                    self.delete_share_server(context, share_server)

    @periodic_task.periodic_task(spacing=600)
    @utils.require_driver_initialized
    def delete_free_share_servers(self, ctxt):
        if not (self.driver.driver_handles_share_servers and
                self.configuration.automatic_share_server_cleanup):
            return
        LOG.info("Check for unused share servers to delete.")
        updated_before = timeutils.utcnow() - datetime.timedelta(
            minutes=self.configuration.unused_share_server_cleanup_interval)
        servers = self.db.share_server_get_all_unused_deletable(ctxt,
                                                                self.host,
                                                                updated_before)
        for server in servers:
            self.delete_share_server(ctxt, server)

    @periodic_task.periodic_task(
        spacing=CONF.check_for_expired_shares_in_recycle_bin_interval)
    @utils.require_driver_initialized
    def delete_expired_share(self, ctxt):
        LOG.debug("Check for expired share in recycle bin to delete.")
        expired_shares = self.db.get_all_expired_shares(ctxt)

        for share in expired_shares:
            if share['status'] == constants.STATUS_ERROR_DELETING:
                LOG.info("Share %s was soft-deleted but a prior deletion "
                         "attempt failed. Resetting status and re-attempting "
                         "deletion", share['id'])
                # reset share status to error in order to try deleting again
                update_data = {'status': constants.STATUS_ERROR}
                self.db.share_update(ctxt, share['id'], update_data)
            else:
                LOG.info("share %s has expired, will be deleted", share['id'])
            self.share_api.delete(ctxt, share)

    @periodic_task.periodic_task(
        spacing=CONF.check_for_expired_transfers)
    def delete_expired_transfers(self, ctxt):
        LOG.info("Checking for expired transfers.")
        expired_transfers = self.db.get_all_expired_transfers(ctxt)

        for transfer in expired_transfers:
            LOG.debug("Transfer %s has expired, will be destroyed.",
                      transfer['id'])
            self.transfer_api.delete(ctxt, transfer_id=transfer['id'])

    @utils.require_driver_initialized
    def transfer_accept(self, context, share_id, new_user,
                        new_project, clear_rules):
        # need elevated context as we haven't "given" the share yet
        elevated_context = context.elevated()
        share_ref = self.db.share_get(elevated_context, share_id)
        access_rules = self.db.share_access_get_all_for_share(
            elevated_context, share_id)
        share_instances = self.db.share_instances_get_all_by_share(
            elevated_context, share_id)
        share_server = self._get_share_server(context, share_ref)

        for share_instance in share_instances:
            share_instance = self.db.share_instance_get(context,
                                                        share_instance['id'],
                                                        with_share_data=True)
            if clear_rules and access_rules:
                try:
                    self.access_helper.update_access_rules(
                        context,
                        share_instance['id'],
                        delete_all_rules=True
                    )
                    access_rules = []
                except Exception:
                    with excutils.save_and_reraise_exception():
                        msg = (
                            "Can not remove access rules for share "
                            "instance %(si)s belonging to share %(shr)s.")
                        msg_payload = {
                            'si': share_instance['id'],
                            'shr': share_id,
                        }
                        LOG.error(msg, msg_payload)
            try:
                self.driver.transfer_accept(context, share_instance,
                                            new_user,
                                            new_project,
                                            access_rules=access_rules,
                                            share_server=share_server)
            except exception.DriverCannotTransferShareWithRules as e:
                with excutils.save_and_reraise_exception():
                    self.message_api.create(
                        context,
                        message_field.Action.TRANSFER_ACCEPT,
                        new_project,
                        resource_type=message_field.Resource.SHARE,
                        resource_id=share_id,
                        detail=(message_field.Detail.
                                DRIVER_FAILED_TRANSFER_ACCEPT))
                    msg = _("The backend failed to accept the share: %s.")
                    LOG.error(msg, e)

        msg = ('Share %(share_id)s has transfer from %(old_project_id)s to '
               '%(new_project_id)s completed successfully.')
        msg_args = {
            "share_id": share_id,
            "old_project_id": share_ref['project_id'],
            "new_project_id": context.project_id
        }
        LOG.info(msg, msg_args)

    @add_hooks
    @utils.require_driver_initialized
    def create_snapshot(self, context, share_id, snapshot_id):
        """Create snapshot for share."""
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
        share_server = self._get_share_server(
            context, snapshot_ref['share']['instance'])
        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_ref.instance['id'], with_share_data=True
        )
        snapshot_instance_id = snapshot_instance['id']

        snapshot_instance = self._get_snapshot_instance_dict(
            context, snapshot_instance)

        try:

            model_update = self.driver.create_snapshot(
                context, snapshot_instance, share_server=share_server) or {}

        except Exception as excep:
            with excutils.save_and_reraise_exception():
                self.db.share_snapshot_instance_update(
                    context,
                    snapshot_instance_id,
                    {'status': constants.STATUS_ERROR})
                self.message_api.create(
                    context,
                    message_field.Action.CREATE,
                    snapshot_ref['project_id'],
                    resource_type=message_field.Resource.SHARE_SNAPSHOT,
                    resource_id=snapshot_instance_id,
                    exception=excep)

        snapshot_export_locations = model_update.pop('export_locations', [])

        if snapshot_instance['share']['mount_snapshot_support']:

            for el in snapshot_export_locations:
                values = {
                    'share_snapshot_instance_id': snapshot_instance_id,
                    'path': el['path'],
                    'is_admin_only': el['is_admin_only'],
                }

                self.db.share_snapshot_instance_export_location_create(context,
                                                                       values)

        if model_update.get('status') in (None, constants.STATUS_AVAILABLE):
            model_update['status'] = constants.STATUS_AVAILABLE
            model_update['progress'] = '100%'

        self.db.share_snapshot_instance_update(
            context, snapshot_instance_id, model_update)

    @add_hooks
    @utils.require_driver_initialized
    def delete_snapshot(self, context, snapshot_id, force=False):
        """Delete share snapshot."""
        context = context.elevated()
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)

        share_server = self._get_share_server(
            context, snapshot_ref['share']['instance'])
        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_ref.instance['id'], with_share_data=True)
        snapshot_instance_id = snapshot_instance['id']

        if context.project_id != snapshot_ref['project_id']:
            project_id = snapshot_ref['project_id']
        else:
            project_id = context.project_id

        snapshot_instance = self._get_snapshot_instance_dict(
            context, snapshot_instance)

        share_ref = self.db.share_get(context, snapshot_ref['share_id'])

        if share_ref['mount_snapshot_support']:
            try:
                self.snapshot_access_helper.update_access_rules(
                    context, snapshot_instance['id'], delete_all_rules=True,
                    share_server=share_server)
            except Exception:
                LOG.exception(
                    ("Failed to remove access rules for snapshot %s."),
                    snapshot_instance['id'])
                LOG.warning("The driver was unable to remove access rules "
                            "for snapshot %s. Moving on.",
                            snapshot_instance['snapshot_id'])

        try:
            self.driver.delete_snapshot(context, snapshot_instance,
                                        share_server=share_server)
        except Exception as excep:
            with excutils.save_and_reraise_exception() as exc:
                if force:
                    msg = _("The driver was unable to delete the "
                            "snapshot %s on the backend. Since this "
                            "operation is forced, the snapshot will "
                            "be deleted from Manila's database. A cleanup on "
                            "the backend may be necessary.")
                    LOG.exception(msg, snapshot_id)
                    exc.reraise = False
                else:
                    self.db.share_snapshot_instance_update(
                        context,
                        snapshot_instance_id,
                        {'status': constants.STATUS_ERROR_DELETING})
                self.message_api.create(
                    context,
                    message_field.Action.DELETE,
                    snapshot_ref['project_id'],
                    resource_type=message_field.Resource.SHARE_SNAPSHOT,
                    resource_id=snapshot_instance_id,
                    exception=excep)

        self.db.share_snapshot_instance_delete(context, snapshot_instance_id)

        share_type_id = snapshot_ref['share']['instance']['share_type_id']
        try:
            reservations = QUOTAS.reserve(
                context, project_id=project_id, snapshots=-1,
                snapshot_gigabytes=-snapshot_ref['size'],
                user_id=snapshot_ref['user_id'],
                share_type_id=share_type_id,
            )
        except Exception:
            reservations = None
            LOG.exception("Failed to update quota usages while deleting "
                          "snapshot %s.", snapshot_id)

        if reservations:
            QUOTAS.commit(
                context, reservations, project_id=project_id,
                user_id=snapshot_ref['user_id'],
                share_type_id=share_type_id,
            )

    @add_hooks
    @utils.require_driver_initialized
    @locked_share_replica_operation
    def create_replicated_snapshot(self, context, snapshot_id, share_id=None):
        """Create a snapshot for a replicated share."""
        # Grab the snapshot and replica information from the DB.
        snapshot = self.db.share_snapshot_get(context, snapshot_id)
        share_server = self._get_share_server(context, snapshot['share'])
        replica_snapshots = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, {'snapshot_ids': snapshot['id']},
                with_share_data=True)
        )
        replica_list = (
            self.db.share_replicas_get_all_by_share(
                context, share_id, with_share_data=True,
                with_share_server=True)
        )

        # Make primitives to pass the information to the driver.

        replica_list = [self._get_share_instance_dict(context, r)
                        for r in replica_list]
        replica_snapshots = [self._get_snapshot_instance_dict(context, s)
                             for s in replica_snapshots]
        updated_instances = []

        try:
            updated_instances = self.driver.create_replicated_snapshot(
                context, replica_list, replica_snapshots,
                share_server=share_server) or []
        except Exception:
            with excutils.save_and_reraise_exception():
                for instance in replica_snapshots:
                    self.db.share_snapshot_instance_update(
                        context, instance['id'],
                        {'status': constants.STATUS_ERROR})

        for instance in updated_instances:
            if instance['status'] == constants.STATUS_AVAILABLE:
                instance.update({'progress': '100%'})
            self.db.share_snapshot_instance_update(
                context, instance['id'], instance)

    def _find_active_replica_on_host(self, replica_list):
        """Find the active replica matching this manager's host."""
        for replica in replica_list:
            if (replica['replica_state'] == constants.REPLICA_STATE_ACTIVE and
                    share_utils.extract_host(replica['host']) == self.host):
                return replica

    @locked_share_replica_operation
    def _revert_to_replicated_snapshot(self, context, share, snapshot,
                                       reservations, share_access_rules,
                                       snapshot_access_rules, share_id=None):

        share_server = self._get_share_server(context, share)
        snapshot_id = snapshot['id']
        project_id = share['project_id']
        user_id = share['user_id']

        # Get replicas, including an active replica
        replica_list = self.db.share_replicas_get_all_by_share(
            context, share_id, with_share_data=True, with_share_server=True)
        active_replica = self._find_active_replica_on_host(replica_list)

        # Get snapshot instances, including one on an active replica
        replica_snapshots = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, {'snapshot_ids': snapshot_id},
                with_share_data=True))
        snapshot_instance_filters = {
            'share_instance_ids': active_replica['id'],
            'snapshot_ids': snapshot_id,
        }
        active_replica_snapshot = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, snapshot_instance_filters))[0]

        # Make primitives to pass the information to the driver
        replica_list = [self._get_share_instance_dict(context, replica)
                        for replica in replica_list]
        active_replica = self._get_share_instance_dict(context, active_replica)
        replica_snapshots = [self._get_snapshot_instance_dict(context, s)
                             for s in replica_snapshots]
        active_replica_snapshot = self._get_snapshot_instance_dict(
            context, active_replica_snapshot, snapshot=snapshot)

        try:
            self.driver.revert_to_replicated_snapshot(
                context, active_replica, replica_list, active_replica_snapshot,
                replica_snapshots, share_access_rules,
                snapshot_access_rules, share_server=share_server)
        except Exception:
            with excutils.save_and_reraise_exception():

                msg = ('Share %(share)s could not be reverted '
                       'to snapshot %(snap)s.')
                msg_args = {'share': share_id, 'snap': snapshot_id}
                LOG.exception(msg, msg_args)

                if reservations:
                    QUOTAS.rollback(
                        context, reservations, project_id=project_id,
                        user_id=user_id,
                        share_type_id=active_replica['share_type_id'],
                    )

                self.db.share_replica_update(
                    context, active_replica['id'],
                    {'status': constants.STATUS_REVERTING_ERROR})
                self.db.share_snapshot_instance_update(
                    context, active_replica_snapshot['id'],
                    {'status': constants.STATUS_AVAILABLE})

        if reservations:
            QUOTAS.commit(
                context, reservations, project_id=project_id, user_id=user_id,
                share_type_id=active_replica['share_type_id'],
            )

        self.db.share_update(context, share_id, {'size': snapshot['size']})
        self.db.share_replica_update(
            context, active_replica['id'],
            {'status': constants.STATUS_AVAILABLE})
        self.db.share_snapshot_instance_update(
            context, active_replica_snapshot['id'],
            {'status': constants.STATUS_AVAILABLE})

        msg = ('Share %(share)s reverted to snapshot %(snap)s '
               'successfully.')
        msg_args = {'share': share_id, 'snap': snapshot_id}
        LOG.info(msg, msg_args)

    @add_hooks
    @utils.require_driver_initialized
    @locked_share_replica_operation
    def delete_replicated_snapshot(self, context, snapshot_id,
                                   share_id=None, force=False):
        """Delete a snapshot from a replicated share."""
        # Grab the replica and snapshot information from the DB.
        snapshot = self.db.share_snapshot_get(context, snapshot_id)
        share_server = self._get_share_server(context, snapshot['share'])
        replica_snapshots = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, {'snapshot_ids': snapshot['id']},
                with_share_data=True)
        )
        replica_list = (
            self.db.share_replicas_get_all_by_share(
                context, share_id, with_share_data=True,
                with_share_server=True)
        )

        replica_list = [self._get_share_instance_dict(context, r)
                        for r in replica_list]
        replica_snapshots = [self._get_snapshot_instance_dict(context, s)
                             for s in replica_snapshots]
        deleted_instances = []
        updated_instances = []
        db_force_delete_msg = _('The driver was unable to delete some or all '
                                'of the share replica snapshots on the '
                                'backend/s. Since this operation is forced, '
                                'the replica snapshots will be deleted from '
                                'Manila.')

        try:

            updated_instances = self.driver.delete_replicated_snapshot(
                context, replica_list, replica_snapshots,
                share_server=share_server) or []

        except Exception:
            with excutils.save_and_reraise_exception() as e:
                if force:
                    # Can delete all instances if forced.
                    deleted_instances = replica_snapshots
                    LOG.exception(db_force_delete_msg)
                    e.reraise = False
                else:
                    for instance in replica_snapshots:
                        self.db.share_snapshot_instance_update(
                            context, instance['id'],
                            {'status': constants.STATUS_ERROR_DELETING})

        if not deleted_instances:
            if force:
                # Ignore model updates on 'force' delete.
                LOG.warning(db_force_delete_msg)
                deleted_instances = replica_snapshots
            else:
                deleted_instances = list(filter(
                    lambda x: x['status'] == constants.STATUS_DELETED,
                    updated_instances))
                updated_instances = list(filter(
                    lambda x: x['status'] != constants.STATUS_DELETED,
                    updated_instances))

        for instance in deleted_instances:
            self.db.share_snapshot_instance_delete(context, instance['id'])

        for instance in updated_instances:
            self.db.share_snapshot_instance_update(
                context, instance['id'], instance)

    @periodic_task.periodic_task(spacing=CONF.replica_state_update_interval)
    @utils.require_driver_initialized
    def periodic_share_replica_snapshot_update(self, context):
        LOG.debug("Updating status of share replica snapshots.")
        transitional_statuses = (constants.STATUS_CREATING,
                                 constants.STATUS_DELETING)
        replicas = self.db.share_replicas_get_all(context,
                                                  with_share_data=True)

        def qualified_replica(r):
            # Filter non-active replicas belonging to this backend
            return (share_utils.extract_host(r['host']) ==
                    share_utils.extract_host(self.host) and
                    r['replica_state'] != constants.REPLICA_STATE_ACTIVE)

        host_replicas = list(filter(
            lambda x: qualified_replica(x), replicas))
        transitional_replica_snapshots = []

        # Get snapshot instances for each replica that are in 'creating' or
        # 'deleting' states.
        for replica in host_replicas:
            filters = {
                'share_instance_ids': replica['id'],
                'statuses': transitional_statuses,
            }
            replica_snapshots = (
                self.db.share_snapshot_instance_get_all_with_filters(
                    context, filters, with_share_data=True)
            )
            transitional_replica_snapshots.extend(replica_snapshots)

        for replica_snapshot in transitional_replica_snapshots:
            replica_snapshots = (
                self.db.share_snapshot_instance_get_all_with_filters(
                    context,
                    {'snapshot_ids': replica_snapshot['snapshot_id']})
            )
            share_id = replica_snapshot['share']['share_id']
            self._update_replica_snapshot(
                context, replica_snapshot,
                replica_snapshots=replica_snapshots, share_id=share_id)

    @locked_share_replica_operation
    def _update_replica_snapshot(self, context, replica_snapshot,
                                 replica_snapshots=None, share_id=None):
        # Re-grab the replica:
        try:
            share_replica = self.db.share_replica_get(
                context, replica_snapshot['share_instance_id'],
                with_share_data=True, with_share_server=True)
            replica_snapshot = self.db.share_snapshot_instance_get(
                context, replica_snapshot['id'], with_share_data=True)
        except exception.NotFound:
            # Replica may have been deleted, try to cleanup the snapshot
            # instance
            try:
                self.db.share_snapshot_instance_delete(
                    context, replica_snapshot['id'])
            except exception.ShareSnapshotInstanceNotFound:
                # snapshot instance has been deleted, nothing to do here
                pass
            return

        msg_payload = {
            'snapshot_instance': replica_snapshot['id'],
            'replica': share_replica['id'],
        }

        LOG.debug("Updating status of replica snapshot %(snapshot_instance)s: "
                  "on replica: %(replica)s", msg_payload)

        # Grab all the replica and snapshot information.
        replica_list = (
            self.db.share_replicas_get_all_by_share(
                context, share_replica['share_id'],
                with_share_data=True, with_share_server=True)
        )

        replica_list = [self._get_share_instance_dict(context, r)
                        for r in replica_list]
        replica_snapshots = replica_snapshots or []

        # Convert data to primitives to send to the driver.

        replica_snapshots = [self._get_snapshot_instance_dict(context, s)
                             for s in replica_snapshots]
        replica_snapshot = self._get_snapshot_instance_dict(
            context, replica_snapshot)
        share_replica = self._get_share_instance_dict(context, share_replica)
        share_server = share_replica['share_server']
        snapshot_update = None

        try:

            snapshot_update = self.driver.update_replicated_snapshot(
                context, replica_list, share_replica, replica_snapshots,
                replica_snapshot, share_server=share_server) or {}

        except exception.SnapshotResourceNotFound:
            if replica_snapshot['status'] == constants.STATUS_DELETING:
                LOG.info('Snapshot %(snapshot_instance)s on replica '
                         '%(replica)s has been deleted.', msg_payload)
                self.db.share_snapshot_instance_delete(
                    context, replica_snapshot['id'])
            else:
                LOG.exception("Replica snapshot %s was not found on "
                              "the backend.", replica_snapshot['id'])
                self.db.share_snapshot_instance_update(
                    context, replica_snapshot['id'],
                    {'status': constants.STATUS_ERROR})
        except Exception:
            LOG.exception("Driver error while updating replica snapshot: "
                          "%s", replica_snapshot['id'])
            self.db.share_snapshot_instance_update(
                context, replica_snapshot['id'],
                {'status': constants.STATUS_ERROR})

        if snapshot_update:
            snapshot_status = snapshot_update.get('status')
            if snapshot_status == constants.STATUS_AVAILABLE:
                snapshot_update['progress'] = '100%'
            self.db.share_snapshot_instance_update(
                context, replica_snapshot['id'], snapshot_update)

    @add_hooks
    @utils.require_driver_initialized
    def update_access(self, context, share_instance_id):
        """Allow/Deny access to some share."""
        share_instance = self._get_share_instance(context, share_instance_id)
        share_server_id = share_instance.get('share_server_id')

        self.update_access_for_instances(context, [share_instance_id],
                                         share_server_id=share_server_id)

    def update_access_for_instances(self, context, share_instance_ids,
                                    share_server_id=None):
        """Allow/Deny access to shares that belong to the same share server."""
        share_server = None
        if share_server_id:
            share_server = self.db.share_server_get(context, share_server_id)

        for instance_id in share_instance_ids:
            LOG.debug("Received request to update access for share instance"
                      " %s.", instance_id)

            self.access_helper.update_access_rules(
                context,
                instance_id,
                share_server=share_server)

    @periodic_task.periodic_task(spacing=CONF.periodic_interval)
    @utils.require_driver_initialized
    def _report_driver_status(self, context):
        LOG.info('Updating share status')
        share_stats = self.driver.get_share_stats(refresh=True)

        if not share_stats:
            return

        if self.driver.driver_handles_share_servers:
            share_stats['server_pools_mapping'] = (
                self._get_servers_pool_mapping(context)
            )

        self.update_service_capabilities(share_stats)

    @periodic_task.periodic_task(spacing=CONF.periodic_hooks_interval)
    @utils.require_driver_initialized
    def _execute_periodic_hook(self, context):
        """Executes periodic-based hooks."""
        # TODO(vponomaryov): add also access rules and share servers
        share_instances = (
            self.db.share_instances_get_all_by_host(
                context=context, host=self.host))
        periodic_hook_data = self.driver.get_periodic_hook_data(
            context=context, share_instances=share_instances)
        for hook in self.hooks:
            hook.execute_periodic_hook(
                context=context, periodic_hook_data=periodic_hook_data)

    def _get_servers_pool_mapping(self, context):
        """Get info about relationships between pools and share_servers."""
        share_servers = self.db.share_server_get_all_by_host(context,
                                                             self.host)
        return {server['id']: self.driver.get_share_server_pools(server)
                for server in share_servers}

    @add_hooks
    @utils.require_driver_initialized
    def publish_service_capabilities(self, context):
        """Collect driver status and then publish it."""
        self._report_driver_status(context)
        self._publish_service_capabilities(context)

    def _form_server_setup_info(self, context, share_server, share_network,
                                share_network_subnets):
        share_server_id = share_server['id']
        # Network info is used by driver for setting up share server
        # and getting server info on share creation.
        admin_network_allocations = (
            self.db.network_allocations_get_for_share_server(
                context, share_server_id, label='admin'))

        # NOTE(felipe_rodrigues): items in the network_info list contain
        # same values for the keys: server_id, admin_network_allocations,
        # security_services and backend_details.
        network_info = []
        for share_network_subnet in share_network_subnets:
            network_allocations = (
                self.db.network_allocations_get_for_share_server(
                    context, share_server_id, label='user',
                    subnet_id=share_network_subnet['id']))
            # NOTE(vponomaryov): following network_info fields are deprecated:
            # 'segmentation_id', 'cidr' and 'network_type'.
            # And they should be used from network allocations directly.
            # They should be removed right after no one uses them.
            network_info.append({
                'server_id': share_server['id'],
                'segmentation_id': share_network_subnet['segmentation_id'],
                'cidr': share_network_subnet['cidr'],
                'neutron_net_id': share_network_subnet['neutron_net_id'],
                'neutron_subnet_id': share_network_subnet['neutron_subnet_id'],
                'security_services': share_network['security_services'],
                'network_allocations': network_allocations,
                'admin_network_allocations': admin_network_allocations,
                'backend_details': share_server.get('backend_details'),
                'network_type': share_network_subnet['network_type'],
                'subnet_metadata': share_network_subnet['subnet_metadata']
            })
        return network_info

    def _handle_setup_server_error(self, context, share_server_id, e):
        details = getattr(e, "detail_data", {})
        if isinstance(details, dict):
            server_details = details.get("server_details", {})
            if not isinstance(server_details, dict):
                LOG.debug(
                    ("Cannot save non-dict data (%(data)s) provided as "
                     "'server details' of failed share server '%(server)s'."),
                    {"server": share_server_id, "data": server_details})
            else:
                invalid_details = []
                for key, value in server_details.items():
                    try:
                        self.db.share_server_backend_details_set(
                            context, share_server_id, {key: value})
                    except Exception:
                        invalid_details.append("%(key)s: %(value)s" % {
                            'key': str(key),
                            'value': str(value)
                        })
                if invalid_details:
                    LOG.debug(
                        ("Following server details cannot be written to db : "
                         "%s"), str("\n".join(invalid_details)))
        else:
            LOG.debug(
                ("Cannot save non-dict data (%(data)s) provided as 'detail "
                 "data' of failed share server '%(server)s'."),
                {"server": share_server_id, "data": details})

        self.db.share_server_update(
            context, share_server_id, {'status': constants.STATUS_ERROR})

    def _setup_server(self, context, share_server, metadata):
        subnets = share_server['share_network_subnets']
        if not subnets:
            raise exception.NetworkBadConfigurationException(
                reason="share server does not have subnet")

        # all subnets reside on same share network, get it from the first one.
        share_network_id = subnets[0]['share_network_id']
        try:
            share_network = self.db.share_network_get(context,
                                                      share_network_id)
            for share_network_subnet in subnets:
                self.driver.allocate_network(
                    context, share_server, share_network, share_network_subnet)
            self.driver.allocate_admin_network(context, share_server)

            # Get share_network_subnets in case they were updated.
            share_network_subnets = (
                self.db.share_network_subnet_get_all_by_share_server_id(
                    context, share_server['id']))

            network_info_list = self._form_server_setup_info(
                context, share_server, share_network, share_network_subnets)
            for network_info in network_info_list:
                self._validate_segmentation_id(network_info)

            # NOTE(vponomaryov): Save security services data to share server
            # details table to remove dependency from share network after
            # creation operation. It will allow us to delete share server and
            # share network separately without dependency on each other.
            for security_service in network_info_list[0]['security_services']:
                ss_type = security_service['type']
                data = {
                    'name': security_service['name'],
                    'ou': security_service['ou'],
                    'domain': security_service['domain'],
                    'server': security_service['server'],
                    'dns_ip': security_service['dns_ip'],
                    'user': security_service['user'],
                    'type': ss_type,
                    'password': security_service['password'],
                    'default_ad_site': security_service['default_ad_site'],
                }
                self.db.share_server_backend_details_set(
                    context, share_server['id'],
                    {'security_service_' + ss_type: jsonutils.dumps(data)})

            server_info = self.driver.setup_server(
                network_info_list, metadata=metadata)

            self.driver.update_network_allocation(context, share_server)
            self.driver.update_admin_network_allocation(context, share_server)

            if server_info and isinstance(server_info, dict):
                self.db.share_server_backend_details_set(
                    context, share_server['id'], server_info)
            return self.db.share_server_update(
                context, share_server['id'],
                {'status': constants.STATUS_ACTIVE,
                 'identifier': server_info.get(
                     'identifier', share_server['id'])})
        except Exception as e:
            with excutils.save_and_reraise_exception():
                self._handle_setup_server_error(context, share_server['id'], e)
                self.driver.deallocate_network(context, share_server['id'])

    def _validate_segmentation_id(self, network_info):
        """Raises exception if the segmentation type is incorrect."""
        if (network_info['network_type'] in (None, 'flat') and
                network_info['segmentation_id']):
            msg = _('A segmentation ID %(vlan_id)s was specified but can not '
                    'be used with a network of type %(seg_type)s; the '
                    'segmentation ID option must be omitted or set to 0')
            raise exception.NetworkBadConfigurationException(
                reason=msg % {'vlan_id': network_info['segmentation_id'],
                              'seg_type': network_info['network_type']})
        elif (network_info['network_type'] == 'vlan'
              and (network_info['segmentation_id'] is None
                   or int(network_info['segmentation_id']) > 4094
                   or int(network_info['segmentation_id']) < 1)):
            msg = _('A segmentation ID %s was specified but is not valid for '
                    'a VLAN network type; the segmentation ID must be an '
                    'integer value in the range of [1,4094]')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network_info['segmentation_id'])
        elif (network_info['network_type'] == 'vxlan'
              and (network_info['segmentation_id'] is None
                   or int(network_info['segmentation_id']) > 16777215
                   or int(network_info['segmentation_id']) < 1)):
            msg = _('A segmentation ID %s was specified but is not valid for '
                    'a VXLAN network type; the segmentation ID must be an '
                    'integer value in the range of [1,16777215]')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network_info['segmentation_id'])
        elif (network_info['network_type'] == 'gre'
              and (network_info['segmentation_id'] is None
                   or int(network_info['segmentation_id']) > 4294967295
                   or int(network_info['segmentation_id']) < 1)):
            msg = _('A segmentation ID %s was specified but is not valid for '
                    'a GRE network type; the segmentation ID must be an '
                    'integer value in the range of [1, 4294967295]')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network_info['segmentation_id'])

    @add_hooks
    @utils.require_driver_initialized
    def delete_share_server(self, context, share_server):

        subnet_id = (share_server['share_network_subnet_ids'][0]
                     if share_server['share_network_subnet_ids'] else None)

        @utils.synchronized(
            "share_manager_%s" % subnet_id)
        def _wrapped_delete_share_server():
            # NOTE(vponomaryov): Verify that there are no dependent shares.
            # Without this verification we can get here exception in next case:
            # share-server-delete API was called after share creation scheduled
            # and share_server reached ACTIVE status, but before update
            # of share_server_id field for share. If so, after lock realese
            # this method starts executing when amount of dependent shares
            # has been changed.
            server_id = share_server['id']
            shares = self.db.share_instances_get_all_by_share_server(
                context, server_id)

            if shares:
                raise exception.ShareServerInUse(share_server_id=server_id)

            server_details = share_server['backend_details']

            self.db.share_server_update(context, server_id,
                                        {'status': constants.STATUS_DELETING})
            try:
                LOG.debug("Deleting share server '%s'", server_id)
                security_services = []
                for ss_name in constants.SECURITY_SERVICES_ALLOWED_TYPES:
                    ss = server_details.get('security_service_' + ss_name)
                    if ss:
                        security_services.append(jsonutils.loads(ss))

                self.driver.teardown_server(
                    server_details=server_details,
                    security_services=security_services)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(
                        "Share server '%s' failed on deletion.",
                        server_id)
                    self.db.share_server_update(
                        context, server_id, {'status': constants.STATUS_ERROR})
            else:
                self.db.share_server_delete(context, share_server['id'])

        _wrapped_delete_share_server()
        LOG.info(
            "Share server '%s' has been deleted successfully.",
            share_server['id'])
        self.driver.deallocate_network(context, share_server['id'])

    @add_hooks
    @utils.require_driver_initialized
    def extend_share(self, context, share_id, new_size, reservations):
        context = context.elevated()
        share = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share)
        share_server = self._get_share_server(context, share_instance)
        project_id = share['project_id']
        user_id = share['user_id']

        self._notify_about_share_usage(context, share,
                                       share_instance, "extend.start")

        try:
            self.driver.extend_share(
                share_instance, new_size, share_server=share_server)
        except Exception as e:
            LOG.exception("Extend share failed.", resource=share)
            self.message_api.create(
                context,
                message_field.Action.EXTEND,
                project_id,
                resource_type=message_field.Resource.SHARE,
                resource_id=share_id,
                detail=message_field.Detail.DRIVER_FAILED_EXTEND)
            try:
                self.db.share_update(
                    context, share['id'],
                    {'status': constants.STATUS_EXTENDING_ERROR}
                )
                raise exception.ShareExtendingError(
                    reason=str(e), share_id=share_id)
            finally:
                QUOTAS.rollback(
                    context, reservations, project_id=project_id,
                    user_id=user_id,
                    share_type_id=share_instance['share_type_id'],
                )

        # we give the user_id of the share, to update the quota usage
        # for the user, who created the share, because on share delete
        # only this quota will be decreased
        QUOTAS.commit(
            context, reservations, project_id=project_id,
            user_id=user_id, share_type_id=share_instance['share_type_id'],
        )

        share_update = {
            'size': int(new_size),
            # NOTE(u_glide): translation to lower case should be removed in
            # a row with usage of upper case of share statuses in all places
            'status': constants.STATUS_AVAILABLE.lower()
        }
        share = self.db.share_update(context, share['id'], share_update)

        LOG.info("Extend share completed successfully.", resource=share)

        self._notify_about_share_usage(context, share,
                                       share_instance, "extend.end")

    @add_hooks
    @utils.require_driver_initialized
    def shrink_share(self, context, share_id, new_size):
        context = context.elevated()
        share = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share)
        share_server = self._get_share_server(context, share_instance)
        project_id = share['project_id']
        user_id = share['user_id']
        new_size = int(new_size)
        replicas = self.db.share_replicas_get_all_by_share(
            context, share['id'])
        supports_replication = len(replicas) > 0

        self._notify_about_share_usage(context, share,
                                       share_instance, "shrink.start")

        def error_occurred(exc, msg, status=constants.STATUS_SHRINKING_ERROR):
            if isinstance(exc, NotImplementedError):
                msg = _("Shrink share operation not supported.")
                status = constants.STATUS_AVAILABLE
                self.message_api.create(
                    context,
                    message_field.Action.SHRINK,
                    share['project_id'],
                    resource_type=message_field.Resource.SHARE,
                    resource_id=share['id'],
                    detail=message_field.Detail.DRIVER_FAILED_SHRINK)
            LOG.exception(msg, resource=share)
            self.db.share_update(context, share['id'], {'status': status})

            raise exception.ShareShrinkingError(
                reason=str(exc), share_id=share_id)

        reservations = None

        try:
            size_decrease = int(share['size']) - new_size
            # we give the user_id of the share, to update the quota usage
            # for the user, who created the share, because on share delete
            # only this quota will be decreased
            deltas = {
                'project_id': project_id,
                'user_id': user_id,
                'share_type_id': share_instance['share_type_id'],
                'gigabytes': -size_decrease,
            }
            # NOTE(carloss): if the share supports replication we need
            # to query all its replicas and calculate the final size to
            # deallocate (amount of replicas * size to decrease).
            if supports_replication:
                replica_gigs_to_deallocate = len(replicas) * size_decrease
                deltas.update(
                    {'replica_gigabytes': -replica_gigs_to_deallocate})
            reservations = QUOTAS.reserve(context, **deltas)
        except Exception as e:
            error_occurred(
                e, ("Failed to update quota on share shrinking."))

        try:
            self.driver.shrink_share(
                share_instance, new_size, share_server=share_server)
        # NOTE(u_glide): Replace following except block by error notification
        # when Manila has such mechanism. It's possible because drivers
        # shouldn't shrink share when this validation error occurs.
        except Exception as e:
            if isinstance(e, exception.ShareShrinkingPossibleDataLoss):
                msg = ("Shrink share failed due to possible data loss.")
                status = constants.STATUS_AVAILABLE
                error_params = {'msg': msg, 'status': status}
                self.message_api.create(
                    context,
                    message_field.Action.SHRINK,
                    share['project_id'],
                    resource_type=message_field.Resource.SHARE,
                    resource_id=share_id,
                    detail=message_field.Detail.DRIVER_REFUSED_SHRINK)
            else:
                error_params = {'msg': ("Shrink share failed.")}

            try:
                error_occurred(e, **error_params)
            finally:
                QUOTAS.rollback(
                    context, reservations, project_id=project_id,
                    user_id=user_id,
                    share_type_id=share_instance['share_type_id'],
                )

        QUOTAS.commit(
            context, reservations, project_id=project_id,
            user_id=user_id, share_type_id=share_instance['share_type_id'],
        )

        share_update = {
            'size': new_size,
            'status': constants.STATUS_AVAILABLE
        }
        share = self.db.share_update(context, share['id'], share_update)

        LOG.info("Shrink share completed successfully.", resource=share)

        self._notify_about_share_usage(context, share,
                                       share_instance, "shrink.end")

    @utils.require_driver_initialized
    def create_share_group(self, context, share_group_id):
        context = context.elevated()
        share_group_ref = self.db.share_group_get(context, share_group_id)
        share_group_ref['host'] = self.host
        shares = self.db.share_instances_get_all_by_share_group_id(
            context, share_group_id)

        source_share_group_snapshot_id = share_group_ref.get(
            "source_share_group_snapshot_id")
        snap_ref = None
        parent_share_server_id = None
        if source_share_group_snapshot_id:
            snap_ref = self.db.share_group_snapshot_get(
                context, source_share_group_snapshot_id)
            for member in snap_ref['share_group_snapshot_members']:
                member['share'] = self.db.share_instance_get(
                    context, member['share_instance_id'], with_share_data=True)
            if 'share_group' in snap_ref:
                parent_share_server_id = snap_ref['share_group'][
                    'share_server_id']

        status = constants.STATUS_AVAILABLE

        share_network_id = share_group_ref.get('share_network_id')
        share_server = None

        if parent_share_server_id and self.driver.driver_handles_share_servers:
            share_server = self.db.share_server_get(context,
                                                    parent_share_server_id)
            share_network_id = (
                share_server['share_network_id'])

        if share_network_id and not self.driver.driver_handles_share_servers:
            self.db.share_group_update(
                context, share_group_id, {'status': constants.STATUS_ERROR})
            msg = _("Driver does not expect share-network to be provided "
                    "with current configuration.")
            raise exception.InvalidInput(reason=msg)

        if not share_server and share_network_id:

            availability_zone_id = self._get_az_for_share_group(
                context, share_group_ref)
            subnets = (
                self.db.share_network_subnets_get_all_by_availability_zone_id(
                    context, share_network_id, availability_zone_id))

            if not subnets:
                raise exception.ShareNetworkSubnetNotFound(
                    share_network_subnet_id=None)
            try:
                share_server, share_group_ref = (
                    self._provide_share_server_for_share_group(
                        context, share_network_id, subnets, share_group_ref,
                        share_group_snapshot=snap_ref,
                    )
                )
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error("Failed to get share server"
                              " for share group creation.")
                    self.db.share_group_update(
                        context, share_group_id,
                        {'status': constants.STATUS_ERROR})
                    self.message_api.create(
                        context,
                        message_field.Action.CREATE,
                        share_group_ref['project_id'],
                        resource_type=message_field.Resource.SHARE_GROUP,
                        resource_id=share_group_id,
                        detail=message_field.Detail.NO_SHARE_SERVER)

        try:
            # TODO(ameade): Add notification for create.start
            LOG.info("Share group %s: creating", share_group_id)

            model_update, share_update_list = None, None

            share_group_ref['shares'] = shares
            if snap_ref:
                model_update, share_update_list = (
                    self.driver.create_share_group_from_share_group_snapshot(
                        context, share_group_ref, snap_ref,
                        share_server=share_server))
            else:
                model_update = self.driver.create_share_group(
                    context, share_group_ref, share_server=share_server)

            if model_update:
                share_group_ref = self.db.share_group_update(
                    context, share_group_ref['id'], model_update)

            if share_update_list:
                for share in share_update_list:
                    values = copy.deepcopy(share)
                    # NOTE(dviroel): To keep backward compatibility we can't
                    # keep 'status' as a mandatory parameter. We'll set its
                    # value to 'available' as default.
                    i_status = values.get('status', constants.STATUS_AVAILABLE)
                    if i_status not in [
                        constants.STATUS_AVAILABLE,
                            constants.STATUS_CREATING_FROM_SNAPSHOT]:
                        msg = _(
                            'Driver returned an invalid status %s') % i_status
                        raise exception.InvalidShareInstance(reason=msg)
                    values['status'] = i_status
                    values['progress'] = (
                        '100%' if i_status == constants.STATUS_AVAILABLE
                        else '0%')
                    values.pop('id')
                    export_locations = values.pop('export_locations')
                    self.db.share_instance_update(context, share['id'], values)
                    self.db.share_export_locations_update(context,
                                                          share['id'],
                                                          export_locations)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_group_update(
                    context,
                    share_group_ref['id'],
                    {'status': constants.STATUS_ERROR,
                     'availability_zone_id': self._get_az_for_share_group(
                         context, share_group_ref),
                     'consistent_snapshot_support': self.driver._stats[
                         'share_group_stats'].get(
                             'consistent_snapshot_support')})
                for share in shares:
                    self.db.share_instance_update(
                        context, share['id'],
                        {'status': constants.STATUS_ERROR})
                LOG.error("Share group %s: create failed", share_group_id)

        now = timeutils.utcnow()
        for share in shares:
            self.db.share_instance_update(
                context, share['id'], {'status': constants.STATUS_AVAILABLE})
        self.db.share_group_update(
            context,
            share_group_ref['id'],
            {'status': status,
             'created_at': now,
             'availability_zone_id': self._get_az_for_share_group(
                 context, share_group_ref),
             'consistent_snapshot_support': self.driver._stats[
                 'share_group_stats'].get('consistent_snapshot_support')})
        LOG.info("Share group %s: created successfully", share_group_id)

        # TODO(ameade): Add notification for create.end

        return share_group_ref['id']

    def _get_az_for_share_group(self, context, share_group_ref):
        if not share_group_ref['availability_zone_id']:
            return self.db.availability_zone_get(
                context, self.availability_zone)['id']
        return share_group_ref['availability_zone_id']

    @utils.require_driver_initialized
    def delete_share_group(self, context, share_group_id):
        context = context.elevated()
        share_group_ref = self.db.share_group_get(context, share_group_id)
        share_group_ref['host'] = self.host
        share_group_ref['shares'] = (
            self.db.share_instances_get_all_by_share_group_id(
                context, share_group_id))

        # TODO(ameade): Add notification for delete.start

        try:
            LOG.info("Share group %s: deleting", share_group_id)
            share_server = None
            if share_group_ref.get('share_server_id'):
                share_server = self.db.share_server_get(
                    context, share_group_ref['share_server_id'])
            model_update = self.driver.delete_share_group(
                context, share_group_ref, share_server=share_server)

            if model_update:
                share_group_ref = self.db.share_group_update(
                    context, share_group_ref['id'], model_update)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_group_update(
                    context,
                    share_group_ref['id'],
                    {'status': constants.STATUS_ERROR})
                LOG.error("Share group %s: delete failed",
                          share_group_ref['id'])

        self.db.share_group_destroy(context, share_group_id)
        LOG.info("Share group %s: deleted successfully", share_group_id)

        # TODO(ameade): Add notification for delete.end

    @utils.require_driver_initialized
    def create_share_group_snapshot(self, context, share_group_snapshot_id):
        context = context.elevated()
        snap_ref = self.db.share_group_snapshot_get(
            context, share_group_snapshot_id)
        for member in snap_ref['share_group_snapshot_members']:
            member['share'] = self.db.share_instance_get(
                context, member['share_instance_id'], with_share_data=True)

        status = constants.STATUS_AVAILABLE
        now = timeutils.utcnow()
        updated_members_ids = []

        try:
            LOG.info("Share group snapshot %s: creating",
                     share_group_snapshot_id)
            share_server = None
            if snap_ref['share_group'].get('share_server_id'):
                share_server = self.db.share_server_get(
                    context, snap_ref['share_group']['share_server_id'])
            snapshot_update, member_update_list = (
                self.driver.create_share_group_snapshot(
                    context, snap_ref, share_server=share_server))

            for update in (member_update_list or []):
                # NOTE(vponomaryov): we expect that each member is a dict
                # and has required 'id' key and some optional keys
                # to be updated such as 'provider_location'. It is planned
                # to have here also 'export_locations' when it is supported.
                member_id = update.pop('id', None)
                if not member_id:
                    LOG.warning(
                        "One of share group snapshot '%s' members does not "
                        "have reference ID. Its update was skipped.",
                        share_group_snapshot_id)
                    continue
                # TODO(vponomaryov): remove following condition when
                # sgs members start supporting export locations.
                if 'export_locations' in update:
                    LOG.debug(
                        "Removing 'export_locations' data from "
                        "share group snapshot member '%s' update because "
                        "export locations are not supported.",
                        member_id)
                    update.pop('export_locations')

                db_update = {
                    'updated_at': now,
                    'status': update.pop('status', status)
                }
                if 'provider_location' in update:
                    db_update['provider_location'] = (
                        update.pop('provider_location'))
                if 'size' in update:
                    db_update['size'] = int(update.pop('size'))

                updated_members_ids.append(member_id)
                self.db.share_group_snapshot_member_update(
                    context, member_id, db_update)

                if update:
                    LOG.debug(
                        "Share group snapshot ID='%(sgs_id)s', "
                        "share group snapshot member ID='%(sgsm_id)s'. "
                        "Following keys of sgs member were not updated "
                        "as not allowed: %(keys)s.",
                        {'sgs_id': share_group_snapshot_id,
                         'sgsm_id': member_id,
                         'keys': ', '.join(update)})

            if snapshot_update:
                snap_ref = self.db.share_group_snapshot_update(
                    context, snap_ref['id'], snapshot_update)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_group_snapshot_update(
                    context,
                    snap_ref['id'],
                    {'status': constants.STATUS_ERROR})
                LOG.error("Share group snapshot %s: create failed",
                          share_group_snapshot_id)

        for member in (snap_ref.get('share_group_snapshot_members') or []):
            if member['id'] in updated_members_ids:
                continue
            update = {'status': status, 'updated_at': now}
            self.db.share_group_snapshot_member_update(
                context, member['id'], update)

        self.db.share_group_snapshot_update(
            context, snap_ref['id'],
            {'status': status, 'updated_at': now})
        LOG.info("Share group snapshot %s: created successfully",
                 share_group_snapshot_id)

        return snap_ref['id']

    @utils.require_driver_initialized
    def delete_share_group_snapshot(self, context, share_group_snapshot_id):
        context = context.elevated()
        snap_ref = self.db.share_group_snapshot_get(
            context, share_group_snapshot_id)
        for member in snap_ref['share_group_snapshot_members']:
            member['share'] = self.db.share_instance_get(
                context, member['share_instance_id'], with_share_data=True)

        snapshot_update = False

        try:
            LOG.info("Share group snapshot %s: deleting",
                     share_group_snapshot_id)

            share_server = None
            if snap_ref['share_group'].get('share_server_id'):
                share_server = self.db.share_server_get(
                    context, snap_ref['share_group']['share_server_id'])

            snapshot_update, member_update_list = (
                self.driver.delete_share_group_snapshot(
                    context, snap_ref, share_server=share_server))

            if member_update_list:
                snapshot_update = snapshot_update or {}
                snapshot_update['share_group_snapshot_members'] = []
            for update in (member_update_list or []):
                snapshot_update['share_group_snapshot_members'].append(update)

            if snapshot_update:
                snap_ref = self.db.share_group_snapshot_update(
                    context, snap_ref['id'], snapshot_update)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_group_snapshot_update(
                    context,
                    snap_ref['id'],
                    {'status': constants.STATUS_ERROR})
                LOG.error("Share group snapshot %s: delete failed",
                          snap_ref['name'])

        self.db.share_group_snapshot_destroy(context, share_group_snapshot_id)

        LOG.info("Share group snapshot %s: deleted successfully",
                 share_group_snapshot_id)

    def _get_share_server_dict(self, context, share_server):
        share_server_ref = {
            'id': share_server.get('id'),
            'project_id': share_server.get('project_id'),
            'updated_at': share_server.get('updated_at'),
            'status': share_server.get('status'),
            'host': share_server.get('host'),
            'share_network_name': share_server.get('share_network_name'),
            'share_network_id': share_server.get('share_network_id'),
            'created_at': share_server.get('created_at'),
            'backend_details': share_server.get('backend_details'),
            'share_network_subnet_ids':
                share_server.get('share_network_subnet_ids', []),
            'is_auto_deletable': share_server.get('is_auto_deletable', None),
            'identifier': share_server.get('identifier', None),
            'network_allocations': share_server.get('network_allocations',
                                                    None),
        }
        return share_server_ref

    def _get_export_location_dict(self, context, export_location):
        export_location_ref = {
            'id': export_location.get('uuid'),
            'path': export_location.get('path'),
            'created_at': export_location.get('created_at'),
            'updated_at': export_location.get('updated_at'),
            'share_instance_id':
                export_location.get('share_instance_id', None),
            'is_admin_only': export_location.get('is_admin_only', None),
        }
        return export_location_ref

    def _get_share_instance_dict(self, context, share_instance):
        # TODO(gouthamr): remove method when the db layer returns primitives
        share_instance_ref = {
            'id': share_instance.get('id'),
            'name': share_instance.get('name'),
            'share_id': share_instance.get('share_id'),
            'host': share_instance.get('host'),
            'status': share_instance.get('status'),
            'replica_state': share_instance.get('replica_state'),
            'availability_zone_id': share_instance.get('availability_zone_id'),
            'share_network_id': share_instance.get('share_network_id'),
            'share_server_id': share_instance.get('share_server_id'),
            'deleted': share_instance.get('deleted'),
            'terminated_at': share_instance.get('terminated_at'),
            'launched_at': share_instance.get('launched_at'),
            'scheduled_at': share_instance.get('scheduled_at'),
            'updated_at': share_instance.get('updated_at'),
            'deleted_at': share_instance.get('deleted_at'),
            'created_at': share_instance.get('created_at'),
            'share_server': self._get_share_server(context, share_instance),
            'access_rules_status': share_instance.get('access_rules_status'),
            # Share details
            'user_id': share_instance.get('user_id'),
            'project_id': share_instance.get('project_id'),
            'size': share_instance.get('size'),
            'display_name': share_instance.get('display_name'),
            'display_description': share_instance.get('display_description'),
            'snapshot_id': share_instance.get('snapshot_id'),
            'share_proto': share_instance.get('share_proto'),
            'share_type_id': share_instance.get('share_type_id'),
            'is_public': share_instance.get('is_public'),
            'share_group_id': share_instance.get('share_group_id'),
            'source_share_group_snapshot_member_id': share_instance.get(
                'source_share_group_snapshot_member_id'),
            'availability_zone': share_instance.get('availability_zone'),
        }
        if share_instance_ref['share_server']:
            share_instance_ref['share_server'] = self._get_share_server_dict(
                context, share_instance_ref['share_server']
            )
        share_instance_ref['export_locations'] = [
            self._get_export_location_dict(context, el) for
            el in share_instance.get('export_locations') or []
        ]
        return share_instance_ref

    def _get_snapshot_instance_dict(self, context, snapshot_instance,
                                    snapshot=None):
        # TODO(gouthamr): remove method when the db layer returns primitives
        snapshot_instance_ref = {
            'name': snapshot_instance.get('name'),
            'share_id': snapshot_instance.get('share_id'),
            'share_name': snapshot_instance.get('share_name'),
            'status': snapshot_instance.get('status'),
            'id': snapshot_instance.get('id'),
            'deleted': snapshot_instance.get('deleted') or False,
            'created_at': snapshot_instance.get('created_at'),
            'share': snapshot_instance.get('share'),
            'updated_at': snapshot_instance.get('updated_at'),
            'share_instance_id': snapshot_instance.get('share_instance_id'),
            'snapshot_id': snapshot_instance.get('snapshot_id'),
            'progress': snapshot_instance.get('progress'),
            'deleted_at': snapshot_instance.get('deleted_at'),
            'provider_location': snapshot_instance.get('provider_location'),
        }

        if snapshot:
            snapshot_instance_ref.update({
                'size': snapshot.get('size'),
            })

        return snapshot_instance_ref

    def snapshot_update_access(self, context, snapshot_instance_id):
        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_instance_id, with_share_data=True)

        share_server = self._get_share_server(
            context, snapshot_instance['share_instance'])

        self.snapshot_access_helper.update_access_rules(
            context, snapshot_instance['id'], share_server=share_server)

    def _notify_about_share_usage(self, context, share, share_instance,
                                  event_suffix, extra_usage_info=None):
        share_utils.notify_about_share_usage(
            context, share, share_instance, event_suffix,
            extra_usage_info=extra_usage_info, host=self.host)

    @utils.require_driver_initialized
    def create_backup(self, context, backup):
        share_id = backup['share_id']
        backup_id = backup['id']
        share = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share)

        LOG.info('Create backup started, backup: %(backup)s share: '
                 '%(share)s.', {'backup': backup_id, 'share': share_id})

        try:
            self.driver.create_backup(context, share_instance, backup)
        except Exception as err:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to create share backup %s by driver.",
                          backup_id)
                self.db.share_update(
                    context, share_id,
                    {'status': constants.STATUS_AVAILABLE})
                self.db.share_backup_update(
                    context, backup_id,
                    {'status': constants.STATUS_ERROR, 'fail_reason': err})

    @periodic_task.periodic_task(
        spacing=CONF.driver_backup_continue_update_interval)
    @utils.require_driver_initialized
    def create_backup_continue(self, context):
        """Invokes driver to continue backup of share."""
        filters = {'status': constants.STATUS_CREATING,
                   'host': self.host,
                   'topic': CONF.share_topic}
        backups = self.db.share_backups_get_all(context, filters)
        for backup in backups:
            backup_id = backup['id']
            share_id = backup['share_id']
            share = self.db.share_get(context, share_id)
            share_instance = self._get_share_instance(context, share)
            result = {}
            try:
                result = self.driver.create_backup_continue(
                    context, share_instance, backup)
                progress = result.get('total_progress', '0')
                self.db.share_backup_update(context, backup_id,
                                            {'progress': progress})
                if progress == '100':
                    self.db.share_update(
                        context, share_id,
                        {'status': constants.STATUS_AVAILABLE})
                    self.db.share_backup_update(
                        context, backup_id,
                        {'status': constants.STATUS_AVAILABLE})
                    LOG.info("Created share backup %s successfully.",
                             backup_id)
            except Exception:
                LOG.warning("Failed to get progress of share %(share)s "
                            "backing up in share_backup %(backup).",
                            {'share': share_id, 'backup': backup_id})
                self.db.share_update(
                    context, share_id,
                    {'status': constants.STATUS_AVAILABLE})
                self.db.share_backup_update(
                    context, backup_id,
                    {'status': constants.STATUS_ERROR, 'progress': '0'})

    def delete_backup(self, context, backup):
        LOG.info('Delete backup started, backup: %s.', backup['id'])

        backup_id = backup['id']
        project_id = backup['project_id']
        try:
            self.driver.delete_backup(context, backup)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to delete share backup %s.", backup_id)
                self.db.share_backup_update(
                    context, backup_id,
                    {'status': constants.STATUS_ERROR_DELETING})

        try:
            reserve_opts = {
                'backups': -1,
                'backup_gigabytes': -backup['size'],
            }
            reservations = QUOTAS.reserve(
                context, project_id=project_id, **reserve_opts)
        except Exception as e:
            reservations = None
            LOG.warning("Failed to update backup quota for %(pid)s: %(err)s.",
                        {'pid': project_id, 'err': e})

        if reservations:
            QUOTAS.commit(context, reservations, project_id=project_id)

        self.db.share_backup_delete(context, backup_id)
        LOG.info("Share backup %s deleted successfully.", backup_id)

    def restore_backup(self, context, backup, share_id):
        LOG.info('Restore backup started, backup: %(backup_id)s '
                 'share: %(share_id)s.',
                 {'backup_id': backup['id'], 'share_id': share_id})

        backup_id = backup['id']
        share = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share)

        try:
            self.driver.restore_backup(context, backup, share_instance)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to restore backup %(backup)s to share "
                          "%(share)s by driver.",
                          {'backup': backup_id, 'share': share_id})
                self.db.share_update(
                    context, share_id,
                    {'status': constants.STATUS_BACKUP_RESTORING_ERROR})
                self.db.share_backup_update(
                    context, backup['id'],
                    {'status': constants.STATUS_ERROR})

    @periodic_task.periodic_task(
        spacing=CONF.driver_restore_continue_update_interval)
    @utils.require_driver_initialized
    def restore_backup_continue(self, context):
        filters = {'status': constants.STATUS_RESTORING,
                   'host': self.host,
                   'topic': CONF.share_topic}
        backups = self.db.share_backups_get_all(context, filters)
        for backup in backups:
            backup_id = backup['id']
            try:
                filters = {
                    'source_backup_id': backup_id,
                }
                shares = self.db.share_get_all(context, filters)
            except Exception:
                LOG.warning('Failed to get shares for backup %s', backup_id)
                continue

            for share in shares:
                if share['status'] != constants.STATUS_BACKUP_RESTORING:
                    continue

                share_id = share['id']
                share_instance = self._get_share_instance(context, share)
                result = {}
                try:
                    result = self.driver.restore_backup_continue(
                        context, backup, share_instance)
                    progress = result.get('total_progress', '0')
                    self.db.share_backup_update(
                        context, backup_id, {'restore_progress': progress})

                    if progress == '100':
                        self.db.share_update(
                            context, share_id,
                            {'status': constants.STATUS_AVAILABLE})
                        self.db.share_backup_update(
                            context, backup_id,
                            {'status': constants.STATUS_AVAILABLE})
                        LOG.info("Share backup %s restored successfully.",
                                 backup_id)
                except Exception:
                    LOG.exception("Failed to get progress of share_backup "
                                  "%(backup)s restoring in share %(share).",
                                  {'share': share_id, 'backup': backup_id})
                    self.db.share_update(
                        context, share_id,
                        {'status': constants.STATUS_BACKUP_RESTORING_ERROR})
                    self.db.share_backup_update(
                        context, backup_id,
                        {'status': constants.STATUS_AVAILABLE,
                         'restore_progress': '0'})

    @periodic_task.periodic_task(
        spacing=CONF.share_usage_size_update_interval,
        enabled=CONF.enable_gathering_share_usage_size)
    @utils.require_driver_initialized
    def update_share_usage_size(self, context):
        """Invokes driver to gather usage size of shares."""
        updated_share_instances = []
        share_instances = self.db.share_instances_get_all_by_host(
            context, host=self.host, with_share_data=True)

        if share_instances:
            try:
                updated_share_instances = self.driver.update_share_usage_size(
                    context, share_instances)
            except Exception:
                LOG.exception("Gather share usage size failure.")

        for si in updated_share_instances:
            share_instance = self._get_share_instance(context, si['id'])
            share = self.db.share_get(context, share_instance['share_id'])
            self._notify_about_share_usage(
                context, share, share_instance, "consumed.size",
                extra_usage_info={'used_size': si['used_size'],
                                  'gathered_at': si['gathered_at']})

    @periodic_task.periodic_task(spacing=CONF.periodic_interval)
    @utils.require_driver_initialized
    def periodic_share_status_update(self, context):
        """Invokes share driver to update shares status."""
        LOG.debug("Updating status of share instances.")
        share_instances = self.db.share_instances_get_all_by_host(
            context, self.host, with_share_data=True,
            status=constants.STATUS_CREATING_FROM_SNAPSHOT)

        for si in share_instances:
            si_dict = self._get_share_instance_dict(context, si)
            self._update_share_status(context, si_dict)

    def _update_share_status(self, context, share_instance):
        share_server = self._get_share_server(context, share_instance)
        if share_server is not None:
            share_server = self._get_share_server_dict(context,
                                                       share_server)
        try:
            data_updates = self.driver.get_share_status(share_instance,
                                                        share_server)
        except Exception:
            LOG.exception(
                ("Unexpected driver error occurred while updating status for "
                 "share instance %(id)s that belongs to share '%(share_id)s'"),
                {'id': share_instance['id'],
                 'share_id': share_instance['share_id']}
            )
            data_updates = {
                'status': constants.STATUS_ERROR
            }

        status = data_updates.get('status')
        if status == constants.STATUS_ERROR:
            msg = ("Status of share instance %(id)s that belongs to share "
                   "%(share_id)s was updated to '%(status)s'."
                   % {'id': share_instance['id'],
                      'share_id': share_instance['share_id'],
                      'status': status})
            LOG.error(msg)
            self.db.share_instance_update(
                context, share_instance['id'],
                {'status': constants.STATUS_ERROR,
                 'progress': None})
            self.message_api.create(
                context,
                message_field.Action.UPDATE,
                share_instance['project_id'],
                resource_type=message_field.Resource.SHARE,
                resource_id=share_instance['share_id'],
                detail=message_field.Detail.DRIVER_FAILED_CREATING_FROM_SNAP)
            return

        export_locations = data_updates.get('export_locations')
        progress = data_updates.get('progress')

        statuses_requiring_update = [
            constants.STATUS_AVAILABLE,
            constants.STATUS_CREATING_FROM_SNAPSHOT]

        if status in statuses_requiring_update:
            si_updates = {
                'status': status,
            }
            progress = ('100%' if status == constants.STATUS_AVAILABLE
                        else progress)
            if progress is not None:
                si_updates.update({'progress': progress})
            self.db.share_instance_update(
                context, share_instance['id'], si_updates)
            msg = ("Status of share instance %(id)s that belongs to share "
                   "%(share_id)s was updated to '%(status)s'."
                   % {'id': share_instance['id'],
                      'share_id': share_instance['share_id'],
                      'status': status})
            LOG.debug(msg)
        if export_locations:
            self.db.share_export_locations_update(
                context, share_instance['id'], export_locations)

    def _validate_check_compatibility_result(
            self, context, resource_id, share_instances, snapshot_instances,
            driver_compatibility, dest_host, nondisruptive, writable,
            preserve_snapshots, resource_type='share'):
        resource_exception = (
            exception.ShareMigrationFailed
            if resource_type == 'share'
            else exception.ShareServerMigrationFailed)
        if not driver_compatibility.get('compatible'):
            msg = _("Destination host %(host)s is not compatible with "
                    "%(resource_type)s %(resource_id)s's source backend for "
                    "driver-assisted migration.") % {
                        'host': dest_host,
                        'resource_id': resource_id,
                        'resource_type': resource_type,
            }
            raise resource_exception(reason=msg)

        if (not driver_compatibility.get('nondisruptive') and
                nondisruptive):
            msg = _("Driver cannot perform a non-disruptive migration of "
                    "%(resource_type)s %(resource_id)s.") % {
                        'resource_type': resource_type,
                        'resource_id': resource_id
            }
            raise resource_exception(reason=msg)

        if not driver_compatibility.get('writable') and writable:
            msg = _("Driver cannot perform migration of %(resource_type)s "
                    "%(resource_id)s while remaining writable.") % {
                        'resource_type': resource_type,
                        'resource_id': resource_id
            }
            raise resource_exception(reason=msg)

        if (not driver_compatibility.get('preserve_snapshots')
                and preserve_snapshots):
            msg = _("Driver cannot perform migration of %(resource_type)s "
                    "%(resource_id)s while preserving snapshots.") % {
                        'resource_type': resource_type,
                        'resource_id': resource_id
            }
            raise resource_exception(reason=msg)

        if (not driver_compatibility.get('preserve_snapshots')
                and snapshot_instances):
            msg = _("Driver does not support preserving snapshots. The "
                    "migration of the %(resource_type)s %(resource_id)s "
                    "cannot proceed while it has snapshots.") % {
                        'resource_type': resource_type,
                        'resource_id': resource_id
            }
            raise resource_exception(reason=msg)

    def _update_resource_status(self, context, status, task_state=None,
                                share_instance_ids=None,
                                snapshot_instance_ids=None):
        fields = {'status': status}
        if task_state:
            fields['task_state'] = task_state
        if share_instance_ids:
            self.db.share_instances_status_update(
                context, share_instance_ids, fields)
        if snapshot_instance_ids:
            self.db.share_snapshot_instances_status_update(
                context, snapshot_instance_ids, fields)

    def _share_server_migration_start_driver(
            self, context, source_share_server, dest_host, writable,
            nondisruptive, preserve_snapshots, new_share_network_id):

        share_instances = self.db.share_instances_get_all_by_share_server(
            context, source_share_server['id'], with_share_data=True)
        share_instance_ids = [x.id for x in share_instances]

        snapshot_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, {'share_instance_ids': share_instance_ids}))
        snapshot_instance_ids = [x.id for x in snapshot_instances]

        old_share_network = self.db.share_network_get(
            context, share_instances[0]['share_network_id'])
        new_share_network = self.db.share_network_get(
            context, new_share_network_id)

        service_host = share_utils.extract_host(dest_host)
        service = self.db.service_get_by_args(
            context, service_host, 'manila-share')

        # NOTE(dviroel): We'll build a list of request specs and send it to
        # the driver so vendors have a chance to validate if the destination
        # host meets the requirements before starting the migration.
        shares_request_spec = (
            self.share_api.get_share_server_migration_request_spec_dict(
                context,
                share_instances,
                snapshot_instances,
                availability_zone_id=service['availability_zone_id'],
                share_network_id=new_share_network_id))

        dest_share_server = None
        try:
            compatibility = (
                self.driver.share_server_migration_check_compatibility(
                    context, source_share_server, dest_host, old_share_network,
                    new_share_network, shares_request_spec))

            self._validate_check_compatibility_result(
                context, source_share_server, share_instances,
                snapshot_instances, compatibility, dest_host, nondisruptive,
                writable, preserve_snapshots, resource_type='share server')

            create_server_on_backend = not compatibility.get('nondisruptive')
            dest_share_server = self._provide_share_server_for_migration(
                context, source_share_server, new_share_network_id,
                service['availability_zone_id'], dest_host,
                create_on_backend=create_server_on_backend)

            net_changes_identified = False
            if not create_server_on_backend:
                dest_share_server = self.db.share_server_get(
                    context, dest_share_server['id'])
                net_changes_identified = (
                    not share_utils.is_az_subnets_compatible(
                        dest_share_server['share_network_subnets'],
                        source_share_server['share_network_subnets']))

                # NOTE(carloss): Even though the share back end won't need to
                # create a share server, if a network change was identified,
                # there is need to allocate new interfaces to the share server,
                # so the back end can set up the new ips considering
                # the new networking parameters when completing the migration.
                # In such case, the migration will be disruptive, since the old
                # allocations will be replaced by the new ones.
                if net_changes_identified:
                    share_network_subnets = (
                        self.db.
                        share_network_subnet_get_all_by_share_server_id(
                            context, dest_share_server['id']))
                    for share_network_subnet in share_network_subnets:
                        self.driver.allocate_network(
                            context, dest_share_server, new_share_network,
                            share_network_subnet)
                    self.driver.allocate_admin_network(
                        context, dest_share_server)
                    # Refresh the share server so it will have the network
                    # allocations when sent to the driver
                    dest_share_server = self.db.share_server_get(
                        context, dest_share_server['id'])

            self.db.share_server_update(
                context, dest_share_server['id'],
                {'status': constants.STATUS_SERVER_MIGRATING_TO,
                 'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS,
                 'source_share_server_id': source_share_server['id']})

            if not compatibility.get('writable'):
                # NOTE(dviroel): Only modify access rules to read-only if the
                # driver doesn't support 'writable'.
                self._cast_access_rules_to_readonly_for_server(
                    context, share_instances, source_share_server,
                    dest_host=source_share_server['host'])

            LOG.debug("Initiating driver migration for share server %s.",
                      source_share_server['id'])

            self.db.share_server_update(
                context, source_share_server['id'],
                {'task_state': (
                    constants.TASK_STATE_MIGRATION_DRIVER_STARTING)})
            self.db.share_server_update(
                context, dest_share_server['id'],
                {'task_state': (
                    constants.TASK_STATE_MIGRATION_DRIVER_STARTING)})

            server_info = self.driver.share_server_migration_start(
                context, source_share_server, dest_share_server,
                share_instances, snapshot_instances)

            backend_details = (
                server_info.get('backend_details') if server_info else None)
            if backend_details:
                self.db.share_server_backend_details_set(
                    context, dest_share_server['id'], backend_details)

            self.db.share_server_update(
                context, source_share_server['id'],
                {'task_state': (
                    constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)})
            self.db.share_server_update(
                context, dest_share_server['id'],
                {'task_state': (
                    constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)})

        except Exception:
            # Rollback status changes for affected resources
            self._update_resource_status(
                context, constants.STATUS_AVAILABLE,
                share_instance_ids=share_instance_ids,
                snapshot_instance_ids=snapshot_instance_ids)
            # Rollback read only access rules
            self._reset_read_only_access_rules_for_server(
                context, share_instances, source_share_server,
                dest_host=source_share_server['host'])
            if dest_share_server:
                self.db.share_server_update(
                    context, dest_share_server['id'],
                    {'task_state': constants.TASK_STATE_MIGRATION_ERROR,
                     'status': constants.STATUS_ERROR})
                if not create_server_on_backend:
                    if net_changes_identified:
                        self.driver.deallocate_network(
                            context, dest_share_server['id'])
                    self.db.share_server_delete(
                        context, dest_share_server['id'])
                else:
                    self.delete_share_server(context, dest_share_server)
            msg = _("Driver-assisted migration of share server %s "
                    "failed.") % source_share_server['id']
            LOG.exception(msg)
            raise exception.ShareServerMigrationFailed(reason=msg)

        return True

    @add_hooks
    @utils.require_driver_initialized
    def share_server_migration_check(self, context, share_server_id, dest_host,
                                     writable, nondisruptive,
                                     preserve_snapshots, new_share_network_id):
        driver_result = {}
        result = {
            'compatible': False,
            'writable': None,
            'preserve_snapshots': None,
            'nondisruptive': None,
            'share_network_id': new_share_network_id,
            'migration_cancel': None,
            'migration_get_progress': None
        }

        if not self.driver.driver_handles_share_servers:
            LOG.error('This operation is supported only on backends that '
                      'handles share servers.')
            return result

        share_server = self.db.share_server_get(context, share_server_id)
        share_instances = self.db.share_instances_get_all_by_share_server(
            context, share_server_id, with_share_data=True)
        share_instance_ids = [x.id for x in share_instances]

        snapshot_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, {'share_instance_ids': share_instance_ids}))

        old_share_network = self.db.share_network_get(
            context, share_instances[0]['share_network_id'])
        new_share_network = self.db.share_network_get(
            context, new_share_network_id)

        service_host = share_utils.extract_host(dest_host)
        service = self.db.service_get_by_args(
            context, service_host, 'manila-share')

        # NOTE(dviroel): We'll build a list of request specs and send it to
        # the driver so vendors have a chance to validate if the destination
        # host meets the requirements before starting the migration.
        shares_request_spec = (
            self.share_api.get_share_server_migration_request_spec_dict(
                context,
                share_instances,
                snapshot_instances,
                availability_zone_id=service['availability_zone_id'],
                share_network_id=new_share_network_id))

        try:
            driver_result = (
                self.driver.share_server_migration_check_compatibility(
                    context, share_server, dest_host, old_share_network,
                    new_share_network, shares_request_spec))

            self._validate_check_compatibility_result(
                context, share_server, share_instances,
                snapshot_instances, driver_result, dest_host, nondisruptive,
                writable, preserve_snapshots, resource_type='share server')

        except Exception:
            # Update driver result to not compatible since it didn't pass in
            # the validations.
            driver_result['compatible'] = False

        result.update(driver_result)

        return result

    @add_hooks
    @utils.require_driver_initialized
    def share_server_migration_start(
            self, context, share_server_id, dest_host, writable,
            nondisruptive, preserve_snapshots, new_share_network_id=None):
        """Migrates a share server from current host to another host."""
        LOG.debug("Entered share_server_migration_start method for share "
                  "server %s.", share_server_id)

        self.db.share_server_update(
            context, share_server_id,
            {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS})

        share_server = self.db.share_server_get(context, share_server_id)

        try:
            if not self.driver.driver_handles_share_servers:
                LOG.error('This operation is supported only on backends that '
                          'handle share servers.')
                raise

            self._share_server_migration_start_driver(
                context, share_server, dest_host, writable, nondisruptive,
                preserve_snapshots, new_share_network_id)
        except Exception:
            LOG.exception(
                ("The driver could not migrate the share server "
                 "%(server)s"), {'server': share_server_id})
            self.db.share_server_update(
                context, share_server_id,
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR,
                 'status': constants.STATUS_ACTIVE})

    @periodic_task.periodic_task(
        spacing=CONF.server_migration_driver_continue_update_interval)
    @add_hooks
    @utils.require_driver_initialized
    def share_server_migration_driver_continue(self, context):
        """Invokes driver to continue migration of share server."""

        # Searching for destination share servers
        share_servers = self.db.share_server_get_all_by_host(
            context, self.host,
            filters={'status': constants.STATUS_SERVER_MIGRATING_TO})

        dest_updates_on_error = {
            'task_state': constants.TASK_STATE_MIGRATION_ERROR,
            'status': constants.STATUS_ERROR,
        }
        src_updates_on_error = {
            'task_state': constants.TASK_STATE_MIGRATION_ERROR,
            'status': constants.STATUS_ACTIVE,
        }
        updates_on_finished = {
            'task_state': constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE
        }
        for dest_share_server in share_servers:
            if dest_share_server['task_state'] == (
                    constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):
                src_share_server_id = dest_share_server.get(
                    'source_share_server_id')
                if src_share_server_id is None:
                    msg = _('Destination share server %s does not have a '
                            'source share server id.'
                            ) % dest_share_server['id']
                    LOG.error(msg)
                    self.db.share_server_update(
                        context, dest_share_server['id'],
                        dest_updates_on_error)
                    continue
                msg_args = {
                    'src_id': src_share_server_id,
                    'dest_id': dest_share_server['id']
                }
                src_share_server = self.db.share_server_get(
                    context, src_share_server_id)
                if not src_share_server:
                    msg = _('Destination share server %(dest_id)s refers to '
                            'a source share server %(src_id)s that does not '
                            'exists.') % msg_args
                    LOG.error(msg)
                    self.db.share_server_update(
                        context, dest_share_server['id'],
                        dest_updates_on_error)
                    continue
                if (src_share_server['status'] !=
                        constants.STATUS_SERVER_MIGRATING):
                    msg = _('Destination share server %(dest_id)s refers to '
                            'a source share server %(src_id)s that is not '
                            ' being migrated.') % msg_args
                    LOG.error(msg)
                    self.db.share_server_update(
                        context, dest_share_server['id'],
                        dest_updates_on_error)
                    continue

                share_instances = (
                    self.db.share_instances_get_all_by_share_server(
                        context, src_share_server_id, with_share_data=True))
                share_instance_ids = [x.id for x in share_instances]

                snapshot_instances = (
                    self.db.share_snapshot_instance_get_all_with_filters(
                        context,
                        {'share_instance_ids': share_instance_ids}))
                snapshot_instance_ids = [x.id for x in snapshot_instances]

                try:
                    finished = self.driver.share_server_migration_continue(
                        context, src_share_server, dest_share_server,
                        share_instances, snapshot_instances)

                    if finished:
                        self.db.share_server_update(
                            context, src_share_server['id'],
                            updates_on_finished)
                        self.db.share_server_update(
                            context, dest_share_server['id'],
                            updates_on_finished)
                        msg = _("Share server migration for share %s "
                                "completed first phase successfully."
                                ) % src_share_server['id']
                        LOG.info(msg)
                    else:
                        src_share_server = self.db.share_server_get(
                            context, src_share_server['id'])
                        if (src_share_server['task_state'] ==
                                constants.TASK_STATE_MIGRATION_CANCELLED):
                            msg = _("Share server migration for share %s was "
                                    "cancelled.") % src_share_server['id']
                            LOG.warning(msg)
                except Exception:
                    self._update_resource_status(
                        context, constants.STATUS_AVAILABLE,
                        share_instance_ids=share_instance_ids,
                        snapshot_instance_ids=snapshot_instance_ids)
                    self._reset_read_only_access_rules_for_server(
                        context, share_instances, src_share_server,
                        dest_host=dest_share_server['host'])
                    self.db.share_server_update(
                        context, dest_share_server['id'],
                        dest_updates_on_error)
                    if src_share_server:
                        self.db.share_server_update(
                            context, src_share_server['id'],
                            src_updates_on_error)

                    msg = _("Migration of share server %s has failed.")
                    LOG.exception(msg, src_share_server['id'])

    @add_hooks
    @utils.require_driver_initialized
    def share_server_migration_complete(self, context, src_share_server_id,
                                        dest_share_server_id):
        """Invokes driver to complete the migration of share server."""
        dest_server = self.db.share_server_get(context, dest_share_server_id)
        src_server = self.db.share_server_get(context, src_share_server_id)

        share_instances = (
            self.db.share_instances_get_all_by_share_server(
                context, src_share_server_id, with_share_data=True))
        share_instance_ids = [x.id for x in share_instances]

        snapshot_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context,
                {'share_instance_ids': share_instance_ids}))
        snapshot_instance_ids = [x.id for x in snapshot_instances]

        updates_on_error = {
            'task_state': constants.TASK_STATE_MIGRATION_ERROR,
            'status': constants.STATUS_ERROR,
        }
        try:
            self._server_migration_complete_driver(context,
                                                   src_server,
                                                   share_instances,
                                                   snapshot_instances,
                                                   dest_server)
        except Exception:
            msg = _("Driver migration completion failed for"
                    " share server %s.") % src_share_server_id
            LOG.exception(msg)
            self._update_resource_status(
                context, constants.STATUS_ERROR,
                share_instance_ids=share_instance_ids,
                snapshot_instance_ids=snapshot_instance_ids)
            self.db.share_server_update(
                context, src_share_server_id, updates_on_error)
            self.db.share_server_update(
                context, dest_share_server_id, updates_on_error)
            msg_args = {
                'source_id': src_share_server_id,
                'dest_id': dest_share_server_id
            }
            msg = _('Share server migration from %(source_id)s to %(dest_id)s '
                    'has failed in migration-complete phase.') % msg_args
            raise exception.ShareServerMigrationFailed(reason=msg)

        server_update_args = {
            'task_state': constants.TASK_STATE_MIGRATION_SUCCESS,
            'status': constants.STATUS_ACTIVE
        }

        # Migration mechanism reused the share server
        if not dest_server['identifier']:
            server_update_args['identifier'] = src_server['identifier']

        # Update share server status for success scenario
        self.db.share_server_update(
            context, dest_share_server_id, server_update_args)
        self._update_resource_status(
            context, constants.STATUS_AVAILABLE,
            share_instance_ids=share_instance_ids,
            snapshot_instance_ids=snapshot_instance_ids)

        LOG.info("Share Server Migration for share server %s was completed "
                 "with success.", src_share_server_id)

    def _server_migration_complete_driver(self, context, source_share_server,
                                          share_instances,
                                          snapshot_instances,
                                          dest_share_server):

        self.db.share_server_update(
            context, source_share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING})
        self.db.share_server_update(
            context, dest_share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING})

        # Retrieve network allocations reserved for the new share server
        dest_snss = dest_share_server['share_network_subnets']
        dest_sn_id = dest_snss[0]['share_network_id']
        dest_sn = self.db.share_network_get(context, dest_sn_id)
        dest_snss = self.db.share_network_subnet_get_all_by_share_server_id(
            context, dest_share_server['id'])

        migration_reused_network_allocations = (len(
            self.db.network_allocations_get_for_share_server(
                context, dest_share_server['id'])) == 0)

        server_to_get_allocations = (
            dest_share_server
            if not migration_reused_network_allocations
            else source_share_server)

        new_network_allocations = self._form_server_setup_info(
            context, server_to_get_allocations, dest_sn, dest_snss)

        model_update = self.driver.share_server_migration_complete(
            context, source_share_server, dest_share_server, share_instances,
            snapshot_instances, new_network_allocations)

        if not migration_reused_network_allocations:
            network_allocations = []
            for net_allocation in new_network_allocations:
                network_allocations += net_allocation['network_allocations']

            all_allocations = [
                network_allocations,
                new_network_allocations[0]['admin_network_allocations']
            ]
            for allocations in all_allocations:
                for allocation in allocations:
                    allocation_id = allocation['id']
                    values = {
                        'share_server_id': dest_share_server['id']
                    }
                    self.db.network_allocation_update(
                        context, allocation_id, values)

        # If share server doesn't have an identifier, we didn't ask the driver
        # to create a brand new server - this was a nondisruptive migration
        share_server_was_reused = not dest_share_server['identifier']
        if share_server_was_reused:
            driver_backend_details = model_update.get(
                'server_backend_details')
            # Clean up the previous backend details set for migration details
            if driver_backend_details:
                self.db.share_server_backend_details_delete(
                    context, dest_share_server['id'])
            backend_details = (
                driver_backend_details
                or source_share_server.get("backend_details"))
            if backend_details:
                for k, v in backend_details.items():
                    self.db.share_server_backend_details_set(
                        context, dest_share_server['id'], {k: v})

        host_value = share_utils.extract_host(dest_share_server['host'])
        service = self.db.service_get_by_args(
            context, host_value, 'manila-share')
        new_az_id = service['availability_zone_id']

        share_updates = model_update.get('share_updates', {})
        for share_instance in share_instances:
            share_update = share_updates.get(share_instance['id'], {})
            new_share_host = share_utils.append_host(
                dest_share_server['host'], share_update.get('pool_name'))
            # Update share instance with new values
            instance_update = {
                'share_server_id': dest_share_server['id'],
                'host': new_share_host,
                'share_network_id': dest_sn_id,
                'availability_zone_id': new_az_id,
            }
            self.db.share_instance_update(
                context, share_instance['id'], instance_update)
            # Try to update info returned in the model update
            if not share_update:
                continue
            # Update export locations
            update_export_location = (
                share_updates[share_instance['id']].get('export_locations'))
            if update_export_location:
                self.db.share_export_locations_update(
                    context, share_instance['id'], update_export_location)

        snapshot_updates = model_update.get('snapshot_updates', {})
        for snap_instance in snapshot_instances:
            model_update = snapshot_updates.get(snap_instance['id'], {})
            snapshot_export_locations = model_update.pop(
                'export_locations', [])
            if model_update:
                self.db.share_snapshot_instance_update(
                    context, snap_instance['id'], model_update)

            if snapshot_export_locations:
                export_locations_update = []
                for exp_location in snapshot_export_locations:
                    updated_el = {
                        'path': exp_location['path'],
                        'is_admin_only': exp_location['is_admin_only'],
                    }
                    export_locations_update.append(updated_el)
                self.db.share_snapshot_instance_export_locations_update(
                    context, snap_instance['id'], export_locations_update)

        # Reset read only access since migration has finished
        self._reset_read_only_access_rules_for_server(
            context, share_instances, source_share_server,
            dest_host=source_share_server['host'])

        # NOTE(dviroel): Setting the source share server to INACTIVE to avoid
        # being reused for new shares, since it may have some invalid
        # configurations and most of the drivers don't check for compatible
        # share servers on share creation.
        self.db.share_server_update(
            context, source_share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_SUCCESS,
             'status': constants.STATUS_INACTIVE})

        if share_server_was_reused:
            self.driver.deallocate_network(context, source_share_server['id'])
            self.db.share_server_delete(context, source_share_server['id'])
        else:
            source_share_server = self._get_share_server_dict(
                context, source_share_server)
            rpcapi = share_rpcapi.ShareAPI()
            rpcapi.delete_share_server(context, source_share_server)

    @add_hooks
    @utils.require_driver_initialized
    def share_server_migration_cancel(self, context, src_share_server_id,
                                      dest_share_server_id):
        share_server = self.db.share_server_get(context, src_share_server_id)
        dest_share_server = self.db.share_server_get(context,
                                                     dest_share_server_id)

        if share_server['task_state'] not in (
                constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):
            msg = _("Migration of share server %s cannot be cancelled at this "
                    "moment.") % src_share_server_id
            raise exception.InvalidShareServer(reason=msg)

        share_instances = (
            self.db.share_instances_get_all_by_share_server(
                context, src_share_server_id, with_share_data=True))
        share_instance_ids = [x.id for x in share_instances]

        snapshot_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context,
                {'share_instance_ids': share_instance_ids}))
        snapshot_instance_ids = [x.id for x in snapshot_instances]

        # Avoid new migration continue and cancel calls while cancelling the
        # migration, which can take some time to finish. The cancel in progress
        # state will help administrator to identify if the operation is still
        # in progress.
        self.db.share_server_update(
            context, share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_CANCEL_IN_PROGRESS})

        self.driver.share_server_migration_cancel(
            context, share_server, dest_share_server,
            share_instances, snapshot_instances)

        # NOTE(dviroel): After cancelling the migration we should set the new
        # share server to INVALID since it may contain an invalid configuration
        # to be reused. We also cleanup the source_share_server_id to unblock
        # new migrations.
        self.db.share_server_update(
            context, dest_share_server_id,
            {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED,
             'status': constants.STATUS_INACTIVE})

        self._check_delete_share_server(context,
                                        share_server=dest_share_server)

        self._update_resource_status(
            context, constants.STATUS_AVAILABLE,
            share_instance_ids=share_instance_ids,
            snapshot_instance_ids=snapshot_instance_ids)

        self._reset_read_only_access_rules_for_server(
            context, share_instances, share_server,
            dest_host=share_server['host'])

        self.db.share_server_update(
            context, share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED,
             'status': constants.STATUS_ACTIVE})

        LOG.info("Share Server Migration for share server %s was cancelled.",
                 share_server['id'])

    @add_hooks
    @utils.require_driver_initialized
    def share_server_migration_get_progress(
            self, context, src_share_server_id, dest_share_server_id):

        src_share_server = self.db.share_server_get(context,
                                                    src_share_server_id)
        if src_share_server['task_state'] != (
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):
            msg = _("Driver is not performing migration for"
                    " share server %s at this moment.") % src_share_server_id
            raise exception.InvalidShareServer(reason=msg)

        dest_share_server = self.db.share_server_get(context,
                                                     dest_share_server_id)
        share_instances = (
            self.db.share_instances_get_all_by_share_server(
                context, src_share_server_id, with_share_data=True))
        share_instance_ids = [x.id for x in share_instances]

        snapshot_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context,
                {'share_instance_ids': share_instance_ids}))

        return self.driver.share_server_migration_get_progress(
            context, src_share_server, dest_share_server, share_instances,
            snapshot_instances)

    @locked_share_network_operation
    def _check_share_network_update_finished(
            self, context, share_network_id=None):
        # Check if this share network is already active
        share_network = self.db.share_network_get(context, share_network_id)
        if share_network['status'] == constants.STATUS_NETWORK_ACTIVE:
            return

        share_servers = self.db.share_server_get_all_with_filters(
            context, {'share_network_id': share_network_id}
        )

        if all([ss['status'] != constants.STATUS_SERVER_NETWORK_CHANGE
                for ss in share_servers]):
            # All share servers have updated their configuration
            self.db.share_network_update(
                context, share_network_id,
                {'status': constants.STATUS_NETWORK_ACTIVE})

    def _update_share_network_security_service(
            self, context, share_network_id, new_security_service_id,
            current_security_service_id=None, check_only=False):

        new_security_service = self.db.security_service_get(
            context, new_security_service_id)

        current_security_service = None
        if current_security_service_id:
            current_security_service = self.db.security_service_get(
                context, current_security_service_id)

        new_ss_type = new_security_service['type']
        backend_details_data = {
            'name': new_security_service['name'],
            'ou': new_security_service['ou'],
            'default_ad_site': new_security_service['default_ad_site'],
            'domain': new_security_service['domain'],
            'server': new_security_service['server'],
            'dns_ip': new_security_service['dns_ip'],
            'user': new_security_service['user'],
            'type': new_ss_type,
            'password': new_security_service['password'],
        }

        share_network = self.db.share_network_get(
            context, share_network_id)

        share_servers = self.db.share_server_get_all_by_host(
            context, self.host,
            filters={'share_network_id': share_network_id})

        for share_server in share_servers:

            # Get share_network_subnet in case it was updated.
            share_network_subnets = (
                self.db.share_network_subnet_get_all_by_share_server_id(
                    context, share_server['id']))

            network_info = self._form_server_setup_info(
                context, share_server, share_network, share_network_subnets)

            share_instances = (
                self.db.share_instances_get_all_by_share_server(
                    context, share_server['id'], with_share_data=True))
            share_instance_ids = [sn.id for sn in share_instances]

            share_instances_rules = []
            for share_instance_id in share_instance_ids:
                instance_rules = {
                    'share_instance_id': share_instance_id,
                    'access_rules': (
                        self.db.share_access_get_all_for_instance(
                            context, share_instance_id))
                }
                share_instances_rules.append(instance_rules)

            # Only check if the driver supports this kind of update.
            if check_only:
                if self.driver.check_update_share_server_security_service(
                        context, share_server, network_info,
                        share_instances, share_instances_rules,
                        new_security_service,
                        current_security_service=current_security_service):
                    # Check the next share server.
                    continue
                else:
                    # At least one share server doesn't support this update
                    return False

            # NOTE(dviroel): We always do backend details update since it
            # should be the expected configuration for this share server. Any
            # issue with this operation should be fixed by the admin which will
            # guarantee that storage and backend_details configurations match.
            self.db.share_server_backend_details_set(
                context, share_server['id'],
                {'security_service_' + new_ss_type: jsonutils.dumps(
                    backend_details_data)})
            try:
                updates = self.driver.update_share_server_security_service(
                    context, share_server, network_info,
                    share_instances, share_instances_rules,
                    new_security_service,
                    current_security_service=current_security_service) or {}
            except Exception:
                operation = 'add'
                sec_serv_info = ('new security service %s'
                                 % new_security_service_id)
                if current_security_service_id:
                    operation = 'update'
                    sec_serv_info = ('current security service %s and '
                                     % current_security_service_id +
                                     sec_serv_info)
                msg = _("Share server %(server_id)s has failed on security "
                        "service %(operation)s operation for "
                        "%(sec_serv_ids)s.") % {
                    'server_id': share_server['id'],
                    'operation': operation,
                    'sec_serv_ids': sec_serv_info,
                }
                LOG.exception(msg)
                # Set share server to error. Security service configuration
                # must be fixed before restoring it to active again.
                self.db.share_server_update(
                    context, share_server['id'],
                    {'status': constants.STATUS_ERROR})

                if current_security_service:
                    # NOTE(dviroel): An already configured security service has
                    # failed on update operation. We will set all share
                    # instances to 'error'.
                    if share_instance_ids:
                        self.db.share_instances_status_update(
                            context, share_instance_ids,
                            {'status': constants.STATUS_ERROR})
                        # Update share instance access rules status
                        (self.access_helper
                            .update_share_instances_access_rules_status(
                                context, constants.SHARE_INSTANCE_RULES_ERROR,
                                share_instance_ids))
                # Go to the next share server
                continue

            # Update access rules based on drivers updates
            for instance_id, rules_updates in updates.items():
                self.access_helper.process_driver_rule_updates(
                    context, rules_updates, instance_id)

            msg = _("Security service was successfully updated on share "
                    "server %s.") % share_server['id']
            LOG.info(msg)
            self.db.share_server_update(
                context, share_server['id'],
                {'status': constants.STATUS_ACTIVE})

        if check_only:
            # All share servers support the requested update
            return True

        # Check if all share servers have already finished their updates in
        # order to properly update share network status
        self._check_share_network_update_finished(
            context, share_network_id=share_network['id'])

    def update_share_network_security_service(
            self, context, share_network_id, new_security_service_id,
            current_security_service_id=None):
        self._update_share_network_security_service(
            context, share_network_id, new_security_service_id,
            current_security_service_id=current_security_service_id,
            check_only=False)

    def check_update_share_network_security_service(
            self, context, share_network_id, new_security_service_id,
            current_security_service_id=None):
        is_supported = self._update_share_network_security_service(
            context, share_network_id, new_security_service_id,
            current_security_service_id=current_security_service_id,
            check_only=True)
        self._update_share_network_security_service_operations(
            context, share_network_id, is_supported,
            new_security_service_id=new_security_service_id,
            current_security_service_id=current_security_service_id)

    @api.locked_security_service_update_operation
    def _update_share_network_security_service_operations(
            self, context, share_network_id, is_supported,
            new_security_service_id=None,
            current_security_service_id=None):
        update_check_key = self.share_api.get_security_service_update_key(
            'hosts_check', new_security_service_id,
            current_security_service_id)
        current_hosts_info = self.db.async_operation_data_get(
            context, share_network_id, update_check_key)
        if current_hosts_info:
            current_hosts = json.loads(current_hosts_info)
            current_hosts[self.host] = is_supported
            self.db.async_operation_data_update(
                context, share_network_id,
                {update_check_key: json.dumps(current_hosts)})
        else:
            LOG.debug('A share network security service check was requested '
                      'but no entries were found in database. Ignoring call '
                      'and returning.')

    @api.locked_share_server_update_allocations_operation
    def _update_share_server_allocations_check_operation(
            self, context, is_supported, share_network_id=None,
            availability_zone_id=None):
        update_key = self.share_api.get_share_server_update_allocations_key(
            share_network_id, availability_zone_id)
        current_hosts_info = self.db.async_operation_data_get(
            context, share_network_id, update_key)
        if current_hosts_info:
            current_hosts = json.loads(current_hosts_info)
            current_hosts[self.host] = is_supported
            self.db.async_operation_data_update(
                context, share_network_id,
                {update_key: json.dumps(current_hosts)})
        else:
            LOG.debug('A share network subnet create check was requested '
                      'but no entries were found in database. Ignoring call '
                      'and returning.')

    def _get_subnet_allocations(self, context, share_server_id,
                                share_network_subnet):

        network_allocations = (
            self.db.network_allocations_get_for_share_server(
                context, share_server_id, label='user',
                subnet_id=share_network_subnet['id']))

        return {
            'share_network_subnet_id': share_network_subnet['id'],
            'neutron_net_id': share_network_subnet['neutron_net_id'],
            'neutron_subnet_id': share_network_subnet['neutron_subnet_id'],
            'network_allocations': network_allocations,
        }

    def _form_network_allocations(self, context, share_server_id,
                                  share_network_subnets):

        subnet_allocations = []
        for share_network_subnet in share_network_subnets:
            subnet_allocations.append(self._get_subnet_allocations(
                context, share_server_id, share_network_subnet))

        admin_network_allocations = (
            self.db.network_allocations_get_for_share_server(
                context, share_server_id, label='admin'))

        return {
            'admin_network_allocations': admin_network_allocations,
            'subnets': subnet_allocations,
        }

    def check_update_share_server_network_allocations(
            self, context, share_network_id, new_share_network_subnet):

        share_network = self.db.share_network_get(
            context, share_network_id)
        az_subnets = (
            self.db.share_network_subnets_get_all_by_availability_zone_id(
                context, share_network_id,
                new_share_network_subnet['availability_zone_id'],
                fallback_to_default=False)
        )
        self.driver.network_api.include_network_info(new_share_network_subnet)

        # all subnets have the same set of share servers, so do the check from
        # servers in the first subnet.
        share_servers = az_subnets[0]['share_servers'] if az_subnets else []
        is_supported = True
        for share_server in share_servers:

            current_network_allocations = self._form_network_allocations(
                context, share_server['id'], az_subnets)

            share_instances = (
                self.db.share_instances_get_all_by_share_server(
                    context, share_server['id'], with_share_data=True))
            share_instance_ids = [sn.id for sn in share_instances]

            share_instances_rules = []
            for share_instance_id in share_instance_ids:
                instance_rules = {
                    'share_instance_id': share_instance_id,
                    'access_rules': (
                        self.db.share_access_get_all_for_instance(
                            context, share_instance_id))
                }
                share_instances_rules.append(instance_rules)

            if self.driver.check_update_share_server_network_allocations(
                    context, share_server, current_network_allocations,
                    new_share_network_subnet,
                    share_network['security_services'],
                    share_instances, share_instances_rules):
                # Check the next share server.
                continue
            else:
                # At least one share server doesn't support this update.
                is_supported = False
                break

        self._update_share_server_allocations_check_operation(
            context, is_supported, share_network_id=share_network_id,
            availability_zone_id=(
                new_share_network_subnet['availability_zone_id']))

    def _do_update_share_server_network_allocations(
            self, context, share_server, share_network, new_subnet,
            current_network_allocations, share_instances,
            snapshot_instance_ids):

        self.driver.allocate_network(
            context, share_server, share_network, new_subnet)
        new_network_allocations = self._get_subnet_allocations(
            context, share_server['id'], new_subnet)
        if not new_network_allocations['network_allocations']:
            raise exception.AllocationsNotFoundForShareServer(
                share_server_id=share_server['id'])

        # NOTE(felipe_rodrigues): all allocations have the same network
        # segmentation info, so validation from the first one.
        self._validate_segmentation_id(
            new_network_allocations['network_allocations'][0])

        model_update = self.driver.update_share_server_network_allocations(
            context, share_server, current_network_allocations,
            new_network_allocations, share_network['security_services'],
            share_instances, snapshot_instance_ids)

        self.driver.update_network_allocation(context, share_server)

        driver_backend_details = model_update.get('server_details')
        if driver_backend_details:
            self.db.share_server_backend_details_set(
                context, share_server['id'], driver_backend_details)

        share_updates = model_update.get('share_updates', {})
        for share_instance_id, export_locations in share_updates.items():
            self.db.share_export_locations_update(
                context, share_instance_id, export_locations)

        snapshot_updates = model_update.get('snapshot_updates', {})
        for snap_instance_id, model_update in snapshot_updates.items():
            snapshot_export_locations = model_update.pop(
                'export_locations', [])
            if model_update:
                self.db.share_snapshot_instance_update(
                    context, snap_instance_id, model_update)

            if snapshot_export_locations:
                export_locations_update = []
                for exp_location in snapshot_export_locations:
                    updated_el = {
                        'path': exp_location['path'],
                        'is_admin_only': exp_location['is_admin_only'],
                    }
                    export_locations_update.append(updated_el)
                self.db.share_snapshot_instance_export_locations_update(
                    context, snap_instance_id, export_locations_update)

    def update_share_server_network_allocations(
            self, context, share_network_id, new_share_network_subnet_id):

        share_network = self.db.share_network_get(
            context, share_network_id)
        new_subnet = self.db.share_network_subnet_get(
            context, new_share_network_subnet_id)
        current_subnets = (
            self.db.share_network_subnets_get_all_by_availability_zone_id(
                context, share_network_id,
                new_subnet['availability_zone_id'],
                fallback_to_default=False)
        )
        current_subnets = [subnet for subnet in current_subnets
                           if subnet['id'] != new_share_network_subnet_id]
        share_servers = (
            self.db.share_server_get_all_by_host_and_share_subnet(
                context, self.host, new_share_network_subnet_id))
        for share_server in share_servers:

            share_server_id = share_server['id']
            current_network_allocations = self._form_network_allocations(
                context, share_server_id, current_subnets)
            share_instances = (
                self.db.share_instances_get_all_by_share_server(
                    context, share_server_id, with_share_data=True))
            share_instance_ids = [x['id'] for x in share_instances]
            snapshot_instances = (
                self.db.share_snapshot_instance_get_all_with_filters(
                    context,
                    {'share_instance_ids': share_instance_ids}))
            snapshot_instance_ids = [x['id'] for x in snapshot_instances]

            try:
                self._do_update_share_server_network_allocations(
                    context, share_server, share_network, new_subnet,
                    current_network_allocations, share_instances,
                    snapshot_instances)
            except Exception as e:
                msg = ('Failed to update allocations of share server '
                       '%(server_id)s on subnet %(subnet_id)s: %(e)s.')
                data = {
                    'server_id': share_server_id,
                    'subnet_id': new_share_network_subnet_id,
                    'e': str(e),
                }
                LOG.exception(msg, data)

                # Set resources to error. Allocations configuration must be
                # fixed before restoring it to active again.
                self._handle_setup_server_error(context, share_server_id, e)
                self._update_resource_status(
                    context, constants.STATUS_ERROR,
                    share_instance_ids=share_instance_ids,
                    snapshot_instance_ids=snapshot_instance_ids)

                continue

            msg = _(
                "Network allocations was successfully updated on share "
                "server %s.") % share_server['id']
            LOG.info(msg)
            self.db.share_server_update(
                context, share_server['id'],
                {'status': constants.STATUS_ACTIVE})

        # Check if all share servers have already finished their updates in
        # order to properly update share network status.
        self._check_share_network_update_finished(
            context, share_network_id=share_network['id'])
