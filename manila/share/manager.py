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

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_service import periodic_task
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import strutils
from oslo_utils import timeutils
import six

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
import manila.share.configuration
from manila.share import drivers_private_data
from manila.share import migration
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types
from manila.share import snapshot_access
from manila.share import utils as share_utils
from manila import utils

LOG = log.getLogger(__name__)

share_manager_opts = [
    cfg.StrOpt('share_driver',
               default='manila.share.drivers.generic.GenericShareDriver',
               help='Driver to use for share creation.'),
    cfg.ListOpt('hook_drivers',
                default=[],
                help='Driver(s) to perform some additional actions before and '
                     'after share driver actions and on a periodic basis. '
                     'Default is [].',
                deprecated_group='DEFAULT'),
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
                     'will be disabled.',
                deprecated_group='DEFAULT'),
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
               deprecated_group='DEFAULT',
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

    RPC_API_VERSION = '1.18'

    def __init__(self, share_driver=None, service_name=None, *args, **kwargs):
        """Load the driver from args, or from flags."""
        self.configuration = manila.share.configuration.Configuration(
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

        self.access_helper = access.ShareInstanceAccess(self.db, self.driver)
        self.snapshot_access_helper = (
            snapshot_access.ShareSnapshotInstanceAccess(self.db, self.driver))
        self.migration_wait_access_rules_timeout = (
            CONF.migration_wait_access_rules_timeout)

        self.message_api = message_api.API()
        self.hooks = []
        self._init_hook_drivers()

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
    def init_host(self):
        """Initialization for a standalone service."""

        ctxt = context.get_admin_context()
        driver_host_pair = "{}@{}".format(
            self.driver.__class__.__name__,
            self.host)

        # we want to retry to setup the driver. In case of a multi-backend
        # scenario, working backends are usable and the non-working ones (where
        # do_setup() or check_for_setup_error() fail) retry.
        @utils.retry(Exception, interval=2, backoff_rate=2,
                     backoff_sleep_max=600, retries=0)
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

    def ensure_driver_resources(self, ctxt):
        old_backend_info_hash = self.db.backend_info_get(ctxt, self.host)
        new_backend_info = None
        new_backend_info_hash = None
        update_share_instances = []
        try:
            new_backend_info = self.driver.get_backend_info(ctxt)
        except Exception as e:
            if not isinstance(e, NotImplementedError):
                LOG.exception(
                    ("The backend %(host)s could not get backend info."),
                    {'host': self.host})
                raise
            else:
                LOG.debug(
                    ("The backend %(host)s does not support get backend"
                     " info method."),
                    {'host': self.host})

        if new_backend_info:
            new_backend_info_hash = hashlib.sha1(six.text_type(
                sorted(new_backend_info.items())).encode('utf-8')).hexdigest()

        if (old_backend_info_hash and
                old_backend_info_hash == new_backend_info_hash):
            LOG.debug(
                ("The ensure share be skipped because the The old backend "
                 "%(host)s info as the same as new backend info"),
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
            update_share_instances.append(share_instance)

        try:
            update_share_instances = self.driver.ensure_shares(
                ctxt, update_share_instances)
        except Exception as e:
            if not isinstance(e, NotImplementedError):
                LOG.exception("Caught exception trying ensure "
                              "share instances.")
            else:
                self._ensure_share(ctxt, update_share_instances)

        if new_backend_info:
            self.db.backend_info_update(
                ctxt, self.host, new_backend_info_hash)

        for share_instance in share_instances:
            if share_instance['id'] not in update_share_instances:
                continue
            if update_share_instances[share_instance['id']].get('status'):
                self.db.share_instance_update(
                    ctxt, share_instance['id'],
                    {'status': (
                        update_share_instances[share_instance['id']].
                        get('status')),
                     'host': share_instance['host']}
                )

            update_export_location = (
                update_share_instances[share_instance['id']]
                .get('export_locations'))
            if update_export_location:
                self.db.share_export_locations_update(
                    ctxt, share_instance['id'], update_export_location)

            share_server = self._get_share_server(ctxt, share_instance)

            if share_instance['access_rules_status'] != (
                    constants.STATUS_ACTIVE):
                try:
                    # Cast any existing 'applying' rules to 'new'
                    self.access_helper.reset_applying_rules(
                        ctxt, share_instance['id'])
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

    def _ensure_share(self, ctxt, share_instances):
        for share_instance in share_instances:
            try:
                share_server = self._get_share_server(
                    ctxt, share_instance)
                export_locations = self.driver.ensure_share(
                    ctxt, share_instance, share_server=share_server)
            except Exception:
                LOG.exception("Caught exception trying ensure "
                              "share '%(s_id)s'.",
                              {'s_id': share_instance['id']})
                continue
            if export_locations:
                self.db.share_export_locations_update(
                    ctxt, share_instance['id'], export_locations)

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

        parent_share_server = None

        def error(msg, *args):
            LOG.error(msg, *args)
            self.db.share_instance_update(context, share_instance['id'],
                                          {'status': constants.STATUS_ERROR})

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
                error("Parent share server %(id)s has invalid status "
                      "'%(status)s'.", error_params)
                raise exception.InvalidShareServer(
                    share_server_id=parent_share_server
                )

        if parent_share_server and not share_network_id:
            share_network_id = parent_share_server['share_network_id']

        def get_available_share_servers():
            if parent_share_server:
                return [parent_share_server]
            else:
                return (
                    self.db.share_server_get_all_by_host_and_share_net_valid(
                        context, self.host, share_network_id)
                )

        @utils.synchronized("share_manager_%s" % share_network_id,
                            external=True)
        def _wrapped_provide_share_server_for_share():
            try:
                available_share_servers = get_available_share_servers()
            except exception.ShareServerNotFound:
                available_share_servers = None

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
                        'share_network_id': share_network_id,
                        'status': constants.STATUS_CREATING
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
                metadata = {'request_host': share_instance['host']}
                compatible_share_server = (
                    self._create_share_server_in_backend(
                        context, compatible_share_server,
                        metadata=metadata))

            return compatible_share_server, share_instance_ref

        return _wrapped_provide_share_server_for_share()

    def _create_share_server_in_backend(self, context, share_server,
                                        metadata=None):
        """Perform setup_server on backend

        :param metadata: A dictionary, to be passed to driver's setup_server()
        """

        if share_server['status'] == constants.STATUS_CREATING:
            # Create share server on backend with data from db.
            share_server = self._setup_server(context, share_server,
                                              metadata=metadata)
            LOG.info("Share server created successfully.")
        else:
            LOG.info("Using preexisting share server: "
                     "'%(share_server_id)s'",
                     {'share_server_id': share_server['id']})
        return share_server

    def create_share_server(self, context, share_server_id):
        """Invoked to create a share server in this backend.

        This method is invoked to create the share server defined in the model
        obtained by the supplied id.

        :param context: The 'context.RequestContext' object for the request.
        :param share_server_id: The id of the server to be created.
        """
        share_server = self.db.share_server_get(context, share_server_id)

        self._create_share_server_in_backend(context, share_server)

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

    def _provide_share_server_for_share_group(self, context, share_network_id,
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
            try:
                available_share_servers = (
                    self.db.share_server_get_all_by_host_and_share_net_valid(
                        context, self.host, share_network_id))
            except exception.ShareServerNotFound:
                available_share_servers = None

            compatible_share_server = None
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
                        'share_network_id': share_network_id,
                        'status': constants.STATUS_CREATING
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
                compatible_share_server = self._setup_server(
                    context, compatible_share_server)
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

        share_api = api.API()

        request_spec, dest_share_instance = (
            share_api.create_share_instance_and_get_request_spec(
                context, share_ref, new_az_id, None, dest_host,
                new_share_network_id, new_share_type_id))

        self.db.share_instance_update(
            context, dest_share_instance['id'],
            {'status': constants.STATUS_MIGRATING_TO})

        # refresh and obtain proxified properties
        dest_share_instance = self.db.share_instance_get(
            context, dest_share_instance['id'], with_share_data=True)

        helper = migration.ShareMigrationHelper(
            context, self.db, share_ref, self.access_helper)

        try:
            if dest_share_instance['share_network_id']:
                rpcapi = share_rpcapi.ShareAPI()

                # NOTE(ganso): Obtaining the share_server_id asynchronously so
                # we can wait for it to be ready.
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
                                       share_server):
        self.db.share_instance_update(
            context, src_share_instance['id'],
            {'cast_rules_to_readonly': True})

        # Set all 'applying' or 'active' rules to 'queued_to_apply'. Since the
        # share instance has its cast_rules_to_readonly attribute set to True,
        # existing rules will be cast to read/only.
        acceptable_past_states = (constants.ACCESS_STATE_APPLYING,
                                  constants.ACCESS_STATE_ACTIVE)
        new_state = constants.ACCESS_STATE_QUEUED_TO_APPLY
        conditionally_change = {k: new_state for k in acceptable_past_states}
        self.access_helper.get_and_update_share_instance_access_rules(
            context, share_instance_id=src_share_instance['id'],
            conditionally_change=conditionally_change)

        self.access_helper.update_access_rules(
            context, src_share_instance['id'],
            share_server=share_server)

        utils.wait_for_access_update(
            context, self.db, src_share_instance,
            self.migration_wait_access_rules_timeout)

    def _reset_read_only_access_rules(
            self, context, share, share_instance_id, supress_errors=True,
            helper=None):

        instance = self.db.share_instance_get(context, share_instance_id,
                                              with_share_data=True)
        if instance['cast_rules_to_readonly']:
            update = {'cast_rules_to_readonly': False}

            self.db.share_instance_update(
                context, share_instance_id, update)

            share_server = self._get_share_server(context, instance)

            if helper is None:
                helper = migration.ShareMigrationHelper(
                    context, self.db, share, self.access_helper)

            if supress_errors:
                helper.cleanup_access_rules(instance, share_server)
            else:
                helper.revert_access_rules(instance, share_server)

    @periodic_task.periodic_task(
        spacing=CONF.migration_driver_continue_update_interval)
    @utils.require_driver_initialized
    def migration_driver_continue(self, context):
        """Invokes driver to continue migration of shares."""

        instances = self.db.share_instances_get_all_by_host(context, self.host)

        for instance in instances:

            if instance['status'] != constants.STATUS_MIGRATING:
                continue

            share = self.db.share_get(context, instance['share_id'])

            if share['task_state'] == (
                    constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):

                share_api = api.API()

                src_share_instance_id, dest_share_instance_id = (
                    share_api.get_migrating_instances(share))

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

                    # NOTE(ganso): Cleaning up error'ed destination share
                    # instance from database. It is assumed that driver cleans
                    # up leftovers in backend when migration fails.
                    self._migration_delete_instance(
                        context, dest_share_instance['id'])
                    self._restore_migrating_snapshots_status(
                        context, src_share_instance['id'])
                    self._reset_read_only_access_rules(
                        context, share, src_share_instance_id)
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
                context, share_ref, share_instance['id'])
            self.db.share_instance_update(
                context, share_instance['id'],
                {'status': constants.STATUS_AVAILABLE})

            raise exception.ShareMigrationFailed(reason=msg)

    def _migration_start_host_assisted(
            self, context, share, src_share_instance, dest_host,
            new_share_network_id, new_az_id, new_share_type_id):

        rpcapi = share_rpcapi.ShareAPI()

        helper = migration.ShareMigrationHelper(
            context, self.db, share, self.access_helper)

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
            context, self.db, share_ref, self.access_helper)

        helper.apply_new_access_rules(dest_share_instance)

        self.db.share_instance_update(
            context, dest_share_instance['id'],
            {'status': constants.STATUS_AVAILABLE})

        self.db.share_instance_update(context, src_share_instance['id'],
                                      {'status': constants.STATUS_INACTIVE})

        self._migration_delete_instance(context, src_share_instance['id'])

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

        self._check_delete_share_server(context, share_instance)

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

        share_api = api.API()

        return share_api.get_share_attributes_from_share_type(share_type)

    def _migration_complete_host_assisted(self, context, share_ref,
                                          src_instance_id, dest_instance_id):

        src_share_instance = self.db.share_instance_get(
            context, src_instance_id, with_share_data=True)
        dest_share_instance = self.db.share_instance_get(
            context, dest_instance_id, with_share_data=True)

        helper = migration.ShareMigrationHelper(
            context, self.db, share_ref, self.access_helper)

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
                context, share_ref, src_instance_id,
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
            helper.apply_new_access_rules(dest_share_instance)
        except Exception:
            msg = _("Failed to apply new access rules during migration "
                    "of share %s.") % share_ref['id']
            LOG.exception(msg)
            helper.cleanup_new_instance(dest_share_instance)
            self._reset_read_only_access_rules(
                context, share_ref, src_instance_id, helper=helper,
                supress_errors=True)
            self.db.share_instance_update(
                context, src_instance_id,
                {'status': constants.STATUS_AVAILABLE})

            raise exception.ShareMigrationFailed(reason=msg)

        self.db.share_instance_update(
            context, dest_share_instance['id'],
            {'status': constants.STATUS_AVAILABLE})

        self.db.share_instance_update(context, src_instance_id,
                                      {'status': constants.STATUS_INACTIVE})

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
            context, self.db, share_ref, self.access_helper)

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
            context, share_ref, src_instance_id, supress_errors=False,
            helper=helper)

        self.db.share_instance_update(
            context, src_instance_id,
            {'status': constants.STATUS_AVAILABLE})

        self.db.share_update(
            context, share_ref['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED})

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
        if isinstance(share, six.string_types):
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
                {'availability_zone': CONF.storage_availability_zone},
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

        try:
            if snapshot_ref:
                export_locations = self.driver.create_share_from_snapshot(
                    context, share_instance, snapshot_ref.instance,
                    share_server=share_server)
            else:
                export_locations = self.driver.create_share(
                    context, share_instance, share_server=share_server)

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
            updates = {
                'status': constants.STATUS_AVAILABLE,
                'launched_at': timeutils.utcnow(),
            }
            if share.get('replication_type'):
                updates['replica_state'] = constants.REPLICA_STATE_ACTIVE

            self.db.share_instance_update(context, share_instance_id, updates)

            self._notify_about_share_usage(context, share,
                                           share_instance, "create.end")

    def _update_share_replica_access_rules_state(self, context,
                                                 share_replica_id, state):
        """Update the access_rules_status for the share replica."""
        self.access_helper.get_and_update_share_instance_access_rules_status(
            context, status=state, share_instance_id=share_replica_id)

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
                {'availability_zone': CONF.storage_availability_zone},
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

        if (share_network_id and
                not self.driver.driver_handles_share_servers):
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
                "Driver does not expect share-network to be provided "
                "with current configuration.")

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

        replica_list = [self._get_share_replica_dict(context, r)
                        for r in replica_list]
        share_replica = self._get_share_replica_dict(context, share_replica)

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
                self._update_share_replica_access_rules_state(
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
                 'replica_state': replica_ref.get('replica_state')})

        if replica_ref.get('access_rules_status'):
            self._update_share_replica_access_rules_state(
                context, share_replica['id'],
                replica_ref.get('access_rules_status'))
        else:
            self._update_share_replica_access_rules_state(
                context, share_replica['id'],
                constants.STATUS_ACTIVE)

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

        replica_list = [self._get_share_replica_dict(context, r)
                        for r in replica_list]
        replica_snapshots = [self._get_snapshot_instance_dict(context, s)
                             for s in replica_snapshots]
        share_server = self._get_share_server(context, share_replica)
        share_replica = self._get_share_replica_dict(context, share_replica)

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
    def promote_share_replica(self, context, share_replica_id, share_id=None):
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

        replica_list = [self._get_share_replica_dict(context, r)
                        for r in replica_list]
        share_replica = self._get_share_replica_dict(context, share_replica)

        try:
            updated_replica_list = (
                self.driver.promote_replica(
                    context, replica_list, share_replica, access_rules,
                    share_server=share_server)
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
                    self._update_share_replica_access_rules_state(
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
                    share_utils.extract_host(self.host))

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
        share_server = self._get_share_server(context, share_replica)

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
            or share_replica['replica_state'] ==
                constants.REPLICA_STATE_ACTIVE):
            return

        access_rules = self.db.share_access_get_all_for_share(
            context, share_replica['share_id'])

        LOG.debug("Updating status of share share_replica %s: ",
                  share_replica['id'])

        replica_list = (
            self.db.share_replicas_get_all_by_share(
                context, share_replica['share_id'],
                with_share_data=True, with_share_server=True)
        )

        _active_replica = [x for x in replica_list
                           if x['replica_state'] ==
                           constants.REPLICA_STATE_ACTIVE][0]

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

        replica_list = [self._get_share_replica_dict(context, r)
                        for r in replica_list]

        share_replica = self._get_share_replica_dict(context, share_replica)

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

    @add_hooks
    @utils.require_driver_initialized
    def manage_share(self, context, share_id, driver_options):
        context = context.elevated()
        share_ref = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share_ref)
        project_id = share_ref['project_id']

        try:
            if self.driver.driver_handles_share_servers:
                msg = _("Manage share is not supported for "
                        "driver_handles_share_servers=True mode.")
                raise exception.InvalidDriverMode(driver_mode=msg)

            driver_mode = share_types.get_share_type_extra_specs(
                share_instance['share_type_id'],
                constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS)

            if strutils.bool_from_string(driver_mode):
                msg = _("%(mode)s != False") % {
                    'mode': constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS
                }
                raise exception.ManageExistingShareTypeMismatch(reason=msg)

            share_update = (
                self.driver.manage_existing(share_instance, driver_options)
                or {}
            )

            if not share_update.get('size'):
                msg = _("Driver cannot calculate share size.")
                raise exception.InvalidShare(reason=msg)

            reservations = QUOTAS.reserve(
                context,
                project_id=project_id,
                user_id=context.user_id,
                shares=1,
                gigabytes=share_update['size'],
                share_type_id=share_instance['share_type_id'],
            )
            QUOTAS.commit(
                context, reservations, project_id=project_id,
                share_type_id=share_instance['share_type_id'],
            )

            share_update.update({
                'status': constants.STATUS_AVAILABLE,
                'launched_at': timeutils.utcnow(),
                'availability_zone': CONF.storage_availability_zone,
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
            # NOTE(vponomaryov): set size as 1 because design expects size
            # to be set, it also will allow us to handle delete/unmanage
            # operations properly with this errored share according to quotas.
            self.db.share_update(
                context, share_id,
                {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})
            raise

    @add_hooks
    @utils.require_driver_initialized
    def manage_snapshot(self, context, snapshot_id, driver_options):
        if self.driver.driver_handles_share_servers:
            msg = _("Manage snapshot is not supported for "
                    "driver_handles_share_servers=True mode.")
            # NOTE(vponomaryov): set size as 1 because design expects size
            # to be set, it also will allow us to handle delete/unmanage
            # operations properly with this errored snapshot according to
            # quotas.
            self.db.share_snapshot_update(
                context, snapshot_id,
                {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})
            raise exception.InvalidDriverMode(driver_mode=msg)

        context = context.elevated()
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
        share_server = self._get_share_server(context,
                                              snapshot_ref['share'])

        if share_server:
            msg = _("Manage snapshot is not supported for "
                    "share snapshots with share servers.")
            # NOTE(vponomaryov): set size as 1 because design expects size
            # to be set, it also will allow us to handle delete/unmanage
            # operations properly with this errored snapshot according to
            # quotas.
            self.db.share_snapshot_update(
                context, snapshot_id,
                {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})
            raise exception.InvalidShareSnapshot(reason=msg)

        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_ref.instance['id'], with_share_data=True
        )
        project_id = snapshot_ref['project_id']

        try:
            snapshot_update = (
                self.driver.manage_existing_snapshot(
                    snapshot_instance,
                    driver_options)
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
        share_server = self._get_share_server(context, share_instance)
        project_id = share_ref['project_id']

        def share_manage_set_error_status(msg, exception):
            status = {'status': constants.STATUS_UNMANAGE_ERROR}
            self.db.share_update(context, share_id, status)
            LOG.error(msg, exception)

        try:
            if self.driver.driver_handles_share_servers:
                msg = _("Unmanage share is not supported for "
                        "driver_handles_share_servers=True mode.")
                raise exception.InvalidShare(reason=msg)

            if share_server:
                msg = _("Unmanage share is not supported for "
                        "shares with share servers.")
                raise exception.InvalidShare(reason=msg)

            self.driver.unmanage(share_instance)

        except exception.InvalidShare as e:
            share_manage_set_error_status(
                ("Share can not be unmanaged: %s."), e)
            return

        try:
            reservations = QUOTAS.reserve(
                context,
                project_id=project_id,
                shares=-1,
                gigabytes=-share_ref['size'],
                share_type_id=share_instance['share_type_id'],
            )
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
        LOG.info("Share %s: unmanaged successfully.", share_id)

    @add_hooks
    @utils.require_driver_initialized
    def unmanage_snapshot(self, context, snapshot_id):
        status = {'status': constants.STATUS_UNMANAGE_ERROR}
        if self.driver.driver_handles_share_servers:
            msg = _("Unmanage snapshot is not supported for "
                    "driver_handles_share_servers=True mode.")
            self.db.share_snapshot_update(context, snapshot_id, status)
            LOG.error("Share snapshot cannot be unmanaged: %s.",
                      msg)
            return

        context = context.elevated()
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
        share_server = self._get_share_server(context,
                                              snapshot_ref['share'])

        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_ref.instance['id'], with_share_data=True
        )

        project_id = snapshot_ref['project_id']

        if share_server:
            msg = _("Unmanage snapshot is not supported for "
                    "share snapshots with share servers.")
            self.db.share_snapshot_update(context, snapshot_id, status)
            LOG.error("Share snapshot cannot be unmanaged: %s.",
                      msg)
            return

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

        try:
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

        self._check_delete_share_server(context, share_instance)

        self._notify_about_share_usage(context, share,
                                       share_instance, "delete.end")

    def _check_delete_share_server(self, context, share_instance):

        if CONF.delete_share_server_with_last_share:
            share_server = self._get_share_server(context, share_instance)
            if share_server and len(share_server.share_instances) == 0:
                LOG.debug("Scheduled deletion of share-server "
                          "with id '%s' automatically by "
                          "deletion of last share.", share_server['id'])
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

        replica_list = [self._get_share_replica_dict(context, r)
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
        replica_list = [self._get_share_replica_dict(context, replica)
                        for replica in replica_list]
        active_replica = self._get_share_replica_dict(context, active_replica)
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

        replica_list = [self._get_share_replica_dict(context, r)
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

        replica_list = [self._get_share_replica_dict(context, r)
                        for r in replica_list]
        replica_snapshots = replica_snapshots or []

        # Convert data to primitives to send to the driver.

        replica_snapshots = [self._get_snapshot_instance_dict(context, s)
                             for s in replica_snapshots]
        replica_snapshot = self._get_snapshot_instance_dict(
            context, replica_snapshot)
        share_replica = self._get_share_replica_dict(context, share_replica)
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
        share_server = self._get_share_server(context, share_instance)

        LOG.debug("Received request to update access for share instance"
                  " %s.", share_instance_id)

        self.access_helper.update_access_rules(
            context,
            share_instance_id,
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

    def _form_server_setup_info(self, context, share_server, share_network):
        # Network info is used by driver for setting up share server
        # and getting server info on share creation.
        network_allocations = self.db.network_allocations_get_for_share_server(
            context, share_server['id'], label='user')
        admin_network_allocations = (
            self.db.network_allocations_get_for_share_server(
                context, share_server['id'], label='admin'))
        # NOTE(vponomaryov): following network_info fields are deprecated:
        # 'segmentation_id', 'cidr' and 'network_type'.
        # And they should be used from network allocations directly.
        # They should be removed right after no one uses them.
        network_info = {
            'server_id': share_server['id'],
            'segmentation_id': share_network['segmentation_id'],
            'cidr': share_network['cidr'],
            'neutron_net_id': share_network['neutron_net_id'],
            'neutron_subnet_id': share_network['neutron_subnet_id'],
            'security_services': share_network['security_services'],
            'network_allocations': network_allocations,
            'admin_network_allocations': admin_network_allocations,
            'backend_details': share_server.get('backend_details'),
            'network_type': share_network['network_type'],
        }
        return network_info

    def _setup_server(self, context, share_server, metadata=None):
        try:
            share_network = self.db.share_network_get(
                context, share_server['share_network_id'])
            self.driver.allocate_network(context, share_server, share_network)
            self.driver.allocate_admin_network(context, share_server)

            # Get share_network again in case it was updated.
            share_network = self.db.share_network_get(
                context, share_server['share_network_id'])
            network_info = self._form_server_setup_info(
                context, share_server, share_network)
            self._validate_segmentation_id(network_info)

            # NOTE(vponomaryov): Save security services data to share server
            # details table to remove dependency from share network after
            # creation operation. It will allow us to delete share server and
            # share network separately without dependency on each other.
            for security_service in network_info['security_services']:
                ss_type = security_service['type']
                data = {
                    'name': security_service['name'],
                    'domain': security_service['domain'],
                    'server': security_service['server'],
                    'dns_ip': security_service['dns_ip'],
                    'user': security_service['user'],
                    'type': ss_type,
                    'password': security_service['password'],
                }
                self.db.share_server_backend_details_set(
                    context, share_server['id'],
                    {'security_service_' + ss_type: jsonutils.dumps(data)})

            server_info = self.driver.setup_server(
                network_info, metadata=metadata)

            self.driver.update_network_allocation(context, share_server)
            self.driver.update_admin_network_allocation(context, share_server)

            if server_info and isinstance(server_info, dict):
                self.db.share_server_backend_details_set(
                    context, share_server['id'], server_info)
            return self.db.share_server_update(
                context, share_server['id'],
                {'status': constants.STATUS_ACTIVE})
        except Exception as e:
            with excutils.save_and_reraise_exception():
                details = getattr(e, "detail_data", {})

                if isinstance(details, dict):
                    server_details = details.get("server_details", {})
                    if not isinstance(server_details, dict):
                        LOG.debug(
                            ("Cannot save non-dict data (%(data)s) "
                             "provided as 'server details' of "
                             "failed share server '%(server)s'."),
                            {"server": share_server["id"],
                             "data": server_details})
                    else:
                        invalid_details = []
                        for key, value in server_details.items():
                            try:
                                self.db.share_server_backend_details_set(
                                    context, share_server['id'], {key: value})
                            except Exception:
                                invalid_details.append("%(key)s: %(value)s" % {
                                    'key': six.text_type(key),
                                    'value': six.text_type(value)
                                })
                        if invalid_details:
                            LOG.debug(
                                ("Following server details "
                                 "cannot be written to db : %s"),
                                six.text_type("\n".join(invalid_details)))
                else:
                    LOG.debug(
                        ("Cannot save non-dict data (%(data)s) provided as "
                         "'detail data' of failed share server '%(server)s'."),
                        {"server": share_server["id"], "data": details})

                self.db.share_server_update(
                    context, share_server['id'],
                    {'status': constants.STATUS_ERROR})
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

        @utils.synchronized(
            "share_manager_%s" % share_server['share_network_id'])
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

            try:
                self.db.share_update(
                    context, share['id'],
                    {'status': constants.STATUS_EXTENDING_ERROR}
                )
                raise exception.ShareExtendingError(
                    reason=six.text_type(e), share_id=share_id)
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

        self._notify_about_share_usage(context, share,
                                       share_instance, "shrink.start")

        def error_occurred(exc, msg, status=constants.STATUS_SHRINKING_ERROR):
            LOG.exception(msg, resource=share)
            self.db.share_update(context, share['id'], {'status': status})

            raise exception.ShareShrinkingError(
                reason=six.text_type(exc), share_id=share_id)

        reservations = None

        try:
            size_decrease = int(share['size']) - new_size
            # we give the user_id of the share, to update the quota usage
            # for the user, who created the share, because on share delete
            # only this quota will be decreased
            reservations = QUOTAS.reserve(
                context,
                project_id=project_id,
                user_id=user_id,
                share_type_id=share_instance['share_type_id'],
                gigabytes=-size_decrease,
            )
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
                status = constants.STATUS_SHRINKING_POSSIBLE_DATA_LOSS_ERROR
                error_params = {'msg': msg, 'status': status}
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
            share_network_id = share_server['share_network_id']

        if share_network_id and not self.driver.driver_handles_share_servers:
            self.db.share_group_update(
                context, share_group_id, {'status': constants.STATUS_ERROR})
            msg = _("Driver does not expect share-network to be provided "
                    "with current configuration.")
            raise exception.InvalidInput(reason=msg)

        if not share_server and share_network_id:
            try:
                share_server, share_group_ref = (
                    self._provide_share_server_for_share_group(
                        context, share_network_id, share_group_ref,
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
                context, CONF.storage_availability_zone)['id']
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

    def _get_share_replica_dict(self, context, share_replica):
        # TODO(gouthamr): remove method when the db layer returns primitives
        share_replica_ref = {
            'id': share_replica.get('id'),
            'name': share_replica.get('name'),
            'share_id': share_replica.get('share_id'),
            'host': share_replica.get('host'),
            'status': share_replica.get('status'),
            'replica_state': share_replica.get('replica_state'),
            'availability_zone_id': share_replica.get('availability_zone_id'),
            'export_locations': share_replica.get('export_locations') or [],
            'share_network_id': share_replica.get('share_network_id'),
            'share_server_id': share_replica.get('share_server_id'),
            'deleted': share_replica.get('deleted'),
            'terminated_at': share_replica.get('terminated_at'),
            'launched_at': share_replica.get('launched_at'),
            'scheduled_at': share_replica.get('scheduled_at'),
            'share_server': self._get_share_server(context, share_replica),
            'access_rules_status': share_replica.get('access_rules_status'),
            # Share details
            'user_id': share_replica.get('user_id'),
            'project_id': share_replica.get('project_id'),
            'size': share_replica.get('size'),
            'display_name': share_replica.get('display_name'),
            'display_description': share_replica.get('display_description'),
            'snapshot_id': share_replica.get('snapshot_id'),
            'share_proto': share_replica.get('share_proto'),
            'share_type_id': share_replica.get('share_type_id'),
            'is_public': share_replica.get('is_public'),
            'share_group_id': share_replica.get('share_group_id'),
            'source_share_group_snapshot_member_id': share_replica.get(
                'source_share_group_snapshot_member_id'),
        }

        return share_replica_ref

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
