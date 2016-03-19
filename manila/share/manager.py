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
from manila.data import rpcapi as data_rpcapi
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LI
from manila.i18n import _LW
from manila import manager
from manila import quota
from manila.share import access
import manila.share.configuration
from manila.share import drivers_private_data
from manila.share import migration
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types
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
               deprecated_group='DEFAULT'),
    cfg.IntOpt('replica_state_update_interval',
               default=300,
               help='This value, specified in seconds, determines how often '
                    'the share manager will poll for the health '
                    '(replica_state) of each replica instance.'),
]

CONF = cfg.CONF
CONF.register_opts(share_manager_opts)
CONF.import_opt('periodic_hooks_interval', 'manila.share.hook')

# Drivers that need to change module paths or class names can add their
# old/new path here to maintain backward compatibility.
MAPPING = {
    'manila.share.drivers.netapp.cluster_mode.NetAppClusteredShareDriver':
    'manila.share.drivers.netapp.common.NetAppDriver',
    'manila.share.drivers.hp.hp_3par_driver.HP3ParShareDriver':
    'manila.share.drivers.hpe.hpe_3par_driver.HPE3ParShareDriver',
    'manila.share.drivers.glusterfs_native.GlusterfsNativeShareDriver':
    'manila.share.drivers.glusterfs.glusterfs_native.'
    'GlusterfsNativeShareDriver',
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

        @utils.synchronized("%s" % share_id, external=True)
        def locked_operation(*_args, **_kwargs):
            return operation(*_args, **_kwargs)
        return locked_operation(*args, **kwargs)
    return wrapped


def add_hooks(f):

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

    RPC_API_VERSION = '1.11'

    def __init__(self, share_driver=None, service_name=None, *args, **kwargs):
        """Load the driver from args, or from flags."""
        self.configuration = manila.share.configuration.Configuration(
            share_manager_opts,
            config_group=service_name)
        self._verify_unused_share_server_cleanup_interval()
        super(ShareManager, self).__init__(service_name='share',
                                           *args, **kwargs)

        if not share_driver:
            share_driver = self.configuration.share_driver
        if share_driver in MAPPING:
            msg_args = {'old': share_driver, 'new': MAPPING[share_driver]}
            LOG.warning(_LW("Driver path %(old)s is deprecated, update your "
                            "configuration to the new path %(new)s"),
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
            except Exception as err:
                LOG.error(_LE("Failed to fetch pool name for share: "
                              "%(share)s. Error: %(error)s."),
                          {'share': share_instance['id'], 'error': err})
                return

            if pool:
                new_host = share_utils.append_host(
                    share_instance['host'], pool)
                self.db.share_update(
                    ctxt, share_instance['id'], {'host': new_host})

        return pool

    @add_hooks
    def init_host(self):
        """Initialization for a standalone service."""

        ctxt = context.get_admin_context()
        try:
            self.driver.do_setup(ctxt)
            self.driver.check_for_setup_error()
        except Exception as e:
            LOG.exception(
                _LE("Error encountered during initialization of driver "
                    "'%(name)s' on '%(host)s' host. %(exc)s"), {
                        "name": self.driver.__class__.__name__,
                        "host": self.host,
                        "exc": e,
                }
            )
            self.driver.initialized = False
            # we don't want to continue since we failed
            # to initialize the driver correctly.
            return
        else:
            self.driver.initialized = True

        share_instances = self.db.share_instances_get_all_by_host(ctxt,
                                                                  self.host)
        LOG.debug("Re-exporting %s shares", len(share_instances))
        for share_instance in share_instances:
            share_ref = self.db.share_get(ctxt, share_instance['share_id'])
            if share_ref.is_busy:
                LOG.info(
                    _LI("Share instance %(id)s: skipping export, "
                        "because it is busy with an active task: %(task)s."),
                    {'id': share_instance['id'],
                     'task': share_ref['task_state']},
                )
                continue

            if share_instance['status'] != constants.STATUS_AVAILABLE:
                LOG.info(
                    _LI("Share instance %(id)s: skipping export, "
                        "because it has '%(status)s' status."),
                    {'id': share_instance['id'],
                     'status': share_instance['status']},
                )
                continue

            self._ensure_share_instance_has_pool(ctxt, share_instance)
            share_server = self._get_share_server(ctxt, share_instance)
            share_instance = self.db.share_instance_get(
                ctxt, share_instance['id'], with_share_data=True)
            try:
                export_locations = self.driver.ensure_share(
                    ctxt, share_instance, share_server=share_server)
            except Exception as e:
                LOG.error(
                    _LE("Caught exception trying ensure share '%(s_id)s'. "
                        "Exception: \n%(e)s."),
                    {'s_id': share_instance['id'], 'e': six.text_type(e)},
                )
                continue

            if export_locations:
                self.db.share_export_locations_update(
                    ctxt, share_instance['id'], export_locations)

            if share_instance['access_rules_status'] == (
                    constants.STATUS_OUT_OF_SYNC):

                try:
                    self.access_helper.update_access_rules(
                        ctxt, share_instance['id'], share_server=share_server)
                except Exception as e:
                    LOG.error(
                        _LE("Unexpected error occurred while updating access "
                            "rules for share instance %(s_id)s. "
                            "Exception: \n%(e)s."),
                        {'s_id': share_instance['id'], 'e': six.text_type(e)},
                    )

        self.publish_service_capabilities(ctxt)

    def _provide_share_server_for_share(self, context, share_network_id,
                                        share_instance, snapshot=None,
                                        consistency_group=None):
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
                    error(_LE("Parent share server %s does not exist."),
                          parent_share_server_id)

            if parent_share_server['status'] != constants.STATUS_ACTIVE:
                error_params = {
                    'id': parent_share_server_id,
                    'status': parent_share_server['status'],
                }
                error(_LE("Parent share server %(id)s has invalid status "
                          "'%(status)s'."), error_params)
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
        def _provide_share_server_for_share():
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
                            consistency_group=consistency_group
                        )
                    )
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        error(_LE("Cannot choose compatible share server: %s"),
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

            if compatible_share_server['status'] == constants.STATUS_CREATING:
                # Create share server on backend with data from db.
                compatible_share_server = self._setup_server(
                    context, compatible_share_server)
                LOG.info(_LI("Share server created successfully."))
            else:
                LOG.info(_LI("Used preexisting share server "
                             "'%(share_server_id)s'"),
                         {'share_server_id': compatible_share_server['id']})
            return compatible_share_server, share_instance_ref

        return _provide_share_server_for_share()

    def _provide_share_server_for_cg(self, context, share_network_id,
                                     cg_ref, cgsnapshot=None):
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
        :param cg_ref: Consistency Group model
        :param cgsnapshot: Optional -- CGSnapshot model

        :returns: dict, dict -- first value is share_server, that
                  has been chosen for consistency group schedule.
                  Second value is consistency group updated with
                  share_server_id.
        """
        if not (share_network_id or cgsnapshot):
            msg = _("'share_network_id' parameter or 'snapshot'"
                    " should be provided. ")
            raise exception.InvalidInput(reason=msg)

        def error(msg, *args):
            LOG.error(msg, *args)
            self.db.consistency_group_update(
                context, cg_ref['id'], {'status': constants.STATUS_ERROR})

        @utils.synchronized("share_manager_%s" % share_network_id,
                            external=True)
        def _provide_share_server_for_cg():
            try:
                available_share_servers = (
                    self.db.share_server_get_all_by_host_and_share_net_valid(
                        context, self.host, share_network_id))
            except exception.ShareServerNotFound:
                available_share_servers = None

            compatible_share_server = None

            if available_share_servers:
                try:
                    compatible_share_server = (
                        self.driver.choose_share_server_compatible_with_cg(
                            context, available_share_servers, cg_ref,
                            cgsnapshot=cgsnapshot
                        )
                    )
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        error(_LE("Cannot choose compatible share-server: %s"),
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

            msg = ("Using share_server %(share_server)s for consistency "
                   "group %(cg_id)s")
            LOG.debug(msg, {
                'share_server': compatible_share_server['id'],
                'cg_id': cg_ref['id']
            })

            updated_cg = self.db.consistency_group_update(
                context,
                cg_ref['id'],
                {'share_server_id': compatible_share_server['id']},
            )

            if compatible_share_server['status'] == constants.STATUS_CREATING:
                # Create share server on backend with data from db.
                compatible_share_server = self._setup_server(
                    context, compatible_share_server)
                LOG.info(_LI("Share server created successfully."))
            else:
                LOG.info(_LI("Used preexisting share server "
                             "'%(share_server_id)s'"),
                         {'share_server_id': compatible_share_server['id']})
            return compatible_share_server, updated_cg

        return _provide_share_server_for_cg()

    def _get_share_server(self, context, share_instance):
        if share_instance['share_server_id']:
            return self.db.share_server_get(
                context, share_instance['share_server_id'])
        else:
            return None

    @utils.require_driver_initialized
    def migration_get_info(self, context, share_instance_id):
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        share_server = None
        if share_instance.get('share_server_id'):
            share_server = self.db.share_server_get(
                context, share_instance['share_server_id'])

        return self.driver.migration_get_info(context, share_instance,
                                              share_server)

    @utils.require_driver_initialized
    def migration_get_driver_info(self, context, share_instance_id):
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        share_server = None
        if share_instance.get('share_server_id'):
            share_server = self.db.share_server_get(
                context, share_instance['share_server_id'])

        return self.driver.migration_get_driver_info(context, share_instance,
                                                     share_server)

    @utils.require_driver_initialized
    def migration_start(self, context, share_id, host, force_host_copy,
                        notify=True):
        """Migrates a share from current host to another host."""
        LOG.debug("Entered migration_start method for share %s.", share_id)

        self.db.share_update(
            context, share_id,
            {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS})

        rpcapi = share_rpcapi.ShareAPI()
        share_ref = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share_ref)
        moved = False

        self.db.share_instance_update(context, share_instance['id'],
                                      {'status': constants.STATUS_MIGRATING})

        if not force_host_copy:

            try:

                dest_driver_migration_info = rpcapi.migration_get_driver_info(
                    context, share_instance)

                share_server = self._get_share_server(context.elevated(),
                                                      share_instance)

                LOG.debug("Calling driver migration for share %s.", share_id)

                self.db.share_update(
                    context, share_id,
                    {'task_state': (
                        constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)})

                moved, model_update = self.driver.migration_start(
                    context, share_instance, share_server, host,
                    dest_driver_migration_info, notify)

                if moved and not notify:
                    self.db.share_update(
                        context, share_ref['id'],
                        {'task_state':
                            constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE})

                # NOTE(ganso): Here we are allowing the driver to perform
                # changes even if it has not performed migration. While this
                # scenario may not be valid, I do not think it should be
                # forcefully prevented.

                if model_update:
                    self.db.share_instance_update(
                        context, share_instance['id'], model_update)

            except Exception as e:
                msg = six.text_type(e)
                LOG.exception(msg)
                LOG.warning(_LW("Driver did not migrate share %s. Proceeding "
                                "with generic migration approach.") % share_id)

        if not moved:
            try:
                LOG.debug("Starting generic migration "
                          "for share %s.", share_id)

                self._migration_start_generic(context, share_ref,
                                              share_instance, host, notify)
            except Exception:
                msg = _("Generic migration failed for share %s.") % share_id
                LOG.exception(msg)
                self.db.share_update(
                    context, share_id,
                    {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
                self.db.share_instance_update(
                    context, share_instance['id'],
                    {'status': constants.STATUS_AVAILABLE})
                raise exception.ShareMigrationFailed(reason=msg)

    def _migration_start_generic(self, context, share, share_instance, host,
                                 notify):

        rpcapi = share_rpcapi.ShareAPI()

        helper = migration.ShareMigrationHelper(context, self.db, share)

        share_server = self._get_share_server(context.elevated(),
                                              share_instance)

        readonly_support = self.driver.configuration.safe_get(
            'migration_readonly_rules_support')

        helper.change_to_read_only(share_instance, share_server,
                                   readonly_support, self.driver)

        try:
            new_share_instance = helper.create_instance_and_wait(
                share, share_instance, host)

            self.db.share_instance_update(
                context, new_share_instance['id'],
                {'status': constants.STATUS_MIGRATING_TO})

        except Exception:
            msg = _("Failed to create instance on destination "
                    "backend during migration of share %s.") % share['id']
            LOG.exception(msg)
            helper.cleanup_access_rules(share_instance, share_server,
                                        self.driver)
            raise exception.ShareMigrationFailed(reason=msg)

        ignore_list = self.driver.configuration.safe_get(
            'migration_ignore_files')

        data_rpc = data_rpcapi.DataAPI()

        try:
            src_migration_info = self.driver.migration_get_info(
                context, share_instance, share_server)

            dest_migration_info = rpcapi.migration_get_info(
                context, new_share_instance)

            LOG.debug("Time to start copying in migration"
                      " for share %s.", share['id'])

            data_rpc.migration_start(
                context, share['id'], ignore_list, share_instance['id'],
                new_share_instance['id'], src_migration_info,
                dest_migration_info, notify)

        except Exception:
            msg = _("Failed to obtain migration info from backends or"
                    " invoking Data Service for migration of "
                    "share %s.") % share['id']
            LOG.exception(msg)
            helper.cleanup_new_instance(new_share_instance)
            helper.cleanup_access_rules(share_instance, share_server,
                                        self.driver)
            raise exception.ShareMigrationFailed(reason=msg)

    @utils.require_driver_initialized
    def migration_complete(self, context, share_id, share_instance_id,
                           new_share_instance_id):

        LOG.info(_LI("Received request to finish Share Migration for "
                     "share %s."), share_id)

        share_ref = self.db.share_get(context, share_id)

        if share_ref['task_state'] == (
                constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE):

            rpcapi = share_rpcapi.ShareAPI()

            share_instance = self._get_share_instance(context, share_ref)

            share_server = self._get_share_server(context, share_instance)

            try:
                dest_driver_migration_info = rpcapi.migration_get_driver_info(
                    context, share_instance)

                model_update = self.driver.migration_complete(
                    context, share_instance, share_server,
                    dest_driver_migration_info)
                if model_update:
                    self.db.share_instance_update(
                        context, share_instance['id'], model_update)
                self.db.share_update(
                    context, share_id,
                    {'task_state': constants.TASK_STATE_MIGRATION_SUCCESS})
            except Exception:
                    msg = _("Driver migration completion failed for"
                            " share %s.") % share_id
                    LOG.exception(msg)
                    self.db.share_update(
                        context, share_id,
                        {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
                    raise exception.ShareMigrationFailed(reason=msg)

        else:
            try:
                self._migration_complete(
                    context, share_ref, share_instance_id,
                    new_share_instance_id)
            except Exception:
                    msg = _("Generic migration completion failed for"
                            " share %s.") % share_id
                    LOG.exception(msg)
                    self.db.share_update(
                        context, share_id,
                        {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
                    self.db.share_instance_update(
                        context, share_instance_id,
                        {'status': constants.STATUS_AVAILABLE})
                    raise exception.ShareMigrationFailed(reason=msg)

    def _migration_complete(self, context, share_ref, share_instance_id,
                            new_share_instance_id):

        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)
        new_share_instance = self.db.share_instance_get(
            context, new_share_instance_id, with_share_data=True)

        share_server = self._get_share_server(context, share_instance)

        helper = migration.ShareMigrationHelper(context, self.db, share_ref)

        task_state = share_ref['task_state']
        if task_state in (constants.TASK_STATE_DATA_COPYING_ERROR,
                          constants.TASK_STATE_DATA_COPYING_CANCELLED):
            msg = _("Data copy of generic migration for share %s has not "
                    "completed successfully.") % share_ref['id']
            LOG.warning(msg)
            helper.cleanup_new_instance(new_share_instance)

            helper.cleanup_access_rules(share_instance, share_server,
                                        self.driver)
            if task_state == constants.TASK_STATE_DATA_COPYING_CANCELLED:
                self.db.share_instance_update(
                    context, share_instance_id,
                    {'status': constants.STATUS_AVAILABLE})
                self.db.share_update(
                    context, share_ref['id'],
                    {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED})

                LOG.info(_LI("Share Migration for share %s"
                             " was cancelled."), share_ref['id'])
                return
            else:
                raise exception.ShareMigrationFailed(reason=msg)

        elif task_state != constants.TASK_STATE_DATA_COPYING_COMPLETED:
            msg = _("Data copy for migration of share %s not completed"
                    " yet.") % share_ref['id']
            LOG.error(msg)
            raise exception.ShareMigrationFailed(reason=msg)

        try:
            helper.apply_new_access_rules(new_share_instance)
        except Exception:
            msg = _("Failed to apply new access rules during migration "
                    "of share %s.") % share_ref['id']
            LOG.exception(msg)
            helper.cleanup_new_instance(new_share_instance)
            helper.cleanup_access_rules(share_instance, share_server,
                                        self.driver)
            raise exception.ShareMigrationFailed(reason=msg)

        self.db.share_update(
            context, share_ref['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING})

        self.db.share_instance_update(context, new_share_instance_id,
                                      {'status': constants.STATUS_AVAILABLE})

        self.db.share_instance_update(context, share_instance_id,
                                      {'status': constants.STATUS_INACTIVE})

        helper.delete_instance_and_wait(share_instance)

        self.db.share_update(
            context, share_ref['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_SUCCESS})

        LOG.info(_LI("Share Migration for share %s"
                     " completed successfully."), share_ref['id'])

    @utils.require_driver_initialized
    def migration_cancel(self, context, share_id):

        share_ref = self.db.share_get(context, share_id)

        # Confirm that it is driver migration scenario
        if share_ref['task_state'] == (
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):

            share_server = None
            if share_ref.instance.get('share_server_id'):
                share_server = self.db.share_server_get(
                    context, share_ref.instance['share_server_id'])

            share_rpc = share_rpcapi.ShareAPI()

            driver_migration_info = share_rpc.migration_get_driver_info(
                context, share_ref.instance)

            self.driver.migration_cancel(
                context, share_ref.instance, share_server,
                driver_migration_info)
        else:
            msg = _("Driver is not performing migration for"
                    " share %s") % share_id
            raise exception.InvalidShare(reason=msg)

    @utils.require_driver_initialized
    def migration_get_progress(self, context, share_id):

        share_ref = self.db.share_get(context, share_id)

        # Confirm that it is driver migration scenario
        if share_ref['task_state'] == (
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):

            share_server = None
            if share_ref.instance.get('share_server_id'):
                share_server = self.db.share_server_get(
                    context, share_ref.instance['share_server_id'])

            share_rpc = share_rpcapi.ShareAPI()

            driver_migration_info = share_rpc.migration_get_driver_info(
                context, share_ref.instance)

            return self.driver.migration_get_progress(
                context, share_ref.instance, share_server,
                driver_migration_info)
        else:
            msg = _("Driver is not performing migration for"
                    " share %s") % share_id
            raise exception.InvalidShare(reason=msg)

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
        share_network_id = share_instance.get('share_network_id', None)

        if not share_instance['availability_zone']:
            share_instance = self.db.share_instance_update(
                context, share_instance_id,
                {'availability_zone': CONF.storage_availability_zone},
                with_share_data=True
            )

        if share_network_id and not self.driver.driver_handles_share_servers:
            self.db.share_instance_update(
                context, share_instance_id, {'status': constants.STATUS_ERROR})
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

        consistency_group_ref = None
        if share_instance.get('consistency_group_id'):
            consistency_group_ref = self.db.consistency_group_get(
                context, share_instance['consistency_group_id'])

        if share_network_id or parent_share_server_id:
            try:
                share_server, share_instance = (
                    self._provide_share_server_for_share(
                        context, share_network_id, share_instance,
                        snapshot=snapshot_ref,
                        consistency_group=consistency_group_ref
                    )
                )
            except Exception:
                with excutils.save_and_reraise_exception():
                    error = _LE("Creation of share instance %s failed: "
                                "failed to get share server.")
                    LOG.error(error, share_instance_id)
                    self.db.share_instance_update(
                        context, share_instance_id,
                        {'status': constants.STATUS_ERROR}
                    )
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
                LOG.error(_LE("Share instance %s failed on creation."),
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
                    LOG.warning(_LW('Share instance information in exception '
                                    'can not be written to db because it '
                                    'contains %s and it is not a dictionary.'),
                                detail_data)
                self.db.share_instance_update(
                    context, share_instance_id,
                    {'status': constants.STATUS_ERROR}
                )
        else:
            LOG.info(_LI("Share instance %s created successfully."),
                     share_instance_id)
            share = self.db.share_get(context, share_instance['share_id'])
            updates = {
                'status': constants.STATUS_AVAILABLE,
                'launched_at': timeutils.utcnow(),
            }
            if share.get('replication_type'):
                updates['replica_state'] = constants.REPLICA_STATE_ACTIVE

            self.db.share_instance_update(context, share_instance_id, updates)

    def _update_share_replica_access_rules_state(self, context,
                                                 share_replica_id, state):
        """Update the access_rules_status for the share replica."""

        self.db.share_instance_update_access_status(
            context, share_replica_id, state)

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
                    LOG.error(_LE("Failed to get share server "
                                  "for share replica creation."))
                    self.db.share_replica_update(
                        context, share_replica['id'],
                        {'status': constants.STATUS_ERROR,
                         'replica_state': constants.STATUS_ERROR})
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

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Share replica %s failed on creation."),
                          share_replica['id'])
                self.db.share_replica_update(
                    context, share_replica['id'],
                    {'status': constants.STATUS_ERROR,
                     'replica_state': constants.STATUS_ERROR})
                self._update_share_replica_access_rules_state(
                    context, share_replica['id'], constants.STATUS_ERROR)

        if replica_ref.get('export_locations'):
                if isinstance(replica_ref.get('export_locations'), list):
                    self.db.share_export_locations_update(
                        context, share_replica['id'],
                        replica_ref.get('export_locations'))
                else:
                    msg = _LW('Invalid export locations passed to the share '
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
                context, share_replica['id'], constants.STATUS_ACTIVE)

        LOG.info(_LI("Share replica %s created successfully."),
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
                delete_rules="all",
                share_server=share_server
            )
        except Exception:
            with excutils.save_and_reraise_exception() as exc_context:
                # Set status to 'error' from 'deleting' since
                # access_rules_status has been set to 'error'.
                self.db.share_replica_update(
                    context, share_replica['id'],
                    {'status': constants.STATUS_ERROR})
                if force:
                    msg = _("The driver was unable to delete access rules "
                            "for the replica: %s. Will attempt to delete "
                            "the replica anyway.")
                    LOG.exception(msg % share_replica['id'])
                    exc_context.reraise = False

        try:
            self.driver.delete_replica(
                context, replica_list, replica_snapshots, share_replica,
                share_server=share_server)
        except Exception:
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

        for replica_snapshot in replica_snapshots:
            self.db.share_snapshot_instance_delete(
                context, replica_snapshot['id'])

        self.db.share_replica_delete(context, share_replica['id'])
        LOG.info(_LI("Share replica %s deleted successfully."),
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
        except Exception:
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

        # Set any 'creating' snapshots on the currently active replica to
        # 'error' since we cannot guarantee they will finish 'creating'.
        active_replica_snapshot_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, {'share_instance_ids': share_replica['id']})
        )
        for instance in active_replica_snapshot_instances:
            if instance['status'] in (constants.STATUS_CREATING,
                                      constants.STATUS_DELETING):
                msg = _LI("The replica snapshot instance %(instance)s was "
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
                context, share_replica['id'],
                {'status': constants.STATUS_AVAILABLE,
                 'replica_state': constants.REPLICA_STATE_ACTIVE})
            self.db.share_replica_update(
                context, old_active_replica['id'],
                {'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC})
        else:
            for updated_replica in updated_replica_list:
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
                # 'replication_change'.
                if updated_replica['id'] == share_replica['id']:
                    updates['status'] = constants.STATUS_AVAILABLE
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

        LOG.info(_LI("Share replica %s: promoted to active state "
                     "successfully."), share_replica['id'])

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
        except Exception:
            msg = _LE("Driver error when updating replica "
                      "state for replica %s.")
            LOG.exception(msg, share_replica['id'])
            self.db.share_replica_update(
                context, share_replica['id'],
                {'replica_state': constants.STATUS_ERROR,
                 'status': constants.STATUS_ERROR})
            return

        if replica_state in (constants.REPLICA_STATE_IN_SYNC,
                             constants.REPLICA_STATE_OUT_OF_SYNC,
                             constants.STATUS_ERROR):
            self.db.share_replica_update(context, share_replica['id'],
                                         {'replica_state': replica_state})
        elif replica_state:
            msg = (_LW("Replica %(id)s cannot be set to %(state)s "
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

            self._update_quota_usages(context, project_id, {
                "shares": 1,
                "gigabytes": share_update['size'],
            })

            share_update.update({
                'status': constants.STATUS_AVAILABLE,
                'launched_at': timeutils.utcnow(),
                'availability_zone': CONF.storage_availability_zone,
            })

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
                LOG.warning(_LI("Cannot get the size of the snapshot "
                                "%(snapshot_id)s. Using the size of "
                                "the share instead."),
                            {'snapshot_id': snapshot_id})

            self._update_quota_usages(context, project_id, {
                "snapshots": 1,
                "snapshot_gigabytes": snapshot_update['size'],
            })

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
            LOG.error(msg, six.text_type(exception))

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
                _LE("Share can not be unmanaged: %s."), e)
            return

        try:
            reservations = QUOTAS.reserve(context,
                                          project_id=project_id,
                                          shares=-1,
                                          gigabytes=-share_ref['size'])
            QUOTAS.commit(context, reservations, project_id=project_id)
        except Exception as e:
            # Note(imalinovskiy):
            # Quota reservation errors here are not fatal, because
            # unmanage is administrator API and he/she could update user
            # quota usages later if it's required.
            LOG.warning(_LW("Failed to update quota usages: %s."),
                        six.text_type(e))

        if self.configuration.safe_get('unmanage_remove_access_rules'):
            try:
                self.access_helper.update_access_rules(
                    context,
                    share_instance['id'],
                    delete_rules="all",
                    share_server=share_server
                )
            except Exception as e:
                share_manage_set_error_status(
                    _LE("Can not remove access rules of share: %s."), e)
                return

        self.db.share_instance_delete(context, share_instance['id'])
        LOG.info(_LI("Share %s: unmanaged successfully."), share_id)

    @add_hooks
    @utils.require_driver_initialized
    def unmanage_snapshot(self, context, snapshot_id):
        status = {'status': constants.STATUS_UNMANAGE_ERROR}
        if self.driver.driver_handles_share_servers:
            msg = _("Unmanage snapshot is not supported for "
                    "driver_handles_share_servers=True mode.")
            self.db.share_snapshot_update(context, snapshot_id, status)
            LOG.error(_LE("Share snapshot cannot be unmanaged: %s."),
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
            LOG.error(_LE("Share snapshot cannot be unmanaged: %s."),
                      msg)
            return

        try:
            self.driver.unmanage_snapshot(snapshot_instance)
        except exception.UnmanageInvalidShareSnapshot as e:
            self.db.share_snapshot_update(context, snapshot_id, status)
            LOG.error(_LE("Share snapshot cannot be unmanaged: %s."), e)
            return

        try:
            reservations = QUOTAS.reserve(
                context,
                project_id=project_id,
                snapshots=-1,
                snapshot_gigabytes=-snapshot_ref['size'])
            QUOTAS.commit(context, reservations, project_id=project_id)
        except Exception as e:
            # Note(imalinovskiy):
            # Quota reservation errors here are not fatal, because
            # unmanage is administrator API and he/she could update user
            # quota usages later if it's required.
            LOG.warning(_LW("Failed to update quota usages: %s."), e)

        self.db.share_snapshot_instance_delete(
            context, snapshot_instance['id'])

    @add_hooks
    @utils.require_driver_initialized
    def delete_share_instance(self, context, share_instance_id, force=False):
        """Delete a share instance."""
        context = context.elevated()
        share_instance = self._get_share_instance(context, share_instance_id)
        share_server = self._get_share_server(context, share_instance)

        try:
            self.access_helper.update_access_rules(
                context,
                share_instance_id,
                delete_rules="all",
                share_server=share_server
            )
        except exception.ShareResourceNotFound:
            LOG.warning(_LW("Share instance %s does not exist in the "
                            "backend."), share_instance_id)
        except Exception:
            with excutils.save_and_reraise_exception() as exc_context:
                if force:
                    msg = _LE("The driver was unable to delete access rules "
                              "for the instance: %s. Will attempt to delete "
                              "the instance anyway.")
                    LOG.error(msg, share_instance_id)
                    exc_context.reraise = False
                else:
                    self.db.share_instance_update(
                        context,
                        share_instance_id,
                        {'status': constants.STATUS_ERROR_DELETING})

        try:
            self.driver.delete_share(context, share_instance,
                                     share_server=share_server)
        except exception.ShareResourceNotFound:
            LOG.warning(_LW("Share instance %s does not exist in the "
                            "backend."), share_instance_id)
        except Exception:
            with excutils.save_and_reraise_exception() as exc_context:
                if force:
                    msg = _LE("The driver was unable to delete the share "
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

        self.db.share_instance_delete(context, share_instance_id)
        LOG.info(_LI("Share instance %s: deleted successfully."),
                 share_instance_id)

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
        LOG.info(_LI("Check for unused share servers to delete."))
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

        try:
            model_update = self.driver.create_snapshot(
                context, snapshot_instance, share_server=share_server)

            if model_update:
                self.db.share_snapshot_instance_update(
                    context, snapshot_instance_id, model_update)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_snapshot_instance_update(
                    context,
                    snapshot_instance_id,
                    {'status': constants.STATUS_ERROR})

        self.db.share_snapshot_instance_update(
            context,
            snapshot_instance_id,
            {'status': constants.STATUS_AVAILABLE,
             'progress': '100%'}
        )
        return snapshot_id

    @add_hooks
    @utils.require_driver_initialized
    def delete_snapshot(self, context, snapshot_id):
        """Delete share snapshot."""
        context = context.elevated()
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)

        share_server = self._get_share_server(
            context, snapshot_ref['share']['instance'])
        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_ref.instance['id'], with_share_data=True
        )
        snapshot_instance_id = snapshot_instance['id']

        if context.project_id != snapshot_ref['project_id']:
            project_id = snapshot_ref['project_id']
        else:
            project_id = context.project_id

        try:
            self.driver.delete_snapshot(context, snapshot_instance,
                                        share_server=share_server)
        except exception.ShareSnapshotIsBusy:
            self.db.share_snapshot_instance_update(
                context,
                snapshot_instance_id,
                {'status': constants.STATUS_AVAILABLE})
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_snapshot_instance_update(
                    context,
                    snapshot_instance_id,
                    {'status': constants.STATUS_ERROR_DELETING})
        else:
            self.db.share_snapshot_instance_delete(
                context, snapshot_instance_id)
            try:
                reservations = QUOTAS.reserve(
                    context, project_id=project_id, snapshots=-1,
                    snapshot_gigabytes=-snapshot_ref['size'],
                    user_id=snapshot_ref['user_id'])
            except Exception:
                reservations = None
                LOG.exception(_LE("Failed to update usages deleting snapshot"))

            if reservations:
                QUOTAS.commit(context, reservations, project_id=project_id,
                              user_id=snapshot_ref['user_id'])

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
                LOG.info(_LI('Snapshot %(snapshot_instance)s on replica '
                             '%(replica)s has been deleted.'), msg_payload)
                self.db.share_snapshot_instance_delete(
                    context, replica_snapshot['id'])
            else:
                LOG.exception(_LE("Replica snapshot %s was not found on "
                                  "the backend."), replica_snapshot['id'])
                self.db.share_snapshot_instance_update(
                    context, replica_snapshot['id'],
                    {'status': constants.STATUS_ERROR})
        except Exception:
            LOG.exception(_LE("Driver error while updating replica snapshot: "
                              "%s"), replica_snapshot['id'])
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
    def allow_access(self, context, share_instance_id, access_rules):
        """Allow access to some share instance."""
        share_instance = self._get_share_instance(context, share_instance_id)
        status = share_instance['access_rules_status']

        if status not in (constants.STATUS_UPDATING,
                          constants.STATUS_UPDATING_MULTIPLE,
                          constants.STATUS_ACTIVE):
            add_rules = [self.db.share_access_get(context, rule_id)
                         for rule_id in access_rules]

            share_server = self._get_share_server(context, share_instance)

            return self.access_helper.update_access_rules(
                context,
                share_instance_id,
                add_rules=add_rules,
                share_server=share_server
            )

    @add_hooks
    @utils.require_driver_initialized
    def deny_access(self, context, share_instance_id, access_rules):
        """Deny access to some share."""
        delete_rules = [self.db.share_access_get(context, rule_id)
                        for rule_id in access_rules]

        share_instance = self._get_share_instance(context, share_instance_id)
        share_server = self._get_share_server(context, share_instance)

        return self.access_helper.update_access_rules(
            context,
            share_instance_id,
            delete_rules=delete_rules,
            share_server=share_server
        )

    @periodic_task.periodic_task(spacing=CONF.periodic_interval)
    @utils.require_driver_initialized
    def _report_driver_status(self, context):
        LOG.info(_LI('Updating share status'))
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
            'nova_net_id': share_network['nova_net_id'],
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
        def _teardown_server():
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
                        _LE("Share server '%s' failed on deletion."),
                        server_id)
                    self.db.share_server_update(
                        context, server_id, {'status': constants.STATUS_ERROR})
            else:
                self.db.share_server_delete(context, share_server['id'])

        _teardown_server()
        LOG.info(
            _LI("Share server '%s' has been deleted successfully."),
            share_server['id'])
        self.driver.deallocate_network(context, share_server['id'])

    def _verify_unused_share_server_cleanup_interval(self):
        if not 10 <= self.configuration.\
                unused_share_server_cleanup_interval <= 60:
            raise exception.InvalidParameterValue(
                "Option unused_share_server_cleanup_interval should be "
                "between 10 minutes and 1 hour.")

    @add_hooks
    @utils.require_driver_initialized
    def extend_share(self, context, share_id, new_size, reservations):
        context = context.elevated()
        share = self.db.share_get(context, share_id)
        share_instance = self._get_share_instance(context, share)
        share_server = self._get_share_server(context, share_instance)
        project_id = share['project_id']
        user_id = share['user_id']

        try:
            self.driver.extend_share(
                share_instance, new_size, share_server=share_server)
        except Exception as e:
            LOG.exception(_LE("Extend share failed."), resource=share)

            try:
                self.db.share_update(
                    context, share['id'],
                    {'status': constants.STATUS_EXTENDING_ERROR}
                )
                raise exception.ShareExtendingError(
                    reason=six.text_type(e), share_id=share_id)
            finally:
                QUOTAS.rollback(context, reservations, project_id=project_id,
                                user_id=user_id)

        # we give the user_id of the share, to update the quota usage
        # for the user, who created the share, because on share delete
        # only this quota will be decreased
        QUOTAS.commit(context, reservations, project_id=project_id,
                      user_id=user_id)

        share_update = {
            'size': int(new_size),
            # NOTE(u_glide): translation to lower case should be removed in
            # a row with usage of upper case of share statuses in all places
            'status': constants.STATUS_AVAILABLE.lower()
        }
        share = self.db.share_update(context, share['id'], share_update)

        LOG.info(_LI("Extend share completed successfully."), resource=share)

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
            reservations = QUOTAS.reserve(context,
                                          project_id=project_id,
                                          user_id=user_id,
                                          gigabytes=-size_decrease)
        except Exception as e:
            error_occurred(
                e, _LE("Failed to update quota on share shrinking."))

        try:
            self.driver.shrink_share(
                share_instance, new_size, share_server=share_server)
        # NOTE(u_glide): Replace following except block by error notification
        # when Manila has such mechanism. It's possible because drivers
        # shouldn't shrink share when this validation error occurs.
        except Exception as e:
            if isinstance(e, exception.ShareShrinkingPossibleDataLoss):
                msg = _LE("Shrink share failed due to possible data loss.")
                status = constants.STATUS_SHRINKING_POSSIBLE_DATA_LOSS_ERROR
                error_params = {'msg': msg, 'status': status}
            else:
                error_params = {'msg': _LE("Shrink share failed.")}

            try:
                error_occurred(e, **error_params)
            finally:
                QUOTAS.rollback(context, reservations, project_id=project_id,
                                user_id=user_id)

        QUOTAS.commit(context, reservations, project_id=project_id,
                      user_id=user_id)

        share_update = {
            'size': new_size,
            'status': constants.STATUS_AVAILABLE
        }
        share = self.db.share_update(context, share['id'], share_update)

        LOG.info(_LI("Shrink share completed successfully."), resource=share)

    @utils.require_driver_initialized
    def create_consistency_group(self, context, cg_id):
        context = context.elevated()
        group_ref = self.db.consistency_group_get(context, cg_id)
        group_ref['host'] = self.host
        shares = self.db.share_instances_get_all_by_consistency_group_id(
            context, cg_id)

        source_cgsnapshot_id = group_ref.get("source_cgsnapshot_id")
        snap_ref = None
        parent_share_server_id = None
        if source_cgsnapshot_id:
            snap_ref = self.db.cgsnapshot_get(context, source_cgsnapshot_id)
            for member in snap_ref['cgsnapshot_members']:
                member['share'] = self.db.share_instance_get(
                    context, member['share_instance_id'], with_share_data=True)
                member['share_id'] = member['share_instance_id']
            if 'consistency_group' in snap_ref:
                parent_share_server_id = snap_ref['consistency_group'][
                    'share_server_id']

        status = constants.STATUS_AVAILABLE
        model_update = False

        share_network_id = group_ref.get('share_network_id', None)
        share_server = None

        if parent_share_server_id and self.driver.driver_handles_share_servers:
            share_server = self.db.share_server_get(context,
                                                    parent_share_server_id)
            share_network_id = share_server['share_network_id']

        if share_network_id and not self.driver.driver_handles_share_servers:
            self.db.consistency_group_update(
                context, cg_id, {'status': constants.STATUS_ERROR})
            msg = _("Driver does not expect share-network to be provided "
                    "with current configuration.")
            raise exception.InvalidInput(reason=msg)

        if not share_server and share_network_id:
            try:
                share_server, group_ref = self._provide_share_server_for_cg(
                    context, share_network_id, group_ref, cgsnapshot=snap_ref
                )
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to get share server"
                                  " for consistency group creation."))
                    self.db.consistency_group_update(
                        context, cg_id, {'status': constants.STATUS_ERROR})

        try:
            # TODO(ameade): Add notification for create.start
            LOG.info(_LI("Consistency group %s: creating"), cg_id)

            model_update, share_update_list = None, None

            group_ref['shares'] = shares
            if snap_ref:
                model_update, share_update_list = (
                    self.driver.create_consistency_group_from_cgsnapshot(
                        context, group_ref, snap_ref,
                        share_server=share_server))
            else:
                model_update = self.driver.create_consistency_group(
                    context, group_ref, share_server=share_server)

            if model_update:
                group_ref = self.db.consistency_group_update(context,
                                                             group_ref['id'],
                                                             model_update)

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
                self.db.consistency_group_update(
                    context,
                    group_ref['id'],
                    {'status': constants.STATUS_ERROR})
                for share in shares:
                    self.db.share_instance_update(
                        context, share['id'],
                        {'status': constants.STATUS_ERROR})
                LOG.error(_LE("Consistency group %s: create failed"), cg_id)

        now = timeutils.utcnow()
        for share in shares:
            self.db.share_instance_update(
                context, share['id'], {'status': constants.STATUS_AVAILABLE})
        self.db.consistency_group_update(context,
                                         group_ref['id'],
                                         {'status': status,
                                          'created_at': now})
        LOG.info(_LI("Consistency group %s: created successfully"), cg_id)

        # TODO(ameade): Add notification for create.end

        return group_ref['id']

    @utils.require_driver_initialized
    def delete_consistency_group(self, context, cg_id):
        context = context.elevated()
        group_ref = self.db.consistency_group_get(context, cg_id)
        group_ref['host'] = self.host
        group_ref['shares'] = (
            self.db.share_instances_get_all_by_consistency_group_id(
                context, cg_id))

        model_update = False

        # TODO(ameade): Add notification for delete.start

        try:
            LOG.info(_LI("Consistency group %s: deleting"), cg_id)
            share_server = None
            if group_ref.get('share_server_id'):
                share_server = self.db.share_server_get(
                    context, group_ref['share_server_id'])
            model_update = self.driver.delete_consistency_group(
                context, group_ref, share_server=share_server)

            if model_update:
                group_ref = self.db.consistency_group_update(
                    context, group_ref['id'], model_update)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.consistency_group_update(
                    context,
                    group_ref['id'],
                    {'status': constants.STATUS_ERROR})
                LOG.error(_LE("Consistency group %s: delete failed"),
                          group_ref['id'])

        self.db.consistency_group_destroy(context,
                                          cg_id)
        LOG.info(_LI("Consistency group %s: deleted successfully"),
                 cg_id)

        # TODO(ameade): Add notification for delete.end

    @utils.require_driver_initialized
    def create_cgsnapshot(self, context, cgsnapshot_id):
        context = context.elevated()
        snap_ref = self.db.cgsnapshot_get(context, cgsnapshot_id)
        for member in snap_ref['cgsnapshot_members']:
            member['share'] = self.db.share_instance_get(
                context, member['share_instance_id'], with_share_data=True)
            member['share_id'] = member['share_instance_id']

        status = constants.STATUS_AVAILABLE
        snapshot_update = False

        try:
            LOG.info(_LI("Consistency group snapshot %s: creating"),
                     cgsnapshot_id)
            share_server = None
            if snap_ref['consistency_group'].get('share_server_id'):
                share_server = self.db.share_server_get(
                    context, snap_ref['consistency_group']['share_server_id'])
            snapshot_update, member_update_list = (
                self.driver.create_cgsnapshot(context, snap_ref,
                                              share_server=share_server))

            if member_update_list:
                snapshot_update = snapshot_update or {}
                snapshot_update['cgsnapshot_members'] = []
                for update in (member_update_list or []):
                    snapshot_update['cgsnapshot_members'].append(update)

            if snapshot_update:
                snap_ref = self.db.cgsnapshot_update(
                    context, snap_ref['id'], snapshot_update)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.cgsnapshot_update(
                    context,
                    snap_ref['id'],
                    {'status': constants.STATUS_ERROR})
                LOG.error(_LE("Consistency group snapshot %s: create failed"),
                          cgsnapshot_id)

        now = timeutils.utcnow()
        for member in (snap_ref.get('cgsnapshot_members') or []):
            update = {'status': status, 'created_at': now}
            self.db.cgsnapshot_member_update(context, member['id'],
                                             update)

        self.db.cgsnapshot_update(context,
                                  snap_ref['id'],
                                  {'status': status,
                                   'created_at': now})
        LOG.info(_LI("Consistency group snapshot %s: created successfully"),
                 cgsnapshot_id)

        return snap_ref['id']

    @utils.require_driver_initialized
    def delete_cgsnapshot(self, context, cgsnapshot_id):
        context = context.elevated()
        snap_ref = self.db.cgsnapshot_get(context, cgsnapshot_id)
        for member in snap_ref['cgsnapshot_members']:
            member['share'] = self.db.share_instance_get(
                context, member['share_instance_id'], with_share_data=True)
            member['share_id'] = member['share_instance_id']

        snapshot_update = False

        try:
            LOG.info(_LI("Consistency group snapshot %s: deleting"),
                     cgsnapshot_id)

            share_server = None
            if snap_ref['consistency_group'].get('share_server_id'):
                share_server = self.db.share_server_get(
                    context, snap_ref['consistency_group']['share_server_id'])

            snapshot_update, member_update_list = (
                self.driver.delete_cgsnapshot(context, snap_ref,
                                              share_server=share_server))

            if member_update_list:
                snapshot_update = snapshot_update or {}
                snapshot_update['cgsnapshot_members'] = []
            for update in (member_update_list or []):
                snapshot_update['cgsnapshot_members'].append(update)

            if snapshot_update:
                snap_ref = self.db.cgsnapshot_update(
                    context, snap_ref['id'], snapshot_update)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.cgsnapshot_update(
                    context,
                    snap_ref['id'],
                    {'status': constants.STATUS_ERROR})
                LOG.error(_LE("Consistency group snapshot %s: delete failed"),
                          snap_ref['name'])

        self.db.cgsnapshot_destroy(context, cgsnapshot_id)

        LOG.info(_LI("Consistency group snapshot %s: deleted successfully"),
                 cgsnapshot_id)

    def _get_share_replica_dict(self, context, share_replica):
        # TODO(gouthamr): remove method when the db layer returns primitives
        share_replica_ref = {
            'id': share_replica.get('id'),
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
            'consistency_group_id': share_replica.get('consistency_group_id'),
            'source_cgsnapshot_member_id': share_replica.get(
                'source_cgsnapshot_member_id'),
        }

        return share_replica_ref

    def _get_snapshot_instance_dict(self, context, snapshot_instance):
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

        return snapshot_instance_ref
