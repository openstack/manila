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
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LI
from manila.i18n import _LW
from manila import manager
from manila import quota
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
}

QUOTAS = quota.QUOTAS


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

    RPC_API_VERSION = '1.6'

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
            configuration=self.configuration
        )

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

            rules = self.db.share_access_get_all_for_share(
                ctxt, share_instance['share_id'])
            for access_ref in rules:
                if access_ref['state'] != constants.STATUS_ACTIVE:
                    continue

                try:
                    self.driver.allow_access(ctxt, share_instance, access_ref,
                                             share_server=share_server)
                except exception.ShareAccessExists:
                    pass
                except Exception as e:
                    LOG.error(
                        _LE("Unexpected exception during share access"
                            " allow operation. Share id is '%(s_id)s'"
                            ", access rule type is '%(ar_type)s', "
                            "access rule id is '%(ar_id)s', exception"
                            " is '%(e)s'."),
                        {'s_id': share_instance['id'],
                         'ar_type': access_ref['access_type'],
                         'ar_id': access_ref['id'],
                         'e': six.text_type(e)},
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
            parent_share_server_id = snapshot['share']['share_server_id']
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

    def get_migration_info(self, ctxt, share_instance_id, share_server):
        share_instance = self.db.share_instance_get(
            ctxt, share_instance_id, with_share_data=True)
        return self.driver.get_migration_info(ctxt, share_instance,
                                              share_server)

    def get_driver_migration_info(self, ctxt, share_instance_id, share_server):
        share_instance = self.db.share_instance_get(
            ctxt, share_instance_id, with_share_data=True)
        return self.driver.get_driver_migration_info(ctxt, share_instance,
                                                     share_server)

    @utils.require_driver_initialized
    def migrate_share(self, ctxt, share_id, host, force_host_copy=False):
        """Migrates a share from current host to another host."""
        LOG.debug("Entered migrate_share method for share %s." % share_id)

        # NOTE(ganso): Cinder checks if driver is initialized before doing
        # anything. This might not be needed, as this code may not be reached
        # if driver service is not running. If for any reason service is
        # running but driver is not, the following code should fail at specific
        # points, which would be effectively the same as throwing an
        # exception here.

        rpcapi = share_rpcapi.ShareAPI()
        share_ref = self.db.share_get(ctxt, share_id)
        share_instance = self._get_share_instance(ctxt, share_ref)
        moved = False
        msg = None

        self.db.share_update(
            ctxt, share_ref['id'],
            {'task_state': constants.STATUS_TASK_STATE_MIGRATION_IN_PROGRESS})

        if not force_host_copy:
            try:

                share_server = self._get_share_server(ctxt.elevated(),
                                                      share_instance)
                share_server = {
                    'id': share_server['id'],
                    'share_network_id': share_server['share_network_id'],
                    'host': share_server['host'],
                    'status': share_server['status'],
                    'backend_details': share_server['backend_details'],
                } if share_server else share_server

                dest_driver_migration_info = rpcapi.get_driver_migration_info(
                    ctxt, share_instance, share_server)

                LOG.debug("Calling driver migration for share %s." % share_id)

                moved, model_update = self.driver.migrate_share(
                    ctxt, share_instance, host, dest_driver_migration_info)

                # NOTE(ganso): Here we are allowing the driver to perform
                # changes even if it has not performed migration. While this
                # scenario may not be valid, I am not sure if it should be
                # forcefully prevented.

                if model_update:
                    self.db.share_instance_update(ctxt, share_instance['id'],
                                                  model_update)

            except exception.ManilaException as e:
                msg = six.text_type(e)
                LOG.exception(msg)

        if not moved:
            try:
                LOG.debug("Starting generic migration "
                          "for share %s." % share_id)

                moved = self._migrate_share_generic(ctxt, share_ref, host)
            except Exception as e:
                msg = six.text_type(e)
                LOG.exception(msg)
                LOG.error(_LE("Generic migration failed for"
                              " share %s.") % share_id)

        if moved:
            self.db.share_update(
                ctxt, share_id,
                {'task_state': constants.STATUS_TASK_STATE_MIGRATION_SUCCESS})

            LOG.info(_LI("Share Migration for share %s"
                         " completed successfully.") % share_id)
        else:
            self.db.share_update(
                ctxt, share_id,
                {'task_state': constants.STATUS_TASK_STATE_MIGRATION_ERROR})
            raise exception.ShareMigrationFailed(reason=msg)

    def _migrate_share_generic(self, context, share, host):

        rpcapi = share_rpcapi.ShareAPI()

        share_instance = self._get_share_instance(context, share)

        access_rule_timeout = self.driver.configuration.safe_get(
            'migration_wait_access_rules_timeout')

        create_delete_timeout = self.driver.configuration.safe_get(
            'migration_create_delete_share_timeout')

        helper = migration.ShareMigrationHelper(
            context, self.db, create_delete_timeout,
            access_rule_timeout, share)

        # NOTE(ganso): We are going to save all access rules prior to removal.
        # Since we may have several instances of the same share, it may be
        # a good idea to limit or remove all instances/replicas' access
        # so they remain unchanged as well during migration.

        readonly_support = self.driver.configuration.safe_get(
            'migration_readonly_support')

        saved_rules = helper.change_to_read_only(readonly_support)

        try:

            new_share_instance = helper.create_instance_and_wait(
                context, share, share_instance, host)

            self.db.share_instance_update(
                context, new_share_instance['id'],
                {'status': constants.STATUS_INACTIVE}
            )

            LOG.debug("Time to start copying in migration"
                      " for share %s." % share['id'])

            share_server = self._get_share_server(context.elevated(),
                                                  share_instance)
            new_share_server = self._get_share_server(context.elevated(),
                                                      new_share_instance)
            new_share_server = {
                'id': new_share_server['id'],
                'share_network_id': new_share_server['share_network_id'],
                'host': new_share_server['host'],
                'status': new_share_server['status'],
                'backend_details': new_share_server['backend_details'],
            } if new_share_server else new_share_server

            src_migration_info = self.driver.get_migration_info(
                context, share_instance, share_server)

            dest_migration_info = rpcapi.get_migration_info(
                context, new_share_instance, new_share_server)

            self.driver.copy_share_data(context, helper, share, share_instance,
                                        share_server, new_share_instance,
                                        new_share_server, src_migration_info,
                                        dest_migration_info)

        except Exception as e:
            LOG.exception(six.text_type(e))
            LOG.error(_LE("Share migration failed, reverting access rules for "
                          "share %s.") % share['id'])
            helper.revert_access_rules(readonly_support, saved_rules)
            raise

        helper.revert_access_rules(readonly_support, saved_rules)

        self.db.share_update(
            context, share['id'],
            {'task_state': constants.STATUS_TASK_STATE_MIGRATION_COMPLETING})

        self.db.share_instance_update(context, new_share_instance['id'],
                                      {'status': constants.STATUS_AVAILABLE})

        helper.delete_instance_and_wait(context, share_instance)

        return True

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
            parent_share_server_id = snapshot_ref['share']['share_server_id']
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
            self.db.share_instance_update(
                context, share_instance_id,
                {'status': constants.STATUS_AVAILABLE,
                 'launched_at': timeutils.utcnow()}
            )

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

    def _update_quota_usages(self, context, project_id, usages):
        user_id = context.user_id
        for resource, usage in six.iteritems(usages):
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
        share_server = self._get_share_server(context, share_ref)
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
                self._remove_share_access_rules(context, share_ref,
                                                share_instance, share_server)
            except Exception as e:
                share_manage_set_error_status(
                    _LE("Can not remove access rules of share: %s."), e)
                return

        self.db.share_instance_delete(context, share_instance['id'])
        LOG.info(_LI("Share %s: unmanaged successfully."), share_id)

    @add_hooks
    @utils.require_driver_initialized
    def delete_share_instance(self, context, share_instance_id):
        """Delete a share instance."""
        context = context.elevated()
        share_instance = self._get_share_instance(context, share_instance_id)
        share = self.db.share_get(context, share_instance['share_id'])
        share_server = self._get_share_server(context, share_instance)

        try:
            self._remove_share_access_rules(context, share, share_instance,
                                            share_server)
            self.driver.delete_share(context, share_instance,
                                     share_server=share_server)
        except Exception:
            with excutils.save_and_reraise_exception():
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

    def _remove_share_access_rules(self, context, share_ref, share_instance,
                                   share_server):
        rules = self.db.share_access_get_all_for_share(
            context, share_ref['id'])

        for access_ref in rules:
            self._deny_access(context, access_ref,
                              share_instance, share_server)

    @add_hooks
    @utils.require_driver_initialized
    def create_snapshot(self, context, share_id, snapshot_id):
        """Create snapshot for share."""
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
        share_server = self._get_share_server(context,
                                              snapshot_ref['share'])
        snapshot_instance = self.db.share_snapshot_instance_get(
            context, snapshot_ref.instance['id'], with_share_data=True
        )
        snapshot_instance_id = snapshot_instance['id']

        try:
            model_update = self.driver.create_snapshot(
                context, snapshot_instance, share_server=share_server)

            if model_update:
                model_dict = model_update.to_dict()
                self.db.share_snapshot_instance_update(
                    context, snapshot_instance_id, model_dict)

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

        share_server = self._get_share_server(context,
                                              snapshot_ref['share'])
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
            self.db.share_snapshot_destroy(context, snapshot_id)
            try:
                reservations = QUOTAS.reserve(
                    context, project_id=project_id, snapshots=-1,
                    snapshot_gigabytes=-snapshot_ref['size'])
            except Exception:
                reservations = None
                LOG.exception(_LE("Failed to update usages deleting snapshot"))

            if reservations:
                QUOTAS.commit(context, reservations, project_id=project_id)

    @add_hooks
    @utils.require_driver_initialized
    def allow_access(self, context, share_instance_id, access_id):
        """Allow access to some share instance."""
        access_mapping = self.db.share_instance_access_get(context, access_id,
                                                           share_instance_id)

        if access_mapping['state'] != access_mapping.STATE_NEW:
            return

        try:
            access_ref = self.db.share_access_get(context, access_id)
            share_instance = self.db.share_instance_get(
                context, share_instance_id, with_share_data=True)
            share_server = self._get_share_server(context, share_instance)
            self.driver.allow_access(context, share_instance, access_ref,
                                     share_server=share_server)
            self.db.share_instance_access_update_state(
                context, access_mapping['id'], access_mapping.STATE_ACTIVE)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_instance_access_update_state(
                    context, access_mapping['id'], access_mapping.STATE_ERROR)

        LOG.info(_LI("'%(access_to)s' has been successfully allowed "
                     "'%(access_level)s' access on share instance "
                     "%(share_instance_id)s."),
                 {'access_to': access_ref['access_to'],
                  'access_level': access_ref['access_level'],
                  'share_instance_id': share_instance_id})

    @add_hooks
    @utils.require_driver_initialized
    def deny_access(self, context, share_instance_id, access_id):
        """Deny access to some share."""
        access_ref = self.db.share_access_get(context, access_id)
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)
        share_server = self._get_share_server(context, share_instance)
        self._deny_access(context, access_ref, share_instance, share_server)

        LOG.info(_LI("'(access_to)s' has been successfully denied access to "
                     "share instance %(share_instance_id)s."),
                 {'access_to': access_ref['access_to'],
                  'share_instance_id': share_instance_id})

    def _deny_access(self, context, access_ref, share_instance, share_server):
        access_mapping = self.db.share_instance_access_get(
            context, access_ref['id'], share_instance['id'])
        try:
            self.driver.deny_access(context, share_instance, access_ref,
                                    share_server=share_server)
            self.db.share_instance_access_delete(context, access_mapping['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_instance_access_update_state(
                    context, access_mapping['id'], access_mapping.STATE_ERROR)

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
            context, share_server['id'])
        network_info = {
            'server_id': share_server['id'],
            'segmentation_id': share_network['segmentation_id'],
            'cidr': share_network['cidr'],
            'neutron_net_id': share_network['neutron_net_id'],
            'neutron_subnet_id': share_network['neutron_subnet_id'],
            'nova_net_id': share_network['nova_net_id'],
            'security_services': share_network['security_services'],
            'network_allocations': network_allocations,
            'backend_details': share_server.get('backend_details'),
            'network_type': share_network['network_type'],
        }
        return network_info

    def _setup_server(self, context, share_server, metadata=None):
        try:
            share_network = self.db.share_network_get(
                context, share_server['share_network_id'])
            self.driver.allocate_network(context, share_server, share_network)

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
                try:
                    details = getattr(e, 'detail_data', {})
                    if not isinstance(details, dict):
                        msg = (_("Invalid detail_data '%s'")
                               % six.text_type(details))
                        raise exception.Invalid(msg)

                    server_details = details.get('server_details')

                    if not isinstance(server_details, dict):
                        msg = (_("Invalid server_details '%s'")
                               % six.text_type(server_details))
                        raise exception.Invalid(msg)

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
                        msg = (_("Following server details are not valid:\n%s")
                               % six.text_type('\n'.join(invalid_details)))
                        raise exception.Invalid(msg)

                except Exception as e:
                    LOG.warning(_LW('Server Information in '
                                    'exception can not be written to db : %s '
                                    ), six.text_type(e))
                finally:
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
        share_server = self._get_share_server(context, share)
        project_id = share['project_id']

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
                QUOTAS.rollback(context, reservations, project_id=project_id)

        QUOTAS.commit(context, reservations, project_id=project_id)

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
        share_server = self._get_share_server(context, share)
        project_id = share['project_id']
        new_size = int(new_size)

        def error_occurred(exc, msg, status=constants.STATUS_SHRINKING_ERROR):
            LOG.exception(msg, resource=share)
            self.db.share_update(context, share['id'], {'status': status})

            raise exception.ShareShrinkingError(
                reason=six.text_type(exc), share_id=share_id)

        reservations = None

        try:
            size_decrease = int(share['size']) - new_size
            reservations = QUOTAS.reserve(context,
                                          project_id=share['project_id'],
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
                QUOTAS.rollback(context, reservations, project_id=project_id)

        QUOTAS.commit(context, reservations, project_id=project_id)

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
