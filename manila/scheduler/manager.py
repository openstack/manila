# Copyright (c) 2010 OpenStack, LLC.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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
Scheduler Service
"""

from datetime import datetime

from oslo_config import cfg
from oslo_log import log
from oslo_service import periodic_task
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import timeutils

from manila.common import constants
from manila import context
from manila import coordination
from manila import db
from manila import exception
from manila import manager
from manila.message import api as message_api
from manila.message import message_field
from manila import quota
from manila import rpc
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types

LOG = log.getLogger(__name__)
QUOTAS = quota.QUOTAS

scheduler_driver_opt = cfg.StrOpt('scheduler_driver',
                                  default='manila.scheduler.drivers.'
                                          'filter.FilterScheduler',
                                  help='Default scheduler driver to use.')

CONF = cfg.CONF
CONF.register_opt(scheduler_driver_opt)

# Drivers that need to change module paths or class names can add their
# old/new path here to maintain backward compatibility.
MAPPING = {
    'manila.scheduler.chance.ChanceScheduler':
    'manila.scheduler.drivers.chance.ChanceScheduler',
    'manila.scheduler.filter_scheduler.FilterScheduler':
    'manila.scheduler.drivers.filter.FilterScheduler',
    'manila.scheduler.simple.SimpleScheduler':
    'manila.scheduler.drivers.simple.SimpleScheduler',
}


class SchedulerManager(manager.Manager):
    """Chooses a host to create shares."""

    RPC_API_VERSION = '1.11'

    def __init__(self, scheduler_driver=None, service_name=None,
                 *args, **kwargs):

        if not scheduler_driver:
            scheduler_driver = CONF.scheduler_driver
        if scheduler_driver in MAPPING:
            msg_args = {
                'old': scheduler_driver,
                'new': MAPPING[scheduler_driver],
            }
            LOG.warning("Scheduler driver path %(old)s is deprecated, "
                        "update your configuration to the new path "
                        "%(new)s", msg_args)
            scheduler_driver = MAPPING[scheduler_driver]

        self.driver = importutils.import_object(scheduler_driver)
        self.message_api = message_api.API()
        super(SchedulerManager, self).__init__(*args, **kwargs)
        self.service_id = None

    def init_host_with_rpc(self, service_id=None):
        self.service_id = service_id
        ctxt = context.get_admin_context()
        self.request_service_capabilities(ctxt)

    def get_host_list(self, context):
        """Get a list of hosts from the HostManager."""
        return self.driver.get_host_list()

    def get_service_capabilities(self, context):
        """Get the normalized set of capabilities for this zone."""
        return self.driver.get_service_capabilities()

    def update_service_capabilities(self, context, service_name=None,
                                    host=None, capabilities=None,
                                    timestamp=None, **kwargs):
        """Process a capability update from a service node."""
        if capabilities is None:
            capabilities = {}
        elif timestamp:
            timestamp = datetime.strptime(timestamp,
                                          timeutils.PERFECT_TIME_FORMAT)
        self.driver.update_service_capabilities(service_name,
                                                host,
                                                capabilities,
                                                timestamp)

    def create_share_instance(self, context, request_spec=None,
                              filter_properties=None):
        try:
            self.driver.schedule_create_share(context, request_spec,
                                              filter_properties)
        except exception.NoValidHost as ex:
            self._set_share_state_and_notify(
                'create_share', {'status': constants.STATUS_ERROR},
                context, ex, request_spec,
                message_field.Action.ALLOCATE_HOST)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                self._set_share_state_and_notify(
                    'create_share', {'status': constants.STATUS_ERROR},
                    context, ex, request_spec)

    def get_pools(self, context, filters=None, cached=False):
        """Get active pools from the scheduler's cache."""
        return self.driver.get_pools(context, filters, cached)

    def manage_share(self, context, share_id, driver_options, request_spec,
                     filter_properties=None):
        """Ensure that the host exists and can accept the share."""

        def _manage_share_set_error(self, context, ex, request_spec):
            # NOTE(haixin) if failed to scheduler backend for manage share,
            # and we do not commit quota usages here, so we should set size 0
            # because we don't know the real size of the size, and we will
            # skip quota cuts when unmanage share with manage_error status.
            self._set_share_state_and_notify(
                'manage_share',
                {'status': constants.STATUS_MANAGE_ERROR, 'size': 0},
                context, ex, request_spec)

        share_ref = db.share_get(context, share_id)

        try:
            self.driver.host_passes_filters(
                context, share_ref['host'], request_spec, filter_properties)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                _manage_share_set_error(self, context, ex, request_spec)
        else:
            share_rpcapi.ShareAPI().manage_share(context, share_ref,
                                                 driver_options)

    def migrate_share_to_host(
            self, context, share_id, host, force_host_assisted_migration,
            preserve_metadata, writable, nondisruptive, preserve_snapshots,
            new_share_network_id, new_share_type_id, request_spec,
            filter_properties=None):
        """Ensure that the host exists and can accept the share."""

        share_ref = db.share_get(context, share_id)

        def _migrate_share_set_error(self, context, ex, request_spec):
            instance = next((x for x in share_ref.instances
                             if x['status'] == constants.STATUS_MIGRATING),
                            None)
            if instance:
                db.share_instance_update(
                    context, instance['id'],
                    {'status': constants.STATUS_AVAILABLE})
            self._set_share_state_and_notify(
                'migrate_share_to_host',
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR},
                context, ex, request_spec)
            share_types.revert_allocated_share_type_quotas_during_migration(
                context, share_ref, new_share_type_id)

        try:
            tgt_host = self.driver.host_passes_filters(
                context, host, request_spec, filter_properties)

        except Exception as ex:
            with excutils.save_and_reraise_exception():
                _migrate_share_set_error(self, context, ex, request_spec)
        else:

            try:
                share_rpcapi.ShareAPI().migration_start(
                    context, share_ref, tgt_host.host,
                    force_host_assisted_migration, preserve_metadata, writable,
                    nondisruptive, preserve_snapshots, new_share_network_id,
                    new_share_type_id)
            except Exception as ex:
                with excutils.save_and_reraise_exception():
                    _migrate_share_set_error(self, context, ex, request_spec)

    def _set_share_state_and_notify(self, method, state, context, ex,
                                    request_spec, action=None):

        LOG.error("Failed to schedule %(method)s: %(ex)s",
                  {"method": method, "ex": ex})

        properties = request_spec.get('share_properties', {})

        share_id = request_spec.get('share_id', None)

        if share_id:
            db.share_update(context, share_id, state)

        if action:
            self.message_api.create(
                context, action, context.project_id,
                resource_type=message_field.Resource.SHARE,
                resource_id=share_id, exception=ex)

        payload = dict(request_spec=request_spec,
                       share_properties=properties,
                       share_id=share_id,
                       state=state,
                       method=method,
                       reason=ex)

        rpc.get_notifier("scheduler").error(
            context, 'scheduler.' + method, payload)

    def request_service_capabilities(self, context):
        share_rpcapi.ShareAPI().publish_service_capabilities(context)

    def _set_share_group_error_state(self, method, context, ex,
                                     request_spec, action=None):
        LOG.warning("Failed to schedule_%(method)s: %(ex)s",
                    {"method": method, "ex": ex})

        share_group_state = {'status': constants.STATUS_ERROR}

        share_group_id = request_spec.get('share_group_id')

        if share_group_id:
            db.share_group_update(context, share_group_id, share_group_state)

        if action:
            self.message_api.create(
                context, action, context.project_id,
                resource_type=message_field.Resource.SHARE_GROUP,
                resource_id=share_group_id, exception=ex)

    @periodic_task.periodic_task(spacing=600, run_immediately=True)
    def _expire_reservations(self, context):
        quota.QUOTAS.expire(context)

    def create_share_group(self, context, share_group_id, request_spec=None,
                           filter_properties=None):
        try:
            self.driver.schedule_create_share_group(
                context, share_group_id, request_spec, filter_properties)
        except exception.NoValidHost as ex:
            self._set_share_group_error_state(
                'create_share_group', context, ex, request_spec,
                message_field.Action.ALLOCATE_HOST)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                self._set_share_group_error_state(
                    'create_share_group', context, ex, request_spec)

    def _set_share_replica_error_state(self, context, method, exc,
                                       request_spec, action=None):

        LOG.warning("Failed to schedule_%(method)s: %(exc)s",
                    {'method': method, 'exc': exc})
        status_updates = {
            'status': constants.STATUS_ERROR,
            'replica_state': constants.STATUS_ERROR,
        }
        share_replica_id = request_spec.get(
            'share_instance_properties').get('id')

        # Set any snapshot instances to 'error'.
        replica_snapshots = db.share_snapshot_instance_get_all_with_filters(
            context, {'share_instance_ids': share_replica_id})
        for snapshot_instance in replica_snapshots:
            db.share_snapshot_instance_update(
                context, snapshot_instance['id'],
                {'status': constants.STATUS_ERROR})

        db.share_replica_update(context, share_replica_id, status_updates)

        if action:
            self.message_api.create(
                context, action, context.project_id,
                resource_type=message_field.Resource.SHARE_REPLICA,
                resource_id=share_replica_id, exception=exc)

    def create_share_replica(self, context, request_spec=None,
                             filter_properties=None):
        try:
            self.driver.schedule_create_replica(context, request_spec,
                                                filter_properties)

        except exception.NoValidHost as exc:
            self._set_share_replica_error_state(
                context, 'create_share_replica', exc, request_spec,
                message_field.Action.ALLOCATE_HOST)

        except Exception as exc:
            with excutils.save_and_reraise_exception():
                self._set_share_replica_error_state(
                    context, 'create_share_replica', exc, request_spec)

    @periodic_task.periodic_task(spacing=CONF.message_reap_interval,
                                 run_immediately=True)
    @coordination.synchronized('locked-clean-expired-messages')
    def _clean_expired_messages(self, context):
        self.message_api.cleanup_expired_messages(context)

    def extend_share(self, context, share_id, new_size, reservations,
                     request_spec=None, filter_properties=None):

        def _extend_share_set_error(self, context, ex, request_spec):
            share_state = {'status': constants.STATUS_AVAILABLE}
            self._set_share_state_and_notify('extend_share', share_state,
                                             context, ex, request_spec)

        share = db.share_get(context, share_id)
        try:
            size_increase = int(new_size) - share['size']
            if filter_properties:
                filter_properties['size_increase'] = size_increase
            else:
                filter_properties = {'size_increase': size_increase}
            target_host = self.driver.host_passes_filters(
                context,
                share['host'],
                request_spec, filter_properties)
            target_host.consume_from_share({'size': size_increase})
            share_rpcapi.ShareAPI().extend_share(context, share, new_size,
                                                 reservations)
        except exception.NoValidHost as ex:
            quota.QUOTAS.rollback(context, reservations,
                                  project_id=share['project_id'],
                                  user_id=share['user_id'],
                                  share_type_id=share['share_type_id'])
            _extend_share_set_error(self, context, ex, request_spec)
            self.message_api.create(
                context,
                message_field.Action.EXTEND,
                share['project_id'],
                resource_type=message_field.Resource.SHARE,
                resource_id=share['id'],
                exception=ex)
