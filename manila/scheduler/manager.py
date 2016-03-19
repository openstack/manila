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

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
import six

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.i18n import _LE, _LW
from manila import manager
from manila import rpc
from manila.share import rpcapi as share_rpcapi

LOG = log.getLogger(__name__)

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

    RPC_API_VERSION = '1.6'

    def __init__(self, scheduler_driver=None, service_name=None,
                 *args, **kwargs):

        if not scheduler_driver:
            scheduler_driver = CONF.scheduler_driver
        if scheduler_driver in MAPPING:
            msg_args = {
                'old': scheduler_driver,
                'new': MAPPING[scheduler_driver],
            }
            LOG.warning(_LW("Scheduler driver path %(old)s is deprecated, "
                            "update your configuration to the new path "
                            "%(new)s"), msg_args)
            scheduler_driver = MAPPING[scheduler_driver]

        self.driver = importutils.import_object(scheduler_driver)
        super(SchedulerManager, self).__init__(*args, **kwargs)

    def init_host(self):
        ctxt = context.get_admin_context()
        self.request_service_capabilities(ctxt)

    def get_host_list(self, context):
        """Get a list of hosts from the HostManager."""
        return self.driver.get_host_list()

    def get_service_capabilities(self, context):
        """Get the normalized set of capabilities for this zone."""
        return self.driver.get_service_capabilities()

    def update_service_capabilities(self, context, service_name=None,
                                    host=None, capabilities=None, **kwargs):
        """Process a capability update from a service node."""
        if capabilities is None:
            capabilities = {}
        self.driver.update_service_capabilities(service_name,
                                                host,
                                                capabilities)

    def create_share_instance(self, context, request_spec=None,
                              filter_properties=None):
        try:
            self.driver.schedule_create_share(context, request_spec,
                                              filter_properties)
        except exception.NoValidHost as ex:
            self._set_share_state_and_notify('create_share',
                                             {'status':
                                              constants.STATUS_ERROR},
                                             context, ex, request_spec)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                self._set_share_state_and_notify('create_share',
                                                 {'status':
                                                  constants.STATUS_ERROR},
                                                 context, ex, request_spec)

    def get_pools(self, context, filters=None):
        """Get active pools from the scheduler's cache."""
        return self.driver.get_pools(context, filters)

    def manage_share(self, context, share_id, driver_options, request_spec,
                     filter_properties=None):
        """Ensure that the host exists and can accept the share."""

        def _manage_share_set_error(self, context, ex, request_spec):
            self._set_share_state_and_notify(
                'manage_share',
                {'status': constants.STATUS_MANAGE_ERROR},
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

    def migrate_share_to_host(self, context, share_id, host,
                              force_host_copy, notify, request_spec,
                              filter_properties=None):
        """Ensure that the host exists and can accept the share."""

        def _migrate_share_set_error(self, context, ex, request_spec):
            self._set_share_state_and_notify(
                'migrate_share_to_host',
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR},
                context, ex, request_spec)

        try:
            tgt_host = self.driver.host_passes_filters(context, host,
                                                       request_spec,
                                                       filter_properties)

        except exception.NoValidHost as ex:
            with excutils.save_and_reraise_exception():
                _migrate_share_set_error(self, context, ex, request_spec)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                _migrate_share_set_error(self, context, ex, request_spec)
        else:
            share_ref = db.share_get(context, share_id)
            try:
                share_rpcapi.ShareAPI().migration_start(
                    context, share_ref, tgt_host, force_host_copy, notify)
            except Exception as ex:
                with excutils.save_and_reraise_exception():
                    _migrate_share_set_error(self, context, ex, request_spec)

    def _set_share_state_and_notify(self, method, state, context, ex,
                                    request_spec):

        LOG.error(_LE("Failed to schedule %(method)s: %(ex)s"),
                  {"method": method, "ex": six.text_type(ex)})

        properties = request_spec.get('share_properties', {})

        share_id = request_spec.get('share_id', None)

        if share_id:
            db.share_update(context, share_id, state)

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

    def _set_cg_error_state(self, method, context, ex, request_spec):
        LOG.warning(_LW("Failed to schedule_%(method)s: %(ex)s"),
                    {"method": method, "ex": ex})

        cg_state = {'status': constants.STATUS_ERROR}

        consistency_group_id = request_spec.get('consistency_group_id')

        if consistency_group_id:
            db.consistency_group_update(context,
                                        consistency_group_id,
                                        cg_state)

        # TODO(ameade): add notifications

    def create_consistency_group(self, context, cg_id, request_spec=None,
                                 filter_properties=None):
        try:
            self.driver.schedule_create_consistency_group(context, cg_id,
                                                          request_spec,
                                                          filter_properties)
        except exception.NoValidHost as ex:
            self._set_cg_error_state('create_consistency_group',
                                     context, ex, request_spec)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                self._set_cg_error_state('create_consistency_group',
                                         context, ex, request_spec)

    def _set_share_replica_error_state(self, context, method, exc,
                                       request_spec):

        LOG.warning(_LW("Failed to schedule_%(method)s: %(exc)s"),
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

    def create_share_replica(self, context, request_spec=None,
                             filter_properties=None):
        try:
            self.driver.schedule_create_replica(context, request_spec,
                                                filter_properties)

        except exception.NoValidHost as exc:
            self._set_share_replica_error_state(
                context, 'create_share_replica', exc, request_spec)

        except Exception as exc:
            with excutils.save_and_reraise_exception():
                self._set_share_replica_error_state(
                    context, 'create_share_replica', exc, request_spec)
