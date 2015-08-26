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

from manila import context
from manila import db
from manila import exception
from manila.i18n import _LE
from manila import manager
from manila import rpc
from manila.share import rpcapi as share_rpcapi

LOG = log.getLogger(__name__)

scheduler_driver_opt = cfg.StrOpt('scheduler_driver',
                                  default='manila.scheduler.filter_scheduler.'
                                          'FilterScheduler',
                                  help='Default scheduler driver to use.')

CONF = cfg.CONF
CONF.register_opt(scheduler_driver_opt)


class SchedulerManager(manager.Manager):
    """Chooses a host to create shares."""

    RPC_API_VERSION = '1.2'

    def __init__(self, scheduler_driver=None, service_name=None,
                 *args, **kwargs):
        if not scheduler_driver:
            scheduler_driver = CONF.scheduler_driver
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
            self._set_share_error_state_and_notify('create_share',
                                                   context, ex, request_spec)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                self._set_share_error_state_and_notify('create_share',
                                                       context, ex,
                                                       request_spec)

    def get_pools(self, context, filters=None):
        """Get active pools from the scheduler's cache."""
        return self.driver.get_pools(context, filters)

    def _set_share_error_state_and_notify(self, method, context, ex,
                                          request_spec):
        LOG.error(_LE("Failed to schedule_%(method)s: %(ex)s"),
                  {"method": method, "ex": ex})

        share_state = {'status': 'error'}
        properties = request_spec.get('share_properties', {})

        share_id = request_spec.get('share_id', None)

        if share_id:
            db.share_update(context, share_id, share_state)

        payload = dict(request_spec=request_spec,
                       share_properties=properties,
                       share_id=share_id,
                       state=share_state,
                       method=method,
                       reason=ex)

        rpc.get_notifier("scheduler").error(
            context, 'scheduler.' + method, payload)

    def request_service_capabilities(self, context):
        share_rpcapi.ShareAPI().publish_service_capabilities(context)
