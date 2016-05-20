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
Scheduler base class that all Schedulers should inherit from
"""

from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import timeutils

from manila import db
from manila.i18n import _
from manila.share import rpcapi as share_rpcapi
from manila import utils

scheduler_driver_opts = [
    cfg.StrOpt('scheduler_host_manager',
               default='manila.scheduler.host_manager.HostManager',
               help='The scheduler host manager class to use.'),
    cfg.IntOpt('scheduler_max_attempts',
               default=3,
               help='Maximum number of attempts to schedule a share.'),
]

CONF = cfg.CONF
CONF.register_opts(scheduler_driver_opts)


def share_update_db(context, share_id, host):
    '''Set the host and set the scheduled_at field of a share.

    :returns: A Share with the updated fields set properly.
    '''
    now = timeutils.utcnow()
    values = {'host': host, 'scheduled_at': now}
    return db.share_update(context, share_id, values)


def share_replica_update_db(context, share_replica_id, host):
    """Set the host and the scheduled_at field of a share replica.

    :returns: A Share Replica with the updated fields set.
    """
    now = timeutils.utcnow()
    values = {'host': host, 'scheduled_at': now}
    return db.share_replica_update(context, share_replica_id, values)


def share_group_update_db(context, share_group_id, host):
    '''Set the host and set the updated_at field of a share group.

    :returns: A share group with the updated fields set properly.
    '''
    now = timeutils.utcnow()
    values = {'host': host, 'updated_at': now}
    return db.share_group_update(context, share_group_id, values)


class Scheduler(object):
    """The base class that all Scheduler classes should inherit from."""

    def __init__(self):
        self.host_manager = importutils.import_object(
            CONF.scheduler_host_manager)
        self.share_rpcapi = share_rpcapi.ShareAPI()

    def get_host_list(self):
        """Get a list of hosts from the HostManager."""
        return self.host_manager.get_host_list()

    def get_service_capabilities(self):
        """Get the normalized set of capabilities for the services."""
        return self.host_manager.get_service_capabilities()

    def update_service_capabilities(self, service_name, host, capabilities):
        """Process a capability update from a service node."""
        self.host_manager.update_service_capabilities(service_name,
                                                      host,
                                                      capabilities)

    def hosts_up(self, context, topic):
        """Return the list of hosts that have a running service for topic."""

        services = db.service_get_all_by_topic(context, topic)
        return [service['host']
                for service in services
                if utils.service_is_up(service)]

    def schedule(self, context, topic, method, *_args, **_kwargs):
        """Must override schedule method for scheduler to work."""
        raise NotImplementedError(_("Must implement a fallback schedule"))

    def schedule_create_share(self, context, request_spec, filter_properties):
        """Must override schedule method for scheduler to work."""
        raise NotImplementedError(_("Must implement schedule_create_share"))

    def schedule_create_share_group(self, context, share_group_id,
                                    request_spec,
                                    filter_properties):
        """Must override schedule method for scheduler to work."""
        raise NotImplementedError(_(
            "Must implement schedule_create_share_group"))

    def get_pools(self, context, filters):
        """Must override schedule method for scheduler to work."""
        raise NotImplementedError(_("Must implement get_pools"))

    def host_passes_filters(self, context, host, request_spec,
                            filter_properties):
        """Must override schedule method for migration to work."""
        raise NotImplementedError(_("Must implement host_passes_filters"))

    def schedule_create_replica(self, context, request_spec,
                                filter_properties):
        """Must override schedule method for create replica to work."""
        raise NotImplementedError(_("Must implement schedule_create_replica"))
