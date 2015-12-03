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
Simple Scheduler
"""

from oslo_config import cfg

from manila import db
from manila import exception
from manila.i18n import _
from manila.scheduler.drivers import base
from manila.scheduler.drivers import chance
from manila import utils

simple_scheduler_opts = [
    cfg.IntOpt("max_gigabytes",
               default=10000,
               help="Maximum number of volume gigabytes to allow per host."), ]

CONF = cfg.CONF
CONF.register_opts(simple_scheduler_opts)


class SimpleScheduler(chance.ChanceScheduler):
    """Implements Naive Scheduler that tries to find least loaded host."""

    def schedule_create_share(self, context, request_spec, filter_properties):
        """Picks a host that is up and has the fewest shares."""
        # TODO(rushiagr) - pick only hosts that run shares
        elevated = context.elevated()

        share_id = request_spec.get('share_id')
        snapshot_id = request_spec.get('snapshot_id')
        share_properties = request_spec.get('share_properties')
        share_size = share_properties.get('size')

        instance_properties = request_spec.get('share_instance_properties', {})
        availability_zone_id = instance_properties.get('availability_zone_id')

        results = db.service_get_all_share_sorted(elevated)
        if availability_zone_id:
            results = [(service_g, gigs) for (service_g, gigs) in results
                       if (service_g['availability_zone_id']
                           == availability_zone_id)]
        for result in results:
            (service, share_gigabytes) = result
            if share_gigabytes + share_size > CONF.max_gigabytes:
                msg = _("Not enough allocatable share gigabytes remaining")
                raise exception.NoValidHost(reason=msg)
            if utils.service_is_up(service) and not service['disabled']:
                updated_share = base.share_update_db(context,
                                                     share_id,
                                                     service['host'])
                self.share_rpcapi.create_share_instance(
                    context,
                    updated_share.instance,
                    service['host'],
                    request_spec,
                    None,
                    snapshot_id=snapshot_id)
                return None
        msg = _("Is the appropriate service running?")
        raise exception.NoValidHost(reason=msg)
