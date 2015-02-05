# Copyright (c) 2014 eBay Inc.
# Copyright (c) 2015 Rushil Chugh
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

"""The Scheduler Stats extension"""

from manila.api import extensions
from manila.api.openstack import wsgi
from manila.api.views import scheduler_stats as scheduler_stats_view
from manila.scheduler import rpcapi


def authorize(context, action_name):
    action = 'scheduler_stats:%s' % action_name
    extensions.extension_authorizer('scheduler', action)(context)


class SchedulerStatsController(wsgi.Controller):
    """The Scheduler Stats controller for the OpenStack API."""

    _view_builder_class = scheduler_stats_view.ViewBuilder

    def __init__(self):
        self.scheduler_api = rpcapi.SchedulerAPI()
        super(SchedulerStatsController, self).__init__()

    def get_pools(self, req):
        """List all active pools in scheduler."""
        context = req.environ['manila.context']
        authorize(context, 'get_pools')

        detail = req.params.get('detail', False)
        pools = self.scheduler_api.get_pools(context, filters=None)

        return self._view_builder.pools(req, pools, detail)


class Scheduler_stats(extensions.ExtensionDescriptor):
    """Scheduler stats support."""

    name = "Scheduler_stats"
    alias = "scheduler-stats"
    updated = "2015-08-01T00:00:00+00:00"

    def get_resources(self):
        res = extensions.ResourceExtension(
            Scheduler_stats.alias,
            SchedulerStatsController(),
            collection_actions={"get_pools": "GET"})

        return [res]
