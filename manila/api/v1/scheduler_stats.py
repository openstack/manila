# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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

from manila.api.openstack import wsgi
from manila.api.views import scheduler_stats as scheduler_stats_views
from manila.scheduler import rpcapi


class SchedulerStatsController(wsgi.Controller):
    """The Scheduler Stats API controller for the OpenStack API."""

    resource_name = 'scheduler_stats:pools'

    def __init__(self):
        self.scheduler_api = rpcapi.SchedulerAPI()
        self._view_builder_class = scheduler_stats_views.ViewBuilder
        super(SchedulerStatsController, self).__init__()

    @wsgi.Controller.authorize('index')
    def pools_index(self, req):
        """Returns a list of storage pools known to the scheduler."""
        return self._pools(req, action='index')

    @wsgi.Controller.authorize('detail')
    def pools_detail(self, req):
        """Returns a detailed list of storage pools known to the scheduler."""
        return self._pools(req, action='detail')

    def _pools(self, req, action='index'):
        context = req.environ['manila.context']
        search_opts = {}
        search_opts.update(req.GET)
        pools = self.scheduler_api.get_pools(context, filters=search_opts)
        detail = (action == 'detail')
        return self._view_builder.pools(pools, detail=detail)


def create_resource():
    return wsgi.Resource(SchedulerStatsController())
