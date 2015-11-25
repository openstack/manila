# Copyright 2015 Mirantis Inc.
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

from oslo_config import cfg

from manila import context
from manila.db import api as db_api
from manila.scheduler.weighers import base_host
from manila.share import utils

pool_weight_opts = [
    cfg.FloatOpt('pool_weight_multiplier',
                 default=1.0,
                 help='Multiplier used for weighing pools which have '
                      'existing share servers. Negative numbers mean to spread'
                      ' vs stack.'),
]

CONF = cfg.CONF
CONF.register_opts(pool_weight_opts)


class PoolWeigher(base_host.BaseHostWeigher):
    def weight_multiplier(self):
        """Override the weight multiplier."""
        return CONF.pool_weight_multiplier

    def _weigh_object(self, host_state, weight_properties):
        """Pools with existing share server win."""
        pool_mapping = weight_properties.get('server_pools_mapping', {})
        if not pool_mapping:
            return 0

        ctx = context.get_admin_context()
        host = utils.extract_host(host_state.host, 'backend')
        servers = db_api.share_server_get_all_by_host(ctx, host)
        pool = utils.extract_host(host_state.host, 'pool')
        for server in servers:
            if any(pool == p['pool_name'] for p in pool_mapping.get(
                   server['id'], [])):
                return 1
        return 0
