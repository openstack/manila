# Copyright (c) 2012 OpenStack, LLC.
# Copyright (c) 2015 EMC Corporation
#
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
Capacity Weigher.  Weigh hosts by their virtual or actual free capacity.

For thin provisioning, weigh hosts by their virtual free capacity calculated
by the total capacity multiplied by the max over subscription ratio and
subtracting the provisioned capacity; Otherwise, weigh hosts by their actual
free capacity, taking into account the reserved space.

The default is to spread shares across all hosts evenly.  If you prefer
stacking, you can set the 'capacity_weight_multiplier' option to a negative
number and the weighing has the opposite effect of the default.
"""

import math

from oslo_config import cfg


from manila.openstack.common.scheduler import weights

capacity_weight_opts = [
    cfg.FloatOpt('capacity_weight_multiplier',
                 default=1.0,
                 help='Multiplier used for weighing share capacity. '
                 'Negative numbers mean to stack vs spread.'),
]

CONF = cfg.CONF
CONF.register_opts(capacity_weight_opts)


class CapacityWeigher(weights.BaseHostWeigher):
    def weight_multiplier(self):
        """Override the weight multiplier."""
        return CONF.capacity_weight_multiplier

    def _weigh_object(self, host_state, weight_properties):
        """Higher weights win.  We want spreading to be the default."""
        reserved = float(host_state.reserved_percentage) / 100
        free_space = host_state.free_capacity_gb
        total_space = host_state.total_capacity_gb
        if {'unknown', 'infinite'}.intersection({total_space, free_space}):
            # (zhiteng) 'infinite' and 'unknown' are treated the same
            # here, for sorting purpose.
            free = float('inf')
        else:
            total = float(total_space)
            if host_state.thin_provisioning:
                # NOTE(xyang): Calculate virtual free capacity for thin
                # provisioning.
                free = math.floor(
                    total * host_state.max_over_subscription_ratio -
                    host_state.provisioned_capacity_gb -
                    total * reserved)
            else:
                # NOTE(xyang): Calculate how much free space is left after
                # taking into account the reserved space.
                free = math.floor(free_space - total * reserved)
        return free
