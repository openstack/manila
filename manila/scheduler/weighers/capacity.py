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

from manila.scheduler import utils
from manila.scheduler.weighers import base_host

capacity_weight_opts = [
    cfg.FloatOpt('capacity_weight_multiplier',
                 default=1.0,
                 help='Multiplier used for weighing share capacity. '
                 'Negative numbers mean to stack vs spread.'),
]

CONF = cfg.CONF
CONF.register_opts(capacity_weight_opts)


class CapacityWeigher(base_host.BaseHostWeigher):
    def weight_multiplier(self):
        """Override the weight multiplier."""
        return CONF.capacity_weight_multiplier

    def _weigh_object(self, host_state, weight_properties):
        """Higher weighers win.  We want spreading to be the default."""
        reserved = float(host_state.reserved_percentage) / 100
        free_space = host_state.free_capacity_gb
        total_space = host_state.total_capacity_gb
        if 'unknown' in (total_space, free_space):
            # NOTE(u_glide): "unknown" capacity always sorts to the bottom
            if CONF.capacity_weight_multiplier > 0:
                free = float('-inf')
            else:
                free = float('inf')
        else:
            total = float(total_space)

            share_type = weight_properties.get('share_type', {})
            use_thin_logic = utils.use_thin_logic(share_type)
            thin_provisioning = utils.thin_provisioning(
                host_state.thin_provisioning)

            if use_thin_logic and thin_provisioning:
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

    def weigh_objects(self, weighed_obj_list, weight_properties):
        weights = super(CapacityWeigher, self).weigh_objects(weighed_obj_list,
                                                             weight_properties)
        # NOTE(u_glide): Replace -inf with (minimum - 1) and
        # inf with (maximum + 1) to avoid errors in
        # manila.scheduler.weighers.base.normalize() method
        if self.minval == float('-inf'):
            self.minval = self.maxval
            for val in weights:
                if float('-inf') < val < self.minval:
                    self.minval = val
            self.minval -= 1
            return [self.minval if w == float('-inf') else w for w in weights]
        elif self.maxval == float('inf'):
            self.maxval = self.minval
            for val in weights:
                if self.maxval < val < float('inf'):
                    self.maxval = val
            self.maxval += 1
            return [self.maxval if w == float('inf') else w for w in weights]
        else:
            return weights
