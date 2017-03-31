# Copyright (c) 2012 Intel
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


import math

from oslo_log import log

from manila.scheduler.filters import base_host
from manila.scheduler import utils

LOG = log.getLogger(__name__)


class CapacityFilter(base_host.BaseHostFilter):
    """CapacityFilter filters based on share host's capacity utilization."""

    def host_passes(self, host_state, filter_properties):
        """Return True if host has sufficient capacity."""
        share_size = filter_properties.get('size', 0)

        if host_state.free_capacity_gb is None:
            # Fail Safe
            LOG.error("Free capacity not set: "
                      "share node info collection broken.")
            return False

        free_space = host_state.free_capacity_gb
        total_space = host_state.total_capacity_gb
        reserved = float(host_state.reserved_percentage) / 100
        if free_space == 'unknown':
            # NOTE(zhiteng) for those back-ends cannot report actual
            # available capacity, we assume it is able to serve the
            # request.  Even if it was not, the retry mechanism is
            # able to handle the failure by rescheduling
            return True
        elif total_space == 'unknown':
            # NOTE(xyang): If total_space is 'unknown' and
            # reserved is 0, we assume the back-ends can serve the request.
            # If total_space is 'unknown' and reserved
            # is not 0, we cannot calculate the reserved space.
            # float(total_space) will throw an exception. total*reserved
            # also won't work. So the back-ends cannot serve the request.
            return reserved == 0 and share_size <= free_space
        total = float(total_space)
        if total <= 0:
            LOG.warning("Insufficient free space for share creation. "
                        "Total capacity is %(total).2f on host %(host)s.",
                        {"total": total,
                         "host": host_state.host})
            return False
        # NOTE(xyang): Calculate how much free space is left after taking
        # into account the reserved space.
        free = math.floor(free_space - total * reserved)

        msg_args = {"host": host_state.host,
                    "requested": share_size,
                    "available": free}

        LOG.debug("Space information for share creation "
                  "on host %(host)s (requested / avail): "
                  "%(requested)s/%(available)s", msg_args)

        share_type = filter_properties.get('share_type', {})
        use_thin_logic = utils.use_thin_logic(share_type)
        thin_provisioning = utils.thin_provisioning(
            host_state.thin_provisioning)

        # NOTE(xyang): Only evaluate using max_over_subscription_ratio
        # if use_thin_logic and thin_provisioning are True. Check if the
        # ratio of provisioned capacity over total capacity would exceed
        # subscription ratio.
        # If max_over_subscription_ratio = 1, the provisioned_ratio
        # should still be limited by the max_over_subscription_ratio;
        # otherwise, it could result in infinite provisioning.
        if (use_thin_logic and thin_provisioning and
                host_state.max_over_subscription_ratio >= 1):
            provisioned_ratio = ((host_state.provisioned_capacity_gb +
                                  share_size) / total)
            if provisioned_ratio > host_state.max_over_subscription_ratio:
                LOG.warning(
                    "Insufficient free space for thin provisioning. "
                    "The ratio of provisioned capacity over total capacity "
                    "%(provisioned_ratio).2f would exceed the maximum over "
                    "subscription ratio %(oversub_ratio).2f on host "
                    "%(host)s.",
                    {"provisioned_ratio": provisioned_ratio,
                     "oversub_ratio": host_state.max_over_subscription_ratio,
                     "host": host_state.host})
                return False
            else:
                # NOTE(xyang): Adjust free_virtual calculation based on
                # free and max_over_subscription_ratio.
                adjusted_free_virtual = (
                    free * host_state.max_over_subscription_ratio)
                return adjusted_free_virtual >= share_size
        elif (use_thin_logic and thin_provisioning and
              host_state.max_over_subscription_ratio < 1):
            LOG.error("Invalid max_over_subscription_ratio: %(ratio)s. "
                      "Valid value should be >= 1.",
                      {"ratio": host_state.max_over_subscription_ratio})
            return False

        if free < share_size:
            LOG.warning("Insufficient free space for share creation "
                        "on host %(host)s (requested / avail): "
                        "%(requested)s/%(available)s", msg_args)
            return False

        return True
