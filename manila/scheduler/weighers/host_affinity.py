# Copyright 2019 NetApp, Inc.
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

from manila import context
from manila.db import api as db_api
from manila.scheduler.weighers import base_host
from manila.share import utils as share_utils


class HostAffinityWeigher(base_host.BaseHostWeigher):

    def _weigh_object(self, obj, weight_properties):
        """Weigh hosts based on their proximity to the source's share pool.

        If no snapshot_id was provided will return 0, otherwise, if source and
        destination hosts are located on:
        1. same back ends and pools: host is a perfect choice (100)
        2. same back ends and different pools: host is a very good choice (75)
        3. different back ends with the same AZ: host is a good choice (50)
        4. different back ends and AZs: host isn't so good choice (25)
        """

        ctx = context.get_admin_context()
        request_spec = weight_properties.get('request_spec')
        snapshot_id = request_spec.get('snapshot_id')
        snapshot_host = request_spec.get('snapshot_host')

        if None in [snapshot_id, snapshot_host]:
            # NOTE(silvacarlose): if the request does not contain a snapshot_id
            # or a snapshot_host, the user is not creating a share from a
            # snapshot and we don't need to weigh the host.
            return 0

        snapshot_ref = db_api.share_snapshot_get(ctx, snapshot_id)
        # Source host info: pool, backend and availability zone
        src_pool = share_utils.extract_host(snapshot_host, 'pool')
        src_backend = share_utils.extract_host(
            request_spec.get('snapshot_host'), 'backend')
        src_az = snapshot_ref['share']['availability_zone']
        # Destination host info: pool, backend and availability zone
        dst_pool = share_utils.extract_host(obj.host, 'pool')
        dst_backend = share_utils.extract_host(obj.host, 'backend')
        # NOTE(dviroel): All hosts were already filtered by the availability
        # zone parameter.
        dst_az = None
        if weight_properties['availability_zone_id']:
            dst_az = db_api.availability_zone_get(
                ctx, weight_properties['availability_zone_id']).name

        if src_backend == dst_backend:
            return 100 if (src_pool and src_pool == dst_pool) else 75
        else:
            return 50 if (src_az and src_az == dst_az) else 25
