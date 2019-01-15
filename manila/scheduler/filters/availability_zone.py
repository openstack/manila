# Copyright (c) 2011-2012 OpenStack Foundation.
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

from manila.scheduler.filters import base_host


class AvailabilityZoneFilter(base_host.BaseHostFilter):
    """Filters Hosts by availability zone."""

    # Availability zones do not change within a request
    run_filter_once_per_request = True

    def host_passes(self, host_state, filter_properties):
        spec = filter_properties.get('request_spec', {})
        props = spec.get('resource_properties', {})
        request_az_id = props.get('availability_zone_id',
                                  spec.get('availability_zone_id'))
        request_azs = spec.get('availability_zones')
        host_az_id = host_state.service['availability_zone_id']
        host_az = host_state.service['availability_zone']['name']

        host_satisfied = True
        if request_az_id is not None:
            host_satisfied = request_az_id == host_az_id

        if request_azs:
            host_satisfied = host_satisfied and host_az in request_azs

        return host_satisfied
