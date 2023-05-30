# Copyright 2021 Cloudification GmbH.
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

from manila import policy
from manila.scheduler.filters import base_host


class OnlyHostFilter(base_host.BaseHostFilter):
    """Filters Hosts by 'only_host' scheduler_hint."""

    def host_passes(self, host_state, filter_properties):
        context = filter_properties['context']
        if not policy.check_is_host_admin(context):
            return True
        hints = filter_properties.get('scheduler_hints')
        if hints is None:
            return True
        requested_host = hints.get('only_host', None)
        if requested_host is None:
            return True
        # e.g. "only_host=hostname@generic2#GENERIC2"
        return host_state.host == requested_host
