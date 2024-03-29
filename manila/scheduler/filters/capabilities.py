# Copyright (c) 2011 OpenStack Foundation.
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

from oslo_log import log

from manila.scheduler.filters import base_host
from manila.scheduler import utils

LOG = log.getLogger(__name__)


class CapabilitiesFilter(base_host.BaseHostFilter):
    """HostFilter to work with resource (instance & volume) type records."""

    def _satisfies_extra_specs(self, capabilities, resource_type):
        """Compare capabilities against extra specs.

        Check that the capabilities provided by the services satisfy
        the extra specs associated with the resource type.
        """
        extra_specs = resource_type.get('extra_specs', [])
        if not extra_specs:
            return True

        return utils.capabilities_satisfied(capabilities, extra_specs)

    def host_passes(self, host_state, filter_properties):
        """Return a list of hosts that can create resource_type."""
        resource_type = filter_properties.get('resource_type')

        if not self._satisfies_extra_specs(host_state.capabilities,
                                           resource_type):
            LOG.debug("%(host_state)s fails resource_type extra_specs "
                      "requirements", {'host_state': host_state})
            return False
        return True
