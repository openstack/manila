# Copyright (c) 2015 Alex Meade
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
from manila.share import utils as share_utils

LOG = log.getLogger(__name__)


class ConsistencyGroupFilter(base_host.BaseHostFilter):
    """ConsistencyGroupFilter filters host based on compatibility with CG."""

    def host_passes(self, host_state, filter_properties):
        """Return True if host will work with desired consistency group."""
        cg = filter_properties.get('consistency_group')
        cg_support = filter_properties.get('cg_support')

        # NOTE(ameade): If creating a share not in a CG, then of course the
        # host is valid for the cg.
        if not cg:
            return True

        # NOTE(ameade): If the CG host can only support shares on the same
        # pool, then the only valid pool is that one.
        if cg_support == 'pool' and cg.get('host') == host_state.host:
            return True

        # NOTE(ameade): If the CG host can support shares on the same host,
        # then any pool on that backend will work.
        elif cg_support == 'host':
            cg_backend = share_utils.extract_host(cg['host'])
            host_backend = share_utils.extract_host(host_state.host)
            return cg_backend == host_backend

        LOG.debug("Host %(host)s is not compatible with consistency "
                  "group %(cg)s"
                  % {"host": host_state.host, "cg": cg['id']})

        return False
