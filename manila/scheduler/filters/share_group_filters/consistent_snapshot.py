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


class ConsistentSnapshotFilter(base_host.BaseHostFilter):
    """Filters hosts based on possibility to create consistent SG snapshots."""

    def host_passes(self, host_state, filter_properties):
        """Return True if host will work with desired share group."""

        cs_group_spec = filter_properties['share_group_type'].get(
            'group_specs', {}).get('consistent_snapshot_support')

        # NOTE(vpoomaryov): if 'consistent_snapshot_support' group spec
        # is not set, then we assume that share group owner do not care about
        # it, which means any host should pass this filter.
        if cs_group_spec is None:
            return True
        return cs_group_spec == host_state.sg_consistent_snapshot_support
