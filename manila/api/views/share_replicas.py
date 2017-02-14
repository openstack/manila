# Copyright 2015 Goutham Pacha Ravi
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

from manila.api import common


class ReplicationViewBuilder(common.ViewBuilder):
    """Model a server API response as a python dictionary."""

    _collection_name = 'share_replicas'
    _collection_links = 'share_replica_links'

    _detail_version_modifiers = [
        "add_cast_rules_to_readonly_field",
    ]

    def summary_list(self, request, replicas):
        """Summary view of a list of replicas."""
        return self._list_view(self.summary, request, replicas)

    def detail_list(self, request, replicas):
        """Detailed view of a list of replicas."""
        return self._list_view(self.detail, request, replicas)

    def summary(self, request, replica):
        """Generic, non-detailed view of a share replica."""

        replica_dict = {
            'id': replica.get('id'),
            'share_id': replica.get('share_id'),
            'status': replica.get('status'),
            'replica_state': replica.get('replica_state'),
        }
        return {'share_replica': replica_dict}

    def detail(self, request, replica):
        """Detailed view of a single replica."""
        context = request.environ['manila.context']

        replica_dict = {
            'id': replica.get('id'),
            'share_id': replica.get('share_id'),
            'availability_zone': replica.get('availability_zone'),
            'created_at': replica.get('created_at'),
            'status': replica.get('status'),
            'share_network_id': replica.get('share_network_id'),
            'replica_state': replica.get('replica_state'),
            'updated_at': replica.get('updated_at'),
        }

        if context.is_admin:
            replica_dict['share_server_id'] = replica.get('share_server_id')
            replica_dict['host'] = replica.get('host')

        self.update_versioned_resource_dict(request, replica_dict, replica)
        return {'share_replica': replica_dict}

    def _list_view(self, func, request, replicas):
        """Provide a view for a list of replicas."""

        replicas_list = [func(request, replica)['share_replica']
                         for replica in replicas]

        replica_links = self._get_collection_links(request,
                                                   replicas,
                                                   self._collection_name)
        replicas_dict = {self._collection_name: replicas_list}

        if replica_links:
            replicas_dict[self._collection_links] = replica_links

        return replicas_dict

    @common.ViewBuilder.versioned_method("2.30")
    def add_cast_rules_to_readonly_field(self, context, replica_dict, replica):
        if context.is_admin:
            replica_dict['cast_rules_to_readonly'] = replica.get(
                'cast_rules_to_readonly', False)
