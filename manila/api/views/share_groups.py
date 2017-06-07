# Copyright 2015 Alex Meade
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


class ShareGroupViewBuilder(common.ViewBuilder):
    """Model a share group API response as a python dictionary."""

    _collection_name = 'share_groups'
    _detail_version_modifiers = [
        "add_consistent_snapshot_support_and_az_id_fields_to_sg",
    ]

    def summary_list(self, request, share_groups):
        """Show a list of share groups without many details."""
        return self._list_view(self.summary, request, share_groups)

    def detail_list(self, request, share_groups):
        """Detailed view of a list of share groups."""
        return self._list_view(self.detail, request, share_groups)

    def summary(self, request, share_group):
        """Generic, non-detailed view of a share group."""
        return {
            'share_group': {
                'id': share_group.get('id'),
                'name': share_group.get('name'),
                'links': self._get_links(request, share_group['id'])
            }
        }

    def detail(self, request, share_group):
        """Detailed view of a single share group."""
        context = request.environ['manila.context']
        share_group_dict = {
            'id': share_group.get('id'),
            'name': share_group.get('name'),
            'created_at': share_group.get('created_at'),
            'status': share_group.get('status'),
            'description': share_group.get('description'),
            'project_id': share_group.get('project_id'),
            'host': share_group.get('host'),
            'share_group_type_id': share_group.get('share_group_type_id'),
            'source_share_group_snapshot_id': share_group.get(
                'source_share_group_snapshot_id'),
            'share_network_id': share_group.get('share_network_id'),
            'share_types': [st['share_type_id'] for st in share_group.get(
                'share_types')],
            'links': self._get_links(request, share_group['id']),
        }
        self.update_versioned_resource_dict(
            request, share_group_dict, share_group)
        if context.is_admin:
            share_group_dict['share_server_id'] = share_group.get(
                'share_server_id')
        return {'share_group': share_group_dict}

    @common.ViewBuilder.versioned_method("2.34")
    def add_consistent_snapshot_support_and_az_id_fields_to_sg(
            self, context, sg_dict, sg):
        sg_dict['availability_zone'] = sg.get('availability_zone')
        sg_dict['consistent_snapshot_support'] = sg.get(
            'consistent_snapshot_support')

    def _list_view(self, func, request, shares):
        """Provide a view for a list of share groups."""
        share_group_list = [
            func(request, share)['share_group']
            for share in shares
        ]
        share_groups_links = self._get_collection_links(
            request, shares, self._collection_name)
        share_groups_dict = {"share_groups": share_group_list}

        if share_groups_links:
            share_groups_dict['share_groups_links'] = share_groups_links

        return share_groups_dict
