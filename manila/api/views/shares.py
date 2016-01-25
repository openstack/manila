# Copyright 2013 OpenStack LLC.
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


class ViewBuilder(common.ViewBuilder):
    """Model a server API response as a python dictionary."""

    _collection_name = 'shares'
    _detail_version_modifiers = [
        "add_snapshot_support_field",
        "add_consistency_group_fields",
        "add_task_state_field",
        "modify_share_type_field",
        "remove_export_locations",
    ]

    def summary_list(self, request, shares):
        """Show a list of shares without many details."""
        return self._list_view(self.summary, request, shares)

    def detail_list(self, request, shares):
        """Detailed view of a list of shares."""
        return self._list_view(self.detail, request, shares)

    def summary(self, request, share):
        """Generic, non-detailed view of a share."""
        return {
            'share': {
                'id': share.get('id'),
                'name': share.get('display_name'),
                'links': self._get_links(request, share['id'])
            }
        }

    def detail(self, request, share):
        """Detailed view of a single share."""
        context = request.environ['manila.context']
        metadata = share.get('share_metadata')
        if metadata:
            metadata = {item['key']: item['value'] for item in metadata}
        else:
            metadata = {}

        export_locations = share.get('export_locations', [])

        if share['share_type_id'] and share.get('share_type'):
            share_type = share['share_type']['name']
        else:
            share_type = share['share_type_id']

        share_dict = {
            'id': share.get('id'),
            'size': share.get('size'),
            'availability_zone': share.get('availability_zone'),
            'created_at': share.get('created_at'),
            'status': share.get('status'),
            'name': share.get('display_name'),
            'description': share.get('display_description'),
            'project_id': share.get('project_id'),
            'host': share.get('host'),
            'snapshot_id': share.get('snapshot_id'),
            'share_network_id': share.get('share_network_id'),
            'share_proto': share.get('share_proto'),
            'export_location': share.get('export_location'),
            'metadata': metadata,
            'share_type': share_type,
            'volume_type': share_type,
            'links': self._get_links(request, share['id']),
            'is_public': share.get('is_public'),
            'export_locations': export_locations,
        }

        self.update_versioned_resource_dict(request, share_dict, share)

        if context.is_admin:
            share_dict['share_server_id'] = share.get('share_server_id')
        return {'share': share_dict}

    @common.ViewBuilder.versioned_method("2.2")
    def add_snapshot_support_field(self, share_dict, share):
        share_dict['snapshot_support'] = share.get('snapshot_support')

    @common.ViewBuilder.versioned_method("2.4")
    def add_consistency_group_fields(self, share_dict, share):
        share_dict['consistency_group_id'] = share.get(
            'consistency_group_id')
        share_dict['source_cgsnapshot_member_id'] = share.get(
            'source_cgsnapshot_member_id')

    @common.ViewBuilder.versioned_method("2.5")
    def add_task_state_field(self, share_dict, share):
        share_dict['task_state'] = share.get('task_state')

    @common.ViewBuilder.versioned_method("2.6")
    def modify_share_type_field(self, share_dict, share):
        share_type = share.get('share_type_id')

        share_type_name = None
        if share.get('share_type'):
            share_type_name = share.get('share_type').get('name')

        share_dict.update({
            'share_type_name': share_type_name,
            'share_type': share_type,
        })

    @common.ViewBuilder.versioned_method("2.9")
    def remove_export_locations(self, share_dict, share):
        share_dict.pop('export_location')
        share_dict.pop('export_locations')

    def _list_view(self, func, request, shares):
        """Provide a view for a list of shares."""
        shares_list = [func(request, share)['share'] for share in shares]
        shares_links = self._get_collection_links(request,
                                                  shares,
                                                  self._collection_name)
        shares_dict = dict(shares=shares_list)

        if shares_links:
            shares_dict['shares_links'] = shares_links

        return shares_dict
