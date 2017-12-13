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
from manila.common import constants


class ViewBuilder(common.ViewBuilder):
    """Model a server API response as a python dictionary."""

    _collection_name = 'shares'
    _detail_version_modifiers = [
        "add_snapshot_support_field",
        "add_task_state_field",
        "modify_share_type_field",
        "remove_export_locations",
        "add_access_rules_status_field",
        "add_replication_fields",
        "add_user_id",
        "add_create_share_from_snapshot_support_field",
        "add_revert_to_snapshot_support_field",
        "translate_access_rules_status",
        "add_share_group_fields",
        "add_mount_snapshot_support_field",
    ]

    def summary_list(self, request, shares, count=None):
        """Show a list of shares without many details."""
        return self._list_view(self.summary, request, shares, count)

    def detail_list(self, request, shares, count=None):
        """Detailed view of a list of shares."""
        return self._list_view(self.detail, request, shares, count)

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

        share_instance = share.get('instance') or {}

        if share_instance.get('share_type'):
            share_type = share_instance.get('share_type').get('name')
        else:
            share_type = share_instance.get('share_type_id')

        share_dict = {
            'id': share.get('id'),
            'size': share.get('size'),
            'availability_zone': share_instance.get('availability_zone'),
            'created_at': share.get('created_at'),
            'status': share.get('status'),
            'name': share.get('display_name'),
            'description': share.get('display_description'),
            'project_id': share.get('project_id'),
            'snapshot_id': share.get('snapshot_id'),
            'share_network_id': share_instance.get('share_network_id'),
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
            share_dict['share_server_id'] = share_instance.get(
                'share_server_id')
            share_dict['host'] = share_instance.get('host')
        return {'share': share_dict}

    @common.ViewBuilder.versioned_method("2.2")
    def add_snapshot_support_field(self, context, share_dict, share):
        share_dict['snapshot_support'] = share.get('snapshot_support')

    @common.ViewBuilder.versioned_method("2.5")
    def add_task_state_field(self, context, share_dict, share):
        share_dict['task_state'] = share.get('task_state')

    @common.ViewBuilder.versioned_method("2.6")
    def modify_share_type_field(self, context, share_dict, share):
        share_instance = share.get('instance') or {}

        share_type = share_instance.get('share_type_id')

        share_type_name = None
        if share_instance.get('share_type'):
            share_type_name = share_instance.get('share_type').get('name')

        share_dict.update({
            'share_type_name': share_type_name,
            'share_type': share_type,
        })

    @common.ViewBuilder.versioned_method("2.9")
    def remove_export_locations(self, context, share_dict, share):
        share_dict.pop('export_location')
        share_dict.pop('export_locations')

    @common.ViewBuilder.versioned_method("2.10")
    def add_access_rules_status_field(self, context, share_dict, share):
        share_dict['access_rules_status'] = share.get('access_rules_status')

    @common.ViewBuilder.versioned_method('2.11')
    def add_replication_fields(self, context, share_dict, share):
        share_dict['replication_type'] = share.get('replication_type')
        share_dict['has_replicas'] = share['has_replicas']

    @common.ViewBuilder.versioned_method("2.16")
    def add_user_id(self, context, share_dict, share):
        share_dict['user_id'] = share.get('user_id')

    @common.ViewBuilder.versioned_method("2.24")
    def add_create_share_from_snapshot_support_field(self, context,
                                                     share_dict, share):
        share_dict['create_share_from_snapshot_support'] = share.get(
            'create_share_from_snapshot_support')

    @common.ViewBuilder.versioned_method("2.27")
    def add_revert_to_snapshot_support_field(self, context, share_dict, share):
        share_dict['revert_to_snapshot_support'] = share.get(
            'revert_to_snapshot_support')

    @common.ViewBuilder.versioned_method("2.10", "2.27")
    def translate_access_rules_status(self, context, share_dict, share):
        if (share['access_rules_status'] ==
                constants.SHARE_INSTANCE_RULES_SYNCING):
            share_dict['access_rules_status'] = constants.STATUS_OUT_OF_SYNC

    @common.ViewBuilder.versioned_method("2.31")
    def add_share_group_fields(self, context, share_dict, share):
        share_dict['share_group_id'] = share.get(
            'share_group_id')
        share_dict['source_share_group_snapshot_member_id'] = share.get(
            'source_share_group_snapshot_member_id')

    @common.ViewBuilder.versioned_method("2.32")
    def add_mount_snapshot_support_field(self, context, share_dict, share):
        share_dict['mount_snapshot_support'] = share.get(
            'mount_snapshot_support')

    def _list_view(self, func, request, shares, count=None):
        """Provide a view for a list of shares."""
        shares_list = [func(request, share)['share'] for share in shares]
        shares_links = self._get_collection_links(request,
                                                  shares,
                                                  self._collection_name)
        shares_dict = dict(shares=shares_list)

        if count:
            shares_dict['count'] = count
        if shares_links:
            shares_dict['shares_links'] = shares_links

        return shares_dict
