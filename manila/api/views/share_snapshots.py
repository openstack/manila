# Copyright 2013 NetApp
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

    _collection_name = 'snapshots'
    _detail_version_modifiers = [
        "add_provider_location_field",
        "add_project_and_user_ids",
    ]

    def summary_list(self, request, snapshots):
        """Show a list of share snapshots without many details."""
        return self._list_view(self.summary, request, snapshots)

    def detail_list(self, request, snapshots):
        """Detailed view of a list of share snapshots."""
        return self._list_view(self.detail, request, snapshots)

    def summary(self, request, snapshot):
        """Generic, non-detailed view of an share snapshot."""
        return {
            'snapshot': {
                'id': snapshot.get('id'),
                'name': snapshot.get('display_name'),
                'links': self._get_links(request, snapshot['id'])
            }
        }

    def detail(self, request, snapshot):
        """Detailed view of a single share snapshot."""
        snapshot_dict = {
            'id': snapshot.get('id'),
            'share_id': snapshot.get('share_id'),
            'share_size': snapshot.get('share_size'),
            'created_at': snapshot.get('created_at'),
            'status': snapshot.get('aggregate_status'),
            'name': snapshot.get('display_name'),
            'description': snapshot.get('display_description'),
            'size': snapshot.get('size'),
            'share_proto': snapshot.get('share_proto'),
            'links': self._get_links(request, snapshot['id']),
        }

        self.update_versioned_resource_dict(request, snapshot_dict, snapshot)

        return {'snapshot': snapshot_dict}

    @common.ViewBuilder.versioned_method("2.12")
    def add_provider_location_field(self, context, snapshot_dict, snapshot):
        # NOTE(xyang): Only retrieve provider_location for admin.
        if context.is_admin:
            snapshot_dict['provider_location'] = snapshot.get(
                'provider_location')

    @common.ViewBuilder.versioned_method("2.17")
    def add_project_and_user_ids(self, context, snapshot_dict, snapshot):
        snapshot_dict['user_id'] = snapshot.get('user_id')
        snapshot_dict['project_id'] = snapshot.get('project_id')

    def _list_view(self, func, request, snapshots):
        """Provide a view for a list of share snapshots."""
        snapshots_list = [func(request, snapshot)['snapshot']
                          for snapshot in snapshots]
        snapshots_links = self._get_collection_links(request,
                                                     snapshots,
                                                     self._collection_name)
        snapshots_dict = {self._collection_name: snapshots_list}

        if snapshots_links:
            snapshots_dict['share_snapshots_links'] = snapshots_links

        return snapshots_dict

    def detail_access(self, request, access):
        access = {
            'snapshot_access': {
                'id': access['id'],
                'access_type': access['access_type'],
                'access_to': access['access_to'],
                'state': access['state'],
            }
        }
        return access

    def detail_list_access(self, request, access_list):
        return {
            'snapshot_access_list':
                ([self.detail_access(request, access)['snapshot_access']
                 for access in access_list])
        }
