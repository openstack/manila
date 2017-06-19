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


class ShareGroupSnapshotViewBuilder(common.ViewBuilder):
    """Model a share group snapshot API response as a python dictionary."""

    _collection_name = "share_group_snapshot"

    def summary_list(self, request, group_snaps):
        """Show a list of share_group_snapshots without many details."""
        return self._list_view(self.summary, request, group_snaps)

    def detail_list(self, request, group_snaps):
        """Detailed view of a list of share_group_snapshots."""
        return self._list_view(self.detail, request, group_snaps)

    def member_list(self, request, members):
        members_list = []
        for member in members:
            member_dict = {
                'id': member.get('id'),
                'created_at': member.get('created_at'),
                'size': member.get('size'),
                'share_protocol': member.get('share_proto'),
                'project_id': member.get('project_id'),
                'share_group_snapshot_id': member.get(
                    'share_group_snapshot_id'),
                'share_id': member.get('share_instance', {}).get('share_id'),
                # TODO(vponomaryov): add 'provider_location' key in Pike.
            }
            members_list.append(member_dict)

        members_links = self._get_collection_links(
            request, members, "share_group_snapshot_id")
        members_dict = {"share_group_snapshot_members": members_list}

        if members_links:
            members_dict["share_group_snapshot_members_links"] = members_links

        return members_dict

    def summary(self, request, share_group_snap):
        """Generic, non-detailed view of a share group snapshot."""
        return {
            'share_group_snapshot': {
                'id': share_group_snap.get('id'),
                'name': share_group_snap.get('name'),
                'links': self._get_links(request, share_group_snap['id']),
            }
        }

    def detail(self, request, share_group_snap):
        """Detailed view of a single share group snapshot."""

        members = self._format_member_list(
            share_group_snap.get('share_group_snapshot_members', []))

        share_group_snap_dict = {
            'id': share_group_snap.get('id'),
            'name': share_group_snap.get('name'),
            'created_at': share_group_snap.get('created_at'),
            'status': share_group_snap.get('status'),
            'description': share_group_snap.get('description'),
            'project_id': share_group_snap.get('project_id'),
            'share_group_id': share_group_snap.get('share_group_id'),
            'members': members,
            'links': self._get_links(request, share_group_snap['id']),
        }
        return {'share_group_snapshot': share_group_snap_dict}

    def _format_member_list(self, members):
        members_list = []
        for member in members:
            member_dict = {
                'id': member.get('id'),
                'size': member.get('size'),
                'share_id': member.get('share_instance', {}).get('share_id'),
            }
            members_list.append(member_dict)

        return members_list

    def _list_view(self, func, request, snaps):
        """Provide a view for a list of share group snapshots."""
        snap_list = [func(request, snap)["share_group_snapshot"]
                     for snap in snaps]
        snaps_links = self._get_collection_links(request,
                                                 snaps,
                                                 self._collection_name)
        snaps_dict = {"share_group_snapshots": snap_list}

        if snaps_links:
            snaps_dict["share_group_snapshot_links"] = snaps_links

        return snaps_dict
