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

"""The consistency groups snapshot API."""

from manila.api import common


class CGSnapshotViewBuilder(common.ViewBuilder):
    """Model a cgsnapshot API response as a python dictionary."""

    _collection_name = 'cgsnapshot'

    def summary_list(self, request, cgs):
        """Show a list of cgsnapshots without many details."""
        return self._list_view(self.summary, request, cgs)

    def detail_list(self, request, cgs):
        """Detailed view of a list of cgsnapshots."""
        return self._list_view(self.detail, request, cgs)

    def member_list(self, request, members):
        members_list = []
        for member in members:
            member_dict = {
                'id': member.get('id'),
                'created_at': member.get('created_at'),
                'size': member.get('size'),
                'share_protocol': member.get('share_proto'),
                'project_id': member.get('project_id'),
                'share_type_id': member.get('share_type_id'),
                'cgsnapshot_id': member.get('cgsnapshot_id'),
                'share_id': member.get('share_id'),
            }
            members_list.append(member_dict)

        members_links = self._get_collection_links(request,
                                                   members,
                                                   'cgsnapshot_id')
        members_dict = dict(cgsnapshot_members=members_list)

        if members_links:
            members_dict['cgsnapshot_members_links'] = members_links

        return members_dict

    def summary(self, request, cg):
        """Generic, non-detailed view of a cgsnapshot."""
        return {
            'cgsnapshot': {
                'id': cg.get('id'),
                'name': cg.get('name'),
                'links': self._get_links(request, cg['id'])
            }
        }

    def detail(self, request, cg):
        """Detailed view of a single cgsnapshot."""
        cg_dict = {
            'id': cg.get('id'),
            'name': cg.get('name'),
            'created_at': cg.get('created_at'),
            'status': cg.get('status'),
            'description': cg.get('description'),
            'project_id': cg.get('project_id'),
            'consistency_group_id': cg.get('consistency_group_id'),
            'links': self._get_links(request, cg['id']),
        }
        return {'cgsnapshot': cg_dict}

    def _list_view(self, func, request, snaps):
        """Provide a view for a list of cgsnapshots."""
        snap_list = [func(request, snap)['cgsnapshot']
                     for snap in snaps]
        snaps_links = self._get_collection_links(request,
                                                 snaps,
                                                 self._collection_name)
        snaps_dict = dict(cgsnapshots=snap_list)

        if snaps_links:
            snaps_dict['cgsnapshot_links'] = snaps_links

        return snaps_dict
