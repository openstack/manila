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

"""The consistency groups API."""

from manila.api import common


class CGViewBuilder(common.ViewBuilder):
    """Model a consistency group API response as a python dictionary."""

    _collection_name = 'consistency_groups'

    def summary_list(self, request, cgs):
        """Show a list of consistency groups without many details."""
        return self._list_view(self.summary, request, cgs)

    def detail_list(self, request, cgs):
        """Detailed view of a list of consistency groups."""
        return self._list_view(self.detail, request, cgs)

    def summary(self, request, cg):
        """Generic, non-detailed view of a consistency group."""
        return {
            'consistency_group': {
                'id': cg.get('id'),
                'name': cg.get('name'),
                'links': self._get_links(request, cg['id'])
            }
        }

    def detail(self, request, cg):
        """Detailed view of a single consistency group."""
        context = request.environ['manila.context']
        cg_dict = {
            'id': cg.get('id'),
            'name': cg.get('name'),
            'created_at': cg.get('created_at'),
            'status': cg.get('status'),
            'description': cg.get('description'),
            'project_id': cg.get('project_id'),
            'host': cg.get('host'),
            'source_cgsnapshot_id': cg.get('source_cgsnapshot_id'),
            'share_network_id': cg.get('share_network_id'),
            'share_types': [st['share_type_id'] for st in cg.get(
                'share_types')],
            'links': self._get_links(request, cg['id']),
        }
        if context.is_admin:
            cg_dict['share_server_id'] = cg_dict.get('share_server_id')
        return {'consistency_group': cg_dict}

    def _list_view(self, func, request, shares):
        """Provide a view for a list of consistency groups."""
        cg_list = [func(request, share)['consistency_group']
                   for share in shares]
        cgs_links = self._get_collection_links(request,
                                               shares,
                                               self._collection_name)
        cgs_dict = dict(consistency_groups=cg_list)

        if cgs_links:
            cgs_dict['consistency_groups_links'] = cgs_links

        return cgs_dict
