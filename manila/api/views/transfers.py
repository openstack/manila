# Copyright (C) 2022 China Telecom Digital Intelligence.
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
    """Model transfer API responses as a python dictionary."""

    _collection_name = "share-transfer"

    def __init__(self):
        """Initialize view builder."""
        super(ViewBuilder, self).__init__()

    def summary_list(self, request, transfers,):
        """Show a list of transfers without many details."""
        return self._list_view(self.summary, request, transfers)

    def detail_list(self, request, transfers):
        """Detailed view of a list of transfers ."""
        return self._list_view(self.detail, request, transfers)

    def summary(self, request, transfer):
        """Generic, non-detailed view of a transfer."""
        return {
            'transfer': {
                'id': transfer['id'],
                'name': transfer['display_name'],
                'resource_type': transfer['resource_type'],
                'resource_id': transfer['resource_id'],
                'links': self._get_links(request,
                                         transfer['id']),
            },
        }

    def detail(self, request, transfer):
        """Detailed view of a single transfer."""
        detail_body = {
            'transfer': {
                'id': transfer.get('id'),
                'created_at': transfer.get('created_at'),
                'name': transfer.get('display_name'),
                'resource_type': transfer['resource_type'],
                'resource_id': transfer['resource_id'],
                'source_project_id': transfer['source_project_id'],
                'destination_project_id': transfer.get(
                    'destination_project_id'),
                'accepted': transfer['accepted'],
                'expires_at': transfer.get('expires_at'),
                'links': self._get_links(request, transfer['id']),
            }
        }
        return detail_body

    def create(self, request, transfer):
        """Detailed view of a single transfer when created."""
        create_body = self.detail(request, transfer)
        create_body['transfer']['auth_key'] = transfer.get('auth_key')
        return create_body

    def _list_view(self, func, request, transfers):
        """Provide a view for a list of transfers."""
        transfers_list = [func(request, transfer)['transfer'] for transfer in
                          transfers]
        transfers_links = self._get_collection_links(request,
                                                     transfers,
                                                     self._collection_name)
        transfers_dict = dict(transfers=transfers_list)

        if transfers_links:
            transfers_dict['transfers_links'] = transfers_links

        return transfers_dict
