# Copyright 2014 OpenStack Foundation
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

    _collection_name = 'share_servers'

    def build_share_server(self, share_server):
        """View of a share server."""
        return {
            'share_server':
                self._build_share_server_view(share_server, detailed=True)
        }

    def build_share_servers(self, share_servers):
        return {
            'share_servers':
                [self._build_share_server_view(share_server)
                 for share_server in share_servers]
        }

    def build_share_server_details(self, details):
        return {'details': details}

    def _build_share_server_view(self, share_server, detailed=False):
        share_server_dict = {
            'id': share_server.id,
            'project_id': share_server.project_id,
            'updated_at': share_server.updated_at,
            'status': share_server.status,
            'host': share_server.host,
            'share_network_name': share_server.share_network_name,
            'share_network_id': share_server.share_network_id,
        }
        if detailed:
            share_server_dict['created_at'] = share_server.created_at
            share_server_dict['backend_details'] = share_server.backend_details
        return share_server_dict
