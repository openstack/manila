# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
from manila.openstack.common import log as logging


class ViewBuilder(common.ViewBuilder):
    """Model a server API response as a python dictionary."""

    _collection_name = 'shares'

    def summary_list(self, request, shares):
        """Show a list of shares without many details."""
        return self._list_view(self.summary, request, shares)

    def detail_list(self, request, shares):
        """Detailed view of a list of shares."""
        return self._list_view(self.detail, request, shares)

    def summary(self, request, share):
        """Generic, non-detailed view of an share."""
        return {
            'share': {
                'id': share.get('id'),
                'name': share.get('display_name'),
                'links': self._get_links(request, share['id'])
            }
        }

    def detail(self, request, share):
        """Detailed view of a single share."""
        metadata = share.get('share_metadata')
        if metadata:
            metadata = dict((item['key'], item['value']) for item in metadata)
        else:
            metadata = {}

        return {
            'share': {
                'id': share.get('id'),
                'size': share.get('size'),
                'availability_zone': share.get('availability_zone'),
                'created_at': share.get('created_at'),
                'status': share.get('status'),
                'name': share.get('display_name'),
                'description': share.get('display_description'),
                'snapshot_id': share.get('snapshot_id'),
                'share_proto': share.get('share_proto'),
                'export_location': share.get('export_location'),
                'metadata': metadata,
                'links': self._get_links(request, share['id'])
            }
        }

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
