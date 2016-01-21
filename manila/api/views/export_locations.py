# Copyright (c) 2015 Mirantis Inc.
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
    """Model export-locations API responses as a python dictionary."""

    _collection_name = "export_locations"

    def _get_export_location_view(self, export_location, detail=False):
        view = {
            'uuid': export_location['uuid'],
            'path': export_location['path'],
            'created_at': export_location['created_at'],
            'updated_at': export_location['updated_at'],
        }
        # TODO(vponomaryov): include metadata keys here as export location
        # attributes when such appear.
        #
        # Example having export_location['el_metadata'] as following:
        #
        # {'speed': '1Gbps', 'access': 'rw'}
        #
        # or
        #
        # {'speed': '100Mbps', 'access': 'ro'}
        #
        # view['speed'] = export_location['el_metadata'].get('speed')
        # view['access'] = export_location['el_metadata'].get('access')
        if detail:
            view['share_instance_id'] = export_location['share_instance_id']
            view['is_admin_only'] = export_location['is_admin_only']
        return {'export_location': view}

    def summary(self, export_location):
        """Summary view of a single export location."""
        return self._get_export_location_view(export_location, detail=False)

    def detail(self, export_location):
        """Detailed view of a single export location."""
        return self._get_export_location_view(export_location, detail=True)

    def _list_export_locations(self, export_locations, detail=False):
        """View of export locations list."""
        view_method = self.detail if detail else self.summary
        return {self._collection_name: [
            view_method(export_location)['export_location']
            for export_location in export_locations
        ]}

    def detail_list(self, export_locations):
        """Detailed View of export locations list."""
        return self._list_export_locations(export_locations, detail=True)

    def summary_list(self, export_locations):
        """Summary View of export locations list."""
        return self._list_export_locations(export_locations, detail=False)
