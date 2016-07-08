# Copyright (c) 2016 Hitachi Data Systems
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
    _collection_name = "share_snapshot_export_locations"

    def _get_view(self, request, export_location, detail=False):
        context = request.environ['manila.context']

        result = {
            'share_snapshot_export_location': {
                'id': export_location['id'],
                'path': export_location['path'],
                'links': self._get_links(request, export_location['id']),
            }
        }

        ss_el = result['share_snapshot_export_location']
        if context.is_admin:
            ss_el['share_snapshot_instance_id'] = (
                export_location['share_snapshot_instance_id'])
            ss_el['is_admin_only'] = export_location['is_admin_only']

        if detail:
            ss_el['created_at'] = export_location['created_at']
            ss_el['updated_at'] = export_location['updated_at']

        return result

    def list_export_locations(self, request, export_locations):

        context = request.environ['manila.context']

        result = {self._collection_name: []}
        for export_location in export_locations:
            if context.is_admin or not export_location['is_admin_only']:
                result[self._collection_name].append(self._get_view(
                    request,
                    export_location)['share_snapshot_export_location'])
            else:
                continue

        return result

    def detail_export_location(self, request, export_location):
        return self._get_view(request, export_location, detail=True)
