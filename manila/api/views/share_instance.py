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

    _collection_name = 'share_instances'

    _detail_version_modifiers = [
        "remove_export_locations",
    ]

    def detail_list(self, request, instances):
        """Detailed view of a list of share instances."""
        return self._list_view(self.detail, request, instances)

    def detail(self, request, share_instance):
        """Detailed view of a single share instance."""
        export_locations = [e['path'] for e in share_instance.export_locations]

        instance_dict = {
            'id': share_instance.get('id'),
            'share_id': share_instance.get('share_id'),
            'availability_zone': share_instance.get('availability_zone'),
            'created_at': share_instance.get('created_at'),
            'host': share_instance.get('host'),
            'status': share_instance.get('status'),
            'share_network_id': share_instance.get('share_network_id'),
            'share_server_id': share_instance.get('share_server_id'),
            'export_location': share_instance.get('export_location'),
            'export_locations': export_locations,
        }
        self.update_versioned_resource_dict(
            request, instance_dict, share_instance)
        return {'share_instance': instance_dict}

    def _list_view(self, func, request, instances):
        """Provide a view for a list of share instances."""
        instances_list = [func(request, instance)['share_instance']
                          for instance in instances]
        instances_links = self._get_collection_links(request,
                                                     instances,
                                                     self._collection_name)
        instances_dict = {self._collection_name: instances_list}

        if instances_links:
            instances_dict[self._collection_name] = instances_links

        return instances_dict

    @common.ViewBuilder.versioned_method("2.9")
    def remove_export_locations(self, share_instance_dict, share_instance):
        share_instance_dict.pop('export_location')
        share_instance_dict.pop('export_locations')
