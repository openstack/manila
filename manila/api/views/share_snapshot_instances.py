# Copyright 2016 Huawei Inc.
# All Rights Reserved.
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
    """Model the server API response as a python dictionary."""

    _collection_name = 'snapshot_instances'

    def summary_list(self, request, instances):
        """Summary view of a list of share snapshot instances."""
        return self._list_view(self.summary, request, instances)

    def detail_list(self, request, instances):
        """Detailed view of a list of share snapshot instances."""
        return self._list_view(self.detail, request, instances)

    def summary(self, request, instance):
        """Generic, non-detailed view of a share snapshot instance."""
        instance_dict = {
            'id': instance.get('id'),
            'snapshot_id': instance.get('snapshot_id'),
            'status': instance.get('status'),
        }
        return {'snapshot_instance': instance_dict}

    def detail(self, request, instance):
        """Detailed view of a single share snapshot instance."""
        instance_dict = {
            'id': instance.get('id'),
            'snapshot_id': instance.get('snapshot_id'),
            'created_at': instance.get('created_at'),
            'updated_at': instance.get('updated_at'),
            'status': instance.get('status'),
            'share_id': instance.get('share_instance').get('share_id'),
            'share_instance_id': instance.get('share_instance_id'),
            'progress': instance.get('progress'),
            'provider_location': instance.get('provider_location'),
        }

        return {'snapshot_instance': instance_dict}

    def _list_view(self, func, request, instances):
        """Provide a view for a list of share snapshot instances."""
        instances_list = [func(request, instance)['snapshot_instance']
                          for instance in instances]

        instances_dict = {self._collection_name: instances_list}

        return instances_dict
