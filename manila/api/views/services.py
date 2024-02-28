# Copyright (c) 2015 Mirantis inc.
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

    _collection_name = "services"
    _detail_version_modifiers = [
        "add_disabled_reason_field",
    ]

    def summary(self, request, service):
        """Summary view of a single service."""
        keys = 'host', 'binary', 'status',
        service_dict = {key: service.get(key) for key in keys}
        self.update_versioned_resource_dict(request, service_dict, service)
        return service_dict

    def detail(self, request, service):
        """Detailed view of a single service."""
        keys = ('id', 'binary', 'host', 'zone', 'status',
                'state', 'updated_at')
        service_dict = {key: service.get(key) for key in keys}
        self.update_versioned_resource_dict(request, service_dict, service)
        return service_dict

    def detail_list(self, request, services):
        """Detailed view of a list of services."""
        services_list = [self.detail(request, s) for s in services]
        services_dict = dict(services=services_list)
        return services_dict

    @common.ViewBuilder.versioned_method("2.83")
    def add_disabled_reason_field(self, context, service_dict, service):
        service_dict.pop('disabled', None)
        service_dict['status'] = service.get('status')
        service_dict['disabled_reason'] = service.get('disabled_reason')
