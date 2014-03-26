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


class ViewBuilder(common.ViewBuilder):
    """Model a server API response as a python dictionary."""

    _collection_name = 'security_services'

    def summary_list(self, request, security_services):
        """Show a list of security services without many details."""
        return self._list_view(self.summary, request, security_services)

    def detail_list(self, request, security_services):
        """Detailed view of a list of security services."""
        return self._list_view(self.detail, request, security_services)

    def summary(self, request, security_service):
        """Generic, non-detailed view of an security service."""
        return {
            'security_service': {
                'id': security_service.get('id'),
                'name': security_service.get('name'),
                'status': security_service.get('status')
            }
        }

    def detail(self, request, security_service):
        """Detailed view of a single security service."""
        return {
            'security_service': {
                'id': security_service.get('id'),
                'name': security_service.get('name'),
                'created_at': security_service.get('created_at'),
                'updated_at': security_service.get('updated_at'),
                'status': security_service.get('status'),
                'description': security_service.get('description'),
                'dns_ip': security_service.get('dns_ip'),
                'server': security_service.get('server'),
                'domain': security_service.get('domain'),
                'sid': security_service.get('sid'),
                'password': security_service.get('password'),
                'type': security_service.get('type'),
                'project_id': security_service.get('project_id'),
            }
        }

    def _list_view(self, func, request, security_services):
        """Provide a view for a list of security services."""
        security_services_list = [func(request, service)['security_service']
                                  for service in security_services]
        security_services_dict = dict(security_services=security_services_list)
        return security_services_dict
