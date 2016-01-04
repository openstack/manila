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
from manila.common import constants


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
        """Generic, non-detailed view of a security service."""
        return {
            'security_service': {
                'id': security_service.get('id'),
                'name': security_service.get('name'),
                'type': security_service.get('type'),
                # NOTE(vponomaryov): attr "status" was removed from model and
                # is left in view for compatibility purposes since it affects
                # user-facing API. This should be removed right after no one
                # uses it anymore.
                'status': constants.STATUS_NEW,
            }
        }

    def detail(self, request, security_service):
        """Detailed view of a single security service."""
        view = self.summary(request, security_service)
        keys = (
            'created_at', 'updated_at', 'description', 'dns_ip', 'server',
            'domain', 'user', 'password', 'project_id')
        for key in keys:
            view['security_service'][key] = security_service.get(key)
        return view

    def _list_view(self, func, request, security_services):
        """Provide a view for a list of security services."""
        security_services_list = [func(request, service)['security_service']
                                  for service in security_services]
        security_services_dict = dict(security_services=security_services_list)
        return security_services_dict
