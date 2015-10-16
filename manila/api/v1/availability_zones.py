# Copyright (c) 2013 OpenStack Foundation
# Copyright (c) 2015 Mirantis inc.
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

from manila.api.openstack import wsgi
from manila.api.views import availability_zones as availability_zones_views
from manila import db


class AvailabilityZoneController(wsgi.Controller):
    """The Availability Zone API controller for the OpenStack API."""

    resource_name = "availability_zone"
    _view_builder_class = availability_zones_views.ViewBuilder

    def index(self, req):
        self.authorize(req.environ['manila.context'], 'index')
        return self._index(req)

    def _index(self, req):
        """Describe all known availability zones."""
        views = db.availability_zone_get_all(req.environ['manila.context'])
        return self._view_builder.detail_list(views)


def create_resource():
    return wsgi.Resource(AvailabilityZoneController())
