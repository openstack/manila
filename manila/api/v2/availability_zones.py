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


class AvailabilityZoneMixin(object):
    """The Availability Zone API controller common logic.

    Mixin class that should be inherited by Availability Zone API controllers,
    which are used for different API URLs and microversions.
    """

    resource_name = "availability_zone"
    _view_builder_class = availability_zones_views.ViewBuilder

    @wsgi.Controller.authorize("index")
    def _index(self, req):
        """Describe all known availability zones."""
        views = db.availability_zone_get_all(req.environ['manila.context'])
        return self._view_builder.detail_list(views)


class AvailabilityZoneControllerLegacy(AvailabilityZoneMixin, wsgi.Controller):
    """Deprecated Availability Zone API controller.

    Used by legacy API v1 and v2 microversions from 2.0 to 2.6.
    Registered under deprecated API URL 'os-availability-zone'.
    """

    @wsgi.Controller.api_version('1.0', '2.6')
    def index(self, req):
        return self._index(req)


class AvailabilityZoneController(AvailabilityZoneMixin, wsgi.Controller):
    """Availability Zone API controller.

    Used only by API v2 starting from microversion 2.7.
    Registered under API URL 'availability-zones'.
    """

    @wsgi.Controller.api_version('2.7')
    def index(self, req):
        return self._index(req)


def create_resource_legacy():
    return wsgi.Resource(AvailabilityZoneControllerLegacy())


def create_resource():
    return wsgi.Resource(AvailabilityZoneController())
