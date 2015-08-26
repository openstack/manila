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

from manila.api import extensions
from manila.api.openstack import wsgi
from manila import db

authorize = extensions.extension_authorizer('share', 'availability_zones')


class Controller(wsgi.Controller):
    def index(self, req):
        """Describe all known availability zones."""
        context = req.environ['manila.context']
        authorize(context)
        azs = db.availability_zone_get_all(context)
        return {'availability_zones': azs}


class Availability_zones(extensions.ExtensionDescriptor):
    """Describe Availability Zones."""

    name = 'AvailabilityZones'
    alias = 'os-availability-zone'
    updated = '2015-07-28T00:00:00+00:00'

    def get_resources(self):
        controller = Controller()
        res = extensions.ResourceExtension(Availability_zones.alias,
                                           controller)
        return [res]
