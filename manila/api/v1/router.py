# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# Copyright 2011 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""
WSGI middleware for OpenStack Share API.
"""

from manila.api import extensions
import manila.api.openstack
from manila.api.v1 import limits
from manila.api import versions

from manila.api.v1 import security_service
from manila.api.v1 import share_metadata
from manila.api.v1 import share_networks
from manila.api.v1 import share_snapshots
from manila.api.v1 import shares

from manila.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class APIRouter(manila.api.openstack.APIRouter):
    """
    Routes requests on the OpenStack API to the appropriate controller
    and method.
    """
    ExtensionManager = extensions.ExtensionManager

    def _setup_routes(self, mapper, ext_mgr):
        self.resources['versions'] = versions.create_resource()
        mapper.connect("versions", "/",
                       controller=self.resources['versions'],
                       action='show')

        mapper.redirect("", "/")

        self.resources['shares'] = shares.create_resource()
        mapper.resource("share", "shares",
                        controller=self.resources['shares'],
                        collection={'detail': 'GET'},
                        member={'action': 'POST'})

        self.resources['snapshots'] = share_snapshots.create_resource()
        mapper.resource("snapshot", "snapshots",
                        controller=self.resources['snapshots'],
                        collection={'detail': 'GET'},
                        member={'action': 'POST'})

        self.resources['share_metadata'] = share_metadata.create_resource()
        share_metadata_controller = self.resources['share_metadata']

        mapper.resource("share_metadata", "metadata",
                        controller=share_metadata_controller,
                        parent_resource=dict(member_name='share',
                                             collection_name='shares'))

        mapper.connect("metadata",
                       "/{project_id}/shares/{share_id}/metadata",
                       controller=share_metadata_controller,
                       action='update_all',
                       conditions={"method": ['PUT']})

        self.resources['limits'] = limits.create_resource()
        mapper.resource("limit", "limits",
                        controller=self.resources['limits'])

        self.resources["security_services"] = \
            security_service.create_resource()
        mapper.resource("security-service", "security-services",
                        controller=self.resources['security_services'],
                        collection={'detail': 'GET'})

        self.resources['share_networks'] = share_networks.create_resource()
        mapper.resource(share_networks.RESOURCE_NAME,
                        'share-networks',
                        controller=self.resources['share_networks'],
                        collection={'detail': 'GET'},
                        member={'action': 'POST'})
