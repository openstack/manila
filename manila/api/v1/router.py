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

from manila.api.v1 import shares
from manila.api.v1 import share_actions
from manila.api.v1 import share_snapshots

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

        self.resources['share-snapshots'] = share_snapshots.create_resource()
        mapper.resource("share-snapshot", "share-snapshots",
                        controller=self.resources['share-snapshots'],
                        collection={'detail': 'GET'},
                        member={'action': 'POST'})
        #
        # self.resources['shares'] = share_actions.create_resource()
        # mapper.resource("share", "shares",
        #                 controller=self.resources['shares'])

        self.resources['limits'] = limits.create_resource()
        mapper.resource("limit", "limits",
                        controller=self.resources['limits'])

