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

from oslo_log import log

from manila.api import extensions
import manila.api.openstack
from manila.api.v1 import availability_zones
from manila.api.v1 import cgsnapshots
from manila.api.v1 import consistency_groups
from manila.api.v1 import limits
from manila.api.v1 import scheduler_stats
from manila.api.v1 import security_service
from manila.api.v1 import services
from manila.api.v1 import share_instances
from manila.api.v1 import share_manage
from manila.api.v1 import share_metadata
from manila.api.v1 import share_networks
from manila.api.v1 import share_servers
from manila.api.v1 import share_snapshots
from manila.api.v1 import share_types
from manila.api.v1 import share_unmanage
from manila.api.v1 import shares
from manila.api import versions

LOG = log.getLogger(__name__)


class APIRouter(manila.api.openstack.APIRouter):
    """Route API requests.

    Routes requests on the OpenStack API to the appropriate controller
    and method.
    """
    ExtensionManager = extensions.ExtensionManager

    def _setup_routes(self, mapper, ext_mgr):
        self.resources['versions'] = versions.create_resource()
        mapper.connect("versions", "/",
                       controller=self.resources['versions'],
                       action='index')

        mapper.redirect("", "/")

        self.resources["availability_zones"] = (
            availability_zones.create_resource())
        mapper.resource("availability-zone",
                        # TODO(vponomaryov): rename 'os-availability-zone' to
                        # 'availability-zones' when API urls rename happens.
                        "os-availability-zone",
                        controller=self.resources["availability_zones"])

        self.resources["services"] = services.create_resource()
        mapper.resource("service",
                        # TODO(vponomaryov): rename 'os-services' to
                        # 'services' when API urls rename happens.
                        "os-services",
                        controller=self.resources["services"])

        self.resources["share_manage"] = share_manage.create_resource()
        mapper.resource("share_manage",
                        # TODO(vponomaryov): remove it when it is ported
                        # to shares controller.
                        "os-share-manage",
                        controller=self.resources["share_manage"])

        self.resources["share_unmanage"] = share_unmanage.create_resource()
        mapper.resource("share_unmanage",
                        # TODO(vponomaryov): remove it when it is ported
                        # to shares controller.
                        "os-share-unmanage",
                        controller=self.resources["share_unmanage"],
                        member={'unmanage': 'POST'})

        self.resources['shares'] = shares.create_resource()
        mapper.resource("share", "shares",
                        controller=self.resources['shares'],
                        collection={'detail': 'GET'},
                        member={'action': 'POST'})

        self.resources['share_instances'] = share_instances.create_resource()
        mapper.resource("share_instance", "share_instances",
                        controller=self.resources['share_instances'],
                        collection={'detail': 'GET'},
                        member={'action': 'POST'})

        mapper.connect("share_instance",
                       "/{project_id}/shares/{share_id}/instances",
                       controller=self.resources['share_instances'],
                       action='get_share_instances',
                       conditions={"method": ['GET']})

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

        self.resources['share_servers'] = share_servers.create_resource()
        mapper.resource(share_servers.RESOURCE_NAME,
                        'share-servers',
                        controller=self.resources['share_servers'])
        mapper.connect('details',
                       '/{project_id}/share-servers/{id}/details',
                       controller=self.resources['share_servers'],
                       action='details',
                       conditions={"method": ['GET']})

        self.resources['types'] = share_types.create_resource()
        mapper.resource("type", "types",
                        controller=self.resources['types'],
                        collection={'detail': 'GET', 'default': 'GET'},
                        member={'action': 'POST'})

        self.resources['scheduler_stats'] = scheduler_stats.create_resource()
        mapper.connect('pools', '/{project_id}/scheduler-stats/pools',
                       controller=self.resources['scheduler_stats'],
                       action='pools_index',
                       conditions={'method': ['GET']})
        mapper.connect('pools', '/{project_id}/scheduler-stats/pools/detail',
                       controller=self.resources['scheduler_stats'],
                       action='pools_detail',
                       conditions={'method': ['GET']})

        self.resources['consistency-groups'] = (
            consistency_groups.create_resource())
        mapper.resource('consistency-group', 'consistency-groups',
                        controller=self.resources['consistency-groups'],
                        collection={'detail': 'GET'})
        mapper.connect('consistency-groups',
                       '/{project_id}/consistency-groups/{id}/action',
                       controller=self.resources['consistency-groups'],
                       action='action',
                       conditions={"action": ['POST']})

        self.resources['cgsnapshots'] = cgsnapshots.create_resource()
        mapper.resource('cgsnapshot', 'cgsnapshots',
                        controller=self.resources['cgsnapshots'],
                        collection={'detail': 'GET'},
                        member={'members': 'GET', 'action': 'POST'})
