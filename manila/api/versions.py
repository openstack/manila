# Copyright 2010 OpenStack LLC.
# Copyright 2015 Clinton Knight
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

import copy

from oslo_config import cfg

from manila.api import extensions
from manila.api import openstack
from manila.api.openstack import api_version_request
from manila.api.openstack import wsgi
from manila.api.views import versions as views_versions

CONF = cfg.CONF

_LINKS = [{
    'rel': 'describedby',
    'type': 'text/html',
    'href': 'http://docs.openstack.org/',
}]

_MEDIA_TYPES = [{
    'base': 'application/json',
    'type': 'application/vnd.openstack.share+json;version=1',
}]

_KNOWN_VERSIONS = {
    'v1.0': {
        'id': 'v1.0',
        'status': 'DEPRECATED',
        'version': '',
        'min_version': '',
        'updated': '2015-08-27T11:33:21Z',
        'links': _LINKS,
        'media-types': _MEDIA_TYPES,
    },
    'v2.0': {
        'id': 'v2.0',
        'status': 'CURRENT',
        'version': api_version_request._MAX_API_VERSION,
        'min_version': api_version_request._MIN_API_VERSION,
        'updated': '2015-08-27T11:33:21Z',
        'links': _LINKS,
        'media-types': _MEDIA_TYPES,
    },
}


class VersionsRouter(openstack.APIRouter):
    """Route versions requests."""

    ExtensionManager = extensions.ExtensionManager

    def _setup_routes(self, mapper, ext_mgr):
        self.resources['versions'] = create_resource()
        mapper.connect('versions', '/',
                       controller=self.resources['versions'],
                       action='all')
        mapper.redirect('', '/')


class VersionsController(wsgi.Controller):

    def __init__(self):
        super(VersionsController, self).__init__(None)

    @wsgi.Controller.api_version('1.0', '1.0')
    def index(self, req):
        """Return versions supported prior to the microversions epoch."""
        builder = views_versions.get_view_builder(req)
        known_versions = copy.deepcopy(_KNOWN_VERSIONS)
        known_versions.pop('v2.0')
        return builder.build_versions(known_versions)

    @wsgi.Controller.api_version('2.0')  # noqa
    def index(self, req):  # pylint: disable=E0102
        """Return versions supported after the start of microversions."""
        builder = views_versions.get_view_builder(req)
        known_versions = copy.deepcopy(_KNOWN_VERSIONS)
        known_versions.pop('v1.0')
        return builder.build_versions(known_versions)

    # NOTE (cknight): Calling the versions API without
    # /v1 or /v2 in the URL will lead to this unversioned
    # method, which should always return info about all
    # available versions.
    @wsgi.response(300)
    def all(self, req):
        """Return all known versions."""
        builder = views_versions.get_view_builder(req)
        known_versions = copy.deepcopy(_KNOWN_VERSIONS)
        return builder.build_versions(known_versions)


def create_resource():
    return wsgi.Resource(VersionsController())
