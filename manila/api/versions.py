# Copyright 2010 OpenStack LLC.
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

from oslo_config import cfg

from manila.api.openstack import wsgi
from manila.api.views import versions as views_versions

CONF = cfg.CONF


_KNOWN_VERSIONS = {
    "v2.0": {
        "id": "v2.0",
        "status": "CURRENT",
        "updated": "2012-11-21T11:33:21Z",
        "links": [
            {
                "rel": "describedby",
                "type": "application/pdf",
                "href": "http://jorgew.github.com/block-storage-api/"
                        "content/os-block-storage-1.0.pdf",
            },
            {
                "rel": "describedby",
                "type": "application/vnd.sun.wadl+xml",
                # (anthony) FIXME
                "href": "http://docs.rackspacecloud.com/"
                        "servers/api/v1.1/application.wadl",
            },
        ],
        "media-types": [
            {
                "base": "application/json",
            }
        ],
    },
    "v1.0": {
        "id": "v1.0",
        "status": "CURRENT",
        "updated": "2012-01-04T11:33:21Z",
        "links": [
            {
                "rel": "describedby",
                "type": "application/pdf",
                "href": "http://jorgew.github.com/block-storage-api/"
                        "content/os-block-storage-1.0.pdf",
            },
            {
                "rel": "describedby",
                "type": "application/vnd.sun.wadl+xml",
                # (anthony) FIXME
                "href": "http://docs.rackspacecloud.com/"
                        "servers/api/v1.1/application.wadl",
            },
        ],
        "media-types": [
            {
                "base": "application/json",
            }
        ],
    }

}


def get_supported_versions():
    versions = {}

    if CONF.enable_v1_api:
        versions['v1.0'] = _KNOWN_VERSIONS['v1.0']
    if CONF.enable_v2_api:
        versions['v2.0'] = _KNOWN_VERSIONS['v2.0']

    return versions


class Versions(wsgi.Resource):

    def __init__(self):
        super(Versions, self).__init__(None)

    def index(self, req):
        """Return all versions."""
        builder = views_versions.get_view_builder(req)
        return builder.build_versions(get_supported_versions())

    @wsgi.response(300)
    def multi(self, req):
        """Return multiple choices."""
        builder = views_versions.get_view_builder(req)
        return builder.build_choices(get_supported_versions(), req)

    def get_action_args(self, request_environment):
        """Parse dictionary created by routes library."""
        args = {}
        if request_environment['PATH_INFO'] == '/':
            args['action'] = 'index'
        else:
            args['action'] = 'multi'

        return args


class ShareVersionV1(object):
    def show(self, req):
        builder = views_versions.get_view_builder(req)
        return builder.build_version(_KNOWN_VERSIONS['v1.0'])


def create_resource():
    return wsgi.Resource(ShareVersionV1())
