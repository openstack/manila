# Copyright 2018 Huawei Corporation.
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

"""The share access rule metadata api."""

import webob

from manila.api.openstack import wsgi
from manila.api.views import share_accesses as share_access_views
from manila import db
from manila import exception
from manila.i18n import _
from manila import share


class ShareAccessMetadataController(wsgi.Controller):
    """The Share access rule metadata API V2 controller."""

    resource_name = 'share_access_metadata'
    _view_builder_class = share_access_views.ViewBuilder

    def __init__(self):
        super(ShareAccessMetadataController, self).__init__()
        self.share_api = share.API()

    @wsgi.Controller.api_version('2.45')
    @wsgi.Controller.authorize
    def update(self, req, access_id, body=None):
        context = req.environ['manila.context']
        if not self.is_valid_body(body, 'metadata'):
            raise webob.exc.HTTPBadRequest()

        metadata = body['metadata']
        md = self._update_share_access_metadata(context, access_id, metadata)
        return self._view_builder.view_metadata(req, md)

    @wsgi.Controller.api_version('2.45')
    @wsgi.Controller.authorize
    @wsgi.response(200)
    def delete(self, req, access_id, key):
        """Deletes an existing access metadata."""
        context = req.environ['manila.context']
        self._assert_access_exists(context, access_id)
        try:
            db.share_access_metadata_delete(context, access_id, key)
        except exception.ShareAccessMetadataNotFound as error:
            raise webob.exc.HTTPNotFound(explanation=error.msg)

    def _update_share_access_metadata(self, context, access_id, metadata):
        self._assert_access_exists(context, access_id)
        try:
            return self.share_api.update_share_access_metadata(
                context, access_id, metadata)
        except (ValueError, AttributeError):
            msg = _("Malformed request body")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        except exception.InvalidMetadata as error:
            raise webob.exc.HTTPBadRequest(explanation=error.msg)

        except exception.InvalidMetadataSize as error:
            raise webob.exc.HTTPBadRequest(explanation=error.msg)

    def _assert_access_exists(self, context, access_id):
        try:
            self.share_api.access_get(context, access_id)
        except exception.NotFound as ex:
            raise webob.exc.HTTPNotFound(explanation=ex.msg)


def create_resource():
    return wsgi.Resource(ShareAccessMetadataController())
