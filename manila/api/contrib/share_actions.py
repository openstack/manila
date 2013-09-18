#   Copyright 2013 NetApp.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import webob

from manila.api import extensions
from manila.api.openstack import wsgi
from manila import exception
from manila import share


authorize = extensions.extension_authorizer('share', 'services')


class ShareActionsController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ShareActionsController, self).__init__(*args, **kwargs)
        self.share_api = share.API()

    @wsgi.action('os-allow_access')
    def _allow_access(self, req, id, body):
        """Add share access rule."""
        context = req.environ['manila.context']

        share = self.share_api.get(context, id)

        access_type = body['os-allow_access']['access_type']
        access_to = body['os-allow_access']['access_to']

        access = self.share_api.allow_access(
            context, share, access_type, access_to)
        return {'access': access}

    @wsgi.action('os-deny_access')
    def _deny_access(self, req, id, body):
        """Remove access rule."""
        context = req.environ['manila.context']

        access_id = body['os-deny_access']['access_id']

        try:
            access = self.share_api.access_get(context, access_id)
            if access.share_id != id:
                raise exception.NotFound()
            share = self.share_api.get(context, id)
        except exception.NotFound, error:
            raise webob.exc.HTTPNotFound(explanation=unicode(error))
        self.share_api.deny_access(context, share, access)
        return webob.Response(status_int=202)

    @wsgi.action('os-access_list')
    def _access_list(self, req, id, body):
        """list access rules."""
        context = req.environ['manila.context']

        share = self.share_api.get(context, id)
        access_list = self.share_api.access_get_all(context, share)
        return {'access_list': access_list}


# def create_resource():
#     return wsgi.Resource(ShareActionsController())


class Share_actions(extensions.ExtensionDescriptor):
    """Enable share actions."""

    name = 'ShareActions'
    alias = 'share-actions'
    namespace = ''
    updated = '2012-08-14T00:00:00+00:00'

    def get_controller_extensions(self):
        controller = ShareActionsController()
        extension = extensions.ControllerExtension(self, 'shares',
                                                   controller)
        return [extension]
