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

import re

import webob

from manila.api import extensions
from manila.api.openstack import wsgi
from manila.api import xmlutil
from manila import exception
from manila import share


authorize = extensions.extension_authorizer('share', 'services')


class ShareAccessTemplate(xmlutil.TemplateBuilder):
    """XML Template for share access management methods."""

    def construct(self):
        root = xmlutil.TemplateElement('access',
                                       selector='access')
        root.set("share_id")
        root.set("deleted")
        root.set("created_at")
        root.set("updated_at")
        root.set("access_type")
        root.set("access_to")
        root.set("state")
        root.set("deleted_at")
        root.set("id")

        return xmlutil.MasterTemplate(root, 1)


class ShareAccessListTemplate(xmlutil.TemplateBuilder):
    """XML Template for share access list."""

    def construct(self):
        root = xmlutil.TemplateElement('access_list')
        elem = xmlutil.SubTemplateElement(root, 'share',
                                          selector='access_list')
        elem.set("state")
        elem.set("id")
        elem.set("access_type")
        elem.set("access_to")

        return xmlutil.MasterTemplate(root, 1)


class ShareActionsController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ShareActionsController, self).__init__(*args, **kwargs)
        self.share_api = share.API()

    @staticmethod
    def _validate_username(access):
        valid_useraname_re = '[\w\.\-_\`;\'\{\}\[\]]{4,32}$'
        username = access
        if not re.match(valid_useraname_re, username):
            exc_str = ('Invalid user or group name. Must be 4-32 chars long '
                       'and consist of alfanum and ]{.-_\'`;}[')
            raise webob.exc.HTTPBadRequest(explanation=exc_str)

    @staticmethod
    def _validate_ip_range(ip_range):
        ip_range = ip_range.split('/')
        exc_str = ('Supported ip format examples:\n'
                   '\t10.0.0.2, 10.0.0.0/24')
        if len(ip_range) > 2:
            raise webob.exc.HTTPBadRequest(explanation=exc_str)
        if len(ip_range) == 2:
            try:
                prefix = int(ip_range[1])
                if prefix < 0 or prefix > 32:
                    raise ValueError()
            except ValueError:
                msg = 'IP prefix should be in range from 0 to 32'
                raise webob.exc.HTTPBadRequest(explanation=msg)
        ip_range = ip_range[0].split('.')
        if len(ip_range) != 4:
            raise webob.exc.HTTPBadRequest(explanation=exc_str)
        for item in ip_range:
            try:
                if 0 <= int(item) <= 255:
                    continue
                raise ValueError()
            except ValueError:
                raise webob.exc.HTTPBadRequest(explanation=exc_str)

    @wsgi.action('os-allow_access')
    @wsgi.serializers(xml=ShareAccessTemplate)
    def _allow_access(self, req, id, body):
        """Add share access rule."""
        context = req.environ['manila.context']

        share = self.share_api.get(context, id)

        access_type = body['os-allow_access']['access_type']
        access_to = body['os-allow_access']['access_to']
        if access_type == 'ip':
            self._validate_ip_range(access_to)
        elif access_type == 'sid':
            self._validate_username(access_to)
        else:
            exc_str = "Only 'ip' or 'sid' access types are supported"
            raise webob.exc.HTTPBadRequest(explanation=exc_str)
        try:
            access = self.share_api.allow_access(
                context, share, access_type, access_to)
        except exception.ShareAccessExists as e:
            raise webob.exc.HTTPBadRequest(explanation=e.msg)
        return {'access': access}

    @wsgi.action('os-deny_access')
    @wsgi.serializers(xml=ShareAccessTemplate)
    def _deny_access(self, req, id, body):
        """Remove access rule."""
        context = req.environ['manila.context']

        access_id = body['os-deny_access']['access_id']

        try:
            access = self.share_api.access_get(context, access_id)
            if access.share_id != id:
                raise exception.NotFound()
            share = self.share_api.get(context, id)
        except exception.NotFound as error:
            raise webob.exc.HTTPNotFound(explanation=unicode(error))
        self.share_api.deny_access(context, share, access)
        return webob.Response(status_int=202)

    @wsgi.action('os-access_list')
    @wsgi.serializers(xml=ShareAccessListTemplate)
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
