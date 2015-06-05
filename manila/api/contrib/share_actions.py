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

import six
import webob

from manila.api import extensions
from manila.api.openstack import wsgi
from manila import exception
from manila.i18n import _
from manila import share


authorize = extensions.extension_authorizer('share', 'services')


class ShareActionsController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ShareActionsController, self).__init__(*args, **kwargs)
        self.share_api = share.API()

    @staticmethod
    def _validate_common_name(access):
        """Validate common name passed by user.

        'access' is used as the certificate's CN (common name)
        to which access is allowed or denied by the backend.
        The standard allows for just about any string in the
        common name. The meaning of a string depends on its
        interpretation and is limited to 64 characters.
        """
        if len(access) == 0 or len(access) > 64:
            exc_str = _('Invalid CN (common name). Must be 1-64 chars long')
            raise webob.exc.HTTPBadRequest(explanation=exc_str)

    @staticmethod
    def _validate_username(access):
        valid_username_re = '[\w\.\-_\`;\'\{\}\[\]\\\\]{4,32}$'
        username = access
        if not re.match(valid_username_re, username):
            exc_str = ('Invalid user or group name. Must be 4-32 characters '
                       'and consist of alphanumeric characters and '
                       'special characters ]{.-_\'`;}[\\')
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
    def _allow_access(self, req, id, body):
        """Add share access rule."""
        context = req.environ['manila.context']
        access_data = body['os-allow_access']
        share = self.share_api.get(context, id)

        access_type = access_data['access_type']
        access_to = access_data['access_to']
        if access_type == 'ip':
            self._validate_ip_range(access_to)
        elif access_type == 'user':
            self._validate_username(access_to)
        elif access_type == 'cert':
            self._validate_common_name(access_to.strip())
        else:
            exc_str = _("Only 'ip','user',or'cert' access types "
                        "are supported.")
            raise webob.exc.HTTPBadRequest(explanation=exc_str)
        try:
            access = self.share_api.allow_access(
                context, share, access_type, access_to,
                access_data.get('access_level'))
        except exception.ShareAccessExists as e:
            raise webob.exc.HTTPBadRequest(explanation=e.msg)
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
        except exception.NotFound as error:
            raise webob.exc.HTTPNotFound(explanation=six.text_type(error))
        self.share_api.deny_access(context, share, access)
        return webob.Response(status_int=202)

    @wsgi.action('os-access_list')
    def _access_list(self, req, id, body):
        """list access rules."""
        context = req.environ['manila.context']

        share = self.share_api.get(context, id)
        access_list = self.share_api.access_get_all(context, share)
        return {'access_list': access_list}

    @wsgi.action('os-extend')
    def _extend(self, req, id, body):
        """Extend size of share."""
        context = req.environ['manila.context']
        share, size = self._get_valid_resize_parameters(
            context, id, body, 'os-extend')

        try:
            self.share_api.extend(context, share, size)
        except (exception.InvalidInput, exception.InvalidShare) as e:
            raise webob.exc.HTTPBadRequest(explanation=six.text_type(e))
        except exception.ShareSizeExceedsAvailableQuota as e:
            raise webob.exc.HTTPForbidden(explanation=six.text_type(e))

        return webob.Response(status_int=202)

    @wsgi.action('os-shrink')
    def _shrink(self, req, id, body):
        """Shrink size of share."""
        context = req.environ['manila.context']
        share, size = self._get_valid_resize_parameters(
            context, id, body, 'os-shrink')

        try:
            self.share_api.shrink(context, share, size)
        except (exception.InvalidInput, exception.InvalidShare) as e:
            raise webob.exc.HTTPBadRequest(explanation=six.text_type(e))

        return webob.Response(status_int=202)

    def _get_valid_resize_parameters(self, context, id, body, action):
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound as e:
            raise webob.exc.HTTPNotFound(explanation=six.text_type(e))

        try:
            size = int(body[action]['new_size'])
        except (KeyError, ValueError, TypeError):
            msg = _("New share size must be specified as an integer.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        return share, size


# def create_resource():
#     return wsgi.Resource(ShareActionsController())


class Share_actions(extensions.ExtensionDescriptor):
    """Enable share actions."""

    name = 'ShareActions'
    alias = 'share-actions'
    updated = '2012-08-14T00:00:00+00:00'

    def get_controller_extensions(self):
        controller = ShareActionsController()
        extension = extensions.ControllerExtension(self, 'shares',
                                                   controller)
        return [extension]
