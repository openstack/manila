#   Copyright 2015 Mirantis inc.
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

import six
import webob
from webob import exc

from manila.api import extensions
from manila.api.openstack import wsgi
from manila import exception
from manila.i18n import _
from manila import share
from manila.share import share_types
from manila.share import utils as share_utils
from manila import utils

authorize = extensions.extension_authorizer('share', 'manage')


class ShareManageController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ShareManageController, self).__init__(*args, **kwargs)
        self.share_api = share.API()

    def create(self, req, body):
        context = req.environ['manila.context']
        authorize(context)
        share_data = self._validate_manage_parameters(context, body)

        share = {
            'host': share_data['service_host'],
            'export_location': share_data['export_path'],
            'share_proto': share_data['protocol'],
            'share_type_id': share_data['share_type_id'],
            'display_name': share_data.get('display_name', ''),
            'display_description': share_data.get('display_description', ''),
        }

        driver_options = share_data.get('driver_options', {})

        try:
            self.share_api.manage(context, share, driver_options)
        except exception.PolicyNotAuthorized as e:
            raise exc.HTTPForbidden(explanation=six.text_type(e))
        except exception.ManilaException as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))

        return webob.Response(status_int=202)

    def _validate_manage_parameters(self, context, body):
        if not (body and self.is_valid_body(body, 'share')):
            msg = _("Share entity not found in request body")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        required_parameters = ['export_path', 'service_host', 'protocol']

        data = body['share']

        for parameter in required_parameters:
            if parameter not in data:
                msg = _("Required parameter %s not found") % parameter
                raise exc.HTTPUnprocessableEntity(explanation=msg)

        if not share_utils.extract_host(data['service_host'], 'pool'):
            msg = _("service_host parameter should contain pool.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            utils.validate_service_host(
                context, share_utils.extract_host(data['service_host']))
        except exception.ServiceNotFound as e:
            raise exc.HTTPNotFound(explanation=six.text_type(e))
        except exception.PolicyNotAuthorized as e:
            raise exc.HTTPForbidden(explanation=six.text_type(e))
        except exception.ServiceIsDown as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))

        data['share_type_id'] = self._get_share_type_id(
            context, data.get('share_type'))

        return data

    @staticmethod
    def _get_share_type_id(context, share_type):
        try:
            stype = share_types.get_share_type_by_name_or_id(context,
                                                             share_type)
            return stype['id']
        except exception.ShareTypeNotFound as e:
            raise exc.HTTPNotFound(explanation=six.text_type(e))


class Share_manage(extensions.ExtensionDescriptor):
    """Allows existing share to be 'managed' by Manila."""

    name = 'ShareManage'
    alias = 'os-share-manage'
    namespace = ('http://docs.openstack.org/share/ext/'
                 'os-share-manage/api/v1')
    updated = '2015-02-17T00:00:00+00:00'

    def get_resources(self):
        controller = ShareManageController()
        res = extensions.ResourceExtension(Share_manage.alias,
                                           controller)
        return [res]