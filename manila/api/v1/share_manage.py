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
from webob import exc

from manila.api.openstack import wsgi
from manila.api.views import shares as share_views
from manila import exception
from manila.i18n import _
from manila import share
from manila.share import share_types
from manila.share import utils as share_utils
from manila import utils


class ShareManageMixin(object):

    @wsgi.Controller.authorize('manage')
    def _manage(self, req, body):
        context = req.environ['manila.context']
        share_data = self._validate_manage_parameters(context, body)

        # NOTE(vponomaryov): compatibility actions are required between API and
        # DB layers for 'name' and 'description' API params that are
        # represented in DB as 'display_name' and 'display_description'
        # appropriately.
        name = share_data.get('display_name', share_data.get('name', None))
        description = share_data.get(
            'display_description', share_data.get('description', None))

        share = {
            'host': share_data['service_host'],
            'export_location': share_data['export_path'],
            'share_proto': share_data['protocol'].upper(),
            'share_type_id': share_data['share_type_id'],
            'display_name': name,
            'display_description': description,
        }

        if share_data.get('is_public') is not None:
            share['is_public'] = share_data['is_public']

        driver_options = share_data.get('driver_options', {})

        try:
            share_ref = self.share_api.manage(context, share, driver_options)
        except exception.PolicyNotAuthorized as e:
            raise exc.HTTPForbidden(explanation=six.text_type(e))
        except exception.ManilaException as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))

        return self._view_builder.detail(req, share_ref)

    def _validate_manage_parameters(self, context, body):
        if not (body and self.is_valid_body(body, 'share')):
            msg = _("Share entity not found in request body")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        required_parameters = ('export_path', 'service_host', 'protocol')

        data = body['share']

        for parameter in required_parameters:
            if parameter not in data:
                msg = _("Required parameter %s not found") % parameter
                raise exc.HTTPUnprocessableEntity(explanation=msg)
            if not data.get(parameter):
                msg = _("Required parameter %s is empty") % parameter
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
        except exception.AdminRequired as e:
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


class ShareManageController(ShareManageMixin, wsgi.Controller):
    """Allows existing share to be 'managed' by Manila."""

    resource_name = "share"
    _view_builder_class = share_views.ViewBuilder

    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.share_api = share.API()

    @wsgi.Controller.api_version('1.0', '2.6')
    def create(self, req, body):
        """Legacy method for 'manage share' operation.

        Should be removed when minimum API version becomes equal to or
        greater than v2.7
        """
        body.get('share', {}).pop('is_public', None)
        return self._manage(req, body)


def create_resource():
    return wsgi.Resource(ShareManageController())
