# Copyright 2019 NetApp, Inc.
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

from oslo_log import log
from six.moves import http_client
import webob
from webob import exc

from manila.api.openstack import wsgi
from manila.api.v1 import share_servers
from manila.common import constants
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila.share import utils as share_utils
from manila import utils

LOG = log.getLogger(__name__)


class ShareServerController(share_servers.ShareServerController,
                            wsgi.AdminActionsMixin):
    """The Share Server API V2 controller for the OpenStack API."""

    valid_statuses = {
        'status': {
            constants.STATUS_ACTIVE,
            constants.STATUS_ERROR,
            constants.STATUS_DELETING,
            constants.STATUS_CREATING,
            constants.STATUS_MANAGING,
            constants.STATUS_UNMANAGING,
            constants.STATUS_UNMANAGE_ERROR,
            constants.STATUS_MANAGE_ERROR,
        }
    }

    def _update(self, context, id, update):
        db_api.share_server_update(context, id, update)

    @wsgi.Controller.api_version('2.49')
    @wsgi.action('reset_status')
    def share_server_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version("2.49")
    @wsgi.Controller.authorize('manage_share_server')
    @wsgi.response(202)
    def manage(self, req, body):
        """Manage a share server."""
        context = req.environ['manila.context']
        identifier, host, share_network, driver_opts = (
            self._validate_manage_share_server_parameters(context, body))

        try:
            result = self.share_api.manage_share_server(
                context, identifier, host, share_network, driver_opts)
        except exception.InvalidInput as e:
            raise exc.HTTPBadRequest(explanation=e)

        result.project_id = share_network["project_id"]
        if result.share_network['name']:
            result.share_network_name = result.share_network['name']
        else:
            result.share_network_name = result.share_network_id
        return self._view_builder.build_share_server(req, result)

    @wsgi.Controller.authorize('unmanage_share_server')
    def _unmanage(self, req, id, body=None):
        context = req.environ['manila.context']

        LOG.debug("Unmanage Share Server with id: %s", id)

        # force's default value is False
        # force will be True if body is {'unmanage': {'force': True}}
        force = (body.get('unmanage') or {}).get('force', False) or False

        try:
            share_server = db_api.share_server_get(
                context, id)
        except exception.ShareServerNotFound as e:
            raise exc.HTTPNotFound(explanation=e)

        allowed_statuses = [constants.STATUS_ERROR, constants.STATUS_ACTIVE,
                            constants.STATUS_MANAGE_ERROR,
                            constants.STATUS_UNMANAGE_ERROR]
        if share_server['status'] not in allowed_statuses:
            data = {
                'status': share_server['status'],
                'allowed_statuses': ', '.join(allowed_statuses),
            }
            msg = _("Share server's actual status is %(status)s, allowed "
                    "statuses for unmanaging are "
                    "%(allowed_statuses)s.") % data
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            self.share_api.unmanage_share_server(
                context, share_server, force=force)
        except (exception.ShareServerInUse,
                exception.PolicyNotAuthorized) as e:
            raise exc.HTTPBadRequest(explanation=e)

        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version("2.49")
    @wsgi.action('unmanage')
    def unmanage(self, req, id, body=None):
        """Unmanage a share server."""
        return self._unmanage(req, id, body)

    def _validate_manage_share_server_parameters(self, context, body):

        if not (body and self.is_valid_body(body, 'share_server')):
            msg = _("Share Server entity not found in request body")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        required_parameters = ('host', 'share_network_id', 'identifier')
        data = body['share_server']

        for parameter in required_parameters:
            if parameter not in data:
                msg = _("Required parameter %s not found") % parameter
                raise exc.HTTPBadRequest(explanation=msg)
            if not data.get(parameter):
                msg = _("Required parameter %s is empty") % parameter
                raise exc.HTTPBadRequest(explanation=msg)

        identifier = data['identifier']
        host, share_network_id = data['host'], data['share_network_id']

        if share_utils.extract_host(host, 'pool'):
            msg = _("Host parameter should not contain pool.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            utils.validate_service_host(
                context, share_utils.extract_host(host))
        except exception.ServiceNotFound as e:
            raise exc.HTTPBadRequest(explanation=e)
        except exception.PolicyNotAuthorized as e:
            raise exc.HTTPForbidden(explanation=e)
        except exception.AdminRequired as e:
            raise exc.HTTPForbidden(explanation=e)
        except exception.ServiceIsDown as e:
            raise exc.HTTPBadRequest(explanation=e)

        try:
            share_network = db_api.share_network_get(
                context, share_network_id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPBadRequest(explanation=e)

        driver_opts = data.get('driver_options')
        if driver_opts is not None and not isinstance(driver_opts, dict):
            msg = _("Driver options must be in dictionary format.")
            raise exc.HTTPBadRequest(explanation=msg)

        return identifier, host, share_network, driver_opts


def create_resource():
    return wsgi.Resource(ShareServerController())
