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

from http import client as http_client

from oslo_log import log
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.v1 import share_servers
from manila.api.views import share_server_migration as server_migration_views
from manila.common import constants
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila.share import utils as share_utils
from manila import utils

LOG = log.getLogger(__name__)


class ShareServerController(share_servers.ShareServerController,
                            wsgi.Controller,
                            wsgi.AdminActionsMixin):
    """The Share Server API V2 controller for the OpenStack API."""

    def __init__(self):
        super(ShareServerController, self).__init__()
        self._migration_view_builder = server_migration_views.ViewBuilder()

    valid_statuses = {
        'status': set(constants.SHARE_SERVER_STATUSES),
        'task_state': set(constants.SERVER_TASK_STATE_STATUSES),
    }

    def _update(self, context, id, update):
        db_api.share_server_update(context, id, update)

    @wsgi.Controller.api_version('2.49')
    @wsgi.action('reset_status')
    def share_server_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.authorize('manage_share_server')
    def _manage(self, req, body):
        """Manage a share server."""
        LOG.debug("Manage Share Server with id: %s", id)

        context = req.environ['manila.context']
        identifier, host, share_network, driver_opts, network_subnet = (
            self._validate_manage_share_server_parameters(context, body))

        try:
            result = self.share_api.manage_share_server(
                context, identifier, host, network_subnet, driver_opts)
        except exception.InvalidInput as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.PolicyNotAuthorized as e:
            raise exc.HTTPForbidden(explanation=e.msg)

        result.project_id = share_network["project_id"]
        if share_network['name']:
            result.share_network_name = share_network['name']
        else:
            result.share_network_name = share_network['id']
        return self._view_builder.build_share_server(req, result)

    @wsgi.Controller.api_version('2.51')
    @wsgi.response(202)
    def manage(self, req, body):
        return self._manage(req, body)

    @wsgi.Controller.api_version('2.49')  # noqa
    @wsgi.response(202)
    def manage(self, req, body):  # pylint: disable=function-redefined  # noqa F811
        body.get('share_server', {}).pop('share_network_subnet_id', None)
        return self._manage(req, body)

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
            raise exc.HTTPNotFound(explanation=e.msg)

        if len(share_server['share_network_subnets']) > 1:
            msg = _("Cannot unmanage the share server containing multiple "
                    "subnets.")
            raise exc.HTTPBadRequest(explanation=msg)

        share_network_id = share_server['share_network_id']
        share_network = db_api.share_network_get(context, share_network_id)
        common.check_share_network_is_active(share_network)

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
            raise exc.HTTPBadRequest(explanation=e.msg)

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

        network_subnet_id = data.get('share_network_subnet_id')
        if network_subnet_id:
            try:
                network_subnets = (
                    db_api.share_network_subnet_get_all_with_same_az(
                        context, network_subnet_id))
            except exception.ShareNetworkSubnetNotFound:
                msg = _("The share network subnet %s does not "
                        "exist.") % network_subnet_id
                raise exc.HTTPBadRequest(explanation=msg)
        else:
            network_subnets = db_api.share_network_subnet_get_default_subnets(
                context, share_network_id)

        if not network_subnets:
            msg = _("The share network %s does have a default subnet. Create "
                    "one or use a specific subnet to manage this share server "
                    "with API version >= 2.51.") % share_network_id
            raise exc.HTTPBadRequest(explanation=msg)

        if len(network_subnets) > 1:
            msg = _("Cannot manage the share server, since the share network "
                    "subnet %s has more subnets in its availability "
                    "zone and share network.") % network_subnet_id
            raise exc.HTTPBadRequest(explanation=msg)

        network_subnet = network_subnets[0]
        common.check_share_network_is_active(network_subnet['share_network'])

        if share_utils.extract_host(host, 'pool'):
            msg = _("Host parameter should not contain pool.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            utils.validate_service_host(
                context, share_utils.extract_host(host))
        except exception.ServiceNotFound as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.PolicyNotAuthorized as e:
            raise exc.HTTPForbidden(explanation=e.msg)
        except exception.AdminRequired as e:
            raise exc.HTTPForbidden(explanation=e.msg)
        except exception.ServiceIsDown as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        try:
            share_network = db_api.share_network_get(
                context, share_network_id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        driver_opts = data.get('driver_options')
        if driver_opts is not None and not isinstance(driver_opts, dict):
            msg = _("Driver options must be in dictionary format.")
            raise exc.HTTPBadRequest(explanation=msg)

        return identifier, host, share_network, driver_opts, network_subnet

    @wsgi.Controller.api_version('2.57', experimental=True)
    @wsgi.action("migration_start")
    @wsgi.Controller.authorize
    @wsgi.response(http_client.ACCEPTED)
    def share_server_migration_start(self, req, id, body):
        """Migrate a share server to the specified host."""
        context = req.environ['manila.context']
        try:
            share_server = db_api.share_server_get(
                context, id)
        except exception.ShareServerNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        params = body.get('migration_start')

        if not params:
            raise exc.HTTPBadRequest(explanation=_("Request is missing body."))

        bool_params = ['writable', 'nondisruptive', 'preserve_snapshots']
        mandatory_params = bool_params + ['host']

        utils.check_params_exist(mandatory_params, params)
        bool_param_values = utils.check_params_are_boolean(bool_params, params)

        pool_was_specified = len(params['host'].split('#')) > 1

        if pool_was_specified:
            msg = _('The destination host can not contain pool information.')
            raise exc.HTTPBadRequest(explanation=msg)

        new_share_network = None

        new_share_network_id = params.get('new_share_network_id', None)
        if new_share_network_id:
            try:
                new_share_network = db_api.share_network_get(
                    context, new_share_network_id)
            except exception.NotFound:
                msg = _("Share network %s not "
                        "found.") % new_share_network_id
                raise exc.HTTPBadRequest(explanation=msg)
            common.check_share_network_is_active(new_share_network)
        else:
            share_network_id = (
                share_server['share_network_id'])
            current_share_network = db_api.share_network_get(
                context, share_network_id)
            common.check_share_network_is_active(current_share_network)

        try:
            self.share_api.share_server_migration_start(
                context, share_server, params['host'],
                bool_param_values['writable'],
                bool_param_values['nondisruptive'],
                bool_param_values['preserve_snapshots'],
                new_share_network=new_share_network)
        except exception.ServiceIsDown as e:
            # NOTE(dviroel): user should check if the host is healthy
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.InvalidShareServer as e:
            # NOTE(dviroel): invalid share server meaning that some internal
            # resource have a invalid state.
            raise exc.HTTPConflict(explanation=e.msg)
        except exception.InvalidInput as e:
            # User provided controversial parameters in the request
            raise exc.HTTPBadRequest(explanation=e.msg)

    @wsgi.Controller.api_version('2.57', experimental=True)
    @wsgi.action("migration_complete")
    @wsgi.Controller.authorize
    def share_server_migration_complete(self, req, id, body):
        """Invokes 2nd phase of share server migration."""
        context = req.environ['manila.context']
        try:
            share_server = db_api.share_server_get(
                context, id)
        except exception.ShareServerNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        try:
            result = self.share_api.share_server_migration_complete(
                context, share_server)
        except (exception.InvalidShareServer,
                exception.ServiceIsDown) as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        return self._migration_view_builder.migration_complete(req, result)

    @wsgi.Controller.api_version('2.57', experimental=True)
    @wsgi.action("migration_cancel")
    @wsgi.Controller.authorize
    @wsgi.response(http_client.ACCEPTED)
    def share_server_migration_cancel(self, req, id, body):
        """Attempts to cancel share migration."""
        context = req.environ['manila.context']
        try:
            share_server = db_api.share_server_get(
                context, id)
        except exception.ShareServerNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        try:
            self.share_api.share_server_migration_cancel(context, share_server)
        except (exception.InvalidShareServer,
                exception.ServiceIsDown) as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

    @wsgi.Controller.api_version('2.57', experimental=True)
    @wsgi.action("migration_get_progress")
    @wsgi.Controller.authorize
    def share_server_migration_get_progress(self, req, id, body):
        """Retrieve share server migration progress for a given share."""
        context = req.environ['manila.context']
        try:
            result = self.share_api.share_server_migration_get_progress(
                context, id)
        except exception.ServiceIsDown as e:
            raise exc.HTTPConflict(explanation=e.msg)
        except exception.InvalidShareServer as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        return self._migration_view_builder.get_progress(req, result)

    @wsgi.Controller.api_version('2.57', experimental=True)
    @wsgi.action("reset_task_state")
    @wsgi.Controller.authorize
    def share_server_reset_task_state(self, req, id, body):
        return self._reset_status(req, id, body, status_attr='task_state')

    @wsgi.Controller.api_version('2.57', experimental=True)
    @wsgi.action("migration_check")
    @wsgi.Controller.authorize
    def share_server_migration_check(self, req, id, body):
        """Check if can migrate a share server to the specified host."""
        context = req.environ['manila.context']
        try:
            share_server = db_api.share_server_get(
                context, id)
        except exception.ShareServerNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        params = body.get('migration_check')

        if not params:
            raise exc.HTTPBadRequest(explanation=_("Request is missing body."))

        bool_params = ['writable', 'nondisruptive', 'preserve_snapshots']
        mandatory_params = bool_params + ['host']

        utils.check_params_exist(mandatory_params, params)
        bool_param_values = utils.check_params_are_boolean(bool_params, params)

        pool_was_specified = len(params['host'].split('#')) > 1

        if pool_was_specified:
            msg = _('The destination host can not contain pool information.')
            raise exc.HTTPBadRequest(explanation=msg)

        new_share_network = None
        new_share_network_id = params.get('new_share_network_id', None)
        if new_share_network_id:
            try:
                new_share_network = db_api.share_network_get(
                    context, new_share_network_id)
            except exception.NotFound:
                msg = _("Share network %s not "
                        "found.") % new_share_network_id
                raise exc.HTTPBadRequest(explanation=msg)
            common.check_share_network_is_active(new_share_network)
        else:
            share_network_id = (
                share_server['share_network_id'])
            current_share_network = db_api.share_network_get(
                context, share_network_id)
            common.check_share_network_is_active(current_share_network)

        try:
            result = self.share_api.share_server_migration_check(
                context, share_server, params['host'],
                bool_param_values['writable'],
                bool_param_values['nondisruptive'],
                bool_param_values['preserve_snapshots'],
                new_share_network=new_share_network)
        except exception.ServiceIsDown as e:
            # NOTE(dviroel): user should check if the host is healthy
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.InvalidShareServer as e:
            # NOTE(dviroel): invalid share server meaning that some internal
            # resource have a invalid state.
            raise exc.HTTPConflict(explanation=e.msg)

        return self._migration_view_builder.build_check_migration(
            req, params, result)


def create_resource():
    return wsgi.Resource(ShareServerController())
