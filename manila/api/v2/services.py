# Copyright 2012 IBM Corp.
# Copyright (c) 2015 Mirantis inc.
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

import http.client as http_client

from oslo_log import log
from oslo_utils import strutils
import webob.exc

from manila.api.openstack import wsgi
from manila.api.schemas import services as schema
from manila.api import validation
from manila.api.views import services as services_views
from manila.common import constants
from manila import db
from manila import exception
from manila.i18n import _
from manila.services import api as service_api

LOG = log.getLogger(__name__)


class ServiceMixin(object):
    """The Services API controller common logic.

    Mixin class that should be inherited by Services API controllers,
    which are used for different API URLs and microversions.
    """

    resource_name = "service"
    _view_builder_class = services_views.ViewBuilder

    @wsgi.Controller.authorize("index")
    def _index(self, req, support_filtering_by_ensure=False):
        """Return a list of all running services."""

        context = req.environ['manila.context']
        filters = {}
        filters.update(req.GET)

        # NOTE(carloss): support_filtering_by_ensure's only purpose is to
        # determine whether this operation is supported or not. No other
        # validations should depend on it.

        if not support_filtering_by_ensure and filters.get('ensuring'):
            filters.pop('ensuring')

        ensuring = filters.get('ensuring')
        if ensuring is not None:
            try:
                filters['ensuring'] = strutils.bool_from_string(
                    ensuring, strict=True)
            except ValueError:
                msg = _("An invalid value was provided for 'ensuring'. "
                        "Acceptable values are: 'true' or 'false'.")
                LOG.warning(msg)
                return self._view_builder.detail_list(req, [])

        status = filters.get('status')
        valid_statuses = [constants.STATUS_DISABLED, constants.STATUS_ENABLED]
        if status and status not in valid_statuses:
            # NOTE(carloss): Let's maintain backwards compatibility. If the
            # status provided doesn't exist, it is not a bad request, only a
            # user mistake.
            msg = _("An invalid status was provided. Please choose from "
                    "one of the valid statuses while filtering services: "
                    "%s.") % valid_statuses
            LOG.warning(msg)
            return self._view_builder.detail_list(req, [])

        try:
            services = db.service_get_all_with_filters(context, filters)
        except exception.AvailabilityZoneNotFound:
            # NOTE(carloss): we're maintaining backwards compatibility by
            # keeping the behavior where in case an invalid availability zone
            # ID or name is provided, we return an empty list instead of raise
            # an exception.
            services = []

        return self._view_builder.detail_list(req, services)

    @wsgi.Controller.authorize("update")
    def _update(self, req, id, body, support_disabled_reason=True):
        """Enable/Disable scheduling for a service."""
        context = req.environ['manila.context']
        update_dict = {}

        if id == "enable":
            data = {'disabled': False}
            if support_disabled_reason:
                update_dict['disabled_reason'] = None
        elif id == "disable":
            data = {'disabled': True}
            disabled_reason = body.get('disabled_reason')
            if disabled_reason and not support_disabled_reason:
                msg = _("'disabled_reason' option is not supported by this "
                        "microversion. Use 2.83 or greater microversion to "
                        "be able to set 'disabled_reason'.")
                raise webob.exc.HTTPBadRequest(explanation=msg)
            if disabled_reason:
                try:
                    strutils.check_string_length(disabled_reason.strip(),
                                                 name='disabled_reason',
                                                 min_length=1,
                                                 max_length=255)
                except (ValueError, TypeError):
                    msg = _('Disabled reason contains invalid characters '
                            'or is too long')
                    raise webob.exc.HTTPBadRequest(explanation=msg)
                update_dict['disabled_reason'] = disabled_reason.strip()
                data['disabled_reason'] = disabled_reason.strip()
        else:
            raise webob.exc.HTTPNotFound("Unknown action '%s'" % id)

        try:
            data['host'] = body['host']
            data['binary'] = body['binary']
        except (TypeError, KeyError):
            raise webob.exc.HTTPBadRequest()

        svc = db.service_get_by_args(context, data['host'], data['binary'])
        update_dict['disabled'] = data['disabled']

        db.service_update(context, svc['id'], update_dict)
        data['status'] = 'disabled' if id == "disable" else 'enabled'

        return self._view_builder.summary(req, data)


class ServiceControllerLegacy(ServiceMixin, wsgi.Controller):
    """Deprecated Services API controller.

    Used from microversions 2.0 to 2.6. Registered under deprecated API URL
    'os-services'.
    """

    @wsgi.Controller.api_version('2.0', '2.6')
    def index(self, req):
        return self._index(req)

    @wsgi.Controller.api_version('2.0', '2.6')
    def update(self, req, id, body):
        return self._update(req, id, body, support_disabled_reason=False)


class ServiceController(ServiceMixin, wsgi.Controller):
    """Services API controller.

    Used from microversion 2.7. Registered under API URL 'services'.
    """

    def __init__(self):
        super().__init__()
        self.service_api = service_api.API()

    @wsgi.Controller.api_version('2.7', '2.85')
    def index(self, req):
        return self._index(req)

    @wsgi.Controller.api_version('2.86', '2.92') # noqa
    def index(self, req): # pylint: disable=function-redefined  # noqa F811
        return self._index(req)

    @wsgi.Controller.api_version('2.93')  # noqa
    def index(self, req):  # pylint: disable=function-redefined  # noqa F811
        return self._index(req, support_filtering_by_ensure=True)

    @wsgi.Controller.api_version('2.7', '2.82')
    def update(self, req, id, body):
        return self._update(req, id, body, support_disabled_reason=False)

    @wsgi.Controller.api_version('2.83') # noqa
    def update(self, req, id, body): # pylint: disable=function-redefined  # noqa F811
        return self._update(req, id, body)

    @wsgi.Controller.api_version('2.86')
    @wsgi.Controller.authorize
    @validation.request_body_schema(schema.ensure_shares_request_body)
    @validation.response_body_schema(schema.ensure_shares_response_body)
    def ensure_shares(self, req, body):
        """Starts ensure shares for a given manila-share binary."""
        context = req.environ['manila.context']

        host = body['ensure_shares']['host']

        try:
            # The only binary supported is Manila share.
            service = db.service_get_by_args(context, host, 'manila-share')
        except exception.NotFound:
            raise webob.exc.HTTPNotFound(
                "manila-share binary for '%s' host not found" % id
            )

        try:
            self.service_api.ensure_shares(context, service, host)
        except webob.exc.HTTPConflict:
            raise

        return webob.Response(status_int=http_client.ACCEPTED)


def create_resource_legacy():
    return wsgi.Resource(ServiceControllerLegacy())


def create_resource():
    return wsgi.Resource(ServiceController())
