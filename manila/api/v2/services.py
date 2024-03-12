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

from oslo_utils import strutils
import webob.exc

from manila.api.openstack import wsgi
from manila.api.views import services as services_views
from manila import db
from manila.i18n import _


class ServiceMixin(object):
    """The Services API controller common logic.

    Mixin class that should be inherited by Services API controllers,
    which are used for different API URLs and microversions.
    """

    resource_name = "service"
    _view_builder_class = services_views.ViewBuilder

    @wsgi.Controller.authorize("index")
    def _index(self, req):
        """Return a list of all running services."""

        context = req.environ['manila.context']
        all_services = db.service_get_all(context)

        services = []
        for service in all_services:
            service = {
                'id': service['id'],
                'binary': service['binary'],
                'host': service['host'],
                'zone': service['availability_zone']['name'],
                'status': 'disabled' if service['disabled'] else 'enabled',
                'disabled_reason': service.get('disabled_reason'),
                'state': service['state'],
                'updated_at': service['updated_at'],
            }
            services.append(service)

        search_opts = [
            'host',
            'binary',
            'zone',
            'state',
            'status',
        ]
        for search_opt in search_opts:
            if search_opt in req.GET:
                value = req.GET[search_opt]
                services = [s for s in services if s[search_opt] == value]
            if len(services) == 0:
                break

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

    Used by legacy API v1 and v2 microversions from 2.0 to 2.6.
    Registered under deprecated API URL 'os-services'.
    """

    @wsgi.Controller.api_version('1.0', '2.6')
    def index(self, req):
        return self._index(req)

    @wsgi.Controller.api_version('1.0', '2.6')
    def update(self, req, id, body):
        return self._update(req, id, body, support_disabled_reason=False)


class ServiceController(ServiceMixin, wsgi.Controller):
    """Services API controller.

    Used only by API v2 starting from microversion 2.7.
    Registered under API URL 'services'.
    """

    @wsgi.Controller.api_version('2.7')
    def index(self, req):
        return self._index(req)

    @wsgi.Controller.api_version('2.7', '2.82')
    def update(self, req, id, body):
        return self._update(req, id, body, support_disabled_reason=False)

    @wsgi.Controller.api_version('2.83') # noqa
    def update(self, req, id, body): # pylint: disable=function-redefined  # noqa F811
        return self._update(req, id, body)


def create_resource_legacy():
    return wsgi.Resource(ServiceControllerLegacy())


def create_resource():
    return wsgi.Resource(ServiceController())
