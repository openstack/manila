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

from oslo_log import log
import webob.exc

from manila.api.openstack import wsgi
from manila.api.views import services as services_views
from manila import db
from manila import utils

LOG = log.getLogger(__name__)


class ServiceController(wsgi.Controller):
    """The Services API controller for the OpenStack API."""

    resource_name = "service"
    _view_builder_class = services_views.ViewBuilder

    def index(self, req):
        """Return a list of all running services."""

        context = req.environ['manila.context']
        self.authorize(context, 'index')
        all_services = db.service_get_all(context)

        services = []
        for service in all_services:
            service = {
                'id': service['id'],
                'binary': service['binary'],
                'host': service['host'],
                'zone': service['availability_zone']['name'],
                'status': 'disabled' if service['disabled'] else 'enabled',
                'state': 'up' if utils.service_is_up(service) else 'down',
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
            value = ''
            if search_opt in req.GET:
                value = req.GET[search_opt]
                services = [s for s in services if s[search_opt] == value]
            if len(services) == 0:
                break

        return self._view_builder.detail_list(services)

    def update(self, req, id, body):
        """Enable/Disable scheduling for a service."""
        context = req.environ['manila.context']
        self.authorize(context, 'update')

        if id == "enable":
            data = {'disabled': False}
        elif id == "disable":
            data = {'disabled': True}
        else:
            raise webob.exc.HTTPNotFound("Unknown action '%s'" % id)

        try:
            data['host'] = body['host']
            data['binary'] = body['binary']
        except (TypeError, KeyError):
            raise webob.exc.HTTPBadRequest()

        svc = db.service_get_by_args(context, data['host'], data['binary'])
        db.service_update(
            context, svc['id'], {'disabled': data['disabled']})

        return self._view_builder.summary(data)


def create_resource():
    return wsgi.Resource(ServiceController())
