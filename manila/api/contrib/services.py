# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 IBM Corp.
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

import webob.exc

from manila.api import extensions
from manila.api.openstack import wsgi
from manila.api import xmlutil
from manila import db
from manila import exception
from manila.openstack.common import log as logging
from manila.openstack.common import timeutils
from manila import utils


LOG = logging.getLogger(__name__)
authorize = extensions.extension_authorizer('share', 'services')


class ServicesIndexTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('services')
        elem = xmlutil.SubTemplateElement(root, 'service', selector='services')
        elem.set('binary')
        elem.set('host')
        elem.set('zone')
        elem.set('status')
        elem.set('state')
        elem.set('update_at')

        return xmlutil.MasterTemplate(root, 1)


class ServicesUpdateTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('host')
        root.set('host')
        root.set('disabled')
        root.set('binary')
        root.set('status')

        return xmlutil.MasterTemplate(root, 1)


class ServiceController(object):
    @wsgi.serializers(xml=ServicesIndexTemplate)
    def index(self, req):
        """Return a list of all running services. """
        context = req.environ['manila.context']
        authorize(context)
        now = timeutils.utcnow()
        all_services = db.service_get_all(context)

        services = []
        for service in all_services:
            service = {
                'binary': service['binary'],
                'host': service['host'],
                'zone': service['availability_zone'],
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

        return {'services': services}

    @wsgi.serializers(xml=ServicesUpdateTemplate)
    def update(self, req, id, body):
        """Enable/Disable scheduling for a service"""
        context = req.environ['manila.context']
        authorize(context)

        if id == "enable":
            disabled = False
        elif id == "disable":
            disabled = True
        else:
            raise webob.exc.HTTPNotFound("Unknown action")

        try:
            host = body['host']
            binary = body['binary']
        except (TypeError, KeyError):
            raise webob.exc.HTTPBadRequest()

        try:
            svc = db.service_get_by_args(context, host, binary)
            if not svc:
                raise webob.exc.HTTPNotFound('Unknown service')

            db.service_update(context, svc['id'], {'disabled': disabled})
        except exception.ServiceNotFound:
            raise webob.exc.HTTPNotFound("service not found")

        return {'host': host, 'binary': binary, 'disabled': disabled}


class Services(extensions.ExtensionDescriptor):
    """Services support"""

    name = "Services"
    alias = "os-services"
    namespace = "http://docs.openstack.org/volume/ext/services/api/v2"
    updated = "2012-10-28T00:00:00-00:00"

    def get_resources(self):
        resources = []
        resource = extensions.ResourceExtension('os-services',
                                                ServiceController())
        resources.append(resource)
        return resources
