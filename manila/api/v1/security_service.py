# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 Mirantis Inc.
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

"""The security service api."""

import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import security_service as security_service_views
from manila.api import xmlutil
from manila.common import constants
from manila import db
from manila import exception
from manila.openstack.common import log as logging
from manila import policy


LOG = logging.getLogger(__name__)


def make_security_service(elem):
    attrs = ['id', 'name', 'description', 'type', 'server', 'domain', 'sid',
             'dns_ip', 'status', 'updated_at', 'created_at']
    for attr in attrs:
        elem.set(attr)


class SecurityServiceTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('security_service',
                                       selector='security_service')
        make_security_service(root)
        return xmlutil.MasterTemplate(root, 1)


class SecurityServicesTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('security_services')
        elem = xmlutil.SubTemplateElement(root, 'security_service',
                                          selector='security_services')
        make_security_service(elem)
        return xmlutil.MasterTemplate(root, 1)


class SecurityServiceController(wsgi.Controller):
    """The Shares API controller for the OpenStack API."""

    _view_builder_class = security_service_views.ViewBuilder

    @wsgi.serializers(xml=SecurityServiceTemplate)
    def show(self, req, id):
        """Return data about the given security service."""
        context = req.environ['manila.context']
        try:
            security_service = db.security_service_get(context, id)
            policy.check_policy(context, 'show', security_service)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, security_service)

    def delete(self, req, id):
        """Delete a security service."""
        context = req.environ['manila.context']

        LOG.audit(_("Delete security service with id: %s"),
                  id, context=context)

        try:
            security_service = db.security_service_get(context, id)
            policy.check_policy(context, 'show', security_service)
            db.security_service_delete(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()
        except exception.InvalidShare:
            raise exc.HTTPForbidden()

        return webob.Response(status_int=202)

    @wsgi.serializers(xml=SecurityServicesTemplate)
    def index(self, req):
        """Returns a summary list of security services."""
        return self._get_security_services(req, is_detail=False)

    @wsgi.serializers(xml=SecurityServicesTemplate)
    def detail(self, req):
        """Returns a detailed list of security services."""
        return self._get_security_services(req, is_detail=True)

    def _get_security_services(self, req, is_detail):
        """Returns a list of security services, transformed through view
           builder.
        """
        context = req.environ['manila.context']
        policy.check_policy(context, 'get_all_security_services')

        search_opts = {}
        search_opts.update(req.GET)

        common.remove_invalid_options(
            context, search_opts, self._get_security_services_search_options())
        if 'all_tenants' in search_opts:
            security_services = db.security_service_get_all(context)
            del search_opts['all_tenants']
        else:
            security_services = db.security_service_get_all_by_project(
                context, context.project_id)

        if search_opts:
            results = []
            not_found = object()
            for service in security_services:
                for opt, value in search_opts.iteritems():
                    if service.get(opt, not_found) != value:
                        break
                else:
                    results.append(service)
            security_services = results

        limited_list = common.limited(security_services, req)

        if is_detail:
            security_services = self._view_builder.detail_list(
                req, limited_list)
        else:
            security_services = self._view_builder.summary_list(
                req, limited_list)
        return security_services

    def _get_security_services_search_options(self):
        return ('status', 'name', 'id')

    @wsgi.serializers(xml=SecurityServicesTemplate)
    def update(self, req, id, body):
        """Update a security service."""
        context = req.environ['manila.context']

        if not body or 'security_service' not in body:
            raise exc.HTTPUnprocessableEntity()

        security_service_data = body['security_service']
        valid_update_keys = (
            'description',
            'name'
        )

        try:
            security_service = db.security_service_get(context, id)
            policy.check_policy(context, 'show', security_service)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        if security_service['status'].lower() in ['new', 'inactive']:
            update_dict = security_service_data
        else:
            update_dict = dict([(key, security_service_data[key])
                                for key in valid_update_keys
                                if key in security_service_data])

        security_service = db.security_service_update(context, id, update_dict)
        return self._view_builder.detail(req, security_service)

    @wsgi.serializers(xml=SecurityServicesTemplate)
    def create(self, req, body):
        """Creates a new security service."""
        context = req.environ['manila.context']
        policy.check_policy(context, 'create')

        if not self.is_valid_body(body, 'security_service'):
            raise exc.HTTPUnprocessableEntity()

        security_service_args = body['security_service']
        security_srv_type = security_service_args.get('type')
        allowed_types = constants.SECURITY_SERVICES_ALLOWED_TYPES
        if security_srv_type not in allowed_types:
            raise exception.InvalidInput(
                reason=(_("Invalid type %(type)s specified for security "
                          "service. Valid types are %(types)s") %
                        {'type': security_srv_type,
                         'types': ','.join(allowed_types)}))
        security_service_args['project_id'] = context.project_id
        security_service = db.security_service_create(
            context, security_service_args)

        return self._view_builder.detail(req, security_service)


def create_resource():
    return wsgi.Resource(SecurityServiceController())
