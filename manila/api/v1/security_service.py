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

from oslo_log import log
import six
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import security_service as security_service_views
from manila.common import constants
from manila import db
from manila import exception
from manila.i18n import _
from manila.i18n import _LI
from manila import policy


RESOURCE_NAME = 'security_service'
LOG = log.getLogger(__name__)


class SecurityServiceController(wsgi.Controller):
    """The Shares API controller for the OpenStack API."""

    _view_builder_class = security_service_views.ViewBuilder

    def show(self, req, id):
        """Return data about the given security service."""
        context = req.environ['manila.context']
        try:
            security_service = db.security_service_get(context, id)
            policy.check_policy(context, RESOURCE_NAME, 'show',
                                security_service)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, security_service)

    def delete(self, req, id):
        """Delete a security service."""
        context = req.environ['manila.context']

        LOG.info(_LI("Delete security service with id: %s"),
                 id, context=context)

        try:
            security_service = db.security_service_get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        share_nets = db.share_network_get_all_by_security_service(
            context, id)
        if share_nets:
            # Cannot delete security service
            # if it is assigned to share networks
            raise exc.HTTPForbidden()
        policy.check_policy(context, RESOURCE_NAME,
                            'delete', security_service)
        db.security_service_delete(context, id)

        return webob.Response(status_int=202)

    def index(self, req):
        """Returns a summary list of security services."""
        policy.check_policy(req.environ['manila.context'], RESOURCE_NAME,
                            'index')
        return self._get_security_services(req, is_detail=False)

    def detail(self, req):
        """Returns a detailed list of security services."""
        policy.check_policy(req.environ['manila.context'], RESOURCE_NAME,
                            'detail')
        return self._get_security_services(req, is_detail=True)

    def _get_security_services(self, req, is_detail):
        """Returns a transformed list of security services.

        The list gets transformed through view builder.
        """
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # NOTE(vponomaryov): remove 'status' from search opts
        # since it was removed from security service model.
        search_opts.pop('status', None)
        if 'share_network_id' in search_opts:
            share_nw = db.share_network_get(context,
                                            search_opts['share_network_id'])
            security_services = share_nw['security_services']
            del search_opts['share_network_id']
        else:
            if 'all_tenants' in search_opts:
                policy.check_policy(context, RESOURCE_NAME,
                                    'get_all_security_services')
                security_services = db.security_service_get_all(context)
            else:
                security_services = db.security_service_get_all_by_project(
                    context, context.project_id)
        search_opts.pop('all_tenants', None)
        common.remove_invalid_options(
            context,
            search_opts,
            self._get_security_services_search_options())
        if search_opts:
            results = []
            not_found = object()
            for ss in security_services:
                if all(ss.get(opt, not_found) == value for opt, value in
                       six.iteritems(search_opts)):
                    results.append(ss)
            security_services = results

        limited_list = common.limited(security_services, req)

        if is_detail:
            security_services = self._view_builder.detail_list(
                req, limited_list)
            for ss in security_services['security_services']:
                share_networks = db.share_network_get_all_by_security_service(
                    context,
                    ss['id'])
                ss['share_networks'] = [sn['id'] for sn in share_networks]
        else:
            security_services = self._view_builder.summary_list(
                req, limited_list)
        return security_services

    def _get_security_services_search_options(self):
        return ('name', 'id', 'type', 'user',
                'server', 'dns_ip', 'domain', )

    def _share_servers_dependent_on_sn_exist(self, context,
                                             security_service_id):
        share_networks = db.share_network_get_all_by_security_service(
            context, security_service_id)
        for sn in share_networks:
            if sn['share_servers']:
                return True
        return False

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
            policy.check_policy(context, RESOURCE_NAME, 'update',
                                security_service)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        if self._share_servers_dependent_on_sn_exist(context, id):
            for item in security_service_data:
                if item not in valid_update_keys:
                    msg = _("Cannot update security service %s. It is "
                            "attached to share network with share server "
                            "associated. Only 'name' and 'description' "
                            "fields are available for update.") % id
                    raise exc.HTTPForbidden(explanation=msg)

        policy.check_policy(context, RESOURCE_NAME, 'update', security_service)
        security_service = db.security_service_update(
            context, id, security_service_data)
        return self._view_builder.detail(req, security_service)

    def create(self, req, body):
        """Creates a new security service."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'create')

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
