# Copyright 2014 NetApp
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

"""The shares api."""

import webob
from webob import exc

from manila.api.openstack import wsgi
from manila.api.views import share_networks as share_networks_views
from manila.api import xmlutil
from manila.common import constants
from manila.db import api as db_api
from manila import exception
from manila.openstack.common import log as logging

RESOURCE_NAME = 'share_network'
RESOURCES_NAME = 'share_networks'
LOG = logging.getLogger(__name__)
SHARE_NETWORK_ATTRS = ('id',
                       'project_id',
                       'created_at',
                       'updated_at',
                       'neutron_net_id',
                       'neutron_subnet_id',
                       'network_type',
                       'segmentation_id',
                       'cidr',
                       'ip_version',
                       'name',
                       'description',
                       'status')


def _make_share_network(elem):
    for attr in SHARE_NETWORK_ATTRS:
        elem.set(attr)


class ShareNetworkTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement(RESOURCE_NAME, selector=RESOURCE_NAME)
        _make_share_network(root)
        return xmlutil.MasterTemplate(root, 1)


class ShareNetworksTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement(RESOURCES_NAME)
        elem = xmlutil.SubTemplateElement(root, RESOURCE_NAME,
                                          selector=RESOURCES_NAME)
        _make_share_network(elem)
        return xmlutil.MasterTemplate(root, 1)


class ShareNetworkController(wsgi.Controller):
    """The Share Network API controller for the OpenStack API."""

    _view_builder_class = share_networks_views.ViewBuilder

    @wsgi.serializers(xml=ShareNetworkTemplate)
    def show(self, req, id):
        """Return data about the requested network info."""
        context = req.environ['manila.context']

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            msg = "%s" % e
            raise exc.HTTPNotFound(explanation=msg)

        return self._view_builder.build_share_network(share_network)

    def delete(self, req, id):
        """Delete specified share network."""
        context = req.environ['manila.context']

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            msg = "%s" % e
            raise exc.HTTPNotFound(explanation=msg)

        if share_network['status'] == constants.STATUS_ACTIVE:
            msg = "Network %s is in use" % id
            raise exc.HTTPBadRequest(explanation=msg)

        db_api.share_network_delete(context, id)

        return webob.Response(status_int=202)

    @wsgi.serializers(xml=ShareNetworksTemplate)
    def index(self, req):
        """Returns a summary list of share's networks."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        if search_opts.pop('all_tenants', None):
            networks = db_api.share_network_get_all(context)
        else:
            networks = db_api.share_network_get_all_by_project(
                            context,
                            context.project_id)

        if search_opts:
            for key, value in search_opts.iteritems():
                networks = [network for network in networks
                            if network[key] == value]
        return self._view_builder.build_share_networks(networks)

    @wsgi.serializers(xml=ShareNetworkTemplate)
    def update(self, req, id, body):
        """Update specified share network."""
        context = req.environ['manila.context']

        if not body or RESOURCE_NAME not in body:
            raise exc.HTTPUnprocessableEntity()

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            msg = "%s" % e
            raise exc.HTTPNotFound(explanation=msg)

        if share_network['status'] == constants.STATUS_ACTIVE:
            msg = "Network %s is in use" % id
            raise exc.HTTPBadRequest(explanation=msg)

        update_values = body[RESOURCE_NAME]

        try:
            share_network = db_api.share_network_update(context,
                                                        id,
                                                        update_values)
        except exception.DBError:
            msg = "Could not save supplied data due to database error"
            raise exc.HTTPBadRequest(explanation=msg)

        return self._view_builder.build_share_network(share_network)

    @wsgi.serializers(xml=ShareNetworkTemplate)
    def create(self, req, body):
        """Creates a new share network."""
        context = req.environ['manila.context']

        if not body or RESOURCE_NAME not in body:
            raise exc.HTTPUnprocessableEntity()

        values = body[RESOURCE_NAME]
        values['project_id'] = context.project_id

        try:
            share_network = db_api.share_network_create(context, values)
        except exception.DBError:
            msg = "Could not save supplied data due to database error"
            raise exc.HTTPBadRequest(explanation=msg)

        return self._view_builder.build_share_network(share_network)

    @wsgi.serializers(xml=ShareNetworkTemplate)
    def action(self, req, id, body):
        _actions = {
            'add_security_service': self._add_security_service,
            'remove_security_service': self._remove_security_service,
        }
        for action, data in body.iteritems():
            try:
                return _actions[action](req, id, data)
            except KeyError:
                msg = _("Share networks does not have %s action") % action
                raise exc.HTTPBadRequest(explanation=msg)

    def _add_security_service(self, req, id, data):
        context = req.environ['manila.context']
        try:
            share_network = db_api.share_network_add_security_service(
                                context,
                                id,
                                data['security_service_id'])
        except KeyError:
            msg = "Malformed request body"
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.NotFound as e:
            msg = "%s" % e
            raise exc.HTTPNotFound(explanation=msg)
        except exception.ShareNetworkSecurityServiceAssociationError as e:
            msg = "%s" % e
            raise exc.HTTPBadRequest(explanation=msg)

        return self._view_builder.build_share_network(share_network)

    def _remove_security_service(self, req, id, data):
        context = req.environ['manila.context']
        try:
            share_network = db_api.share_network_remove_security_service(
                                context,
                                id,
                                data['security_service_id'])
        except KeyError:
            msg = "Malformed request body"
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.NotFound as e:
            msg = "%s" % e
            raise exc.HTTPNotFound(explanation=msg)
        except exception.ShareNetworkSecurityServiceDissociationError as e:
            msg = "%s" % e
            raise exc.HTTPBadRequest(explanation=msg)

        return self._view_builder.build_share_network(share_network)


def create_resource():
    return wsgi.Resource(ShareNetworkController())
