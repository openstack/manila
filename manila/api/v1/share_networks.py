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

from oslo.db import exception as db_exception
import six
import webob
from webob import exc

from manila.api.openstack import wsgi
from manila.api.views import share_networks as share_networks_views
from manila.api import xmlutil
from manila.db import api as db_api
from manila import exception
from manila.openstack.common import log as logging
from manila import policy
from manila import quota
from manila.share import rpcapi as share_rpcapi

RESOURCE_NAME = 'share_network'
RESOURCES_NAME = 'share_networks'
LOG = logging.getLogger(__name__)
QUOTAS = quota.QUOTAS
SHARE_NETWORK_ATTRS = (
    'id',
    'project_id',
    'user_id',
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
)


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

    def __init__(self):
        super(ShareNetworkController, self).__init__()
        self.share_rpcapi = share_rpcapi.ShareAPI()

    @wsgi.serializers(xml=ShareNetworkTemplate)
    def show(self, req, id):
        """Return data about the requested network info."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'show')

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            msg = "%s" % e
            raise exc.HTTPNotFound(explanation=msg)

        return self._view_builder.build_share_network(share_network)

    def delete(self, req, id):
        """Delete specified share network."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'delete')

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            msg = "%s" % e
            raise exc.HTTPNotFound(explanation=msg)
        if share_network['share_servers']:
            msg = _("Cannot delete share network %s. "
                    "There are share servers using it") % id
            raise exc.HTTPForbidden(explanation=msg)
        db_api.share_network_delete(context, id)

        try:
            reservations = QUOTAS.reserve(
                context, project_id=share_network['project_id'],
                share_networks=-1)
        except Exception:
            msg = _("Failed to update usages deleting share-network.")
            LOG.exception(msg)
        else:
            QUOTAS.commit(context, reservations,
                          project_id=share_network['project_id'])
        return webob.Response(status_int=202)

    @wsgi.serializers(xml=ShareNetworksTemplate)
    def _get_share_networks(self, req, is_detail=True):
        """Returns a list of share networks."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'index')

        search_opts = {}
        search_opts.update(req.GET)

        if search_opts.pop('all_tenants', None):
            networks = db_api.share_network_get_all(context)
        else:
            networks = db_api.share_network_get_all_by_project(
                context,
                context.project_id)

        if search_opts:
            for key, value in six.iteritems(search_opts):
                networks = [network for network in networks
                            if network[key] == value]
        return self._view_builder.build_share_networks(networks, is_detail)

    @wsgi.serializers(xml=ShareNetworksTemplate)
    def index(self, req):
        """Returns a summary list of share networks."""
        return self._get_share_networks(req, is_detail=False)

    @wsgi.serializers(xml=ShareNetworksTemplate)
    def detail(self, req):
        """Returns a detailed list of share networks."""
        return self._get_share_networks(req)

    @wsgi.serializers(xml=ShareNetworkTemplate)
    def update(self, req, id, body):
        """Update specified share network."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'update')

        if not body or RESOURCE_NAME not in body:
            raise exc.HTTPUnprocessableEntity()

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            msg = "%s" % e
            raise exc.HTTPNotFound(explanation=msg)

        update_values = body[RESOURCE_NAME]

        if share_network['share_servers']:
            for value in update_values:
                if value not in ['name', 'description']:
                    msg = _("Cannot update share network %s. It is used by "
                            "share servers. Only 'name' and 'description' "
                            "fields are available for update")\
                        % share_network['id']
                    raise exc.HTTPForbidden(explanation=msg)

        try:
            share_network = db_api.share_network_update(context,
                                                        id,
                                                        update_values)
        except db_exception.DBError:
            msg = "Could not save supplied data due to database error"
            raise exc.HTTPBadRequest(explanation=msg)

        return self._view_builder.build_share_network(share_network)

    @wsgi.serializers(xml=ShareNetworkTemplate)
    def create(self, req, body):
        """Creates a new share network."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'create')

        if not body or RESOURCE_NAME not in body:
            raise exc.HTTPUnprocessableEntity()

        values = body[RESOURCE_NAME]
        values['project_id'] = context.project_id

        try:
            reservations = QUOTAS.reserve(context, share_networks=1)
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'share_networks' in overs:
                msg = _("Quota exceeded for %(s_pid)s, tried to create "
                        "share-network (%(d_consumed)d of %(d_quota)d "
                        "already consumed)")
                LOG.warn(msg, {'s_pid': context.project_id,
                               'd_consumed': _consumed('share_networks'),
                               'd_quota': quotas['share_networks']})
                raise exception.ShareNetworksLimitExceeded(
                    allowed=quotas['share_networks'])
        else:
            try:
                share_network = db_api.share_network_create(context, values)
            except db_exception.DBError:
                msg = "Could not save supplied data due to database error"
                raise exc.HTTPBadRequest(explanation=msg)

            QUOTAS.commit(context, reservations)
            return self._view_builder.build_share_network(share_network)

    @wsgi.serializers(xml=ShareNetworkTemplate)
    def action(self, req, id, body):
        _actions = {
            'add_security_service': self._add_security_service,
            'remove_security_service': self._remove_security_service
        }
        for action, data in six.iteritems(body):
            try:
                return _actions[action](req, id, data)
            except KeyError:
                msg = _("Share networks does not have %s action") % action
                raise exc.HTTPBadRequest(explanation=msg)

    def _add_security_service(self, req, id, data):
        """Associate share network with a given security service."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'add_security_service')
        share_network = db_api.share_network_get(context, id)
        if share_network['share_servers']:
            msg = _("Cannot add security services. Share network is used.")
            raise exc.HTTPForbidden(explanation=msg)
        security_service = db_api.security_service_get(
            context, data['security_service_id'])
        for attached_service in share_network['security_services']:
            if attached_service['type'] == security_service['type']:
                msg = _("Cannot add security service to share network. "
                        "Security service with '%(ss_type)s' type already "
                        "added to '%(sn_id)s' share network") % {
                            'ss_type': security_service['type'],
                            'sn_id': share_network['id']}
                raise exc.HTTPConflict(explanation=msg)
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
        """Dissociate share network from a given security service."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'remove_security_service')
        share_network = db_api.share_network_get(context, id)
        if share_network['share_servers']:
            msg = _("Cannot remove security services. Share network is used.")
            raise exc.HTTPForbidden(explanation=msg)
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
