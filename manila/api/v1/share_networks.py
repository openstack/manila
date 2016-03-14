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

from oslo_db import exception as db_exception
from oslo_log import log
from oslo_utils import timeutils
import six
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import share_networks as share_networks_views
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW
from manila import policy
from manila import quota
from manila.share import rpcapi as share_rpcapi

RESOURCE_NAME = 'share_network'
RESOURCES_NAME = 'share_networks'
LOG = log.getLogger(__name__)
QUOTAS = quota.QUOTAS


class ShareNetworkController(wsgi.Controller):
    """The Share Network API controller for the OpenStack API."""

    _view_builder_class = share_networks_views.ViewBuilder

    def __init__(self):
        super(ShareNetworkController, self).__init__()
        self.share_rpcapi = share_rpcapi.ShareAPI()

    def show(self, req, id):
        """Return data about the requested network info."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'show')

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=six.text_type(e))

        return self._view_builder.build_share_network(share_network)

    def delete(self, req, id):
        """Delete specified share network."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'delete')

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=six.text_type(e))

        share_instances = (
            db_api.share_instances_get_all_by_share_network(context, id)
        )
        if share_instances:
            msg = _("Can not delete share network %(id)s, it has "
                    "%(len)s share(s).") % {'id': id,
                                            'len': len(share_instances)}
            LOG.error(msg)
            raise exc.HTTPConflict(explanation=msg)

        # NOTE(ameade): Do not allow deletion of share network used by CG
        cg_count = db_api.count_consistency_groups_in_share_network(context,
                                                                    id)
        if cg_count:
            msg = _("Can not delete share network %(id)s, it has %(len)s "
                    "consistency group(s).") % {'id': id, 'len': cg_count}
            LOG.error(msg)
            raise exc.HTTPConflict(explanation=msg)

        for share_server in share_network['share_servers']:
            self.share_rpcapi.delete_share_server(context, share_server)
        db_api.share_network_delete(context, id)

        try:
            reservations = QUOTAS.reserve(
                context, project_id=share_network['project_id'],
                share_networks=-1, user_id=share_network['user_id'])
        except Exception:
            LOG.exception(_LE("Failed to update usages deleting "
                              "share-network."))
        else:
            QUOTAS.commit(context, reservations,
                          project_id=share_network['project_id'],
                          user_id=share_network['user_id'])
        return webob.Response(status_int=202)

    def _get_share_networks(self, req, is_detail=True):
        """Returns a list of share networks."""
        context = req.environ['manila.context']
        search_opts = {}
        search_opts.update(req.GET)

        if ('all_tenants' in search_opts or
            ('project_id' in search_opts and
             search_opts['project_id'] != context.project_id)):
                policy.check_policy(context, RESOURCE_NAME,
                                    'get_all_share_networks')

        if 'security_service_id' in search_opts:
            networks = db_api.share_network_get_all_by_security_service(
                context, search_opts['security_service_id'])
        elif ('project_id' in search_opts and
              search_opts['project_id'] != context.project_id):
            networks = db_api.share_network_get_all_by_project(
                context, search_opts['project_id'])
        elif 'all_tenants' in search_opts:
            networks = db_api.share_network_get_all(context)
        else:
            networks = db_api.share_network_get_all_by_project(
                context,
                context.project_id)

        date_parsing_error_msg = '''%s is not in yyyy-mm-dd format.'''
        if 'created_since' in search_opts:
            try:
                created_since = timeutils.parse_strtime(
                    search_opts['created_since'],
                    fmt="%Y-%m-%d")
            except ValueError:
                msg = date_parsing_error_msg % search_opts['created_since']
                raise exc.HTTPBadRequest(explanation=msg)
            networks = [network for network in networks
                        if network['created_at'] >= created_since]
        if 'created_before' in search_opts:
            try:
                created_before = timeutils.parse_strtime(
                    search_opts['created_before'],
                    fmt="%Y-%m-%d")
            except ValueError:
                msg = date_parsing_error_msg % search_opts['created_before']
                raise exc.HTTPBadRequest(explanation=msg)
            networks = [network for network in networks
                        if network['created_at'] <= created_before]
        opts_to_remove = [
            'all_tenants',
            'created_since',
            'created_before',
            'limit',
            'offset',
            'security_service_id',
        ]
        for opt in opts_to_remove:
            search_opts.pop(opt, None)
        if search_opts:
            for key, value in search_opts.items():
                if key in ['ip_version', 'segmentation_id']:
                    value = int(value)
                networks = [network for network in networks
                            if network[key] == value]

        limited_list = common.limited(networks, req)
        return self._view_builder.build_share_networks(limited_list, is_detail)

    def index(self, req):
        """Returns a summary list of share networks."""
        policy.check_policy(req.environ['manila.context'], RESOURCE_NAME,
                            'index')
        return self._get_share_networks(req, is_detail=False)

    def detail(self, req):
        """Returns a detailed list of share networks."""
        policy.check_policy(req.environ['manila.context'], RESOURCE_NAME,
                            'detail')
        return self._get_share_networks(req)

    @staticmethod
    def _verify_no_mutually_exclusive_data(share_network, update_data=None):
        update_data = update_data or dict()
        neutron_net_id = (
            share_network.get('neutron_net_id') or
            update_data.get('neutron_net_id'))
        neutron_subnet_id = (
            share_network.get('neutron_subnet_id') or
            update_data.get('neutron_subnet_id'))
        nova_net_id = (
            share_network.get('nova_net_id') or
            update_data.get('nova_net_id'))
        if nova_net_id and (neutron_net_id or neutron_subnet_id):
            msg = _("Neutron net data and Nova net data are mutually "
                    "exclusive. Only one of these are allowed at a time.")
            raise exc.HTTPBadRequest(explanation=msg)

    def update(self, req, id, body):
        """Update specified share network."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'update')

        if not body or RESOURCE_NAME not in body:
            raise exc.HTTPUnprocessableEntity()

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=six.text_type(e))

        update_values = body[RESOURCE_NAME]

        self._verify_no_mutually_exclusive_data(share_network, update_values)
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

    def create(self, req, body):
        """Creates a new share network."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'create')

        if not body or RESOURCE_NAME not in body:
            raise exc.HTTPUnprocessableEntity()

        values = body[RESOURCE_NAME]
        values['project_id'] = context.project_id
        values['user_id'] = context.user_id
        self._verify_no_mutually_exclusive_data(values)

        try:
            reservations = QUOTAS.reserve(context, share_networks=1)
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'share_networks' in overs:
                LOG.warning(_LW("Quota exceeded for %(s_pid)s, "
                                "tried to create "
                                "share-network (%(d_consumed)d of %(d_quota)d "
                                "already consumed)."), {
                                    's_pid': context.project_id,
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

    def action(self, req, id, body):
        _actions = {
            'add_security_service': self._add_security_service,
            'remove_security_service': self._remove_security_service
        }
        for action, data in body.items():
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
            raise exc.HTTPNotFound(explanation=six.text_type(e))
        except exception.ShareNetworkSecurityServiceAssociationError as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))

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
            raise exc.HTTPNotFound(explanation=six.text_type(e))
        except exception.ShareNetworkSecurityServiceDissociationError as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))

        return self._view_builder.build_share_network(share_network)


def create_resource():
    return wsgi.Resource(ShareNetworkController())
