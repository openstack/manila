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

import copy
from http import client as http_client

from oslo_db import exception as db_exception
from oslo_log import log
from oslo_utils import timeutils
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.views import share_networks as share_networks_views
from manila.common import constants
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila import policy
from manila import quota
from manila import share
from manila.share import rpcapi as share_rpcapi
from manila import utils

RESOURCE_NAME = 'share_network'
RESOURCES_NAME = 'share_networks'
LOG = log.getLogger(__name__)
QUOTAS = quota.QUOTAS


class ShareNetworkController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The Share Network API controller for the OpenStack API."""

    resource_name = 'share_network'
    _view_builder_class = share_networks_views.ViewBuilder

    def __init__(self):
        super(ShareNetworkController, self).__init__()
        self.share_rpcapi = share_rpcapi.ShareAPI()
        self.share_api = share.API()

    valid_statuses = {
        'status': set(constants.SHARE_NETWORK_STATUSES)
    }

    def show(self, req, id):
        """Return data about the requested network info."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'show')

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        return self._view_builder.build_share_network(req, share_network)

    def _all_share_servers_are_auto_deletable(self, share_network):
        return all([ss['is_auto_deletable'] for ss
                    in share_network['share_servers']])

    def _share_network_contains_subnets(self, share_network):
        return len(share_network['share_network_subnets']) > 1

    def _update(self, *args, **kwargs):
        db_api.share_network_update(*args, **kwargs)

    def delete(self, req, id):
        """Delete specified share network."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'delete')

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        share_instances = (
            db_api.share_instances_get_all_by_share_network(context, id)
        )
        if share_instances:
            msg = _("Can not delete share network %(id)s, it has "
                    "%(len)s share(s).") % {'id': id,
                                            'len': len(share_instances)}
            LOG.error(msg)
            raise exc.HTTPConflict(explanation=msg)

        # NOTE(ameade): Do not allow deletion of share network used by share
        # group
        sg_count = db_api.count_share_groups_in_share_network(context, id)
        if sg_count:
            msg = _("Can not delete share network %(id)s, it has %(len)s "
                    "share group(s).") % {'id': id, 'len': sg_count}
            LOG.error(msg)
            raise exc.HTTPConflict(explanation=msg)

        # NOTE(silvacarlose): Do not allow the deletion of share networks
        # if it still contains two or more subnets
        if self._share_network_contains_subnets(share_network):
            msg = _("The share network %(id)s has more than one subnet "
                    "attached. Please remove the subnets untill you have one "
                    "or no subnets remaining.") % {'id': id}
            LOG.error(msg)
            raise exc.HTTPConflict(explanation=msg)

        for subnet in share_network['share_network_subnets']:
            if not self._all_share_servers_are_auto_deletable(subnet):
                msg = _("The service cannot determine if there are any "
                        "non-managed shares on the share network subnet "
                        "%(id)s, so it cannot be deleted. Please contact the "
                        "cloud administrator to rectify.") % {
                    'id': subnet['id']}
                LOG.error(msg)
                raise exc.HTTPConflict(explanation=msg)

        for subnet in share_network['share_network_subnets']:
            for share_server in subnet['share_servers']:
                self.share_rpcapi.delete_share_server(context, share_server)

        db_api.share_network_delete(context, id)

        try:
            reservations = QUOTAS.reserve(
                context, project_id=share_network['project_id'],
                share_networks=-1, user_id=share_network['user_id'])
        except Exception:
            LOG.exception("Failed to update usages deleting "
                          "share-network.")
        else:
            QUOTAS.commit(context, reservations,
                          project_id=share_network['project_id'],
                          user_id=share_network['user_id'])
        return webob.Response(status_int=http_client.ACCEPTED)

    def _subnet_has_search_opt(self, key, value, network, exact_value=False):
        for subnet in network.get('share_network_subnets') or []:
            if subnet.get(key) == value or (
                    not exact_value and
                    value in subnet.get(key.rstrip('~'))
                    if key.endswith('~') and
                    subnet.get(key.rstrip('~')) else ()):
                return True
        return False

    def _get_share_networks(self, req, is_detail=True):
        """Returns a list of share networks."""
        context = req.environ['manila.context']
        search_opts = {}
        search_opts.update(req.GET)
        filters = {}

        # if not context.is_admin, will ignore project_id and all_tenants here,
        # in database will auto add context.project_id to search_opts.
        if context.is_admin:
            if 'project_id' in search_opts:
                # if specified project_id, will not use all_tenants
                filters['project_id'] = search_opts['project_id']
            elif not utils.is_all_tenants(search_opts):
                # if not specified project_id and all_tenants, will get
                # share networks in admin project.
                filters['project_id'] = context.project_id

        date_parsing_error_msg = '''%s is not in yyyy-mm-dd format.'''
        for time_comparison_filter in ['created_since', 'created_before']:
            if time_comparison_filter in search_opts:
                time_str = search_opts.get(time_comparison_filter)
                try:
                    parsed_time = timeutils.parse_strtime(time_str,
                                                          fmt="%Y-%m-%d")
                except ValueError:
                    msg = date_parsing_error_msg % time_str
                    raise exc.HTTPBadRequest(explanation=msg)

                filters[time_comparison_filter] = parsed_time

        if 'security_service_id' in search_opts:
            filters['security_service_id'] = search_opts.get(
                'security_service_id')

        networks = db_api.share_network_get_all_by_filter(context,
                                                          filters=filters)

        opts_to_remove = [
            'all_tenants',
            'created_since',
            'created_before',
            'limit',
            'offset',
            'security_service_id',
            'project_id'
        ]
        for opt in opts_to_remove:
            search_opts.pop(opt, None)
        if search_opts:
            for key, value in search_opts.items():
                if key in ['ip_version', 'segmentation_id']:
                    value = int(value)
                if (req.api_version_request >=
                        api_version.APIVersionRequest("2.36")):
                    networks = [
                        network for network in networks
                        if network.get(key) == value or
                        self._subnet_has_search_opt(key, value, network) or
                        (value in network.get(key.rstrip('~'))
                            if key.endswith('~') and
                            network.get(key.rstrip('~')) else ())]
                else:
                    networks = [
                        network for network in networks
                        if network.get(key) == value or
                        self._subnet_has_search_opt(key, value, network,
                                                    exact_value=True)]

        limited_list = common.limited(networks, req)
        return self._view_builder.build_share_networks(
            req, limited_list, is_detail)

    def _share_network_subnets_contain_share_servers(self, share_network):
        for subnet in share_network['share_network_subnets']:
            if subnet['share_servers'] and len(subnet['share_servers']) > 0:
                return True
        return False

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

    def update(self, req, id, body):
        """Update specified share network."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'update')

        if not body or RESOURCE_NAME not in body:
            raise exc.HTTPUnprocessableEntity()

        try:
            share_network = db_api.share_network_get(context, id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        update_values = body[RESOURCE_NAME]

        if 'nova_net_id' in update_values:
            msg = _("nova networking is not supported starting in Ocata.")
            raise exc.HTTPBadRequest(explanation=msg)

        if self._share_network_subnets_contain_share_servers(share_network):
            for value in update_values:
                if value not in ['name', 'description']:
                    msg = (_("Cannot update share network %s. It is used by "
                             "share servers. Only 'name' and 'description' "
                             "fields are available for update") %
                           share_network['id'])
                    raise exc.HTTPForbidden(explanation=msg)
        try:
            if ('neutron_net_id' in update_values or
                    'neutron_subnet_id' in update_values):
                subnets = db_api.share_network_subnet_get_default_subnets(
                    context, id)
                if not subnets:
                    msg = _("The share network %(id)s does not have a "
                            "'default' subnet that serves all availability "
                            "zones, so subnet details "
                            "('neutron_net_id', 'neutron_subnet_id') cannot "
                            "be updated.") % {'id': id}
                    raise exc.HTTPBadRequest(explanation=msg)
                if len(subnets) > 1:
                    msg = _("The share network %(id)s does not have an unique "
                            "'default' subnet that serves all availability "
                            "zones, so subnet details "
                            "('neutron_net_id', 'neutron_subnet_id') cannot "
                            "be updated.") % {'id': id}
                    raise exc.HTTPBadRequest(explanation=msg)
                subnet = subnets[0]

                # NOTE(silvacarlose): If the default share network subnet have
                # the fields neutron_net_id and neutron_subnet_id set as None,
                # we need to make sure that in the update request the user is
                # passing both parameter since a share network subnet must
                # have both fields filled or empty.
                subnet_neutron_net_and_subnet_id_are_empty = (
                    subnet['neutron_net_id'] is None
                    and subnet['neutron_subnet_id'] is None)
                update_values_without_neutron_net_or_subnet = (
                    update_values.get('neutron_net_id') is None or
                    update_values.get('neutron_subnet_id') is None)
                if (subnet_neutron_net_and_subnet_id_are_empty
                        and update_values_without_neutron_net_or_subnet):
                    msg = _(
                        "To update the share network %(id)s you need to "
                        "specify both 'neutron_net_id' and "
                        "'neutron_subnet_id'.") % {'id': id}
                    raise webob.exc.HTTPBadRequest(explanation=msg)
                db_api.share_network_subnet_update(context,
                                                   subnet['id'],
                                                   update_values)
            share_network = db_api.share_network_update(context,
                                                        id,
                                                        update_values)
        except db_exception.DBError:
            msg = "Could not save supplied data due to database error"
            raise exc.HTTPBadRequest(explanation=msg)

        return self._view_builder.build_share_network(req, share_network)

    def create(self, req, body):
        """Creates a new share network."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'create')

        if not body or RESOURCE_NAME not in body:
            raise exc.HTTPUnprocessableEntity()

        share_network_values = body[RESOURCE_NAME]
        share_network_subnet_values = copy.deepcopy(share_network_values)
        share_network_values['project_id'] = context.project_id
        share_network_values['user_id'] = context.user_id

        if 'nova_net_id' in share_network_values:
            msg = _("nova networking is not supported starting in Ocata.")
            raise exc.HTTPBadRequest(explanation=msg)

        share_network_values.pop('availability_zone', None)
        share_network_values.pop('neutron_net_id', None)
        share_network_values.pop('neutron_subnet_id', None)

        if req.api_version_request >= api_version.APIVersionRequest("2.51"):
            if 'availability_zone' in share_network_subnet_values:
                try:
                    az = db_api.availability_zone_get(
                        context,
                        share_network_subnet_values['availability_zone'])
                    share_network_subnet_values['availability_zone_id'] = (
                        az['id'])
                    share_network_subnet_values.pop('availability_zone')
                except exception.AvailabilityZoneNotFound:
                    msg = (_("The provided availability zone %s does not "
                             "exist.")
                           % share_network_subnet_values['availability_zone'])
                    raise exc.HTTPBadRequest(explanation=msg)

        common.check_net_id_and_subnet_id(share_network_subnet_values)

        try:
            reservations = QUOTAS.reserve(context, share_networks=1)
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'share_networks' in overs:
                LOG.warning("Quota exceeded for %(s_pid)s, "
                            "tried to create "
                            "share-network (%(d_consumed)d of %(d_quota)d "
                            "already consumed).", {
                                's_pid': context.project_id,
                                'd_consumed': _consumed('share_networks'),
                                'd_quota': quotas['share_networks']})
                raise exception.ShareNetworksLimitExceeded(
                    allowed=quotas['share_networks'])
        else:
            # Tries to create the new share network
            try:
                share_network = db_api.share_network_create(
                    context, share_network_values)
            except db_exception.DBError as e:
                QUOTAS.rollback(context, reservations)
                LOG.exception(e)
                msg = "Could not create share network."
                raise exc.HTTPInternalServerError(explanation=msg)

            share_network_subnet_values['share_network_id'] = (
                share_network['id'])
            share_network_subnet_values.pop('id', None)

            # Try to create the share network subnet. If it fails, the service
            # must rollback the share network creation.
            try:
                db_api.share_network_subnet_create(
                    context, share_network_subnet_values)
            except db_exception.DBError:
                db_api.share_network_delete(context, share_network['id'])
                QUOTAS.rollback(context, reservations)
                msg = _('Could not create share network subnet.')
                raise exc.HTTPInternalServerError(explanation=msg)

            QUOTAS.commit(context, reservations)
            share_network = db_api.share_network_get(context,
                                                     share_network['id'])
            return self._view_builder.build_share_network(req, share_network)

    @wsgi.action("add_security_service")
    def add_security_service(self, req, id, body):
        """Associate share network with a given security service."""
        context = req.environ['manila.context']
        share_network = db_api.share_network_get(context, id)
        policy.check_policy(context, RESOURCE_NAME, 'add_security_service',
                            target_obj=share_network)
        try:
            data = body['add_security_service']

            security_service = db_api.security_service_get(
                context, data['security_service_id'])
        except KeyError:
            msg = "Malformed request body"
            raise exc.HTTPBadRequest(explanation=msg)

        contain_share_servers = (
            self._share_network_subnets_contain_share_servers(share_network))

        support_adding_to_in_use_networks = (
            req.api_version_request >= api_version.APIVersionRequest("2.63"))

        if contain_share_servers:
            if not support_adding_to_in_use_networks:
                msg = _("Cannot add security services. Share network is used.")
                raise exc.HTTPForbidden(explanation=msg)
        try:
            self.share_api.update_share_network_security_service(
                context, share_network, security_service)
        except exception.ServiceIsDown as e:
            raise exc.HTTPConflict(explanation=e.msg)
        except exception.InvalidShareNetwork as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.InvalidSecurityService as e:
            raise exc.HTTPConflict(explanation=e.msg)

        try:
            share_network = db_api.share_network_add_security_service(
                context,
                id,
                data['security_service_id'])
        except exception.NotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)
        except exception.ShareNetworkSecurityServiceAssociationError as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        return self._view_builder.build_share_network(req, share_network)

    @wsgi.action('remove_security_service')
    def remove_security_service(self, req, id, body):
        """Dissociate share network from a given security service."""
        context = req.environ['manila.context']
        share_network = db_api.share_network_get(context, id)
        policy.check_policy(context, RESOURCE_NAME, 'remove_security_service',
                            target_obj=share_network)
        data = body['remove_security_service']

        if self._share_network_subnets_contain_share_servers(share_network):
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
            raise exc.HTTPNotFound(explanation=e.msg)
        except exception.ShareNetworkSecurityServiceDissociationError as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        return self._view_builder.build_share_network(req, share_network)

    @wsgi.Controller.api_version('2.63')
    @wsgi.action('update_security_service')
    @wsgi.response(202)
    def update_security_service(self, req, id, body):
        """Update security service parameters from a given share network."""
        context = req.environ['manila.context']
        share_network = db_api.share_network_get(context, id)
        policy.check_policy(context, RESOURCE_NAME, 'update_security_service',
                            target_obj=share_network)
        try:
            data = body['update_security_service']

            current_security_service = db_api.security_service_get(
                context, data['current_service_id']
            )
            new_security_service = db_api.security_service_get(
                context, data['new_service_id']
            )
        except KeyError:
            msg = "Malformed request body."
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.NotFound:
            msg = ("The current security service or the new security service "
                   "doesn't exist.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            self.share_api.update_share_network_security_service(
                context, share_network, new_security_service,
                current_security_service=current_security_service)
        except exception.ServiceIsDown as e:
            raise exc.HTTPConflict(explanation=e.msg)
        except exception.InvalidShareNetwork as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.InvalidSecurityService as e:
            raise exc.HTTPConflict(explanation=e.msg)

        try:
            share_network = db_api.share_network_update_security_service(
                context,
                id,
                data['current_service_id'],
                data['new_service_id'])
        except exception.NotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)
        except (exception.ShareNetworkSecurityServiceDissociationError,
                exception.ShareNetworkSecurityServiceAssociationError) as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        return self._view_builder.build_share_network(req, share_network)

    @wsgi.Controller.api_version('2.63')
    @wsgi.action('update_security_service_check')
    @wsgi.response(202)
    def check_update_security_service(self, req, id, body):
        """Check the feasibility of updating a security service."""
        context = req.environ['manila.context']
        share_network = db_api.share_network_get(context, id)
        policy.check_policy(context, RESOURCE_NAME,
                            'update_security_service_check',
                            target_obj=share_network)
        try:
            data = body['update_security_service_check']

            current_security_service = db_api.security_service_get(
                context, data['current_service_id']
            )
            new_security_service = db_api.security_service_get(
                context, data['new_service_id']
            )
        except KeyError:
            msg = "Malformed request body."
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.NotFound:
            msg = ("The current security service or the new security service "
                   "doesn't exist.")
            raise exc.HTTPBadRequest(explanation=msg)

        reset_check = utils.get_bool_from_api_params('reset_operation', data)

        try:
            result = (
                self.share_api.check_share_network_security_service_update(
                    context, share_network, new_security_service,
                    current_security_service=current_security_service,
                    reset_operation=reset_check))
        except exception.ServiceIsDown as e:
            raise exc.HTTPConflict(explanation=e.msg)
        except exception.InvalidShareNetwork as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.InvalidSecurityService as e:
            raise exc.HTTPConflict(explanation=e.msg)

        return self._view_builder.build_security_service_update_check(
            req, data, result)

    @wsgi.Controller.api_version('2.63')
    @wsgi.action("add_security_service_check")
    @wsgi.response(202)
    def check_add_security_service(self, req, id, body):
        """Check the feasibility of associate a new security service."""
        context = req.environ['manila.context']
        share_network = db_api.share_network_get(context, id)
        policy.check_policy(context, RESOURCE_NAME,
                            'add_security_service_check',
                            target_obj=share_network)
        data = body['add_security_service_check']
        try:
            security_service = db_api.security_service_get(
                context, data['security_service_id'], project_only=True)
        except KeyError:
            msg = "Malformed request body."
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.NotFound:
            msg = ("Security service %s doesn't exist."
                   ) % data['security_service_id']
            raise exc.HTTPBadRequest(explanation=msg)

        reset_check = utils.get_bool_from_api_params('reset_operation', data)

        try:
            result = (
                self.share_api.check_share_network_security_service_update(
                    context, share_network, security_service,
                    reset_operation=reset_check))
        except exception.ServiceIsDown as e:
            raise exc.HTTPConflict(explanation=e.msg)
        except exception.InvalidShareNetwork as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.InvalidSecurityService as e:
            raise exc.HTTPConflict(explanation=e.msg)

        return self._view_builder.build_security_service_update_check(
            req, data, result)

    @wsgi.Controller.api_version('2.70')
    @wsgi.action('share_network_subnet_create_check')
    @wsgi.response(202)
    def share_network_subnet_create_check(self, req, id, body):
        """Check the feasibility of creating a share network subnet."""
        context = req.environ['manila.context']
        if not self.is_valid_body(body, 'share_network_subnet_create_check'):
            msg = _("Share Network Subnet Create Check is missing from "
                    "the request body.")
            raise exc.HTTPBadRequest(explanation=msg)
        data = body['share_network_subnet_create_check']
        share_network, existing_subnets = common.validate_subnet_create(
            context, id, data, True)

        reset_check = utils.get_bool_from_api_params('reset_operation', data)

        # create subnet operation alongside subnets with share servers means
        # that an allocation update is requested.
        if existing_subnets and existing_subnets[0]['share_servers']:

            # NOTE(felipe_rodrigues): all subnets within the same az have the
            # same set of share servers, so we can just get the servers from
            # one of them. Not necessarily all share servers from the specified
            # AZ will be updated, only the ones created with subnets in the AZ.
            # Others created with default AZ will only have its allocations
            # updated when default subnet set is updated.
            data['share_servers'] = existing_subnets[0]['share_servers']
            try:
                check_result = (
                    self.share_api.
                    check_update_share_server_network_allocations(
                        context, share_network, data, reset_check))
            except exception.ServiceIsDown as e:
                msg = _("A share network subnet update check cannot be "
                        "performed at this time.")
                LOG.error(e)
                raise exc.HTTPInternalServerError(explanation=msg)
            except exception.InvalidShareNetwork as e:
                raise exc.HTTPBadRequest(explanation=e.msg)
        else:
            check_result = {
                'compatible': True,
                'hosts_check_result': {}
            }

        return self._view_builder.build_share_network_subnet_create_check(
            req, check_result)

    @wsgi.Controller.api_version('2.63')
    @wsgi.action('reset_status')
    def reset_status(self, req, id, body):
        return self._reset_status(req, id, body)


def create_resource():
    return wsgi.Resource(ShareNetworkController())
