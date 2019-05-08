# Copyright 2019 NetApp, Inc.
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


from manila.api import common
from oslo_db import exception as db_exception
from oslo_log import log
from six.moves import http_client
import webob
from webob import exc

from manila.api.openstack import wsgi
from manila.api.views import share_network_subnets as subnet_views
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila.share import rpcapi as share_rpcapi

LOG = log.getLogger(__name__)


class ShareNetworkSubnetController(wsgi.Controller):
    """The Share Network Subnet API controller for the OpenStack API."""

    resource_name = 'share_network_subnet'
    _view_builder_class = subnet_views.ViewBuilder

    def __init__(self):
        super(ShareNetworkSubnetController, self).__init__()
        self.share_rpcapi = share_rpcapi.ShareAPI()

    @wsgi.Controller.api_version("2.51")
    @wsgi.Controller.authorize
    def index(self, req, share_network_id):
        """Returns a list of share network subnets."""
        context = req.environ['manila.context']

        try:
            share_network = db_api.share_network_get(context, share_network_id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        return self._view_builder.build_share_network_subnets(
            req, share_network.get('share_network_subnets'))

    def _all_share_servers_are_auto_deletable(self, share_network_subnet):
        return all([ss['is_auto_deletable'] for ss
                    in share_network_subnet['share_servers']])

    @wsgi.Controller.api_version('2.51')
    @wsgi.Controller.authorize
    def delete(self, req, share_network_id, share_network_subnet_id):
        """Delete specified share network subnet."""
        context = req.environ['manila.context']

        try:
            db_api.share_network_get(context, share_network_id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        try:
            share_network_subnet = db_api.share_network_subnet_get(
                context, share_network_subnet_id)
        except exception.ShareNetworkSubnetNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        for share_server in share_network_subnet['share_servers'] or []:
            shares = db_api.share_instances_get_all_by_share_server(
                context, share_server['id'])
            if shares:
                msg = _("Cannot delete share network subnet %(id)s, it has "
                        "one or more shares.") % {
                    'id': share_network_subnet_id}
                LOG.error(msg)
                raise exc.HTTPConflict(explanation=msg)

        # NOTE(silvacarlose): Do not allow the deletion of any share server
        # if any of them has the flag is_auto_deletable = False
        if not self._all_share_servers_are_auto_deletable(
                share_network_subnet):
            msg = _("The service cannot determine if there are any "
                    "non-managed shares on the share network subnet %(id)s,"
                    "so it cannot be deleted. Please contact the cloud "
                    "administrator to rectify.") % {
                'id': share_network_subnet_id}
            LOG.error(msg)
            raise exc.HTTPConflict(explanation=msg)

        for share_server in share_network_subnet['share_servers']:
            self.share_rpcapi.delete_share_server(context, share_server)

        db_api.share_network_subnet_delete(context, share_network_subnet_id)
        return webob.Response(status_int=http_client.ACCEPTED)

    def _validate_subnet(self, context, share_network_id, az=None):
        """Validate the az for the given subnet.

        If az is None, the method will search for an existent default subnet.
        In case of a given AZ, validates if there's an existent subnet for it.
        """
        msg = ("Another share network subnet was found in the "
               "specified availability zone. Only one share network "
               "subnet is allowed per availability zone for share "
               "network %s." % share_network_id)
        if az is None:
            default_subnet = db_api.share_network_subnet_get_default_subnet(
                context, share_network_id)
            if default_subnet is not None:
                raise exc.HTTPConflict(explanation=msg)
        else:
            az_subnet = (
                db_api.share_network_subnet_get_by_availability_zone_id(
                    context, share_network_id, az['id'])
            )
            # If the 'availability_zone_id' is not None, we found a conflict,
            # otherwise we just have found the default subnet
            if az_subnet and az_subnet['availability_zone_id']:
                raise exc.HTTPConflict(explanation=msg)

    @wsgi.Controller.api_version("2.51")
    @wsgi.Controller.authorize
    def create(self, req, share_network_id, body):
        """Add a new share network subnet into the share network."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share-network-subnet'):
            msg = _("Share Network Subnet is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        data = body['share-network-subnet']
        data['share_network_id'] = share_network_id

        common.check_net_id_and_subnet_id(data)

        try:
            db_api.share_network_get(context, share_network_id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        availability_zone = data.pop('availability_zone', None)
        subnet_az = None

        if availability_zone:
            try:
                subnet_az = db_api.availability_zone_get(context,
                                                         availability_zone)
            except exception.AvailabilityZoneNotFound:
                msg = _("The provided availability zone %s does not "
                        "exist.") % availability_zone
                raise exc.HTTPBadRequest(explanation=msg)

        self._validate_subnet(context, share_network_id, az=subnet_az)

        try:
            data['availability_zone_id'] = (
                subnet_az['id'] if subnet_az is not None else None)
            share_network_subnet = db_api.share_network_subnet_create(
                context, data)
        except db_exception.DBError as e:
            msg = _('Could not create the share network subnet.')
            LOG.error(e)
            raise exc.HTTPInternalServerError(explanation=msg)
        share_network_subnet = db_api.share_network_subnet_get(
            context, share_network_subnet['id'])
        return self._view_builder.build_share_network_subnet(
            req, share_network_subnet)

    @wsgi.Controller.api_version('2.51')
    @wsgi.Controller.authorize
    def show(self, req, share_network_id, share_network_subnet_id):
        """Show share network subnet."""
        context = req.environ['manila.context']

        try:
            db_api.share_network_get(context, share_network_id)
        except exception.ShareNetworkNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        try:
            share_network_subnet = db_api.share_network_subnet_get(
                context, share_network_subnet_id)
        except exception.ShareNetworkSubnetNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        return self._view_builder.build_share_network_subnet(
            req, share_network_subnet)


def create_resource():
    return wsgi.Resource(ShareNetworkSubnetController())
