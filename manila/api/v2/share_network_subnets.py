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

from http import client as http_client

from manila.api import common
from oslo_db import exception as db_exception
from oslo_log import log
import webob
from webob import exc

from manila.api import common as api_common
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.v2 import metadata as metadata_controller
from manila.api.views import share_network_subnets as subnet_views
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila import share
from manila.share import rpcapi as share_rpcapi

LOG = log.getLogger(__name__)


class ShareNetworkSubnetController(wsgi.Controller,
                                   metadata_controller.MetadataController):
    """The Share Network Subnet API controller for the OpenStack API."""

    resource_name = 'share_network_subnet'
    _view_builder_class = subnet_views.ViewBuilder

    def __init__(self):
        super(ShareNetworkSubnetController, self).__init__()
        self.share_rpcapi = share_rpcapi.ShareAPI()
        self.share_api = share.API()

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

    @wsgi.Controller.api_version("2.51")
    @wsgi.Controller.authorize
    def create(self, req, share_network_id, body):
        """Add a new share network subnet into the share network."""
        context = req.environ['manila.context']
        if not self.is_valid_body(body, 'share-network-subnet'):
            msg = _("Share Network Subnet is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)
        data = body['share-network-subnet']

        if req.api_version_request >= api_version.APIVersionRequest("2.78"):
            api_common.check_metadata_properties(data.get('metadata'))
        else:
            data.pop('metadata', None)

        data['share_network_id'] = share_network_id
        multiple_subnet_support = (req.api_version_request >=
                                   api_version.APIVersionRequest("2.70"))
        share_network, existing_subnets = common.validate_subnet_create(
            context, share_network_id, data, multiple_subnet_support)

        # create subnet operation on subnets with share servers means that an
        # allocation update is requested.
        if existing_subnets and existing_subnets[0]['share_servers']:

            # NOTE(felipe_rodrigues): all subnets have the same set of share
            # servers, so we can just get the servers from one of them. Not
            # necessarily all share servers from the specified AZ will be
            # updated, only the ones created with subnets in the AZ. Others
            # created with default AZ will only have its allocations updated
            # when default subnet set is updated.
            data['share_servers'] = existing_subnets[0]['share_servers']
            try:
                share_network_subnet = (
                    self.share_api.update_share_server_network_allocations(
                        context, share_network, data))
            except exception.ServiceIsDown as e:
                msg = _('Could not add the share network subnet.')
                LOG.error(e)
                raise exc.HTTPInternalServerError(explanation=msg)
            except exception.InvalidShareNetwork as e:
                raise exc.HTTPBadRequest(explanation=e.msg)
            except db_exception.DBError as e:
                msg = _('Could not add the share network subnet.')
                LOG.error(e)
                raise exc.HTTPInternalServerError(explanation=msg)
        else:
            try:
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

    @wsgi.Controller.api_version("2.78")
    @wsgi.Controller.authorize("get_metadata")
    def index_metadata(self, req, share_network_id, resource_id):
        """Returns the list of metadata for a given share network subnet."""
        return self._index_metadata(req, resource_id,
                                    parent_id=share_network_id)

    @wsgi.Controller.api_version("2.78")
    @wsgi.Controller.authorize("update_metadata")
    def create_metadata(self, req, share_network_id, resource_id, body):
        """Create metadata for a given share network subnet."""
        return self._create_metadata(req, resource_id, body,
                                     parent_id=share_network_id)

    @wsgi.Controller.api_version("2.78")
    @wsgi.Controller.authorize("update_metadata")
    def update_all_metadata(self, req, share_network_id, resource_id, body):
        """Update entire metadata for a given share network subnet."""
        return self._update_all_metadata(req, resource_id, body,
                                         parent_id=share_network_id)

    @wsgi.Controller.api_version("2.78")
    @wsgi.Controller.authorize("update_metadata")
    def update_metadata_item(self, req, share_network_id, resource_id, body,
                             key):
        """Update metadata item for a given share network subnet."""
        return self._update_metadata_item(req, resource_id, body, key,
                                          parent_id=share_network_id)

    @wsgi.Controller.api_version("2.78")
    @wsgi.Controller.authorize("get_metadata")
    def show_metadata(self, req, share_network_id, resource_id, key):
        """Show metadata for a given share network subnet."""
        return self._show_metadata(req, resource_id, key,
                                   parent_id=share_network_id)

    @wsgi.Controller.api_version("2.78")
    @wsgi.Controller.authorize("delete_metadata")
    def delete_metadata(self, req, share_network_id, resource_id, key):
        """Delete metadata for a given share network subnet."""
        return self._delete_metadata(req, resource_id, key,
                                     parent_id=share_network_id)


def create_resource():
    return wsgi.Resource(ShareNetworkSubnetController())
