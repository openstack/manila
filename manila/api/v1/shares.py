# Copyright 2013 NetApp
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

import ast

from oslo_log import log
from oslo_utils import strutils
from oslo_utils import uuidutils
import six
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import shares as share_views
from manila import db
from manila import exception
from manila.i18n import _
from manila.i18n import _LI
from manila import share
from manila.share import share_types

LOG = log.getLogger(__name__)


class ShareController(wsgi.Controller):
    """The Shares API controller for the OpenStack API."""

    _view_builder_class = share_views.ViewBuilder

    def __init__(self):
        super(ShareController, self).__init__()
        self.share_api = share.API()

    def show(self, req, id):
        """Return data about the given share."""
        context = req.environ['manila.context']

        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, share)

    def delete(self, req, id):
        """Delete a share."""
        context = req.environ['manila.context']

        LOG.info(_LI("Delete share with id: %s"), id, context=context)

        try:
            share = self.share_api.get(context, id)

            # NOTE(ameade): If the share is in a consistency group, we require
            # it's id be specified as a param.
            if share.get('consistency_group_id'):
                consistency_group_id = req.params.get('consistency_group_id')
                if (share.get('consistency_group_id') and
                        not consistency_group_id):
                    msg = _("Must provide 'consistency_group_id' as a request "
                            "parameter when deleting a share in a consistency "
                            "group.")
                    raise exc.HTTPBadRequest(explanation=msg)
                elif consistency_group_id != share.get('consistency_group_id'):
                    msg = _("The specified 'consistency_group_id' does not "
                            "match the consistency group id of the share.")
                    raise exc.HTTPBadRequest(explanation=msg)

            self.share_api.delete(context, share)
        except exception.NotFound:
            raise exc.HTTPNotFound()
        except exception.InvalidShare as e:
            raise exc.HTTPForbidden(explanation=six.text_type(e))

        return webob.Response(status_int=202)

    @wsgi.Controller.api_version("1.6", None, True)
    @wsgi.action("os-migrate_share")
    def migrate_share(self, req, id, body):
        """Migrate a share to the specified host."""
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            msg = _("Share %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)
        params = body['os-migrate_share']
        try:
            host = params['host']
        except KeyError:
            raise exc.HTTPBadRequest(explanation=_("Must specify 'host'"))
        force_host_copy = params.get('force_host_copy', False)
        try:
            force_host_copy = strutils.bool_from_string(force_host_copy,
                                                        strict=True)
        except ValueError:
            raise exc.HTTPBadRequest(
                explanation=_("Bad value for 'force_host_copy'"))
        self.share_api.migrate_share(context, share, host, force_host_copy)
        return webob.Response(status_int=202)

    def index(self, req):
        """Returns a summary list of shares."""
        return self._get_shares(req, is_detail=False)

    def detail(self, req):
        """Returns a detailed list of shares."""
        return self._get_shares(req, is_detail=True)

    def _get_shares(self, req, is_detail):
        """Returns a list of shares, transformed through view builder."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # Remove keys that are not related to share attrs
        search_opts.pop('limit', None)
        search_opts.pop('offset', None)
        sort_key = search_opts.pop('sort_key', 'created_at')
        sort_dir = search_opts.pop('sort_dir', 'desc')

        # Deserialize dicts
        if 'metadata' in search_opts:
            search_opts['metadata'] = ast.literal_eval(search_opts['metadata'])
        if 'extra_specs' in search_opts:
            search_opts['extra_specs'] = ast.literal_eval(
                search_opts['extra_specs'])

        # NOTE(vponomaryov): Manila stores in DB key 'display_name', but
        # allows to use both keys 'name' and 'display_name'. It is leftover
        # from Cinder v1 and v2 APIs.
        if 'name' in search_opts:
            search_opts['display_name'] = search_opts.pop('name')
        if sort_key == 'name':
            sort_key = 'display_name'

        common.remove_invalid_options(
            context, search_opts, self._get_share_search_options())

        shares = self.share_api.get_all(
            context, search_opts=search_opts, sort_key=sort_key,
            sort_dir=sort_dir)

        limited_list = common.limited(shares, req)

        if is_detail:
            shares = self._view_builder.detail_list(req, limited_list)
        else:
            shares = self._view_builder.summary_list(req, limited_list)
        return shares

    def _get_share_search_options(self):
        """Return share search options allowed by non-admin."""
        # NOTE(vponomaryov): share_server_id depends on policy, allow search
        #                    by it for non-admins in case policy changed.
        #                    Also allow search by extra_specs in case policy
        #                    for it allows non-admin access.
        return (
            'display_name', 'status', 'share_server_id', 'volume_type_id',
            'share_type_id', 'snapshot_id', 'host', 'share_network_id',
            'is_public', 'metadata', 'extra_specs', 'sort_key', 'sort_dir',
            'consistency_group_id', 'cgsnapshot_id'
        )

    def update(self, req, id, body):
        """Update a share."""
        context = req.environ['manila.context']

        if not body or 'share' not in body:
            raise exc.HTTPUnprocessableEntity()

        share_data = body['share']
        valid_update_keys = (
            'display_name',
            'display_description',
            'is_public',
        )

        update_dict = dict([(key, share_data[key])
                            for key in valid_update_keys
                            if key in share_data])

        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        share = self.share_api.update(context, share, update_dict)
        share.update(update_dict)
        return self._view_builder.detail(req, share)

    @wsgi.Controller.api_version("1.5")
    def create(self, req, body):
        return self._create(req, body)

    @wsgi.Controller.api_version("1.0", "1.4")  # noqa
    def create(self, req, body):  # pylint: disable=E0102
        # Remove consistency group attributes
        share = body.get('share', {})
        if 'consistency_group_id' in share:
            del body['share']['consistency_group_id']

        share = self._create(req, body)
        return share

    def _create(self, req, body):
        """Creates a new share."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share'):
            raise exc.HTTPUnprocessableEntity()

        share = body['share']

        # NOTE(rushiagr): v2 API allows name instead of display_name
        if share.get('name'):
            share['display_name'] = share.get('name')
            del share['name']

        # NOTE(rushiagr): v2 API allows description instead of
        #                display_description
        if share.get('description'):
            share['display_description'] = share.get('description')
            del share['description']

        size = share['size']
        share_proto = share['share_proto'].upper()

        msg = (_LI("Create %(share_proto)s share of %(size)s GB") %
               {'share_proto': share_proto, 'size': size})
        LOG.info(msg, context=context)

        availability_zone = share.get('availability_zone')

        if availability_zone:
            try:
                db.availability_zone_get(context, availability_zone)
            except exception.AvailabilityZoneNotFound as e:
                raise exc.HTTPNotFound(explanation=six.text_type(e))

        kwargs = {
            'availability_zone': availability_zone,
            'metadata': share.get('metadata'),
            'is_public': share.get('is_public', False),
            'consistency_group_id': share.get('consistency_group_id')
        }

        snapshot_id = share.get('snapshot_id')
        if snapshot_id:
            snapshot = self.share_api.get_snapshot(context, snapshot_id)
        else:
            snapshot = None

        kwargs['snapshot'] = snapshot

        share_network_id = share.get('share_network_id')

        if snapshot:
            # Need to check that share_network_id from snapshot's
            # parents share equals to share_network_id from args.
            # If share_network_id is empty than update it with
            # share_network_id of parent share.
            parent_share = self.share_api.get(context, snapshot['share_id'])
            parent_share_net_id = parent_share['share_network_id']
            if share_network_id:
                if share_network_id != parent_share_net_id:
                    msg = "Share network ID should be the same as snapshot's" \
                          " parent share's or empty"
                    raise exc.HTTPBadRequest(explanation=msg)
            elif parent_share_net_id:
                share_network_id = parent_share_net_id

        if share_network_id:
            try:
                self.share_api.get_share_network(
                    context,
                    share_network_id)
            except exception.ShareNetworkNotFound as e:
                raise exc.HTTPNotFound(explanation=six.text_type(e))
            kwargs['share_network_id'] = share_network_id

        display_name = share.get('display_name')
        display_description = share.get('display_description')

        if 'share_type' in share and 'volume_type' in share:
            msg = 'Cannot specify both share_type and volume_type'
            raise exc.HTTPBadRequest(explanation=msg)
        req_share_type = share.get('share_type', share.get('volume_type'))

        if req_share_type:
            try:
                if not uuidutils.is_uuid_like(req_share_type):
                    kwargs['share_type'] = \
                        share_types.get_share_type_by_name(
                            context, req_share_type)
                else:
                    kwargs['share_type'] = share_types.get_share_type(
                        context, req_share_type)
            except exception.ShareTypeNotFound:
                msg = _("Share type not found.")
                raise exc.HTTPNotFound(explanation=msg)
        elif not snapshot:
            def_share_type = share_types.get_default_share_type()
            if def_share_type:
                kwargs['share_type'] = def_share_type

        new_share = self.share_api.create(context,
                                          share_proto,
                                          size,
                                          display_name,
                                          display_description,
                                          **kwargs)

        return self._view_builder.detail(req, dict(six.iteritems(new_share)))


def create_resource():
    return wsgi.Resource(ShareController())
