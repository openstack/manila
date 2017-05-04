# Copyright 2015 Alex Meade
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

from oslo_log import log
from oslo_utils import uuidutils
import six
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.views import share_groups as share_group_views
from manila import db
from manila import exception
from manila.i18n import _
from manila.share import share_types
from manila.share_group import api as share_group_api
from manila.share_group import share_group_types


LOG = log.getLogger(__name__)


class ShareGroupController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The Share Groups API controller for the OpenStack API."""

    resource_name = 'share_group'
    _view_builder_class = share_group_views.ShareGroupViewBuilder

    def __init__(self):
        super(ShareGroupController, self).__init__()
        self.share_group_api = share_group_api.API()

    def _get_share_group(self, context, share_group_id):
        try:
            return self.share_group_api.get(context, share_group_id)
        except exception.NotFound:
            msg = _("Share group %s not found.") % share_group_id
            raise exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Return data about the given share group."""
        context = req.environ['manila.context']
        share_group = self._get_share_group(context, id)
        return self._view_builder.detail(req, share_group)

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize
    def delete(self, req, id):
        """Delete a share group."""
        context = req.environ['manila.context']

        LOG.info("Delete share group with id: %s", id, context=context)
        share_group = self._get_share_group(context, id)
        try:
            self.share_group_api.delete(context, share_group)
        except exception.InvalidShareGroup as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))
        return webob.Response(status_int=202)

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize('get_all')
    def index(self, req):
        """Returns a summary list of share groups."""
        return self._get_share_groups(req, is_detail=False)

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize('get_all')
    def detail(self, req):
        """Returns a detailed list of share groups."""
        return self._get_share_groups(req, is_detail=True)

    def _get_share_groups(self, req, is_detail):
        """Returns a list of share groups, transformed through view builder."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # Remove keys that are not related to share group attrs
        search_opts.pop('limit', None)
        search_opts.pop('offset', None)
        sort_key = search_opts.pop('sort_key', 'created_at')
        sort_dir = search_opts.pop('sort_dir', 'desc')
        if req.api_version_request < api_version.APIVersionRequest("2.36"):
            search_opts.pop('name~', None)
            search_opts.pop('description~', None)
        if 'group_type_id' in search_opts:
            search_opts['share_group_type_id'] = search_opts.pop(
                'group_type_id')

        share_groups = self.share_group_api.get_all(
            context, detailed=is_detail, search_opts=search_opts,
            sort_dir=sort_dir, sort_key=sort_key,
        )

        limited_list = common.limited(share_groups, req)

        if is_detail:
            share_groups = self._view_builder.detail_list(req, limited_list)
        else:
            share_groups = self._view_builder.summary_list(req, limited_list)
        return share_groups

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize
    def update(self, req, id, body):
        """Update a share group."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share_group'):
            msg = _("'share_group' is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        share_group_data = body['share_group']
        valid_update_keys = {'name', 'description'}
        invalid_fields = set(share_group_data.keys()) - valid_update_keys
        if invalid_fields:
            msg = _("The fields %s are invalid or not allowed to be updated.")
            raise exc.HTTPBadRequest(explanation=msg % invalid_fields)

        share_group = self._get_share_group(context, id)
        share_group = self.share_group_api.update(
            context, share_group, share_group_data)
        return self._view_builder.detail(req, share_group)

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def create(self, req, body):
        """Creates a new share group."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share_group'):
            msg = _("'share_group' is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        share_group = body['share_group']
        valid_fields = {
            'name',
            'description',
            'share_types',
            'share_group_type_id',
            'source_share_group_snapshot_id',
            'share_network_id',
            'availability_zone',
        }
        invalid_fields = set(share_group.keys()) - valid_fields
        if invalid_fields:
            msg = _("The fields %s are invalid.") % invalid_fields
            raise exc.HTTPBadRequest(explanation=msg)

        if ('share_types' in share_group and
                'source_share_group_snapshot_id' in share_group):
            msg = _("Cannot supply both 'share_types' and "
                    "'source_share_group_snapshot_id' attributes.")
            raise exc.HTTPBadRequest(explanation=msg)

        if not (share_group.get('share_types') or
                'source_share_group_snapshot_id' in share_group):
            default_share_type = share_types.get_default_share_type()
            if default_share_type:
                share_group['share_types'] = [default_share_type['id']]
            else:
                msg = _("Must specify at least one share type as a default "
                        "share type has not been configured.")
                raise exc.HTTPBadRequest(explanation=msg)

        kwargs = {}

        if 'name' in share_group:
            kwargs['name'] = share_group.get('name')
        if 'description' in share_group:
            kwargs['description'] = share_group.get('description')

        _share_types = share_group.get('share_types')
        if _share_types:
            if not all([uuidutils.is_uuid_like(st) for st in _share_types]):
                msg = _("The 'share_types' attribute must be a list of uuids")
                raise exc.HTTPBadRequest(explanation=msg)
            kwargs['share_type_ids'] = _share_types

        if ('share_network_id' in share_group and
                'source_share_group_snapshot_id' in share_group):
            msg = _("Cannot supply both 'share_network_id' and "
                    "'source_share_group_snapshot_id' attributes as the share "
                    "network is inherited from the source.")
            raise exc.HTTPBadRequest(explanation=msg)

        availability_zone = share_group.get('availability_zone')
        if availability_zone:
            if 'source_share_group_snapshot_id' in share_group:
                msg = _(
                    "Cannot supply both 'availability_zone' and "
                    "'source_share_group_snapshot_id' attributes as the "
                    "availability zone is inherited from the source.")
                raise exc.HTTPBadRequest(explanation=msg)
            try:
                az_id = db.availability_zone_get(context, availability_zone).id
                kwargs['availability_zone_id'] = az_id
            except exception.AvailabilityZoneNotFound as e:
                raise exc.HTTPNotFound(explanation=six.text_type(e))

        if 'source_share_group_snapshot_id' in share_group:
            source_share_group_snapshot_id = share_group.get(
                'source_share_group_snapshot_id')
            if not uuidutils.is_uuid_like(source_share_group_snapshot_id):
                msg = _("The 'source_share_group_snapshot_id' attribute "
                        "must be a uuid.")
                raise exc.HTTPBadRequest(explanation=six.text_type(msg))
            kwargs['source_share_group_snapshot_id'] = (
                source_share_group_snapshot_id)
        elif 'share_network_id' in share_group:
            share_network_id = share_group.get('share_network_id')
            if not uuidutils.is_uuid_like(share_network_id):
                msg = _("The 'share_network_id' attribute must be a uuid.")
                raise exc.HTTPBadRequest(explanation=six.text_type(msg))
            kwargs['share_network_id'] = share_network_id

        if 'share_group_type_id' in share_group:
            share_group_type_id = share_group.get('share_group_type_id')
            if not uuidutils.is_uuid_like(share_group_type_id):
                msg = _("The 'share_group_type_id' attribute must be a uuid.")
                raise exc.HTTPBadRequest(explanation=six.text_type(msg))
            kwargs['share_group_type_id'] = share_group_type_id
        else:  # get default
            def_share_group_type = share_group_types.get_default()
            if def_share_group_type:
                kwargs['share_group_type_id'] = def_share_group_type['id']
            else:
                msg = _("Must specify a share group type as a default "
                        "share group type has not been configured.")
                raise exc.HTTPBadRequest(explanation=msg)

        try:
            new_share_group = self.share_group_api.create(context, **kwargs)
        except exception.InvalidShareGroupSnapshot as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))
        except (exception.ShareGroupSnapshotNotFound,
                exception.InvalidInput) as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))

        return self._view_builder.detail(
            req, {k: v for k, v in new_share_group.items()})

    def _update(self, *args, **kwargs):
        db.share_group_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return self.share_group_api.get(*args, **kwargs)

    def _delete(self, context, resource, force=True):
        # Delete all share group snapshots
        for snap in resource['snapshots']:
            db.share_group_snapshot_destroy(context, snap['id'])

        # Delete all shares in share group
        for share in db.get_all_shares_by_share_group(context, resource['id']):
            db.share_delete(context, share['id'])

        db.share_group_destroy(context.elevated(), resource['id'])

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.action('reset_status')
    def share_group_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.action('force_delete')
    def share_group_force_delete(self, req, id, body):
        return self._force_delete(req, id, body)


def create_resource():
    return wsgi.Resource(ShareGroupController())
