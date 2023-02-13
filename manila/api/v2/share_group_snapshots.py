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

from http import client as http_client

from oslo_log import log
from oslo_utils import uuidutils
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
import manila.api.views.share_group_snapshots as share_group_snapshots_views
from manila import db
from manila import exception
from manila.i18n import _
import manila.share_group.api as share_group_api

LOG = log.getLogger(__name__)
SG_GRADUATION_VERSION = '2.55'


class ShareGroupSnapshotController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The share group snapshots API controller for the OpenStack API."""

    resource_name = 'share_group_snapshot'
    _view_builder_class = (
        share_group_snapshots_views.ShareGroupSnapshotViewBuilder)

    def __init__(self):
        super(ShareGroupSnapshotController, self).__init__()
        self.share_group_api = share_group_api.API()

    def _get_share_group_snapshot(self, context, sg_snapshot_id):
        try:
            return self.share_group_api.get_share_group_snapshot(
                context, sg_snapshot_id)
        except exception.NotFound:
            msg = _("Share group snapshot %s not found.") % sg_snapshot_id
            raise exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.authorize('get')
    def _show(self, req, id):
        """Return data about the given share group snapshot."""
        context = req.environ['manila.context']
        sg_snapshot = self._get_share_group_snapshot(context, id)
        return self._view_builder.detail(req, sg_snapshot)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def show(self, req, id):
        return self._show(req, id)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def show(self, req, id):  # pylint: disable=function-redefined  # noqa F811
        return self._show(req, id)

    @wsgi.Controller.authorize('delete')
    def _delete_group_snapshot(self, req, id):
        """Delete a share group snapshot."""
        context = req.environ['manila.context']
        LOG.info("Delete share group snapshot with id: %s",
                 id, context=context)
        sg_snapshot = self._get_share_group_snapshot(context, id)
        try:
            self.share_group_api.delete_share_group_snapshot(
                context, sg_snapshot)
        except exception.InvalidShareGroupSnapshot as e:
            raise exc.HTTPConflict(explanation=e.msg)
        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def delete(self, req, id):
        return self._delete_group_snapshot(req, id)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def delete(self, req, id):  # pylint: disable=function-redefined  # noqa F811
        return self._delete_group_snapshot(req, id)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def index(self, req):
        """Returns a summary list of share group snapshots."""
        return self._get_share_group_snaps(req, is_detail=False)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def index(self, req):  # pylint: disable=function-redefined  # noqa F811
        """Returns a summary list of share group snapshots."""
        return self._get_share_group_snaps(req, is_detail=False)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def detail(self, req):
        """Returns a detailed list of share group snapshots."""
        return self._get_share_group_snaps(req, is_detail=True)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def detail(self, req):  # pylint: disable=function-redefined  # noqa F811
        """Returns a detailed list of share group snapshots."""
        return self._get_share_group_snaps(req, is_detail=True)

    @wsgi.Controller.authorize('get_all')
    def _get_share_group_snaps(self, req, is_detail):
        """Returns a list of share group snapshots."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # Remove keys that are not related to group attrs
        search_opts.pop('limit', None)
        search_opts.pop('offset', None)
        sort_key = search_opts.pop('sort_key', 'created_at')
        sort_dir = search_opts.pop('sort_dir', 'desc')

        snaps = self.share_group_api.get_all_share_group_snapshots(
            context, detailed=is_detail, search_opts=search_opts,
            sort_dir=sort_dir, sort_key=sort_key)

        limited_list = common.limited(snaps, req)

        if is_detail:
            snaps = self._view_builder.detail_list(req, limited_list)
        else:
            snaps = self._view_builder.summary_list(req, limited_list)
        return snaps

    @wsgi.Controller.authorize('update')
    def _update_group_snapshot(self, req, id, body):
        """Update a share group snapshot."""
        context = req.environ['manila.context']
        key = 'share_group_snapshot'
        if not self.is_valid_body(body, key):
            msg = _("'%s' is missing from the request body.") % key
            raise exc.HTTPBadRequest(explanation=msg)

        sg_snapshot_data = body[key]
        valid_update_keys = {
            'name',
            'description',
        }
        invalid_fields = set(sg_snapshot_data.keys()) - valid_update_keys
        if invalid_fields:
            msg = _("The fields %s are invalid or not allowed to be updated.")
            raise exc.HTTPBadRequest(explanation=msg % invalid_fields)

        sg_snapshot = self._get_share_group_snapshot(context, id)
        sg_snapshot = self.share_group_api.update_share_group_snapshot(
            context, sg_snapshot, sg_snapshot_data)
        return self._view_builder.detail(req, sg_snapshot)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def update(self, req, id, body):
        return self._update_group_snapshot(req, id, body)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def update(self, req, id, body):  # pylint: disable=function-redefined  # noqa F811
        return self._update_group_snapshot(req, id, body)

    @wsgi.Controller.authorize('create')
    def _create(self, req, body):
        """Creates a new share group snapshot."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share_group_snapshot'):
            msg = _("'share_group_snapshot' is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        share_group_snapshot = body.get('share_group_snapshot', {})

        share_group_id = share_group_snapshot.get('share_group_id')
        if not share_group_id:
            msg = _("Must supply 'share_group_id' attribute.")
            raise exc.HTTPBadRequest(explanation=msg)
        if not uuidutils.is_uuid_like(share_group_id):
            msg = _("The 'share_group_id' attribute must be a uuid.")
            raise exc.HTTPBadRequest(explanation=msg)

        kwargs = {"share_group_id": share_group_id}
        if 'name' in share_group_snapshot:
            kwargs['name'] = share_group_snapshot.get('name')
        if 'description' in share_group_snapshot:
            kwargs['description'] = share_group_snapshot.get('description')

        try:
            new_snapshot = self.share_group_api.create_share_group_snapshot(
                context, **kwargs)
        except exception.ShareGroupNotFound as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.InvalidShareGroup as e:
            raise exc.HTTPConflict(explanation=e.msg)

        return self._view_builder.detail(req, dict(new_snapshot.items()))

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    @wsgi.response(202)
    def create(self, req, body):
        return self._create(req, body)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    @wsgi.response(202)
    def create(self, req, body):  # pylint: disable=function-redefined  # noqa F811
        return self._create(req, body)

    @wsgi.Controller.authorize('get')
    def _members(self, req, id):
        """Returns a list of share group snapshot members."""
        context = req.environ['manila.context']

        snaps = self.share_group_api.get_all_share_group_snapshot_members(
            context, id)

        limited_list = common.limited(snaps, req)

        snaps = self._view_builder.member_list(req, limited_list)
        return snaps

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def members(self, req, id):
        return self._members(req, id)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def members(self, req, id):  # pylint: disable=function-redefined  # noqa F811
        return self._members(req, id)

    def _update(self, *args, **kwargs):
        db.share_group_snapshot_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return self.share_group_api.get_share_group_snapshot(*args, **kwargs)

    def _delete(self, context, resource, force=True):
        db.share_group_snapshot_destroy(context.elevated(), resource['id'])

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    @wsgi.action('reset_status')
    def share_group_snapshot_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    @wsgi.action('reset_status')
    def share_group_snapshot_reset_status(self, req, id, body):  # noqa F811
        return self._reset_status(req, id, body)

    # pylint: enable=function-redefined
    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    @wsgi.action('force_delete')
    def share_group_snapshot_force_delete(self, req, id, body):
        return self._force_delete(req, id, body)

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    @wsgi.action('force_delete')
    def share_group_snapshot_force_delete(self, req, id, body):  # noqa F811
        return self._force_delete(req, id, body)


def create_resource():
    return wsgi.Resource(ShareGroupSnapshotController())
