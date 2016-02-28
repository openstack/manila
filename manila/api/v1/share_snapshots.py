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

"""The share snapshots api."""

from oslo_log import log
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import share_snapshots as snapshot_views
from manila import db
from manila import exception
from manila.i18n import _, _LI
from manila import share

LOG = log.getLogger(__name__)


class ShareSnapshotMixin(object):
    """Mixin class for Share Snapshot Controllers."""

    def _update(self, *args, **kwargs):
        db.share_snapshot_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return self.share_api.get_snapshot(*args, **kwargs)

    def _delete(self, *args, **kwargs):
        return self.share_api.delete_snapshot(*args, **kwargs)

    def show(self, req, id):
        """Return data about the given snapshot."""
        context = req.environ['manila.context']

        try:
            snapshot = self.share_api.get_snapshot(context, id)

            # Snapshot with no instances is filtered out.
            if(snapshot.get('status') is None):
                raise exc.HTTPNotFound()
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, snapshot)

    def delete(self, req, id):
        """Delete a snapshot."""
        context = req.environ['manila.context']

        LOG.info(_LI("Delete snapshot with id: %s"), id, context=context)

        try:
            snapshot = self.share_api.get_snapshot(context, id)
            self.share_api.delete_snapshot(context, snapshot)
        except exception.NotFound:
            raise exc.HTTPNotFound()
        return webob.Response(status_int=202)

    def index(self, req):
        """Returns a summary list of snapshots."""
        return self._get_snapshots(req, is_detail=False)

    def detail(self, req):
        """Returns a detailed list of snapshots."""
        return self._get_snapshots(req, is_detail=True)

    def _get_snapshots(self, req, is_detail):
        """Returns a list of snapshots."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # Remove keys that are not related to share attrs
        search_opts.pop('limit', None)
        search_opts.pop('offset', None)
        sort_key = search_opts.pop('sort_key', 'created_at')
        sort_dir = search_opts.pop('sort_dir', 'desc')

        # NOTE(vponomaryov): Manila stores in DB key 'display_name', but
        # allows to use both keys 'name' and 'display_name'. It is leftover
        # from Cinder v1 and v2 APIs.
        if 'name' in search_opts:
            search_opts['display_name'] = search_opts.pop('name')

        common.remove_invalid_options(context, search_opts,
                                      self._get_snapshots_search_options())

        snapshots = self.share_api.get_all_snapshots(
            context,
            search_opts=search_opts,
            sort_key=sort_key,
            sort_dir=sort_dir,
        )

        # Snapshots with no instances are filtered out.
        snapshots = list(filter(lambda x: x.get('status') is not None,
                                snapshots))

        limited_list = common.limited(snapshots, req)
        if is_detail:
            snapshots = self._view_builder.detail_list(req, limited_list)
        else:
            snapshots = self._view_builder.summary_list(req, limited_list)
        return snapshots

    def _get_snapshots_search_options(self):
        """Return share search options allowed by non-admin."""
        return ('display_name', 'name', 'status', 'share_id', 'size')

    def update(self, req, id, body):
        """Update a snapshot."""
        context = req.environ['manila.context']

        if not body or 'snapshot' not in body:
            raise exc.HTTPUnprocessableEntity()

        snapshot_data = body['snapshot']
        valid_update_keys = (
            'display_name',
            'display_description',
        )

        update_dict = {key: snapshot_data[key]
                       for key in valid_update_keys
                       if key in snapshot_data}

        try:
            snapshot = self.share_api.get_snapshot(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        snapshot = self.share_api.snapshot_update(context, snapshot,
                                                  update_dict)
        snapshot.update(update_dict)
        return self._view_builder.detail(req, snapshot)

    @wsgi.response(202)
    def create(self, req, body):
        """Creates a new snapshot."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'snapshot'):
            raise exc.HTTPUnprocessableEntity()

        snapshot = body['snapshot']

        share_id = snapshot['share_id']
        share = self.share_api.get(context, share_id)

        # Verify that share can be snapshotted
        if not share['snapshot_support']:
            msg = _("Snapshot cannot be created from share '%s', because "
                    "share back end does not support it.") % share_id
            LOG.error(msg)
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        LOG.info(_LI("Create snapshot from share %s"),
                 share_id, context=context)

        # NOTE(rushiagr): v2 API allows name instead of display_name
        if 'name' in snapshot:
            snapshot['display_name'] = snapshot.get('name')
            del snapshot['name']

        # NOTE(rushiagr): v2 API allows description instead of
        #                display_description
        if 'description' in snapshot:
            snapshot['display_description'] = snapshot.get('description')
            del snapshot['description']

        new_snapshot = self.share_api.create_snapshot(
            context,
            share,
            snapshot.get('display_name'),
            snapshot.get('display_description'))
        return self._view_builder.detail(
            req, dict(new_snapshot.items()))


class ShareSnapshotsController(ShareSnapshotMixin, wsgi.Controller,
                               wsgi.AdminActionsMixin):
    """The Share Snapshots API controller for the OpenStack API."""

    resource_name = 'share_snapshot'
    _view_builder_class = snapshot_views.ViewBuilder

    def __init__(self):
        super(ShareSnapshotsController, self).__init__()
        self.share_api = share.API()

    @wsgi.action('os-reset_status')
    def snapshot_reset_status_legacy(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.action('os-force_delete')
    def snapshot_force_delete_legacy(self, req, id, body):
        return self._force_delete(req, id, body)


def create_resource():
    return wsgi.Resource(ShareSnapshotsController())
