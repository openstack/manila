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

import six
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import share_snapshots as snapshot_views
from manila.api import xmlutil
from manila import exception
from manila.openstack.common import log as logging
from manila import share


LOG = logging.getLogger(__name__)


def make_snapshot(elem):
    attrs = ['id', 'size', 'status', 'name', 'description', 'share_proto',
             'export_location', 'links', 'share_id', 'created_at',
             'share_size']
    for attr in attrs:
        elem.set(attr)


class SnapshotTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('snapshot',
                                       selector='snapshot')
        make_snapshot(root)
        return xmlutil.MasterTemplate(root, 1)


class SnapshotsTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('snapshots')
        elem = xmlutil.SubTemplateElement(root, 'snapshot',
                                          selector='snapshots')
        make_snapshot(elem)
        return xmlutil.MasterTemplate(root, 1)


class ShareSnapshotsController(wsgi.Controller):
    """The Share Snapshots API controller for the OpenStack API."""

    _view_builder_class = snapshot_views.ViewBuilder

    def __init__(self):
        super(ShareSnapshotsController, self).__init__()
        self.share_api = share.API()

    @wsgi.serializers(xml=SnapshotTemplate)
    def show(self, req, id):
        """Return data about the given snapshot."""
        context = req.environ['manila.context']

        try:
            snapshot = self.share_api.get_snapshot(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, snapshot)

    def delete(self, req, id):
        """Delete a snapshot."""
        context = req.environ['manila.context']

        LOG.info(_("Delete snapshot with id: %s"), id, context=context)

        try:
            snapshot = self.share_api.get_snapshot(context, id)
            self.share_api.delete_snapshot(context, snapshot)
        except exception.NotFound:
            raise exc.HTTPNotFound()
        return webob.Response(status_int=202)

    @wsgi.serializers(xml=SnapshotsTemplate)
    def index(self, req):
        """Returns a summary list of snapshots."""
        return self._get_snapshots(req, is_detail=False)

    @wsgi.serializers(xml=SnapshotsTemplate)
    def detail(self, req):
        """Returns a detailed list of snapshots."""
        return self._get_snapshots(req, is_detail=True)

    def _get_snapshots(self, req, is_detail):
        """Returns a list of snapshots."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # NOTE(rushiagr): v2 API allows name instead of display_name
        if 'name' in search_opts:
            search_opts['display_name'] = search_opts['name']
            del search_opts['name']

        common.remove_invalid_options(context, search_opts,
                                      self._get_snapshots_search_options())

        snapshots = self.share_api.get_all_snapshots(context,
                                                     search_opts=search_opts)
        limited_list = common.limited(snapshots, req)
        if is_detail:
            snapshots = self._view_builder.detail_list(req, limited_list)
        else:
            snapshots = self._view_builder.summary_list(req, limited_list)
        return snapshots

    def _get_snapshots_search_options(self):
        """Return share search options allowed by non-admin."""
        return ('name', 'status', 'share_id')

    @wsgi.serializers(xml=SnapshotTemplate)
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

        update_dict = dict([(key, snapshot_data[key])
                            for key in valid_update_keys
                            if key in snapshot_data])

        try:
            snapshot = self.share_api.get_snapshot(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        snapshot = self.share_api.snapshot_update(context, snapshot,
                                                  update_dict)
        snapshot.update(update_dict)
        return self._view_builder.detail(req, snapshot)

    @wsgi.response(202)
    @wsgi.serializers(xml=SnapshotTemplate)
    def create(self, req, body):
        """Creates a new snapshot."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'snapshot'):
            raise exc.HTTPUnprocessableEntity()

        snapshot = body['snapshot']

        share_id = snapshot['share_id']
        share = self.share_api.get(context, share_id)
        msg = _("Create snapshot from share %s")
        LOG.info(msg, share_id, context=context)

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
        return self._view_builder.summary(
            req, dict(six.iteritems(new_snapshot)))


def create_resource():
    return wsgi.Resource(ShareSnapshotsController())

#
# class Share_snapshots(extensions.ExtensionDescriptor):
#     """Enable share snapshtos API."""
#     name = 'ShareSnapshots'
#     alias = 'snapshots'
#     namespace = ''
#     updated = '2013-03-01T00:00:00+00:00'
#
#     def get_resources(self):
#         controller = ShareSnapshotsController()
#         resource = extensions.ResourceExtension(
#             'snapshots', controller,
#             collection_actions={'detail': 'GET'})
#         return [resource]
