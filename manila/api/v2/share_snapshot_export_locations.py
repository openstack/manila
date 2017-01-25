# Copyright (c) 2016 Hitachi Data Systems
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

from webob import exc

from manila.api.openstack import wsgi
from manila.api.views import share_snapshot_export_locations
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila import policy


class ShareSnapshotExportLocationController(wsgi.Controller):

    def __init__(self):
        self._view_builder_class = (
            share_snapshot_export_locations.ViewBuilder)
        self.resource_name = 'share_snapshot_export_location'
        super(self.__class__, self).__init__()

    @wsgi.Controller.api_version('2.32')
    @wsgi.Controller.authorize
    def index(self, req, snapshot_id):
        context = req.environ['manila.context']
        snapshot = self._verify_snapshot(context, snapshot_id)
        return self._view_builder.list_export_locations(
            req, snapshot['export_locations'])

    @wsgi.Controller.api_version('2.32')
    @wsgi.Controller.authorize
    def show(self, req, snapshot_id, export_location_id):
        context = req.environ['manila.context']
        self._verify_snapshot(context, snapshot_id)
        export_location = db_api.share_snapshot_instance_export_location_get(
            context, export_location_id)

        return self._view_builder.detail_export_location(req, export_location)

    def _verify_snapshot(self, context, snapshot_id):
        try:
            snapshot = db_api.share_snapshot_get(context, snapshot_id)
            share = db_api.share_get(context, snapshot['share_id'])
            if not share['is_public']:
                policy.check_policy(context, 'share', 'get', share)
        except exception.NotFound:
            msg = _("Snapshot '%s' not found.") % snapshot_id
            raise exc.HTTPNotFound(explanation=msg)
        return snapshot


def create_resource():
    return wsgi.Resource(ShareSnapshotExportLocationController())
