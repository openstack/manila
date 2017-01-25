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


class ShareSnapshotInstanceExportLocationController(wsgi.Controller):

    def __init__(self):
        self._view_builder_class = (
            share_snapshot_export_locations.ViewBuilder)
        self.resource_name = 'share_snapshot_instance_export_location'
        super(self.__class__, self).__init__()

    @wsgi.Controller.api_version('2.32')
    @wsgi.Controller.authorize
    def index(self, req, snapshot_instance_id):
        context = req.environ['manila.context']
        instance = self._verify_snapshot_instance(
            context, snapshot_instance_id)
        export_locations = (
            db_api.share_snapshot_instance_export_locations_get_all(
                context, instance['id']))

        return self._view_builder.list_export_locations(req, export_locations)

    @wsgi.Controller.api_version('2.32')
    @wsgi.Controller.authorize
    def show(self, req, snapshot_instance_id, export_location_id):
        context = req.environ['manila.context']
        self._verify_snapshot_instance(context, snapshot_instance_id)
        export_location = db_api.share_snapshot_instance_export_location_get(
            context, export_location_id)
        return self._view_builder.detail_export_location(req, export_location)

    def _verify_snapshot_instance(self, context, snapshot_instance_id):
        try:
            snapshot_instance = db_api.share_snapshot_instance_get(
                context, snapshot_instance_id)
            share = db_api.share_get(
                context, snapshot_instance.share_instance['share_id'])
            if not share['is_public']:
                policy.check_policy(context, 'share', 'get', share)
        except exception.NotFound:
            msg = _("Snapshot instance '%s' not found.") % snapshot_instance_id
            raise exc.HTTPNotFound(explanation=msg)
        return snapshot_instance


def create_resource():
    return wsgi.Resource(ShareSnapshotInstanceExportLocationController())
