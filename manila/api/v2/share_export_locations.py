# Copyright 2015 Mirantis inc.
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
from manila.api.views import export_locations as export_locations_views
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila import policy


class ShareExportLocationController(wsgi.Controller):
    """The Share Export Locations API controller."""

    def __init__(self):
        self._view_builder_class = export_locations_views.ViewBuilder
        self.resource_name = 'share_export_location'
        super(ShareExportLocationController, self).__init__()

    def _verify_share(self, context, share_id):
        try:
            share = db_api.share_get(context, share_id)
            if not share['is_public']:
                policy.check_policy(context, 'share', 'get', share)
        except exception.NotFound:
            msg = _("Share '%s' not found.") % share_id
            raise exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.authorize('index')
    def _index(self, req, share_id, ignore_secondary_replicas=False):
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        kwargs = {
            'include_admin_only': context.is_admin,
            'ignore_migration_destination': True,
            'ignore_secondary_replicas': ignore_secondary_replicas,
        }
        export_locations = db_api.share_export_locations_get_by_share_id(
            context, share_id, **kwargs)
        return self._view_builder.summary_list(req, export_locations)

    @wsgi.Controller.authorize('show')
    def _show(self, req, share_id, export_location_uuid,
              ignore_secondary_replicas=False):
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        try:
            export_location = db_api.share_export_location_get_by_uuid(
                context, export_location_uuid,
                ignore_secondary_replicas=ignore_secondary_replicas)
        except exception.ExportLocationNotFound:
            msg = _("Export location '%s' not found.") % export_location_uuid
            raise exc.HTTPNotFound(explanation=msg)

        if export_location.is_admin_only and not context.is_admin:
            raise exc.HTTPForbidden()

        return self._view_builder.detail(req, export_location)

    @wsgi.Controller.api_version('2.9', '2.46')
    def index(self, req, share_id):
        """Return a list of export locations for share."""
        return self._index(req, share_id)

    @wsgi.Controller.api_version('2.47')  # noqa: F811
    def index(self, req, share_id):  # pylint: disable=function-redefined  # noqa F811
        """Return a list of export locations for share."""
        return self._index(req, share_id,
                           ignore_secondary_replicas=True)

    @wsgi.Controller.api_version('2.9', '2.46')
    def show(self, req, share_id, export_location_uuid):
        """Return data about the requested export location."""
        return self._show(req, share_id, export_location_uuid)

    @wsgi.Controller.api_version('2.47')  # noqa: F811
    def show(self, req, share_id,  # pylint: disable=function-redefined  # noqa F811
             export_location_uuid):
        """Return data about the requested export location."""
        return self._show(req, share_id, export_location_uuid,
                          ignore_secondary_replicas=True)


def create_resource():
    return wsgi.Resource(ShareExportLocationController())
