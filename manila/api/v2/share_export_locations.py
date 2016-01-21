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


class ShareExportLocationController(wsgi.Controller):
    """The Share Export Locations API controller."""

    def __init__(self):
        self._view_builder_class = export_locations_views.ViewBuilder
        self.resource_name = 'share_export_location'
        super(self.__class__, self).__init__()

    def _verify_share(self, context, share_id):
        try:
            db_api.share_get(context, share_id)
        except exception.NotFound:
            msg = _("Share '%s' not found.") % share_id
            raise exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.api_version('2.9')
    @wsgi.Controller.authorize
    def index(self, req, share_id):
        """Return a list of export locations for share."""

        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        if context.is_admin:
            export_locations = db_api.share_export_locations_get_by_share_id(
                context, share_id, include_admin_only=True)
            return self._view_builder.detail_list(export_locations)
        else:
            export_locations = db_api.share_export_locations_get_by_share_id(
                context, share_id, include_admin_only=False)
            return self._view_builder.summary_list(export_locations)

    @wsgi.Controller.api_version('2.9')
    @wsgi.Controller.authorize
    def show(self, req, share_id, export_location_uuid):
        """Return data about the requested export location."""
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        try:
            el = db_api.share_export_location_get_by_uuid(
                context, export_location_uuid)
        except exception.ExportLocationNotFound:
            msg = _("Export location '%s' not found.") % export_location_uuid
            raise exc.HTTPNotFound(explanation=msg)

        if context.is_admin:
            return self._view_builder.detail(el)
        else:
            if not el.is_admin_only:
                return self._view_builder.summary(el)
            raise exc.HTTPForbidden()


def create_resource():
    return wsgi.Resource(ShareExportLocationController())
