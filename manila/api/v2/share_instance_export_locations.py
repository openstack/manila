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

import six
from webob import exc

from manila.api.openstack import wsgi
from manila.api.views import export_locations as export_locations_views
from manila.db import api as db_api
from manila import exception
from manila.i18n import _


class ShareInstanceExportLocationController(wsgi.Controller):
    """The Share Instance Export Locations API controller."""

    def __init__(self):
        self._view_builder_class = export_locations_views.ViewBuilder
        self.resource_name = 'share_instance_export_location'
        super(self.__class__, self).__init__()

    def _verify_share_instance(self, context, share_instance_id):
        try:
            db_api.share_instance_get(context, share_instance_id)
        except exception.NotFound:
            msg = _("Share instance '%s' not found.") % share_instance_id
            raise exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.api_version('2.9')
    @wsgi.Controller.authorize
    def index(self, req, share_instance_id):
        """Return a list of export locations for the share instance."""
        context = req.environ['manila.context']
        self._verify_share_instance(context, share_instance_id)
        export_locations = (
            db_api.share_export_locations_get_by_share_instance_id(
                context, share_instance_id))
        return self._view_builder.detail_list(export_locations)

    @wsgi.Controller.api_version('2.9')
    @wsgi.Controller.authorize
    def show(self, req, share_instance_id, export_location_uuid):
        """Return data about the requested export location."""
        context = req.environ['manila.context']
        self._verify_share_instance(context, share_instance_id)
        try:
            el = db_api.share_export_location_get_by_uuid(
                context, export_location_uuid)
            return self._view_builder.detail(el)
        except exception.ExportLocationNotFound as e:
            raise exc.HTTPNotFound(explanation=six.text_type(e))


def create_resource():
    return wsgi.Resource(ShareInstanceExportLocationController())
