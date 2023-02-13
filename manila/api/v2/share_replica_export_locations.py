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

PRE_GRADUATION_VERSION = '2.55'
GRADUATION_VERSION = '2.56'


class ShareReplicaExportLocationController(wsgi.Controller):
    """The Share Instance Export Locations API controller."""

    def __init__(self):
        self._view_builder_class = export_locations_views.ViewBuilder
        self.resource_name = 'share_replica_export_location'
        super(ShareReplicaExportLocationController, self).__init__()

    def _verify_share_replica(self, context, share_replica_id):
        try:
            db_api.share_replica_get(context, share_replica_id)
        except exception.NotFound:
            msg = _("Share replica '%s' not found.") % share_replica_id
            raise exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.api_version(
        '2.47', PRE_GRADUATION_VERSION, experimental=True)
    def index(self, req, share_replica_id):
        return self._index(req, share_replica_id)

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    def index(self, req, share_replica_id):  # noqa F811
        return self._index(req, share_replica_id)

    # pylint: enable=function-redefined
    @wsgi.Controller.authorize('index')
    def _index(self, req, share_replica_id):
        """Return a list of export locations for the share instance."""
        context = req.environ['manila.context']
        self._verify_share_replica(context, share_replica_id)
        export_locations = (
            db_api.share_export_locations_get_by_share_instance_id(
                context, share_replica_id,
                include_admin_only=context.is_admin)
        )
        return self._view_builder.summary_list(req, export_locations,
                                               replica=True)

    @wsgi.Controller.api_version(
        '2.47', PRE_GRADUATION_VERSION, experimental=True)
    def show(self, req, share_replica_id, export_location_uuid):
        return self._show(req, share_replica_id, export_location_uuid)

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    def show(self, req, share_replica_id, export_location_uuid):  # noqa F811
        return self._show(req, share_replica_id, export_location_uuid)

    # pylint: enable=function-redefined
    @wsgi.Controller.authorize('show')
    def _show(self, req, share_replica_id, export_location_uuid):
        """Return data about the requested export location."""
        context = req.environ['manila.context']
        self._verify_share_replica(context, share_replica_id)
        try:
            export_location = db_api.share_export_location_get_by_uuid(
                context, export_location_uuid)
            return self._view_builder.detail(req, export_location,
                                             replica=True)
        except exception.ExportLocationNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)


def create_resource():
    return wsgi.Resource(ShareReplicaExportLocationController())
