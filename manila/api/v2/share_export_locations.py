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

from oslo_config import cfg
from oslo_log import log
from webob import exc

from manila.api.openstack import wsgi
from manila.api.v2 import metadata
from manila.api.views import export_locations as export_locations_views
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila import policy

LOG = log.getLogger(__name__)
CONF = cfg.CONF


class ShareExportLocationController(wsgi.Controller,
                                    metadata.MetadataController):
    """The Share Export Locations API controller."""

    def __init__(self):
        self._view_builder_class = export_locations_views.ViewBuilder
        self.resource_name = 'share_export_location'
        super(ShareExportLocationController, self).__init__()
        self._conf_admin_only_metadata_keys = getattr(
            CONF, 'admin_only_el_metadata', []
        )

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
        export_locations = db_api.export_location_get_all_by_share_id(
            context, share_id, **kwargs)
        return self._view_builder.summary_list(req, export_locations)

    @wsgi.Controller.authorize('show')
    def _show(self, req, share_id, export_location_uuid,
              ignore_secondary_replicas=False):
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        try:
            export_location = db_api.export_location_get_by_uuid(
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

    def _validate_metadata_for_update(self, req, share_export_location,
                                      metadata, delete=True):
        persistent_keys = set(self._conf_admin_only_metadata_keys)
        context = req.environ['manila.context']
        if set(metadata).intersection(persistent_keys):
            try:
                policy.check_policy(
                    context, 'share_export_location',
                    'update_admin_only_metadata')
            except exception.PolicyNotAuthorized:
                msg = _("Cannot set or update admin only metadata.")
                LOG.exception(msg)
                raise exc.HTTPForbidden(explanation=msg)
            persistent_keys = []

        current_export_metadata = db_api.export_location_metadata_get(
            context, share_export_location)
        if delete:
            _metadata = metadata
            for key in persistent_keys:
                if key in current_export_metadata:
                    _metadata[key] = current_export_metadata[key]
        else:
            metadata_copy = metadata.copy()
            for key in persistent_keys:
                metadata_copy.pop(key, None)
            _metadata = current_export_metadata.copy()
            _metadata.update(metadata_copy)

        return _metadata

    @wsgi.Controller.api_version("2.87")
    @wsgi.Controller.authorize("get_metadata")
    def index_metadata(self, req, share_id, resource_id):
        """Returns the list of metadata for a given share export location."""
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        return self._index_metadata(req, resource_id)

    @wsgi.Controller.api_version("2.87")
    @wsgi.Controller.authorize("update_metadata")
    def create_metadata(self, req, share_id, resource_id, body):
        """Create metadata for a given share export location."""
        _metadata = self._validate_metadata_for_update(req, resource_id,
                                                       body['metadata'],
                                                       delete=False)
        body['metadata'] = _metadata
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        return self._create_metadata(req, resource_id, body)

    @wsgi.Controller.api_version("2.87")
    @wsgi.Controller.authorize("update_metadata")
    def update_all_metadata(self, req, share_id, resource_id, body):
        """Update entire metadata for a given share export location."""
        _metadata = self._validate_metadata_for_update(req, resource_id,
                                                       body['metadata'])
        body['metadata'] = _metadata
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        return self._update_all_metadata(req, resource_id, body)

    @wsgi.Controller.api_version("2.87")
    @wsgi.Controller.authorize("update_metadata")
    def update_metadata_item(self, req, share_id, resource_id, body, key):
        """Update metadata item for a given share export location."""
        _metadata = self._validate_metadata_for_update(req, resource_id,
                                                       body['metadata'],
                                                       delete=False)
        body['metadata'] = _metadata
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        return self._update_metadata_item(req, resource_id, body, key)

    @wsgi.Controller.api_version("2.87")
    @wsgi.Controller.authorize("get_metadata")
    def show_metadata(self, req, share_id, resource_id, key):
        """Show metadata for a given share export location."""
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        return self._show_metadata(req, resource_id, key)

    @wsgi.Controller.api_version("2.87")
    @wsgi.Controller.authorize("delete_metadata")
    def delete_metadata(self, req, share_id, resource_id, key):
        """Delete metadata for a given share export location."""
        context = req.environ['manila.context']
        self._verify_share(context, share_id)
        return self._delete_metadata(req, resource_id, key)


def create_resource():
    return wsgi.Resource(ShareExportLocationController())
