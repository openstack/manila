# Copyright 2013 NetApp
# Copyright 2015 EMC Corporation.
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

import ast
from http import client as http_client

from oslo_log import log
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.schemas import share_snapshots as schema
from manila.api.v2 import metadata
from manila.api import validation
from manila.api.views import share_snapshots as snapshot_views
from manila.common import constants
from manila import db
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila import policy
from manila import share
from manila import utils

LOG = log.getLogger(__name__)


class ShareSnapshotMixin:
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
            if snapshot.get('status') is None:
                raise exc.HTTPNotFound()
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, snapshot)

    def delete(self, req, id):
        """Delete a snapshot."""
        context = req.environ['manila.context']

        LOG.info("Delete snapshot with id: %s", id, context=context)
        policy.check_policy(context, 'share', 'delete_snapshot')

        try:
            snapshot = self.share_api.get_snapshot(context, id)
            self.share_api.delete_snapshot(context, snapshot)
        except exception.NotFound:
            raise exc.HTTPNotFound()
        return webob.Response(status_int=http_client.ACCEPTED)

    def index(self, req):
        """Returns a summary list of snapshots."""
        req.GET.pop('name~', None)
        req.GET.pop('description~', None)
        req.GET.pop('description', None)
        return self._get_snapshots(req, is_detail=False)

    def detail(self, req):
        """Returns a detailed list of snapshots."""
        req.GET.pop('name~', None)
        req.GET.pop('description~', None)
        req.GET.pop('description', None)
        return self._get_snapshots(req, is_detail=True)

    def _get_snapshots(self, req, is_detail):
        """Returns a list of snapshots."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)
        params = common.get_pagination_params(req)
        limit, offset = [params.get('limit'), params.get('offset')]

        # Remove keys that are not related to share attrs
        search_opts.pop('limit', None)
        search_opts.pop('offset', None)

        show_count = False
        if 'with_count' in search_opts:
            show_count = utils.get_bool_from_api_params(
                'with_count', search_opts)
            search_opts.pop('with_count')

        sort_key, sort_dir = common.get_sort_params(search_opts)
        key_dict = {"name": "display_name",
                    "description": "display_description"}
        for key in key_dict:
            if sort_key == key:
                sort_key = key_dict[key]

        # NOTE(vponomaryov): Manila stores in DB key 'display_name', but
        # allows to use both keys 'name' and 'display_name'. It is leftover
        # from Cinder v1 and v2 APIs.
        if 'name' in search_opts:
            search_opts['display_name'] = search_opts.pop('name')
        if 'description' in search_opts:
            search_opts['display_description'] = search_opts.pop(
                'description')

        # Deserialize dicts
        if req.api_version_request >= api_version.APIVersionRequest("2.73"):
            if 'metadata' in search_opts:
                try:
                    search_opts['metadata'] = ast.literal_eval(
                        search_opts['metadata'])
                except ValueError:
                    msg = _('Invalid value for metadata filter.')
                    raise webob.exc.HTTPBadRequest(explanation=msg)
        else:
            search_opts.pop('metadata', None)

        # like filter
        for key, db_key in (('name~', 'display_name~'),
                            ('description~', 'display_description~')):
            if key in search_opts:
                search_opts[db_key] = search_opts.pop(key)

        common.remove_invalid_options(context, search_opts,
                                      self._get_snapshots_search_options())

        total_count = None
        if show_count:
            count, snapshots = self.share_api.get_all_snapshots_with_count(
                context, search_opts=search_opts, limit=limit, offset=offset,
                sort_key=sort_key, sort_dir=sort_dir)
            total_count = count
        else:
            snapshots = self.share_api.get_all_snapshots(
                context, search_opts=search_opts, limit=limit, offset=offset,
                sort_key=sort_key, sort_dir=sort_dir)

        if is_detail:
            snapshots = self._view_builder.detail_list(
                req, snapshots, total_count)
        else:
            snapshots = self._view_builder.summary_list(
                req, snapshots, total_count)
        return snapshots

    def _get_snapshots_search_options(self):
        """Return share snapshot search options allowed by non-admin."""
        return ('display_name', 'status', 'share_id', 'size', 'display_name~',
                'display_description~', 'display_description', 'metadata')

    def update(self, req, id, body):
        """Update a snapshot."""
        context = req.environ['manila.context']
        policy.check_policy(context, 'share', 'snapshot_update')

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

        common.check_display_field_length(
            update_dict.get('display_name'), 'display_name')
        common.check_display_field_length(
            update_dict.get('display_description'), 'display_description')

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
            msg = _("Snapshots cannot be created for share '%s' "
                    "since it does not have that capability.") % share_id
            LOG.error(msg)
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        # we do not allow soft delete share with snapshot, and also
        # do not allow create snapshot for shares in recycle bin,
        # since it will lead to auto delete share failed.
        if share['is_soft_deleted']:
            msg = _("Snapshots cannot be created for share '%s' "
                    "since it has been soft deleted.") % share_id
            raise exc.HTTPForbidden(explanation=msg)

        LOG.info("Create snapshot from share %s",
                 share_id, context=context)

        # NOTE(rushiagr): v2 API allows name instead of display_name
        if 'name' in snapshot:
            snapshot['display_name'] = snapshot.get('name')
            common.check_display_field_length(
                snapshot['display_name'], 'name')
            del snapshot['name']

        # NOTE(rushiagr): v2 API allows description instead of
        #                display_description
        if 'description' in snapshot:
            snapshot['display_description'] = snapshot.get('description')
            common.check_display_field_length(
                snapshot['display_description'], 'description')
            del snapshot['description']

        kwargs = {}
        if req.api_version_request >= api_version.APIVersionRequest("2.73"):
            if snapshot.get('metadata'):
                metadata = snapshot.get('metadata')
                kwargs.update({
                    'metadata': metadata,
                })

        new_snapshot = self.share_api.create_snapshot(
            context,
            share,
            snapshot.get('display_name'),
            snapshot.get('display_description'),
            **kwargs)
        return self._view_builder.detail(
            req, dict(new_snapshot.items()))


class ShareSnapshotsController(
    ShareSnapshotMixin,
    wsgi.Controller,
    metadata.MetadataController,
    wsgi.AdminActionsMixin,
):
    """The Share Snapshots API V2 controller for the OpenStack API."""

    resource_name = 'share_snapshot'
    _view_builder_class = snapshot_views.ViewBuilder

    def __init__(self):
        super().__init__()
        self.share_api = share.API()

    @wsgi.Controller.authorize('unmanage_snapshot')
    def _unmanage(self, req, id, body=None, allow_dhss_true=False):
        """Unmanage a share snapshot."""
        context = req.environ['manila.context']

        LOG.info("Unmanage share snapshot with id: %s.", id)

        try:
            snapshot = self.share_api.get_snapshot(context, id)

            share = self.share_api.get(context, snapshot['share_id'])
            if not allow_dhss_true and share.get('share_server_id'):
                msg = _("Operation 'unmanage_snapshot' is not supported for "
                        "snapshots of shares that are created with share"
                        " servers (created with share-networks).")
                raise exc.HTTPForbidden(explanation=msg)
            elif share.get('has_replicas'):
                msg = _("Share %s has replicas. Snapshots of this share "
                        "cannot currently be unmanaged until all replicas "
                        "are removed.") % share['id']
                raise exc.HTTPConflict(explanation=msg)
            elif snapshot['status'] in constants.TRANSITIONAL_STATUSES:
                msg = _("Snapshot with transitional state cannot be "
                        "unmanaged. Snapshot '%(s_id)s' is in '%(state)s' "
                        "state.") % {'state': snapshot['status'],
                                     's_id': snapshot['id']}
                raise exc.HTTPForbidden(explanation=msg)

            self.share_api.unmanage_snapshot(context, snapshot, share['host'])
        except (exception.ShareSnapshotNotFound, exception.ShareNotFound) as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.authorize('manage_snapshot')
    def _manage(self, req, body):
        """Instruct Manila to manage an existing snapshot.

        Required HTTP Body:

        .. code-block:: json

            {
                "snapshot":
                {
                    "share_id": <Manila share id>,
                    "provider_location": <A string parameter that identifies
                                          the snapshot on the backend>
                }
            }

        Optional elements in 'snapshot' are:
            name              A name for the new snapshot.
            description       A description for the new snapshot.
            driver_options    Driver specific dicts for the existing snapshot.
        """

        context = req.environ['manila.context']
        snapshot_data = self._validate_manage_parameters(context, body)

        # NOTE(vponomaryov): compatibility actions are required between API and
        # DB layers for 'name' and 'description' API params that are
        # represented in DB as 'display_name' and 'display_description'
        # appropriately.
        name = snapshot_data.get('display_name',
                                 snapshot_data.get('name'))
        description = snapshot_data.get(
            'display_description', snapshot_data.get('description'))

        share_id = snapshot_data['share_id']
        snapshot = {
            'share_id': share_id,
            'provider_location': snapshot_data['provider_location'],
            'display_name': name,
            'display_description': description,
        }
        if req.api_version_request >= api_version.APIVersionRequest("2.73"):
            if snapshot_data.get('metadata'):
                metadata = snapshot_data.get('metadata')
                snapshot.update({
                    'metadata': metadata,
                })

        try:
            share_ref = self.share_api.get(context, share_id)
        except exception.NotFound:
            raise exception.ShareNotFound(share_id=share_id)
        if share_ref.get('is_soft_deleted'):
            msg = _("Can not manage snapshot for share '%s' "
                    "since it has been soft deleted.") % share_id
            raise exc.HTTPForbidden(explanation=msg)

        driver_options = snapshot_data.get('driver_options', {})

        try:
            snapshot_ref = self.share_api.manage_snapshot(context, snapshot,
                                                          driver_options,
                                                          share=share_ref)
        except (exception.ShareNotFound, exception.ShareSnapshotNotFound) as e:
            raise exc.HTTPNotFound(explanation=e.msg)
        except (exception.InvalidShare,
                exception.ManageInvalidShareSnapshot) as e:
            raise exc.HTTPConflict(explanation=e.msg)

        return self._view_builder.detail(req, snapshot_ref)

    def _validate_manage_parameters(self, context, body):
        if not (body and self.is_valid_body(body, 'snapshot')):
            msg = _("Snapshot entity not found in request body.")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        data = body['snapshot']

        required_parameters = ('share_id', 'provider_location')
        self._validate_parameters(data, required_parameters)

        return data

    def _validate_parameters(self, data, required_parameters,
                             fix_response=False):

        if fix_response:
            exc_response = exc.HTTPBadRequest
        else:
            exc_response = exc.HTTPUnprocessableEntity

        for parameter in required_parameters:
            if parameter not in data:
                msg = _("Required parameter %s not found.") % parameter
                raise exc_response(explanation=msg)
            if not data.get(parameter):
                msg = _("Required parameter %s is empty.") % parameter
                raise exc_response(explanation=msg)
            if not isinstance(data[parameter], str):
                msg = _("Parameter %s must be a string.") % parameter
                raise exc_response(explanation=msg)

    def _check_if_share_share_network_is_active(self, context, snapshot):
        share_network_id = snapshot['share'].get('share_network_id')
        if share_network_id:
            share_network = db_api.share_network_get(
                context, share_network_id)
            common.check_share_network_is_active(share_network)

    def _allow(self, req, id, body, enable_ipv6=False):
        context = req.environ['manila.context']

        if not (body and self.is_valid_body(body, 'allow_access')):
            msg = _("Access data not found in request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        access_data = body.get('allow_access')

        required_parameters = ('access_type', 'access_to')
        self._validate_parameters(access_data, required_parameters,
                                  fix_response=True)

        access_type = access_data['access_type']
        access_to = access_data['access_to']

        common.validate_access(access_type=access_type,
                               access_to=access_to,
                               enable_ipv6=enable_ipv6)

        snapshot = self.share_api.get_snapshot(context, id)

        self._check_if_share_share_network_is_active(context, snapshot)

        self._check_mount_snapshot_support(context, snapshot)

        try:
            access = self.share_api.snapshot_allow_access(
                context, snapshot, access_type, access_to)
        except exception.ShareSnapshotAccessExists as e:
            raise webob.exc.HTTPBadRequest(explanation=e.msg)

        return self._view_builder.detail_access(req, access)

    def _deny(self, req, id, body):
        context = req.environ['manila.context']

        if not (body and self.is_valid_body(body, 'deny_access')):
            msg = _("Access data not found in request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        access_data = body.get('deny_access')

        self._validate_parameters(
            access_data, ('access_id',), fix_response=True)

        access_id = access_data['access_id']

        snapshot = self.share_api.get_snapshot(context, id)

        self._check_mount_snapshot_support(context, snapshot)

        self._check_if_share_share_network_is_active(context, snapshot)

        access = self.share_api.snapshot_access_get(context, access_id)

        if access['share_snapshot_id'] != snapshot['id']:
            msg = _("Access rule provided is not associated with given"
                    " snapshot.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        self.share_api.snapshot_deny_access(context, snapshot, access)
        return webob.Response(status_int=http_client.ACCEPTED)

    def _check_mount_snapshot_support(self, context, snapshot):
        share = self.share_api.get(context, snapshot['share_id'])
        if not share['mount_snapshot_support']:
            msg = _("Cannot control access to the snapshot %(snap)s since the "
                    "parent share %(share)s does not support mounting its "
                    "snapshots.") % {'snap': snapshot['id'],
                                     'share': share['id']}
            raise exc.HTTPBadRequest(explanation=msg)

    def _access_list(self, req, snapshot_id):
        context = req.environ['manila.context']

        snapshot = self.share_api.get_snapshot(context, snapshot_id)
        self._check_mount_snapshot_support(context, snapshot)
        access_list = self.share_api.snapshot_access_get_all(context, snapshot)

        return self._view_builder.detail_list_access(req, access_list)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-reset_status')
    def snapshot_reset_status_legacy(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('reset_status')
    def snapshot_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-force_delete')
    def snapshot_force_delete_legacy(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('force_delete')
    def snapshot_force_delete(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.12')
    @wsgi.response(202)
    def manage(self, req, body):
        return self._manage(req, body)

    @wsgi.Controller.api_version('2.12', '2.48')
    @wsgi.action('unmanage')
    def unmanage(self, req, id, body=None):
        return self._unmanage(req, id, body)

    @wsgi.Controller.api_version('2.49')  # noqa
    @wsgi.action('unmanage')
    def unmanage(self, req, id,   # pylint: disable=function-redefined  # noqa F811
                 body=None):
        return self._unmanage(req, id, body, allow_dhss_true=True)

    @wsgi.Controller.api_version('2.32')
    @wsgi.action('allow_access')
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def allow_access(self, req, id, body=None):
        enable_ipv6 = False
        if req.api_version_request >= api_version.APIVersionRequest("2.38"):
            enable_ipv6 = True
        return self._allow(req, id, body, enable_ipv6)

    @wsgi.Controller.api_version('2.32')
    @wsgi.action('deny_access')
    @wsgi.Controller.authorize
    def deny_access(self, req, id, body=None):
        return self._deny(req, id, body)

    @wsgi.Controller.api_version('2.32')
    @wsgi.Controller.authorize
    def access_list(self, req, snapshot_id):
        return self._access_list(req, snapshot_id)

    @wsgi.Controller.api_version("2.0")
    @validation.request_query_schema(schema.index_request_query, "2.0", "2.35")
    @validation.request_query_schema(
        schema.index_request_query_v236, "2.36", "2.72")
    @validation.request_query_schema(
        schema.index_request_query_v273, "2.73", "2.78")
    @validation.request_query_schema(schema.index_request_query_v279, "2.79")
    @validation.response_body_schema(schema.index_response_body)
    def index(self, req):
        """Returns a summary list of shares."""
        if req.api_version_request < api_version.APIVersionRequest("2.36"):
            req.GET.pop('name~', None)
            req.GET.pop('description~', None)
            req.GET.pop('description', None)

        if req.api_version_request < api_version.APIVersionRequest("2.79"):
            req.GET.pop('with_count', None)

        return self._get_snapshots(req, is_detail=False)

    @wsgi.Controller.api_version("2.0")
    def detail(self, req):
        """Returns a detailed list of shares."""
        if req.api_version_request < api_version.APIVersionRequest("2.36"):
            req.GET.pop('name~', None)
            req.GET.pop('description~', None)
            req.GET.pop('description', None)
        return self._get_snapshots(req, is_detail=True)

    @wsgi.Controller.api_version("2.73")
    @wsgi.Controller.authorize("get_metadata")
    def index_metadata(self, req, resource_id):
        """Returns the list of metadata for a given share snapshot."""
        return self._index_metadata(req, resource_id)

    @wsgi.Controller.api_version("2.73")
    @wsgi.Controller.authorize("update_metadata")
    def create_metadata(self, req, resource_id, body):
        return self._create_metadata(req, resource_id, body)

    @wsgi.Controller.api_version("2.73")
    @wsgi.Controller.authorize("update_metadata")
    def update_all_metadata(self, req, resource_id, body):
        return self._update_all_metadata(req, resource_id, body)

    @wsgi.Controller.api_version("2.73")
    @wsgi.Controller.authorize("update_metadata")
    def update_metadata_item(self, req, resource_id, body, key):
        return self._update_metadata_item(req, resource_id, body, key)

    @wsgi.Controller.api_version("2.73")
    @wsgi.Controller.authorize("get_metadata")
    def show_metadata(self, req, resource_id, key):
        return self._show_metadata(req, resource_id, key)

    @wsgi.Controller.api_version("2.73")
    @wsgi.Controller.authorize("delete_metadata")
    def delete_metadata(self, req, resource_id, key):
        return self._delete_metadata(req, resource_id, key)


def create_resource():
    return wsgi.Resource(ShareSnapshotsController())
