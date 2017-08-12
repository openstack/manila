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

from oslo_log import log
import six
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.v1 import share_snapshots
from manila.api.views import share_snapshots as snapshot_views
from manila.common import constants
from manila import exception
from manila.i18n import _
from manila import share

LOG = log.getLogger(__name__)


class ShareSnapshotsController(share_snapshots.ShareSnapshotMixin,
                               wsgi.Controller, wsgi.AdminActionsMixin):
    """The Share Snapshots API V2 controller for the OpenStack API."""

    resource_name = 'share_snapshot'
    _view_builder_class = snapshot_views.ViewBuilder

    def __init__(self):
        super(ShareSnapshotsController, self).__init__()
        self.share_api = share.API()

    @wsgi.Controller.authorize('unmanage_snapshot')
    def _unmanage(self, req, id, body=None):
        """Unmanage a share snapshot."""
        context = req.environ['manila.context']

        LOG.info("Unmanage share snapshot with id: %s.", id)

        try:
            snapshot = self.share_api.get_snapshot(context, id)

            share = self.share_api.get(context, snapshot['share_id'])
            if share.get('share_server_id'):
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
            raise exc.HTTPNotFound(explanation=six.text_type(e))

        return webob.Response(status_int=202)

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

        snapshot = {
            'share_id': snapshot_data['share_id'],
            'provider_location': snapshot_data['provider_location'],
            'display_name': name,
            'display_description': description,
        }

        driver_options = snapshot_data.get('driver_options', {})

        try:
            snapshot_ref = self.share_api.manage_snapshot(context, snapshot,
                                                          driver_options)
        except (exception.ShareNotFound, exception.ShareSnapshotNotFound) as e:
            raise exc.HTTPNotFound(explanation=six.text_type(e))
        except (exception.InvalidShare,
                exception.ManageInvalidShareSnapshot) as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))

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

        access = self.share_api.snapshot_access_get(context, access_id)

        if access['share_snapshot_id'] != snapshot['id']:
            msg = _("Access rule provided is not associated with given"
                    " snapshot.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        self.share_api.snapshot_deny_access(context, snapshot, access)
        return webob.Response(status_int=202)

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

    @wsgi.Controller.api_version('2.12')
    @wsgi.action('unmanage')
    def unmanage(self, req, id, body=None):
        return self._unmanage(req, id, body)

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
    def index(self, req):
        """Returns a summary list of shares."""
        if req.api_version_request < api_version.APIVersionRequest("2.36"):
            req.GET.pop('name~', None)
            req.GET.pop('description~', None)
            req.GET.pop('description', None)
        return self._get_snapshots(req, is_detail=False)

    @wsgi.Controller.api_version("2.0")
    def detail(self, req):
        """Returns a detailed list of shares."""
        if req.api_version_request < api_version.APIVersionRequest("2.36"):
            req.GET.pop('name~', None)
            req.GET.pop('description~', None)
            req.GET.pop('description', None)
        return self._get_snapshots(req, is_detail=True)


def create_resource():
    return wsgi.Resource(ShareSnapshotsController())
