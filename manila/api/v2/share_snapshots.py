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

from manila.api.openstack import wsgi
from manila.api.v1 import share_snapshots
from manila.api.views import share_snapshots as snapshot_views
from manila.common import constants
from manila import exception
from manila.i18n import _, _LI
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

        LOG.info(_LI("Unmanage share snapshot with id: %s."), id)

        try:
            snapshot = self.share_api.get_snapshot(context, id)

            share = self.share_api.get(context, snapshot['share_id'])
            if share.get('share_server_id'):
                msg = _("Operation 'unmanage_snapshot' is not supported for "
                        "snapshots of shares that are created with share"
                        " servers (created with share-networks).")
                raise exc.HTTPForbidden(explanation=msg)
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
        {
         "snapshot":
          {
           "share_id": <Manila share id>,
           "provider_location": <A string parameter that identifies the
                                 snapshot on the backend>
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
        except exception.ManageInvalidShareSnapshot as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))

        return self._view_builder.detail(req, snapshot_ref)

    def _validate_manage_parameters(self, context, body):
        if not (body and self.is_valid_body(body, 'snapshot')):
            msg = _("Snapshot entity not found in request body.")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        required_parameters = ('share_id', 'provider_location')

        data = body['snapshot']

        for parameter in required_parameters:
            if parameter not in data:
                msg = _("Required parameter %s not found.") % parameter
                raise exc.HTTPUnprocessableEntity(explanation=msg)
            if not data.get(parameter):
                msg = _("Required parameter %s is empty.") % parameter
                raise exc.HTTPUnprocessableEntity(explanation=msg)

        return data

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


def create_resource():
    return wsgi.Resource(ShareSnapshotsController())
