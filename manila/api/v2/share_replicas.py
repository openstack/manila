# Copyright 2015 Goutham Pacha Ravi
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

"""The Share Replication API."""

import six
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import share_replicas as replication_view
from manila.common import constants
from manila import db
from manila import exception
from manila.i18n import _
from manila import share


MIN_SUPPORTED_API_VERSION = '2.11'


class ShareReplicationController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The Share Replication API controller for the OpenStack API."""

    resource_name = 'share_replica'
    _view_builder_class = replication_view.ReplicationViewBuilder

    def __init__(self):
        super(ShareReplicationController, self).__init__()
        self.share_api = share.API()

    def _update(self, *args, **kwargs):
        db.share_replica_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return db.share_replica_get(*args, **kwargs)

    def _delete(self, context, resource, force=True):
        try:
            self.share_api.delete_share_replica(context, resource, force=True)
        except exception.ReplicationException as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    def index(self, req):
        """Return a summary list of replicas."""
        return self._get_replicas(req)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    def detail(self, req):
        """Returns a detailed list of replicas."""
        return self._get_replicas(req, is_detail=True)

    @wsgi.Controller.authorize('get_all')
    def _get_replicas(self, req, is_detail=False):
        """Returns list of replicas."""
        context = req.environ['manila.context']

        share_id = req.params.get('share_id')
        if share_id:
            try:
                replicas = db.share_replicas_get_all_by_share(
                    context, share_id)
            except exception.NotFound:
                msg = _("Share with share ID %s not found.") % share_id
                raise exc.HTTPNotFound(explanation=msg)
        else:
            replicas = db.share_replicas_get_all(context)

        limited_list = common.limited(replicas, req)
        if is_detail:
            replicas = self._view_builder.detail_list(req, limited_list)
        else:
            replicas = self._view_builder.summary_list(req, limited_list)

        return replicas

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize
    def show(self, req, id):
        """Return data about the given replica."""
        context = req.environ['manila.context']

        try:
            replica = db.share_replica_get(context, id)
        except exception.ShareReplicaNotFound:
            msg = _("Replica %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)

        return self._view_builder.detail(req, replica)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def create(self, req, body):
        """Add a replica to an existing share."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share_replica'):
            msg = _("Body does not contain 'share_replica' information.")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        share_id = body.get('share_replica').get('share_id')
        availability_zone = body.get('share_replica').get('availability_zone')
        share_network_id = body.get('share_replica').get('share_network_id')

        if not share_id:
            msg = _("Must provide Share ID to add replica.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            share_ref = db.share_get(context, share_id)
        except exception.NotFound:
            msg = _("No share exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % share_id)

        try:
            new_replica = self.share_api.create_share_replica(
                context, share_ref, availability_zone=availability_zone,
                share_network_id=share_network_id)
        except exception.AvailabilityZoneNotFound as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))
        except exception.ReplicationException as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))
        except exception.ShareBusyException as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))

        return self._view_builder.detail(req, new_replica)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize
    def delete(self, req, id):
        """Delete a replica."""
        context = req.environ['manila.context']

        try:
            replica = db.share_replica_get(context, id)
        except exception.ShareReplicaNotFound:
            msg = _("No replica exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        try:
            self.share_api.delete_share_replica(context, replica)
        except exception.ReplicationException as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))

        return webob.Response(status_int=202)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('promote')
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def promote(self, req, id, body):
        """Promote a replica to active state."""
        context = req.environ['manila.context']

        try:
            replica = db.share_replica_get(context, id)
        except exception.ShareReplicaNotFound:
            msg = _("No replica exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        replica_state = replica.get('replica_state')

        if replica_state == constants.REPLICA_STATE_ACTIVE:
            return webob.Response(status_int=200)

        try:
            replica = self.share_api.promote_share_replica(context, replica)
        except exception.ReplicationException as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))
        except exception.AdminRequired as e:
            raise exc.HTTPForbidden(explanation=six.text_type(e))

        return self._view_builder.detail(req, replica)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('reset_status')
    def reset_status(self, req, id, body):
        """Reset the 'status' attribute in the database."""
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('force_delete')
    def force_delete(self, req, id, body):
        """Force deletion on the database, attempt on the backend."""
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('reset_replica_state')
    @wsgi.Controller.authorize
    def reset_replica_state(self, req, id, body):
        """Reset the 'replica_state' attribute in the database."""
        return self._reset_status(req, id, body, status_attr='replica_state')

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('resync')
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def resync(self, req, id, body):
        """Attempt to update/sync the replica with its source."""
        context = req.environ['manila.context']
        try:
            replica = db.share_replica_get(context, id)
        except exception.ShareReplicaNotFound:
            msg = _("No replica exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        replica_state = replica.get('replica_state')

        if replica_state == constants.REPLICA_STATE_ACTIVE:
            return webob.Response(status_int=200)

        try:
            self.share_api.update_share_replica(context, replica)
        except exception.InvalidHost as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))


def create_resource():
    return wsgi.Resource(ShareReplicationController())
