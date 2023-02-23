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

from http import client as http_client

from oslo_utils import strutils
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.views import share_replicas as replication_view
from manila.common import constants
from manila import db
from manila import exception
from manila.i18n import _
from manila import share


MIN_SUPPORTED_API_VERSION = '2.11'
PRE_GRADUATION_VERSION = '2.55'
GRADUATION_VERSION = '2.56'


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
            raise exc.HTTPBadRequest(explanation=e.msg)

    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    def index(self, req):
        """Return a summary list of replicas."""
        return self._get_replicas(req)

    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    def index(self, req):  # pylint: disable=function-redefined  # noqa F811
        """Return a summary list of replicas."""
        return self._get_replicas(req)

    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    def detail(self, req):
        """Returns a detailed list of replicas."""
        return self._get_replicas(req, is_detail=True)

    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    def detail(self, req):  # pylint: disable=function-redefined  # noqa F811
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

    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    def show(self, req, id):
        """Return data about the given replica."""
        return self._show(req, id)

    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    def show(self, req, id):  # pylint: disable=function-redefined   # noqa F811
        """Return data about the given replica."""
        return self._show(req, id)

    @wsgi.Controller.authorize('show')
    def _show(self, req, id):
        """Return data about the given replica."""
        context = req.environ['manila.context']

        try:
            replica = db.share_replica_get(context, id)
        except exception.ShareReplicaNotFound:
            msg = _("Replica %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)

        return self._view_builder.detail(req, replica)

    def _validate_body(self, body):
        if not self.is_valid_body(body, 'share_replica'):
            msg = _("Body does not contain 'share_replica' information.")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    @wsgi.response(202)
    def create(self, req, body):
        return self._create(req, body)

    @wsgi.Controller.api_version(GRADUATION_VERSION, "2.66")  # noqa
    @wsgi.response(202)
    def create(self, req, body):  # pylint: disable=function-redefined  # noqa F811
        return self._create(req, body)

    @wsgi.Controller.api_version("2.67") # noqa
    @wsgi.response(202)
    def create(self, req, body): # pylint: disable=function-redefined  # noqa F811
        return self._create(req, body, allow_scheduler_hints=True)

    @wsgi.Controller.authorize('create')
    def _create(self, req, body, allow_scheduler_hints=False):
        """Add a replica to an existing share."""
        context = req.environ['manila.context']
        self._validate_body(body)
        share_id = body.get('share_replica').get('share_id')
        availability_zone = body.get('share_replica').get('availability_zone')
        scheduler_hints = None
        if allow_scheduler_hints:
            scheduler_hints = body.get('share_replica').get('scheduler_hints')

        if not share_id:
            msg = _("Must provide Share ID to add replica.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            share_ref = db.share_get(context, share_id)
        except exception.NotFound:
            msg = _("No share exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % share_id)

        if share_ref.get('is_soft_deleted'):
            msg = _("Replica cannot be created for share '%s' "
                    "since it has been soft deleted.") % share_id
            raise exc.HTTPForbidden(explanation=msg)

        share_network_id = body.get('share_replica').get('share_network_id')
        if share_network_id:
            if req.api_version_request < api_version.APIVersionRequest("2.72"):
                msg = _("'share_network_id' option is not supported by this "
                        "microversion. Use 2.72 or greater microversion to "
                        "be able to use 'share_network_id'.")
                raise exc.HTTPBadRequest(explanation=msg)
        else:
            share_network_id = share_ref.get('share_network_id', None)

        try:
            if share_network_id:
                share_network = db.share_network_get(context, share_network_id)
                common.check_share_network_is_active(share_network)
        except exception.ShareNetworkNotFound:
            msg = _("No share network exists with ID %s.")
            raise exc.HTTPBadRequest(explanation=msg % share_network_id)

        try:
            new_replica = self.share_api.create_share_replica(
                context, share_ref, availability_zone=availability_zone,
                share_network_id=share_network_id,
                scheduler_hints=scheduler_hints)
        except exception.AvailabilityZoneNotFound as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.ReplicationException as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.ShareBusyException as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        return self._view_builder.detail(req, new_replica)

    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    def delete(self, req, id):
        return self._delete_share_replica(req, id)

    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    def delete(self, req, id):  # pylint: disable=function-redefined  # noqa F811
        return self._delete_share_replica(req, id)

    @wsgi.Controller.authorize('delete')
    def _delete_share_replica(self, req, id):
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
            raise exc.HTTPBadRequest(explanation=e.msg)

        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    @wsgi.response(202)
    @wsgi.action('promote')
    def promote(self, req, id, body):
        return self._promote(req, id, body)

    @wsgi.Controller.api_version(GRADUATION_VERSION, "2.74")  # noqa
    @wsgi.response(202)
    @wsgi.action('promote')
    def promote(self, req, id, body): # pylint: disable=function-redefined  # noqa F811
        return self._promote(req, id, body)

    @wsgi.Controller.api_version("2.75")  # noqa
    @wsgi.response(202)
    @wsgi.action('promote')
    def promote(self, req, id, body):  # pylint: disable=function-redefined  # noqa F811
        return self._promote(req, id, body, allow_quiesce_wait_time=True)

    @wsgi.Controller.authorize('promote')
    def _promote(self, req, id, body,
                 allow_quiesce_wait_time=False):
        """Promote a replica to active state."""
        context = req.environ['manila.context']

        try:
            replica = db.share_replica_get(context, id)
        except exception.ShareReplicaNotFound:
            msg = _("No replica exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        share_network_id = replica.get('share_network_id')
        if share_network_id:
            share_network = db.share_network_get(context, share_network_id)
            common.check_share_network_is_active(share_network)

        replica_state = replica.get('replica_state')

        if replica_state == constants.REPLICA_STATE_ACTIVE:
            return webob.Response(status_int=http_client.OK)

        quiesce_wait_time = None
        if allow_quiesce_wait_time:
            # NOTE(carloss): there is a chance that we receive
            # {'promote': null}, so we need to prevent that
            promote_data = body.get('promote', {})
            promote_data = {} if promote_data is None else promote_data
            wait_time = promote_data.get('quiesce_wait_time')
            if wait_time:
                if not strutils.is_int_like(wait_time) or int(wait_time) <= 0:
                    msg = _("quiesce_wait_time must be an integer and "
                            "greater than 0.")
                    raise exc.HTTPBadRequest(explanation=msg)
                else:
                    quiesce_wait_time = int(wait_time)

        try:
            replica = self.share_api.promote_share_replica(
                context, replica,
                quiesce_wait_time=quiesce_wait_time)
        except exception.ReplicationException as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.AdminRequired as e:
            raise exc.HTTPForbidden(explanation=e.message)

        return self._view_builder.detail(req, replica)

    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    @wsgi.action('reset_status')
    def reset_status(self, req, id, body):
        """Reset the 'status' attribute in the database."""
        return self._reset_status(req, id, body)

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    @wsgi.action('reset_status')
    def reset_status(self, req, id, body):  # noqa F811
        """Reset the 'status' attribute in the database."""
        return self._reset_status(req, id, body)

    # pylint: enable=function-redefined
    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    @wsgi.action('force_delete')
    def force_delete(self, req, id, body):
        """Force deletion on the database, attempt on the backend."""
        return self._force_delete(req, id, body)

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    @wsgi.action('force_delete')
    def force_delete(self, req, id, body):  # noqa F811
        """Force deletion on the database, attempt on the backend."""
        return self._force_delete(req, id, body)

    # pylint: enable=function-redefined
    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    @wsgi.action('reset_replica_state')
    @wsgi.Controller.authorize
    def reset_replica_state(self, req, id, body):
        """Reset the 'replica_state' attribute in the database."""
        return self._reset_status(req, id, body, status_attr='replica_state')

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    @wsgi.action('reset_replica_state')
    @wsgi.Controller.authorize
    def reset_replica_state(self, req, id, body):  # noqa F811
        """Reset the 'replica_state' attribute in the database."""
        return self._reset_status(req, id, body, status_attr='replica_state')

    # pylint: enable=function-redefined
    @wsgi.Controller.api_version(
        MIN_SUPPORTED_API_VERSION, PRE_GRADUATION_VERSION, experimental=True)
    @wsgi.response(202)
    @wsgi.action('resync')
    def resync(self, req, id, body):
        return self._resync(req, id, body)

    @wsgi.Controller.api_version(GRADUATION_VERSION)  # noqa
    @wsgi.response(202)
    @wsgi.action('resync')
    def resync(self, req, id, body):  # pylint: disable=function-redefined  # noqa F811
        return self._resync(req, id, body)

    @wsgi.Controller.authorize('resync')
    def _resync(self, req, id, body):
        """Attempt to update/sync the replica with its source."""
        context = req.environ['manila.context']
        try:
            replica = db.share_replica_get(context, id)
        except exception.ShareReplicaNotFound:
            msg = _("No replica exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        replica_state = replica.get('replica_state')

        if replica_state == constants.REPLICA_STATE_ACTIVE:
            return webob.Response(status_int=http_client.OK)

        try:
            self.share_api.update_share_replica(context, replica)
        except exception.InvalidHost as e:
            raise exc.HTTPBadRequest(explanation=e.msg)


def create_resource():
    return wsgi.Resource(ShareReplicationController())
