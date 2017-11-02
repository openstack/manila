# Copyright (c) 2015 Mirantis inc.
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

from oslo_log import log
import six
import webob
from webob import exc

from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.v1 import share_manage
from manila.api.v1 import share_unmanage
from manila.api.v1 import shares
from manila.api.views import share_accesses as share_access_views
from manila.api.views import share_migration as share_migration_views
from manila.api.views import shares as share_views
from manila.common import constants
from manila import db
from manila import exception
from manila.i18n import _
from manila import share
from manila import utils

LOG = log.getLogger(__name__)


class ShareController(shares.ShareMixin,
                      share_manage.ShareManageMixin,
                      share_unmanage.ShareUnmanageMixin,
                      wsgi.Controller,
                      wsgi.AdminActionsMixin):
    """The Shares API v2 controller for the OpenStack API."""
    resource_name = 'share'
    _view_builder_class = share_views.ViewBuilder

    def __init__(self):
        super(self.__class__, self).__init__()
        self.share_api = share.API()
        self._access_view_builder = share_access_views.ViewBuilder()
        self._migration_view_builder = share_migration_views.ViewBuilder()

    @wsgi.Controller.authorize('revert_to_snapshot')
    def _revert(self, req, id, body=None):
        """Revert a share to a snapshot."""
        context = req.environ['manila.context']
        revert_data = self._validate_revert_parameters(context, body)

        try:
            share_id = id
            snapshot_id = revert_data['snapshot_id']

            share = self.share_api.get(context, share_id)
            snapshot = self.share_api.get_snapshot(context, snapshot_id)

            # Ensure share supports reverting to a snapshot
            if not share['revert_to_snapshot_support']:
                msg_args = {'share_id': share_id, 'snap_id': snapshot_id}
                msg = _('Share %(share_id)s may not be reverted to snapshot '
                        '%(snap_id)s, because the share does not have that '
                        'capability.')
                raise exc.HTTPBadRequest(explanation=msg % msg_args)

            # Ensure requested share & snapshot match.
            if share['id'] != snapshot['share_id']:
                msg_args = {'share_id': share_id, 'snap_id': snapshot_id}
                msg = _('Snapshot %(snap_id)s is not associated with share '
                        '%(share_id)s.')
                raise exc.HTTPBadRequest(explanation=msg % msg_args)

            # Ensure share status is 'available'.
            if share['status'] != constants.STATUS_AVAILABLE:
                msg_args = {
                    'share_id': share_id,
                    'state': share['status'],
                    'available': constants.STATUS_AVAILABLE,
                }
                msg = _("Share %(share_id)s is in '%(state)s' state, but it "
                        "must be in '%(available)s' state to be reverted to a "
                        "snapshot.")
                raise exc.HTTPConflict(explanation=msg % msg_args)

            # Ensure snapshot status is 'available'.
            if snapshot['status'] != constants.STATUS_AVAILABLE:
                msg_args = {
                    'snap_id': snapshot_id,
                    'state': snapshot['status'],
                    'available': constants.STATUS_AVAILABLE,
                }
                msg = _("Snapshot %(snap_id)s is in '%(state)s' state, but it "
                        "must be in '%(available)s' state to be restored.")
                raise exc.HTTPConflict(explanation=msg % msg_args)

            # Ensure a long-running task isn't active on the share
            if share.is_busy:
                msg_args = {'share_id': share_id}
                msg = _("Share %(share_id)s may not be reverted while it has "
                        "an active task.")
                raise exc.HTTPConflict(explanation=msg % msg_args)

            # Ensure the snapshot is the most recent one.
            latest_snapshot = self.share_api.get_latest_snapshot_for_share(
                context, share_id)
            if not latest_snapshot:
                msg_args = {'share_id': share_id}
                msg = _("Could not determine the latest snapshot for share "
                        "%(share_id)s.")
                raise exc.HTTPBadRequest(explanation=msg % msg_args)
            if latest_snapshot['id'] != snapshot_id:
                msg_args = {
                    'share_id': share_id,
                    'snap_id': snapshot_id,
                    'latest_snap_id': latest_snapshot['id'],
                }
                msg = _("Snapshot %(snap_id)s may not be restored because "
                        "it is not the most recent snapshot of share "
                        "%(share_id)s. Currently the latest snapshot is "
                        "%(latest_snap_id)s.")
                raise exc.HTTPConflict(explanation=msg % msg_args)

            # Ensure the access rules are not in the process of updating
            for instance in share['instances']:
                access_rules_status = instance['access_rules_status']
                if access_rules_status != constants.ACCESS_STATE_ACTIVE:
                    msg_args = {
                        'share_id': share_id,
                        'snap_id': snapshot_id,
                        'state': constants.ACCESS_STATE_ACTIVE
                    }
                    msg = _("Snapshot %(snap_id)s belongs to a share "
                            "%(share_id)s which has access rules that are"
                            "not %(state)s.")
                    raise exc.HTTPConflict(explanation=msg % msg_args)

            msg_args = {'share_id': share_id, 'snap_id': snapshot_id}
            msg = 'Reverting share %(share_id)s to snapshot %(snap_id)s.'
            LOG.info(msg, msg_args)

            self.share_api.revert_to_snapshot(context, share, snapshot)
        except exception.ShareNotFound as e:
            raise exc.HTTPNotFound(explanation=six.text_type(e))
        except exception.ShareSnapshotNotFound as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))
        except exception.ShareSizeExceedsAvailableQuota as e:
            raise exc.HTTPForbidden(explanation=six.text_type(e))
        except exception.ReplicationException as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))

        return webob.Response(status_int=202)

    def _validate_revert_parameters(self, context, body):
        if not (body and self.is_valid_body(body, 'revert')):
            msg = _("Revert entity not found in request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        required_parameters = ('snapshot_id',)
        data = body['revert']

        for parameter in required_parameters:
            if parameter not in data:
                msg = _("Required parameter %s not found.") % parameter
                raise exc.HTTPBadRequest(explanation=msg)
            if not data.get(parameter):
                msg = _("Required parameter %s is empty.") % parameter
                raise exc.HTTPBadRequest(explanation=msg)

        return data

    @wsgi.Controller.api_version("2.31")
    def create(self, req, body):
        return self._create(
            req, body, check_create_share_from_snapshot_support=True)

    @wsgi.Controller.api_version("2.24", "2.30")  # noqa
    def create(self, req, body):  # pylint: disable=E0102
        body.get('share', {}).pop('share_group_id', None)
        return self._create(req, body,
                            check_create_share_from_snapshot_support=True)

    @wsgi.Controller.api_version("2.0", "2.23")  # noqa
    def create(self, req, body):  # pylint: disable=E0102
        body.get('share', {}).pop('share_group_id', None)
        return self._create(req, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-reset_status')
    def share_reset_status_legacy(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('reset_status')
    def share_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-force_delete')
    def share_force_delete_legacy(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('force_delete')
    def share_force_delete(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.29', experimental=True)
    @wsgi.action("migration_start")
    @wsgi.Controller.authorize
    def migration_start(self, req, id, body):
        """Migrate a share to the specified host."""
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            msg = _("Share %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)
        params = body.get('migration_start')

        if not params:
            raise exc.HTTPBadRequest(explanation=_("Request is missing body."))

        driver_assisted_params = ['preserve_metadata', 'writable',
                                  'nondisruptive', 'preserve_snapshots']
        bool_params = (driver_assisted_params +
                       ['force_host_assisted_migration'])
        mandatory_params = driver_assisted_params + ['host']

        utils.check_params_exist(mandatory_params, params)
        bool_param_values = utils.check_params_are_boolean(bool_params, params)

        new_share_network = None
        new_share_type = None

        new_share_network_id = params.get('new_share_network_id', None)
        if new_share_network_id:
            try:
                new_share_network = db.share_network_get(
                    context, new_share_network_id)
            except exception.NotFound:
                msg = _("Share network %s not "
                        "found.") % new_share_network_id
                raise exc.HTTPBadRequest(explanation=msg)

        new_share_type_id = params.get('new_share_type_id', None)
        if new_share_type_id:
            try:
                new_share_type = db.share_type_get(
                    context, new_share_type_id)
            except exception.NotFound:
                msg = _("Share type %s not found.") % new_share_type_id
                raise exc.HTTPBadRequest(explanation=msg)

        try:
            return_code = self.share_api.migration_start(
                context, share, params['host'],
                bool_param_values['force_host_assisted_migration'],
                bool_param_values['preserve_metadata'],
                bool_param_values['writable'],
                bool_param_values['nondisruptive'],
                bool_param_values['preserve_snapshots'],
                new_share_network=new_share_network,
                new_share_type=new_share_type)
        except exception.Conflict as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))

        return webob.Response(status_int=return_code)

    @wsgi.Controller.api_version('2.22', experimental=True)
    @wsgi.action("migration_complete")
    @wsgi.Controller.authorize
    def migration_complete(self, req, id, body):
        """Invokes 2nd phase of share migration."""
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            msg = _("Share %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)
        self.share_api.migration_complete(context, share)
        return webob.Response(status_int=202)

    @wsgi.Controller.api_version('2.22', experimental=True)
    @wsgi.action("migration_cancel")
    @wsgi.Controller.authorize
    def migration_cancel(self, req, id, body):
        """Attempts to cancel share migration."""
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            msg = _("Share %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)
        self.share_api.migration_cancel(context, share)
        return webob.Response(status_int=202)

    @wsgi.Controller.api_version('2.22', experimental=True)
    @wsgi.action("migration_get_progress")
    @wsgi.Controller.authorize
    def migration_get_progress(self, req, id, body):
        """Retrieve share migration progress for a given share."""
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            msg = _("Share %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)
        result = self.share_api.migration_get_progress(context, share)

        # refresh share model
        share = self.share_api.get(context, id)

        return self._migration_view_builder.get_progress(req, share, result)

    @wsgi.Controller.api_version('2.22', experimental=True)
    @wsgi.action("reset_task_state")
    @wsgi.Controller.authorize
    def reset_task_state(self, req, id, body):
        return self._reset_status(req, id, body, status_attr='task_state')

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-allow_access')
    def allow_access_legacy(self, req, id, body):
        """Add share access rule."""
        return self._allow_access(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('allow_access')
    def allow_access(self, req, id, body):
        """Add share access rule."""
        args = (req, id, body)
        kwargs = {}
        if req.api_version_request >= api_version.APIVersionRequest("2.13"):
            kwargs['enable_ceph'] = True
        if req.api_version_request >= api_version.APIVersionRequest("2.28"):
            kwargs['allow_on_error_status'] = True
        if req.api_version_request >= api_version.APIVersionRequest("2.38"):
            kwargs['enable_ipv6'] = True

        return self._allow_access(*args, **kwargs)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-deny_access')
    def deny_access_legacy(self, req, id, body):
        """Remove share access rule."""
        return self._deny_access(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('deny_access')
    def deny_access(self, req, id, body):
        """Remove share access rule."""
        return self._deny_access(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-access_list')
    def access_list_legacy(self, req, id, body):
        """List share access rules."""
        return self._access_list(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('access_list')
    def access_list(self, req, id, body):
        """List share access rules."""
        return self._access_list(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-extend')
    def extend_legacy(self, req, id, body):
        """Extend size of a share."""
        return self._extend(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('extend')
    def extend(self, req, id, body):
        """Extend size of a share."""
        return self._extend(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-shrink')
    def shrink_legacy(self, req, id, body):
        """Shrink size of a share."""
        return self._shrink(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('shrink')
    def shrink(self, req, id, body):
        """Shrink size of a share."""
        return self._shrink(req, id, body)

    @wsgi.Controller.api_version('2.7', '2.7')
    def manage(self, req, body):
        body.get('share', {}).pop('is_public', None)
        detail = self._manage(req, body)
        return detail

    @wsgi.Controller.api_version("2.8")  # noqa
    def manage(self, req, body):  # pylint: disable=E0102
        detail = self._manage(req, body)
        return detail

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('unmanage')
    def unmanage(self, req, id, body=None):
        return self._unmanage(req, id, body)

    @wsgi.Controller.api_version('2.27')
    @wsgi.action('revert')
    def revert(self, req, id, body=None):
        return self._revert(req, id, body)

    @wsgi.Controller.api_version("2.0")
    def index(self, req):
        """Returns a summary list of shares."""
        if req.api_version_request < api_version.APIVersionRequest("2.35"):
            req.GET.pop('export_location_id', None)
            req.GET.pop('export_location_path', None)

        if req.api_version_request < api_version.APIVersionRequest("2.36"):
            req.GET.pop('name~', None)
            req.GET.pop('description~', None)
            req.GET.pop('description', None)

        if req.api_version_request < api_version.APIVersionRequest("2.42"):
            req.GET.pop('with_count', None)

        return self._get_shares(req, is_detail=False)

    @wsgi.Controller.api_version("2.0")
    def detail(self, req):
        """Returns a detailed list of shares."""
        if req.api_version_request < api_version.APIVersionRequest("2.35"):
            req.GET.pop('export_location_id', None)
            req.GET.pop('export_location_path', None)

        if req.api_version_request < api_version.APIVersionRequest("2.36"):
            req.GET.pop('name~', None)
            req.GET.pop('description~', None)
            req.GET.pop('description', None)

        return self._get_shares(req, is_detail=True)


def create_resource():
    return wsgi.Resource(ShareController())
