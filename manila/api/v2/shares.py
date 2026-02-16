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

import ast
from http import client as http_client

from oslo_config import cfg
from oslo_log import log
from oslo_utils import strutils
from oslo_utils import uuidutils
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.schemas import shares as schema
from manila.api.v2 import metadata
from manila.api import validation
from manila.api.views import share_accesses as share_access_views
from manila.api.views import share_migration as share_migration_views
from manila.api.views import shares as share_views
from manila.common import constants
from manila import db
from manila import exception
from manila.i18n import _
from manila.lock import api as resource_locks
from manila import policy
from manila import share
from manila.share import share_types
from manila.share import utils as share_utils
from manila import utils

LOG = log.getLogger(__name__)
CONF = cfg.CONF


class ShareController(
    wsgi.Controller, metadata.MetadataController, wsgi.AdminActionsMixin
):
    """The Shares API v2 controller for the OpenStack API."""
    resource_name = 'share'
    _view_builder_class = share_views.ViewBuilder

    def __init__(self):
        super(ShareController, self).__init__()
        self.share_api = share.API()
        self.resource_locks_api = resource_locks.API()
        self._access_view_builder = share_access_views.ViewBuilder()
        self._migration_view_builder = share_migration_views.ViewBuilder()
        self._conf_admin_only_metadata_keys = getattr(
            CONF, 'admin_only_metadata', []
        )

    def _update(self, *args, **kwargs):
        db.share_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return self.share_api.get(*args, **kwargs)

    def _delete(self, *args, **kwargs):
        return self.share_api.delete(*args, **kwargs)

    @wsgi.Controller.authorize('create')
    def _create(self, req, body,
                check_create_share_from_snapshot_support=False,
                check_availability_zones_extra_spec=False,
                scheduler_hints=None, encryption_key_ref=None):
        """Creates a new share."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share'):
            raise exc.HTTPUnprocessableEntity()

        share = body['share']
        share = common.validate_public_share_policy(context, share)

        # NOTE(rushiagr): Manila API allows 'name' instead of 'display_name'.
        if share.get('name'):
            share['display_name'] = share.get('name')
            common.check_display_field_length(share['display_name'], 'name')
            del share['name']

        # NOTE(rushiagr): Manila API allows 'description' instead of
        #                 'display_description'.
        if share.get('description'):
            share['display_description'] = share.get('description')
            common.check_display_field_length(
                share['display_description'], 'description')
            del share['description']

        size = share['size']
        share_proto = share['share_proto'].upper()

        msg = ("Create %(share_proto)s share of %(size)s GB" %
               {'share_proto': share_proto, 'size': size})
        LOG.info(msg, context=context)

        availability_zone_id = None
        availability_zone = share.get('availability_zone')
        if availability_zone:
            try:
                availability_zone_db = db.availability_zone_get(
                    context, availability_zone)
                availability_zone_id = availability_zone_db.id
                availability_zone = availability_zone_db.name
            except exception.AvailabilityZoneNotFound as e:
                raise exc.HTTPNotFound(explanation=e.msg)

        share_group_id = share.get('share_group_id')
        if share_group_id:
            try:
                share_group = db.share_group_get(context, share_group_id)
            except exception.ShareGroupNotFound as e:
                raise exc.HTTPNotFound(explanation=e.msg)
            sg_az_id = share_group['availability_zone_id']
            if availability_zone and availability_zone_id != sg_az_id:
                msg = _("Share cannot have AZ ('%(s_az)s') different than "
                        "share group's one (%(sg_az)s).") % {
                            's_az': availability_zone_id, 'sg_az': sg_az_id}
                raise exception.InvalidInput(msg)
            availability_zone = db.availability_zone_get(
                context, sg_az_id).name

        kwargs = {
            'availability_zone': availability_zone,
            'metadata': share.get('metadata'),
            'is_public': share.get('is_public', False),
            'share_group_id': share_group_id,
        }

        snapshot_id = share.get('snapshot_id')
        if snapshot_id:
            snapshot = self.share_api.get_snapshot(context, snapshot_id)
        else:
            snapshot = None

        kwargs['snapshot_id'] = snapshot_id

        share_network_id = share.get('share_network_id')

        parent_share_type = {}
        if snapshot:
            # Need to check that share_network_id from snapshot's
            # parents share equals to share_network_id from args.
            # If share_network_id is empty then update it with
            # share_network_id of parent share.
            parent_share = self.share_api.get(context, snapshot['share_id'])
            parent_share_net_id = parent_share.instance['share_network_id']
            parent_share_type = share_types.get_share_type(
                context, parent_share.instance['share_type_id'])
            if share_network_id:
                if share_network_id != parent_share_net_id:
                    msg = ("Share network ID should be the same as snapshot's"
                           " parent share's or empty")
                    raise exc.HTTPBadRequest(explanation=msg)
            elif parent_share_net_id:
                share_network_id = parent_share_net_id

            # Verify that share can be created from a snapshot
            if (check_create_share_from_snapshot_support and
                    not parent_share['create_share_from_snapshot_support']):
                msg = (_("A new share may not be created from snapshot '%s', "
                         "because the snapshot's parent share does not have "
                         "that capability.")
                       % snapshot_id)
                LOG.error(msg)
                raise exc.HTTPBadRequest(explanation=msg)

        if share_network_id:
            try:
                share_network = self.share_api.get_share_network(
                    context,
                    share_network_id)
            except exception.ShareNetworkNotFound as e:
                raise exc.HTTPNotFound(explanation=e.msg)

            common.check_share_network_is_active(share_network)

            if availability_zone_id:
                subnets = (
                    db.share_network_subnets_get_all_by_availability_zone_id(
                        context, share_network_id,
                        availability_zone_id=availability_zone_id))
                if not subnets:
                    msg = _("A share network subnet was not found for the "
                            "requested availability zone.")
                    raise exc.HTTPBadRequest(explanation=msg)
                kwargs['az_request_multiple_subnet_support_map'] = {
                    availability_zone_id: len(subnets) > 1,
                }

        display_name = share.get('display_name')
        display_description = share.get('display_description')

        if 'share_type' in share and 'volume_type' in share:
            msg = 'Cannot specify both share_type and volume_type'
            raise exc.HTTPBadRequest(explanation=msg)
        req_share_type = share.get('share_type', share.get('volume_type'))

        share_type = None
        if req_share_type:
            try:
                if not uuidutils.is_uuid_like(req_share_type):
                    share_type = share_types.get_share_type_by_name(
                        context, req_share_type)
                else:
                    share_type = share_types.get_share_type(
                        context, req_share_type)
            except (exception.ShareTypeNotFound,
                    exception.ShareTypeNotFoundByName):
                msg = _("Share type not found.")
                raise exc.HTTPNotFound(explanation=msg)
            except exception.InvalidShareType as e:
                raise exc.HTTPBadRequest(explanation=e.message)
        elif not snapshot:
            def_share_type = share_types.get_default_share_type()
            if def_share_type:
                share_type = def_share_type

        # Only use in create share feature. Create share from snapshot
        # and create share with share group features not
        # need this check.
        if share_type and share_type.get('extra_specs'):
            dhss = (strutils.bool_from_string(
                share_type.get('extra_specs').get(
                    'driver_handles_share_servers')))
        else:
            dhss = False

        if (not share_network_id and not snapshot
                and not share_group_id
                and dhss):
            msg = _('Share network must be set when the '
                    'driver_handles_share_servers is true.')
            raise exc.HTTPBadRequest(explanation=msg)

        type_chosen = share_type or parent_share_type
        if type_chosen and check_availability_zones_extra_spec:
            type_azs = type_chosen.get(
                'extra_specs', {}).get('availability_zones', '')
            type_azs = type_azs.split(',') if type_azs else []
            kwargs['availability_zones'] = type_azs
            if (availability_zone and type_azs and
                    availability_zone not in type_azs):
                msg = _("Share type %(type)s is not supported within the "
                        "availability zone chosen %(az)s.")
                type_chosen = (
                    req_share_type or "%s (from source snapshot)" % (
                        parent_share_type.get('name') or
                        parent_share_type.get('id'))
                )
                payload = {'type': type_chosen, 'az': availability_zone}
                raise exc.HTTPBadRequest(explanation=msg % payload)

        if share_type and encryption_key_ref:
            type_enc = share_type.get(
                'extra_specs', {}).get('encryption_support')
            if type_enc not in constants.SUPPORTED_ENCRYPTION_TYPES:
                msg = _("Share type %(type)s extra-specs 'encryption_support' "
                        "is missing valid value e.g. share, share_server.")
                payload = {'type': share_type}
                raise exc.HTTPBadRequest(explanation=msg % payload)
            if not dhss:
                msg = _("Share type %(type)s must set dhss=True for share "
                        "encryption.")
                payload = {'type': share_type}
                raise exc.HTTPBadRequest(explanation=msg % payload)

        if share_type:
            kwargs['share_type'] = share_type
        if share_network_id:
            kwargs['share_network_id'] = share_network_id

        kwargs['scheduler_hints'] = scheduler_hints
        kwargs['encryption_key_ref'] = encryption_key_ref

        if req.api_version_request >= api_version.APIVersionRequest("2.84"):
            kwargs['mount_point_name'] = share.pop('mount_point_name', None)

        new_share = self.share_api.create(context,
                                          share_proto,
                                          size,
                                          display_name,
                                          display_description,
                                          **kwargs)

        return self._view_builder.detail(req, new_share)

    @wsgi.Controller.api_version("2.90")
    def create(self, req, body):
        if not self.is_valid_body(body, 'share'):
            raise exc.HTTPUnprocessableEntity()

        share = body['share']
        scheduler_hints = share.pop('scheduler_hints', None)
        encryption_key_ref = share.pop('encryption_key_ref', None)

        return self._create(
            req, body,
            check_create_share_from_snapshot_support=True,
            check_availability_zones_extra_spec=True,
            scheduler_hints=scheduler_hints,
            encryption_key_ref=encryption_key_ref)

    @wsgi.Controller.api_version("2.65", "2.89")
    def create(self, req, body): # pylint: disable=function-redefined  # noqa F811
        if not self.is_valid_body(body, 'share'):
            raise exc.HTTPUnprocessableEntity()

        share = body['share']
        scheduler_hints = share.pop('scheduler_hints', None)
        if req.api_version_request < api_version.APIVersionRequest("2.67"):
            if scheduler_hints:
                scheduler_hints.pop('only_host', None)

        return self._create(
            req, body,
            check_create_share_from_snapshot_support=True,
            check_availability_zones_extra_spec=True,
            scheduler_hints=scheduler_hints)

    @wsgi.Controller.api_version("2.48", "2.64") # noqa
    def create(self, req, body):  # pylint: disable=function-redefined  # noqa F811
        return self._create(req, body,
                            check_create_share_from_snapshot_support=True,
                            check_availability_zones_extra_spec=True)

    @wsgi.Controller.api_version("2.31", "2.47")  # noqa
    def create(self, req, body):  # pylint: disable=function-redefined  # noqa F811
        return self._create(
            req, body, check_create_share_from_snapshot_support=True)

    @wsgi.Controller.api_version("2.24", "2.30")  # noqa
    def create(self, req, body):  # pylint: disable=function-redefined  # noqa F811
        body.get('share', {}).pop('share_group_id', None)
        return self._create(req, body,
                            check_create_share_from_snapshot_support=True)

    @wsgi.Controller.api_version("2.0", "2.23")  # noqa
    def create(self, req, body):  # pylint: disable=function-redefined  # noqa F811
        body.get('share', {}).pop('share_group_id', None)
        return self._create(req, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-reset_status')
    @validation.request_body_schema(schema.reset_status_request_body, '2.0', '2.6')  # noqa: E501
    @validation.response_body_schema(schema.reset_status_response_body)
    def share_reset_status_legacy(self, req, id, body):
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound("Share %s not found" % id)
        if share.get('is_soft_deleted'):
            msg = _("status cannot be reset for share '%s' "
                    "since it has been soft deleted.") % id
            raise exc.HTTPForbidden(explanation=msg)
        return self._reset_status(req, id, body, resource=share)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('reset_status')
    @wsgi.Controller.authorize('reset_status')
    @validation.request_body_schema(schema.reset_status_request_body_v27, '2.7')  # noqa: E501
    @validation.response_body_schema(schema.reset_status_response_body)
    def share_reset_status(self, req, id, body):
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound("Share %s not found" % id)
        if share.get('is_soft_deleted'):
            msg = _("status cannot be reset for share '%s' "
                    "since it has been soft deleted.") % id
            raise exc.HTTPForbidden(explanation=msg)
        return self._reset_status(req, id, body, resource=share)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-force_delete')
    @validation.request_body_schema(schema.force_delete_request_body)
    @validation.response_body_schema(schema.force_delete_response_body)
    def share_force_delete_legacy(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('force_delete')
    @validation.request_body_schema(schema.force_delete_request_body_v27)
    @validation.response_body_schema(schema.force_delete_response_body)
    def share_force_delete(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.69')
    @wsgi.action('soft_delete')
    @wsgi.Controller.authorize('soft_delete')
    @validation.request_body_schema(schema.soft_delete_request_body)
    @validation.response_body_schema(schema.soft_delete_response_body)
    def share_soft_delete(self, req, id, body):
        """Soft delete a share."""
        context = req.environ['manila.context']

        LOG.debug("Soft delete share with id: %s", id, context=context)

        try:
            share = self.share_api.get(context, id)
            self.share_api.soft_delete(context, share)
        except exception.NotFound:
            raise exc.HTTPNotFound()
        except exception.InvalidShare as e:
            raise exc.HTTPForbidden(explanation=e.msg)
        except exception.ShareBusyException as e:
            raise exc.HTTPForbidden(explanation=e.msg)
        except exception.Conflict as e:
            raise exc.HTTPConflict(explanation=e.msg)

        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.69')
    @wsgi.action('restore')
    @wsgi.Controller.authorize("restore")
    @validation.request_body_schema(schema.restore_request_body)
    @validation.response_body_schema(schema.restore_response_body)
    def share_restore(self, req, id, body):
        """Restore a share from recycle bin."""
        context = req.environ['manila.context']

        LOG.debug("Restore share with id: %s", id, context=context)

        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            msg = _("No share exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        # If the share not exist in Recycle Bin, the API will return
        # success directly.
        is_soft_deleted = share.get('is_soft_deleted')
        if not is_soft_deleted:
            return webob.Response(status_int=http_client.OK)

        # If the share has reached the expired time, and is been deleting,
        # it too late to restore the share.
        if share['status'] in [constants.STATUS_DELETING,
                               constants.STATUS_ERROR_DELETING]:
            msg = _("Share %s is being deleted or has suffered an error "
                    "during deletion, cannot be restored.")
            raise exc.HTTPForbidden(explanation=msg % id)

        self.share_api.restore(context, share)

        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.29', experimental=True)
    @wsgi.action("migration_start")
    @wsgi.Controller.authorize
    @validation.request_body_schema(schema.migration_start_request_body)
    @validation.response_body_schema(schema.migration_start_response_body)
    def migration_start(self, req, id, body):
        """Migrate a share to the specified host."""
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            msg = _("Share %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)

        if share.get('is_soft_deleted'):
            msg = _("Migration cannot start for share '%s' "
                    "since it has been soft deleted.") % id
            raise exception.InvalidShare(reason=msg)

        params = body['migration_start']

        bool_params = ['preserve_metadata', 'writable', 'nondisruptive',
                       'preserve_snapshots', 'force_host_assisted_migration']
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
            common.check_share_network_is_active(new_share_network)
        else:
            share_network_id = share.get('share_network_id', None)
            if share_network_id:
                current_share_network = db.share_network_get(
                    context, share_network_id)
                common.check_share_network_is_active(current_share_network)

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
            raise exc.HTTPConflict(explanation=e.msg)

        return webob.Response(status_int=return_code)

    @wsgi.Controller.api_version('2.22', experimental=True)
    @wsgi.action("migration_complete")
    @validation.request_body_schema(schema.migration_complete_request_body)
    @validation.response_body_schema(schema.migration_complete_response_body)
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
        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.22', experimental=True)
    @wsgi.action("migration_cancel")
    @wsgi.Controller.authorize
    @validation.request_body_schema(schema.migration_cancel_request_body)
    @validation.response_body_schema(schema.migration_cancel_response_body)
    def migration_cancel(self, req, id, body):
        """Attempts to cancel share migration."""
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            msg = _("Share %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)
        self.share_api.migration_cancel(context, share)
        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.22', experimental=True)
    @wsgi.action("migration_get_progress")
    @wsgi.Controller.authorize
    @validation.request_body_schema(schema.migration_get_progress_request_body)
    @validation.response_body_schema(schema.migration_get_progress_response_body, '2.22', '2.58')  # noqa: E501
    @validation.response_body_schema(schema.migration_get_progress_response_body_v259, '2.59')  # noqa: E501
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
    @validation.request_body_schema(schema.reset_task_state_request_body)
    @validation.response_body_schema(schema.reset_task_state_response_body)
    def reset_task_state(self, req, id, body):
        context = req.environ['manila.context']
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exception.ShareNotFound(share_id=id)
        if share.get('is_soft_deleted'):
            msg = _("task state cannot be reset for share '%s' "
                    "since it has been soft deleted.") % id
            raise exc.HTTPForbidden(explanation=msg)
        return self._reset_status(req, id, body, status_attr='task_state',
                                  resource=share)

    def _create_access_locks(
        self, context, access, lock_deletion=False, lock_visibility=False,
        lock_reason=None
    ):
        """Creates locks for access rules and rollback if it fails."""

        # We must populate project_id and user_id in the access object, as this
        # is not in this entity
        access['project_id'] = context.project_id
        access['user_id'] = context.user_id

        def raise_lock_failed(resource_id, lock_action,
                              resource_type='access rule'):
            word_mapping = {
                constants.RESOURCE_ACTION_SHOW: 'visibility',
                constants.RESOURCE_ACTION_DELETE: 'deletion'
            }
            msg = _("Failed to lock the %(action)s of the %(resource_type)s "
                    "%(resource_id)s.") % {
                'action': word_mapping[lock_action],
                'resource_id': resource_id,
                'resource_type': resource_type
            }
            raise webob.exc.HTTPBadRequest(explanation=msg)

        access_deletion_lock = {}
        share_deletion_lock = {}

        if lock_deletion:
            try:
                access_deletion_lock = self.resource_locks_api.create(
                    context, resource_id=access['id'],
                    resource_type='access_rule',
                    resource_action=constants.RESOURCE_ACTION_DELETE,
                    resource=access, lock_reason=lock_reason)
            except Exception:
                raise_lock_failed(
                    access['id'], constants.RESOURCE_ACTION_DELETE
                )
            try:
                share_lock_reason = (
                    constants.SHARE_LOCKED_BY_ACCESS_LOCK_REASON % {
                        'lock_id': access_deletion_lock['id']
                    }
                )
                share_deletion_lock = self.resource_locks_api.create(
                    context, resource_id=access['share_id'],
                    resource_type='share',
                    resource_action=constants.RESOURCE_ACTION_DELETE,
                    lock_reason=share_lock_reason)
            except Exception:
                self.resource_locks_api.delete(
                    context, access_deletion_lock['id'])
                raise_lock_failed(
                    access['share_id'], constants.RESOURCE_ACTION_DELETE,
                    resource_type='share'
                )

        if lock_visibility:
            try:
                self.resource_locks_api.create(
                    context, resource_id=access['id'],
                    resource_type='access_rule',
                    resource_action=constants.RESOURCE_ACTION_SHOW,
                    resource=access, lock_reason=lock_reason)
            except Exception:
                # If a deletion lock was placed and the visibility wasn't,
                # we should rollback the deletion lock.
                if access_deletion_lock:
                    self.resource_locks_api.delete(
                        context, access_deletion_lock['id'])
                if share_deletion_lock:
                    self.resource_locks_api.delete(
                        context, share_deletion_lock['id'])
                raise_lock_failed(access['id'], constants.RESOURCE_ACTION_SHOW)

    @staticmethod
    def _any_instance_has_errored_rules(share):
        for instance in share['instances']:
            access_rules_status = instance['access_rules_status']
            if access_rules_status == constants.SHARE_INSTANCE_RULES_ERROR:
                return True
        return False

    @wsgi.Controller.authorize('allow_access')
    def _allow_access(self, req, id, body, enable_ceph=False,
                      allow_on_error_status=False, enable_ipv6=False,
                      enable_metadata=False, allow_on_error_state=False,
                      lock_visibility=False, lock_deletion=False,
                      lock_reason=None):
        """Add share access rule."""
        context = req.environ['manila.context']
        access_data = body.get('allow_access', body.get('os-allow_access'))
        if not enable_metadata:
            access_data.pop('metadata', None)
        share = self.share_api.get(context, id)

        if share.get('is_soft_deleted'):
            msg = _("Cannot allow access for share '%s' "
                    "since it has been soft deleted.") % id
            raise exc.HTTPForbidden(explanation=msg)
        share_network_id = share.get('share_network_id')
        if share_network_id:
            share_network = db.share_network_get(context, share_network_id)
            common.check_share_network_is_active(share_network)

        if (not allow_on_error_status and
                self._any_instance_has_errored_rules(share)):
            msg = _("Access rules cannot be added while the share or any of "
                    "its replicas or migration copies has its "
                    "access_rules_status set to %(instance_rules_status)s. "
                    "Deny any rules in %(rule_state)s state and try "
                    "again.") % {
                'instance_rules_status': constants.SHARE_INSTANCE_RULES_ERROR,
                'rule_state': constants.ACCESS_STATE_ERROR,
            }
            raise webob.exc.HTTPBadRequest(explanation=msg)

        if not (lock_visibility or lock_deletion) and lock_reason:
            msg = _("Lock reason can only be specified when locking the "
                    "visibility or the deletion of an access rule.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        access_type = access_data['access_type']
        access_to = access_data['access_to']
        common.validate_access(access_type=access_type,
                               access_to=access_to,
                               enable_ceph=enable_ceph,
                               enable_ipv6=enable_ipv6)
        try:
            access = self.share_api.allow_access(
                context, share, access_type, access_to,
                access_data.get('access_level'), access_data.get('metadata'),
                allow_on_error_state)
        except exception.ShareAccessExists as e:
            raise webob.exc.HTTPBadRequest(explanation=e.msg)

        except exception.InvalidMetadata as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

        except exception.InvalidMetadataSize as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

        if lock_deletion or lock_visibility:
            self._create_access_locks(
                context, access, lock_deletion=lock_deletion,
                lock_visibility=lock_visibility, lock_reason=lock_reason)

        return self._access_view_builder.view(req, access)

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
        if req.api_version_request >= api_version.APIVersionRequest("2.45"):
            kwargs['enable_metadata'] = True
        if req.api_version_request >= api_version.APIVersionRequest("2.74"):
            kwargs['allow_on_error_state'] = True
        if req.api_version_request >= api_version.APIVersionRequest("2.82"):
            access_data = body.get('allow_access')
            kwargs['lock_visibility'] = access_data.get(
                'lock_visibility', False)
            kwargs['lock_deletion'] = access_data.get('lock_deletion', False)
            kwargs['lock_reason'] = access_data.get('lock_reason')

        return self._allow_access(*args, **kwargs)

    def _check_for_access_rule_locks(self, context, access_data, access_id,
                                     share_id):
        """Fetches locks for access rules and attempts deleting them."""

        # ensure the requester is asking to remove the restrictions of the rule
        unrestrict = access_data.get('unrestrict', False)
        search_opts = {
            'resource_id': access_id,
            'resource_action': constants.RESOURCE_ACTION_DELETE,
            'all_projects': True,
        }

        locks, locks_count = (
            self.resource_locks_api.get_all(
                context.elevated(), search_opts=search_opts,
                show_count=True) or []
        )

        # no locks placed, nothing to do
        if not locks:
            return

        def raise_rule_is_locked(share_id, unrestrict=False):
            msg = _(
                "Cannot deny access for share '%s' since it has been "
                "locked. Please remove the locks and retry the "
                "operation") % share_id
            if unrestrict:
                msg = _(
                    "Unable to drop access rule restrictions that are not "
                    "placed by you.")
            raise exc.HTTPForbidden(explanation=msg)

        if locks_count and not unrestrict:
            raise_rule_is_locked(share_id)

        non_deletable_locks = []
        for lock in locks:
            try:
                self.resource_locks_api.ensure_context_can_delete_lock(
                    context, lock['id'])
            except (exception.NotAuthorized, exception.ResourceLockNotFound):
                # If it is not found, then it means that the context doesn't
                # have access to this resource and should be denied.
                non_deletable_locks.append(lock)

        if non_deletable_locks:
            raise_rule_is_locked(share_id, unrestrict=unrestrict)

    @wsgi.Controller.authorize('deny_access')
    def _deny_access(self, req, id, body, allow_on_error_state=False):
        """Remove share access rule."""
        context = req.environ['manila.context']

        access_data = body.get('deny_access', body.get('os-deny_access'))
        access_id = access_data['access_id']

        self._check_for_access_rule_locks(context, access_data, access_id, id)

        share = self.share_api.get(context, id)

        if share.get('is_soft_deleted'):
            msg = _("Cannot deny access for share '%s' "
                    "since it has been soft deleted.") % id
            raise exc.HTTPForbidden(explanation=msg)

        share_network_id = share.get('share_network_id', None)

        if share_network_id:
            share_network = db.share_network_get(context, share_network_id)
            common.check_share_network_is_active(share_network)

        try:
            access = self.share_api.access_get(context, access_id)
            if access.share_id != id:
                raise exception.NotFound()
            share = self.share_api.get(context, id)
        except exception.NotFound as error:
            raise webob.exc.HTTPNotFound(explanation=error.message)
        self.share_api.deny_access(context, share, access,
                                   allow_on_error_state)
        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-deny_access')
    def deny_access_legacy(self, req, id, body):
        """Remove share access rule."""
        return self._deny_access(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('deny_access')
    def deny_access(self, req, id, body):
        """Remove share access rule."""
        args = (req, id, body)
        kwargs = {}
        if req.api_version_request >= api_version.APIVersionRequest("2.74"):
            kwargs['allow_on_error_state'] = True
        return self._deny_access(*args, **kwargs)

    def _access_list(self, req, id, body):
        """List share access rules."""
        context = req.environ['manila.context']

        share = self.share_api.get(context, id)
        access_rules = self.share_api.access_get_all(context, share)

        return self._access_view_builder.list_view(req, access_rules)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-access_list')
    def access_list_legacy(self, req, id, body):
        """List share access rules."""
        return self._access_list(req, id, body)

    @wsgi.Controller.api_version('2.7', '2.44')
    @wsgi.action('access_list')
    def access_list(self, req, id, body):
        """List share access rules."""
        return self._access_list(req, id, body)

    def _get_valid_extend_parameters(self, context, id, body, action):
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.message)

        try:
            size = int(body.get(action, body.get('extend'))['new_size'])
        except (KeyError, ValueError, TypeError):
            msg = _("New share size must be specified as an integer.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        # force is True means share extend will extend directly, is False
        # means will go through scheduler. Default value is False,
        try:
            force = strutils.bool_from_string(body.get(
                action, body.get('extend'))['force'], strict=True)
        except KeyError:
            force = False
        except (ValueError, TypeError):
            msg = (_('Invalid boolean force : %(value)s') %
                   {'value': body.get('extend')['force']})
            raise webob.exc.HTTPBadRequest(explanation=msg)

        return share, size, force

    @wsgi.Controller.authorize("extend")
    def _extend(self, req, id, body):
        """Extend size of a share."""
        context = req.environ['manila.context']
        share, size, force = self._get_valid_extend_parameters(
            context, id, body, 'os-extend')

        if share.get('is_soft_deleted'):
            msg = _("Cannot extend share '%s' "
                    "since it has been soft deleted.") % id
            raise exc.HTTPForbidden(explanation=msg)

        try:
            self.share_api.extend(context, share, size, force=force)
        except (exception.InvalidInput, exception.InvalidShare) as e:
            raise webob.exc.HTTPBadRequest(explanation=str(e))
        except exception.ShareSizeExceedsAvailableQuota as e:
            raise webob.exc.HTTPForbidden(explanation=e.message)

        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-extend')
    @validation.request_body_schema(schema.extend_request_body)
    @validation.response_body_schema(schema.extend_response_body)
    def extend_legacy(self, req, id, body):
        """Extend size of a share."""
        body.get('os-extend', {}).pop('force', None)
        return self._extend(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('extend')
    @validation.request_body_schema(schema.extend_request_body_v27, '2.7', '2.63')  # noqa: E501
    @validation.request_body_schema(schema.extend_request_body_v264, '2.64')
    @validation.response_body_schema(schema.extend_response_body)
    def extend(self, req, id, body):
        """Extend size of a share."""
        if req.api_version_request < api_version.APIVersionRequest('2.64'):
            body.get('extend', {}).pop('force', None)
        return self._extend(req, id, body)

    def _get_valid_shrink_parameters(self, context, id, body, action):
        try:
            share = self.share_api.get(context, id)
        except exception.NotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.message)

        try:
            size = int(body.get(action, body.get('shrink'))['new_size'])
        except (KeyError, ValueError, TypeError):
            msg = _("New share size must be specified as an integer.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        return share, size

    @wsgi.Controller.authorize("shrink")
    def _shrink(self, req, id, body):
        """Shrink size of a share."""
        context = req.environ['manila.context']
        share, size = self._get_valid_shrink_parameters(
            context, id, body, 'os-shrink')

        if share.get('is_soft_deleted'):
            msg = _("Cannot shrink share '%s' "
                    "since it has been soft deleted.") % id
            raise exc.HTTPForbidden(explanation=msg)

        try:
            self.share_api.shrink(context, share, size)
        except (exception.InvalidInput, exception.InvalidShare) as e:
            raise webob.exc.HTTPBadRequest(explanation=str(e))

        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-shrink')
    @validation.request_body_schema(schema.shrink_request_body)
    @validation.response_body_schema(schema.shrink_response_body)
    def shrink_legacy(self, req, id, body):
        """Shrink size of a share."""
        return self._shrink(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('shrink')
    @validation.request_body_schema(schema.shrink_request_body_v27, '2.7')
    @validation.response_body_schema(schema.shrink_response_body)
    def shrink(self, req, id, body):
        """Shrink size of a share."""
        return self._shrink(req, id, body)

    @wsgi.Controller.authorize("manage")
    def _manage(self, req, body, allow_dhss_true=False):
        context = req.environ['manila.context']
        share_data = self._validate_manage_parameters(context, body)
        share_data = common.validate_public_share_policy(context, share_data)

        # NOTE(vponomaryov): compatibility actions are required between API and
        # DB layers for 'name' and 'description' API params that are
        # represented in DB as 'display_name' and 'display_description'
        # appropriately.
        name = share_data.get('display_name', share_data.get('name'))
        description = share_data.get(
            'display_description', share_data.get('description'))

        share = {
            'host': share_data['service_host'],
            'export_location_path': share_data['export_path'],
            'share_proto': share_data['protocol'].upper(),
            'share_type_id': share_data['share_type_id'],
            'display_name': name,
            'display_description': description,
        }

        if share_data.get('is_public') is not None:
            share['is_public'] = share_data['is_public']

        driver_options = share_data.get('driver_options', {})

        if allow_dhss_true:
            share['share_server_id'] = share_data.get('share_server_id')

        try:
            share_ref = self.share_api.manage(context, share, driver_options)
        except exception.PolicyNotAuthorized as e:
            raise exc.HTTPForbidden(explanation=e.msg)
        except (exception.InvalidShare, exception.InvalidShareServer) as e:
            raise exc.HTTPConflict(explanation=e.msg)
        except exception.InvalidInput as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        return self._view_builder.detail(req, share_ref)

    def _validate_manage_parameters(self, context, body):
        if not (body and self.is_valid_body(body, 'share')):
            msg = _("Share entity not found in request body")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        required_parameters = ('export_path', 'service_host', 'protocol')

        data = body['share']

        for parameter in required_parameters:
            if parameter not in data:
                msg = _("Required parameter %s not found") % parameter
                raise exc.HTTPUnprocessableEntity(explanation=msg)
            if not data.get(parameter):
                msg = _("Required parameter %s is empty") % parameter
                raise exc.HTTPUnprocessableEntity(explanation=msg)

        if isinstance(data['export_path'], dict):
            # the path may be inside this dictionary
            try:
                data['export_path'] = data['export_path']['path']
            except KeyError:
                msg = ("Export path must be a string, or a dictionary "
                       "with a 'path' item")
                raise exc.HTTPUnprocessableEntity(explanation=msg)

        if not share_utils.extract_host(data['service_host'], 'pool'):
            msg = _("service_host parameter should contain pool.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            utils.validate_service_host(
                context, share_utils.extract_host(data['service_host']))
        except exception.ServiceNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)
        except exception.PolicyNotAuthorized as e:
            raise exc.HTTPForbidden(explanation=e.msg)
        except exception.AdminRequired as e:
            raise exc.HTTPForbidden(explanation=e.msg)
        except exception.ServiceIsDown as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        data['share_type_id'] = self._get_share_type_id(
            context, data.get('share_type'))

        return data

    @staticmethod
    def _get_share_type_id(context, share_type):
        try:
            stype = share_types.get_share_type_by_name_or_id(context,
                                                             share_type)
            return stype['id']
        except exception.ShareTypeNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

    @wsgi.Controller.api_version('2.7')
    def manage(self, req, body):
        if req.api_version_request < api_version.APIVersionRequest('2.8'):
            body.get('share', {}).pop('is_public', None)

        allow_dhss_true = False
        if req.api_version_request >= api_version.APIVersionRequest('2.49'):
            allow_dhss_true = True

        detail = self._manage(req, body, allow_dhss_true=allow_dhss_true)
        return detail

    @wsgi.Controller.authorize("unmanage")
    def _unmanage(self, req, id, body=None, allow_dhss_true=False):
        """Unmanage a share."""
        context = req.environ['manila.context']

        LOG.info("Unmanage share with id: %s", id, context=context)

        try:
            share = self.share_api.get(context, id)
            if share.get('is_soft_deleted'):
                msg = _("Share '%s cannot be unmanaged, "
                        "since it has been soft deleted.") % share['id']
                raise exc.HTTPForbidden(explanation=msg)
            if share.get('has_replicas'):
                msg = _("Share %s has replicas. It cannot be unmanaged "
                        "until all replicas are removed.") % share['id']
                raise exc.HTTPConflict(explanation=msg)
            if (not allow_dhss_true and
                    share['instance'].get('share_server_id')):
                msg = _("Operation 'unmanage' is not supported for shares "
                        "that are created on top of share servers "
                        "(created with share-networks).")
                raise exc.HTTPForbidden(explanation=msg)
            elif share['status'] in constants.TRANSITIONAL_STATUSES:
                msg = _("Share with transitional state can not be unmanaged. "
                        "Share '%(s_id)s' is in '%(state)s' state.") % dict(
                            state=share['status'], s_id=share['id'])
                raise exc.HTTPForbidden(explanation=msg)
            snapshots = self.share_api.db.share_snapshot_get_all_for_share(
                context, id)
            if snapshots:
                msg = _("Share '%(s_id)s' can not be unmanaged because it has "
                        "'%(amount)s' dependent snapshot(s).") % {
                            's_id': id, 'amount': len(snapshots)}
                raise exc.HTTPForbidden(explanation=msg)
            filters = {'share_id': id}
            backups = self.share_api.db.share_backups_get_all(context, filters)
            if backups:
                msg = _("Share '%(s_id)s' can not be unmanaged because it has "
                        "'%(amount)s' dependent backup(s).") % {
                            's_id': id, 'amount': len(backups)}
                raise exc.HTTPForbidden(explanation=msg)
            self.share_api.unmanage(context, share)
        except exception.NotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)
        except (exception.InvalidShare, exception.PolicyNotAuthorized) as e:
            raise exc.HTTPForbidden(explanation=e.msg)

        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('unmanage')
    @validation.request_body_schema(schema.unmanage_request_body)
    @validation.response_body_schema(schema.unmanage_response_body)
    def unmanage(self, req, id, body):
        allow_dhss_true = False
        if req.api_version_request >= api_version.APIVersionRequest('2.49'):
            allow_dhss_true = True
        return self._unmanage(req, id, body, allow_dhss_true=allow_dhss_true)

    @wsgi.Controller.authorize('revert_to_snapshot')
    def _revert(self, req, id, body=None):
        """Revert a share to a snapshot."""
        context = req.environ['manila.context']

        try:
            share_id = id
            snapshot_id = body['revert']['snapshot_id']

            share = self.share_api.get(context, share_id)
            snapshot = self.share_api.get_snapshot(context, snapshot_id)

            if share.get('is_soft_deleted'):
                msg = _("Share '%s cannot revert to snapshot, "
                        "since it has been soft deleted.") % share_id
                raise exc.HTTPForbidden(explanation=msg)

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
                            "%(share_id)s which has access rules that are "
                            "not %(state)s.")
                    raise exc.HTTPConflict(explanation=msg % msg_args)

            msg_args = {'share_id': share_id, 'snap_id': snapshot_id}
            msg = 'Reverting share %(share_id)s to snapshot %(snap_id)s.'
            LOG.info(msg, msg_args)

            self.share_api.revert_to_snapshot(context, share, snapshot)
        except exception.ShareNotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)
        except exception.ShareSnapshotNotFound as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.ShareSizeExceedsAvailableQuota as e:
            raise exc.HTTPForbidden(explanation=e.msg)
        except exception.ReplicationException as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        return webob.Response(status_int=http_client.ACCEPTED)

    @wsgi.Controller.api_version('2.27')
    @wsgi.action('revert')
    @validation.request_body_schema(schema.revert_request_body)
    @validation.response_body_schema(schema.revert_response_body)
    def revert(self, req, id, body=None):
        return self._revert(req, id, body)

    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Return data about the given share."""
        context = req.environ['manila.context']

        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, share)

    @wsgi.Controller.authorize
    def update(self, req, id, body):
        """Update a share."""
        context = req.environ['manila.context']

        if not body or 'share' not in body:
            raise exc.HTTPUnprocessableEntity()

        share_data = body['share']
        valid_update_keys = (
            'display_name',
            'display_description',
            'is_public',
        )

        update_dict = {key: share_data[key]
                       for key in valid_update_keys
                       if key in share_data}

        common.check_display_field_length(
            update_dict.get('display_name'), 'display_name')
        common.check_display_field_length(
            update_dict.get('display_description'), 'display_description')

        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        if share.get('is_soft_deleted'):
            msg = _("Share '%s cannot be updated, "
                    "since it has been soft deleted.") % share['id']
            raise exc.HTTPForbidden(explanation=msg)

        update_dict = common.validate_public_share_policy(
            context, update_dict, api='update')

        share = self.share_api.update(context, share, update_dict)
        share.update(update_dict)
        return self._view_builder.detail(req, share)

    @wsgi.Controller.authorize
    def delete(self, req, id):
        """Delete a share."""
        context = req.environ['manila.context']

        LOG.info("Delete share with id: %s", id, context=context)

        try:
            share = self.share_api.get(context, id)

            # NOTE(ameade): If the share is in a share group, we require its
            # id be specified as a param.
            sg_id_key = 'share_group_id'
            if share.get(sg_id_key):
                share_group_id = req.params.get(sg_id_key)
                if not share_group_id:
                    msg = _("Must provide '%s' as a request "
                            "parameter when deleting a share in a share "
                            "group.") % sg_id_key
                    raise exc.HTTPBadRequest(explanation=msg)
                elif share_group_id != share.get(sg_id_key):
                    msg = _("The specified '%s' does not match "
                            "the share group id of the share.") % sg_id_key
                    raise exc.HTTPBadRequest(explanation=msg)

            self.share_api.delete(context, share)
        except exception.NotFound:
            raise exc.HTTPNotFound()
        except exception.InvalidShare as e:
            raise exc.HTTPForbidden(explanation=e.msg)
        except exception.Conflict as e:
            raise exc.HTTPConflict(explanation=e.msg)

        return webob.Response(status_int=http_client.ACCEPTED)

    def _get_shares(self, req, is_detail):
        """Returns a list of shares, transformed through view builder."""
        context = req.environ['manila.context']

        common._validate_pagination_query(req)

        search_opts = {}
        search_opts.update(req.GET)

        # Remove keys that are not related to share attrs
        sort_key = search_opts.pop('sort_key', 'created_at')
        sort_dir = search_opts.pop('sort_dir', 'desc')

        show_count = False
        if 'with_count' in search_opts:
            show_count = utils.get_bool_from_api_params(
                'with_count', search_opts)
            search_opts.pop('with_count')

        if 'is_soft_deleted' in search_opts:
            is_soft_deleted = utils.get_bool_from_api_params(
                'is_soft_deleted', search_opts)
            search_opts['is_soft_deleted'] = is_soft_deleted

        # Deserialize dicts
        if 'metadata' in search_opts:
            search_opts['metadata'] = ast.literal_eval(search_opts['metadata'])
        if 'extra_specs' in search_opts:
            search_opts['extra_specs'] = ast.literal_eval(
                search_opts['extra_specs'])

        # NOTE(vponomaryov): Manila stores in DB key 'display_name', but
        # allows to use both keys 'name' and 'display_name'. It is leftover
        # from Cinder v1 and v2 APIs.
        if 'name' in search_opts:
            search_opts['display_name'] = search_opts.pop('name')
        if 'description' in search_opts:
            search_opts['display_description'] = search_opts.pop(
                'description')

        # like filter
        for key, db_key in (('name~', 'display_name~'),
                            ('description~', 'display_description~')):
            if key in search_opts:
                search_opts[db_key] = search_opts.pop(key)

        if sort_key == 'name':
            sort_key = 'display_name'

        common.remove_invalid_options(
            context, search_opts, self._get_share_search_options())

        total_count = None
        if show_count:
            count, shares = self.share_api.get_all_with_count(
                context, search_opts=search_opts, sort_key=sort_key,
                sort_dir=sort_dir)
            total_count = count
        else:
            shares = self.share_api.get_all(
                context, search_opts=search_opts, sort_key=sort_key,
                sort_dir=sort_dir)

        if is_detail:
            shares = self._view_builder.detail_list(req, shares, total_count)
        else:
            shares = self._view_builder.summary_list(req, shares, total_count)
        return shares

    def _get_share_search_options(self):
        """Return share search options allowed by non-admin."""
        # NOTE(vponomaryov): share_server_id depends on policy, allow search
        #                    by it for non-admins in case policy changed.
        #                    Also allow search by extra_specs in case policy
        #                    for it allows non-admin access.
        return (
            'display_name', 'status', 'share_server_id', 'volume_type_id',
            'share_type_id', 'snapshot_id', 'host', 'share_network_id',
            'is_public', 'metadata', 'extra_specs', 'sort_key', 'sort_dir',
            'share_group_id', 'share_group_snapshot_id', 'export_location_id',
            'export_location_path', 'display_name~', 'display_description~',
            'display_description', 'limit', 'offset', 'is_soft_deleted',
            'mount_point_name')

    @wsgi.Controller.api_version("2.0")
    @wsgi.Controller.authorize("get_all")
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

        if req.api_version_request < api_version.APIVersionRequest("2.69"):
            req.GET.pop('is_soft_deleted', None)

        if req.api_version_request < api_version.APIVersionRequest("2.90"):
            req.GET.pop('encryption_key_ref', None)

        return self._get_shares(req, is_detail=False)

    @wsgi.Controller.api_version("2.0")
    @wsgi.Controller.authorize("get_all")
    def detail(self, req):
        """Returns a detailed list of shares."""
        if req.api_version_request < api_version.APIVersionRequest("2.35"):
            req.GET.pop('export_location_id', None)
            req.GET.pop('export_location_path', None)

        if req.api_version_request < api_version.APIVersionRequest("2.36"):
            req.GET.pop('name~', None)
            req.GET.pop('description~', None)
            req.GET.pop('description', None)

        if req.api_version_request < api_version.APIVersionRequest("2.69"):
            req.GET.pop('is_soft_deleted', None)

        if req.api_version_request < api_version.APIVersionRequest("2.90"):
            req.GET.pop('encryption_key_ref', None)

        return self._get_shares(req, is_detail=True)

    def _validate_metadata_for_update(self, req, share_id, metadata,
                                      delete=True):
        persistent_keys = set(self._conf_admin_only_metadata_keys)
        context = req.environ['manila.context']
        if set(metadata).intersection(persistent_keys):
            try:
                policy.check_policy(
                    context, 'share', 'update_admin_only_metadata')
            except exception.PolicyNotAuthorized:
                msg = _("Cannot set or update admin only metadata.")
                LOG.exception(msg)
                raise exc.HTTPForbidden(explanation=msg)
            persistent_keys = []

        current_share_metadata = db.share_metadata_get(context, share_id)
        if delete:
            _metadata = metadata
            for key in persistent_keys:
                if key in current_share_metadata:
                    _metadata[key] = current_share_metadata[key]
        else:
            metadata_copy = metadata.copy()
            for key in persistent_keys:
                metadata_copy.pop(key, None)
            _metadata = current_share_metadata.copy()
            _metadata.update(metadata_copy)

        return _metadata

    # NOTE: (ashrod98) original metadata method and policy overrides
    @wsgi.Controller.api_version("2.0")
    @wsgi.Controller.authorize("get_share_metadata")
    def index_metadata(self, req, resource_id):
        """Returns the list of metadata for a given share."""
        return self._index_metadata(req, resource_id)

    @wsgi.Controller.api_version("2.0")
    @wsgi.Controller.authorize("update_share_metadata")
    def create_metadata(self, req, resource_id, body):
        if not self.is_valid_body(body, 'metadata'):
            expl = _('Malformed request body')
            raise exc.HTTPBadRequest(explanation=expl)
        _metadata = self._validate_metadata_for_update(req, resource_id,
                                                       body['metadata'],
                                                       delete=False)
        body['metadata'] = _metadata
        metadata = self._create_metadata(req, resource_id, body)

        context = req.environ['manila.context']
        self.share_api.update_share_from_metadata(context, resource_id,
                                                  metadata.get('metadata'))
        return metadata

    @wsgi.Controller.api_version("2.0")
    @wsgi.Controller.authorize("update_share_metadata")
    def update_all_metadata(self, req, resource_id, body):
        if not self.is_valid_body(body, 'metadata'):
            expl = _('Malformed request body')
            raise exc.HTTPBadRequest(explanation=expl)
        _metadata = self._validate_metadata_for_update(req, resource_id,
                                                       body['metadata'])
        body['metadata'] = _metadata
        metadata = self._update_all_metadata(req, resource_id, body)

        context = req.environ['manila.context']
        self.share_api.update_share_from_metadata(context, resource_id,
                                                  metadata.get('metadata'))
        return metadata

    @wsgi.Controller.api_version("2.0")
    @wsgi.Controller.authorize("update_share_metadata")
    def update_metadata_item(self, req, resource_id, body, key):
        if not self.is_valid_body(body, 'meta'):
            expl = _('Malformed request body')
            raise exc.HTTPBadRequest(explanation=expl)
        _metadata = self._validate_metadata_for_update(req, resource_id,
                                                       body['metadata'],
                                                       delete=False)
        body['metadata'] = _metadata
        metadata = self._update_metadata_item(req, resource_id, body, key)

        context = req.environ['manila.context']
        self.share_api.update_share_from_metadata(context, resource_id,
                                                  metadata.get('metadata'))
        return metadata

    @wsgi.Controller.api_version("2.0")
    @wsgi.Controller.authorize("get_share_metadata")
    def show_metadata(self, req, resource_id, key):
        return self._show_metadata(req, resource_id, key)

    @wsgi.Controller.api_version("2.0")
    @wsgi.Controller.authorize("delete_share_metadata")
    def delete_metadata(self, req, resource_id, key):
        context = req.environ['manila.context']
        if key in self._conf_admin_only_metadata_keys:
            policy.check_policy(context, 'share',
                                'update_admin_only_metadata')
        return self._delete_metadata(req, resource_id, key)


def create_resource():
    return wsgi.Resource(ShareController())
