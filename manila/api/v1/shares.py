# Copyright 2013 NetApp
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

"""The shares api."""

import ast
from http import client as http_client

from oslo_log import log
from oslo_utils import strutils
from oslo_utils import uuidutils
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import share_accesses as share_access_views
from manila.api.views import shares as share_views
from manila.common import constants
from manila import db
from manila import exception
from manila.i18n import _
from manila.lock import api as resource_locks
from manila import share
from manila.share import share_types
from manila import utils

LOG = log.getLogger(__name__)


class ShareMixin(object):
    """Mixin class for Share API Controllers."""

    def _update(self, *args, **kwargs):
        db.share_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return self.share_api.get(*args, **kwargs)

    def _delete(self, *args, **kwargs):
        return self.share_api.delete(*args, **kwargs)

    def show(self, req, id):
        """Return data about the given share."""
        context = req.environ['manila.context']

        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, share)

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

    def index(self, req):
        """Returns a summary list of shares."""
        req.GET.pop('export_location_id', None)
        req.GET.pop('export_location_path', None)
        req.GET.pop('name~', None)
        req.GET.pop('description~', None)
        req.GET.pop('description', None)
        req.GET.pop('with_count', None)
        return self._get_shares(req, is_detail=False)

    def detail(self, req):
        """Returns a detailed list of shares."""
        req.GET.pop('export_location_id', None)
        req.GET.pop('export_location_path', None)
        req.GET.pop('name~', None)
        req.GET.pop('description~', None)
        req.GET.pop('description', None)
        req.GET.pop('with_count', None)
        return self._get_shares(req, is_detail=True)

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
            'display_description', 'limit', 'offset', 'is_soft_deleted')

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

    def create(self, req, body):
        # Remove share group attributes
        body.get('share', {}).pop('share_group_id', None)
        share = self._create(req, body)
        return share

    @wsgi.Controller.authorize('create')
    def _create(self, req, body,
                check_create_share_from_snapshot_support=False,
                check_availability_zones_extra_spec=False,
                scheduler_hints=None):
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
        elif not snapshot:
            def_share_type = share_types.get_default_share_type()
            if def_share_type:
                share_type = def_share_type

        # Only use in create share feature. Create share from snapshot
        # and create share with share group features not
        # need this check.
        if (not share_network_id and not snapshot
                and not share_group_id
                and share_type and share_type.get('extra_specs')
                and (strutils.bool_from_string(share_type.get('extra_specs').
                     get('driver_handles_share_servers')))):
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

        if share_type:
            kwargs['share_type'] = share_type
        if share_network_id:
            kwargs['share_network_id'] = share_network_id

        kwargs['scheduler_hints'] = scheduler_hints

        new_share = self.share_api.create(context,
                                          share_proto,
                                          size,
                                          display_name,
                                          display_description,
                                          **kwargs)

        return self._view_builder.detail(req, new_share)

    @staticmethod
    def _any_instance_has_errored_rules(share):
        for instance in share['instances']:
            access_rules_status = instance['access_rules_status']
            if access_rules_status == constants.SHARE_INSTANCE_RULES_ERROR:
                return True
        return False

    def _create_access_locks(
            self, context, access, lock_deletion=False, lock_visibility=False,
            lock_reason=None):
        """Creates locks for access rules and rollback if it fails."""

        # We must populate project_id and user_id in the access object, as this
        # is not in this entity
        access['project_id'] = context.project_id
        access['user_id'] = context.user_id

        def raise_lock_failed(access, lock_action):
            word_mapping = {
                constants.RESOURCE_ACTION_SHOW: 'visibility',
                constants.RESOURCE_ACTION_DELETE: 'deletion'
            }
            msg = _("Failed to lock the %(action)s of the access rule "
                    "%(rule)s.") % {
                'action': word_mapping[lock_action],
                'rule': access['id']
            }
            raise webob.exc.HTTPBadRequest(explanation=msg)

        deletion_lock = {}

        if lock_deletion:
            try:
                deletion_lock = self.resource_locks_api.create(
                    context, resource_id=access['id'],
                    resource_type='access_rule',
                    resource_action=constants.RESOURCE_ACTION_DELETE,
                    resource=access, lock_reason=lock_reason)
            except Exception:
                raise_lock_failed(access, constants.RESOURCE_ACTION_DELETE)

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
                if deletion_lock:
                    self.resource_locks_api.delete(
                        context, deletion_lock['id'])
                raise_lock_failed(access, constants.RESOURCE_ACTION_SHOW)

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

    def _check_for_access_rule_locks(self, context, access_data, access_id,
                                     share_id):
        """Fetches locks for access rules and attempts deleting them."""

        # ensure the requester is asking to remove the restrictions of the rule
        unrestrict = access_data.get('unrestrict', False)
        search_opts = {
            'resource_id': access_id,
            'resource_action': constants.RESOURCE_ACTION_DELETE
        }

        locks, locks_count = (
            self.resource_locks_api.get_all(
                context, search_opts=search_opts, show_count=True) or []
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
            except exception.NotAuthorized:
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

    def _access_list(self, req, id, body):
        """List share access rules."""
        context = req.environ['manila.context']

        share = self.share_api.get(context, id)
        access_rules = self.share_api.access_get_all(context, share)

        return self._access_view_builder.list_view(req, access_rules)

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


class ShareController(wsgi.Controller, ShareMixin, wsgi.AdminActionsMixin):
    """The Shares API v1 controller for the OpenStack API."""
    resource_name = 'share'
    _view_builder_class = share_views.ViewBuilder

    def __init__(self):
        super(ShareController, self).__init__()
        self.share_api = share.API()
        self.resource_locks_api = resource_locks.API()
        self._access_view_builder = share_access_views.ViewBuilder()

    @wsgi.action('os-reset_status')
    def share_reset_status(self, req, id, body):
        """Reset status of a share."""
        return self._reset_status(req, id, body)

    @wsgi.action('os-force_delete')
    def share_force_delete(self, req, id, body):
        """Delete a share, bypassing the check for status."""
        return self._force_delete(req, id, body)

    @wsgi.action('os-allow_access')
    def allow_access(self, req, id, body):
        """Add share access rule."""
        return self._allow_access(req, id, body)

    @wsgi.action('os-deny_access')
    def deny_access(self, req, id, body):
        """Remove share access rule."""
        return self._deny_access(req, id, body)

    @wsgi.action('os-access_list')
    def access_list(self, req, id, body):
        """List share access rules."""
        return self._access_list(req, id, body)

    @wsgi.action('os-extend')
    def extend(self, req, id, body):
        """Extend size of a share."""
        return self._extend(req, id, body)

    @wsgi.action('os-shrink')
    def shrink(self, req, id, body):
        """Shrink size of a share."""
        return self._shrink(req, id, body)


def create_resource():
    return wsgi.Resource(ShareController())
