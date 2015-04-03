# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
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

"""
Handles all requests relating to shares.
"""

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import strutils
from oslo_utils import timeutils
import six

from manila.api import extensions
from manila.common import constants
from manila.db import base
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW
from manila import policy
from manila import quota
from manila.scheduler import rpcapi as scheduler_rpcapi
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types

share_api_opts = [
    cfg.BoolOpt('use_scheduler_creating_share_from_snapshot',
                default=False,
                help='If set to False, then share creation from snapshot will '
                     'be performed on the same host. '
                     'If set to True, then scheduling step will be used.')
]

CONF = cfg.CONF
CONF.register_opts(share_api_opts)

LOG = log.getLogger(__name__)
GB = 1048576 * 1024
QUOTAS = quota.QUOTAS


class API(base.Base):
    """API for interacting with the share manager."""

    def __init__(self, db_driver=None):
        self.scheduler_rpcapi = scheduler_rpcapi.SchedulerAPI()
        self.share_rpcapi = share_rpcapi.ShareAPI()
        super(API, self).__init__(db_driver)

    def create(self, context, share_proto, size, name, description,
               snapshot=None, availability_zone=None, metadata=None,
               share_network_id=None, share_type=None, is_public=False):
        """Create new share."""
        policy.check_policy(context, 'share', 'create')

        self._check_metadata_properties(context, metadata)

        if snapshot is not None:
            if snapshot['status'] != 'available':
                msg = _("status must be 'available'")
                raise exception.InvalidShareSnapshot(reason=msg)
            if not size:
                size = snapshot['size']

            snapshot_id = snapshot['id']
        else:
            snapshot_id = None

        def as_int(s):
            try:
                return int(s)
            except (ValueError, TypeError):
                return s

        # tolerate size as stringified int
        size = as_int(size)

        if not isinstance(size, int) or size <= 0:
            msg = (_("Share size '%s' must be an integer and greater than 0")
                   % size)
            raise exception.InvalidInput(reason=msg)

        if snapshot and size < snapshot['size']:
            msg = (_("Share size '%s' must be equal or greater "
                     "than snapshot size") % size)
            raise exception.InvalidInput(reason=msg)

        if snapshot is None:
            share_type_id = share_type['id'] if share_type else None
        else:
            source_share = self.db.share_get(context, snapshot['share_id'])
            if share_type is None:
                share_type_id = source_share['share_type_id']
                if share_type_id is not None:
                    share_type = share_types.get_share_type(context,
                                                            share_type_id)
            else:
                share_type_id = share_type['id']
                if share_type_id != source_share['share_type_id']:
                    msg = _("Invalid share type specified: the requested "
                            "share type must match the type of the source "
                            "share. If a share type is not specified when "
                            "requesting a new share from a snapshot, the "
                            "share type of the source share will be applied "
                            "to the new share.")
                    raise exception.InvalidInput(reason=msg)

        supported_share_protocols = (
            proto.upper() for proto in CONF.enabled_share_protocols)
        if not (share_proto and
                share_proto.upper() in supported_share_protocols):
            msg = (_("Invalid share protocol provided: %(provided)s. "
                     "It is either disabled or unsupported. Available "
                     "protocols: %(supported)s") % dict(
                         provided=share_proto,
                         supported=CONF.enabled_share_protocols))
            raise exception.InvalidInput(reason=msg)

        try:
            reservations = QUOTAS.reserve(context, shares=1, gigabytes=size)
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'gigabytes' in overs:
                LOG.warn(_LW("Quota exceeded for %(s_pid)s, tried to create "
                             "%(s_size)sG share (%(d_consumed)dG of "
                             "%(d_quota)dG already consumed)"), {
                                 's_pid': context.project_id,
                                 's_size': size,
                                 'd_consumed': _consumed('gigabytes'),
                                 'd_quota': quotas['gigabytes']})
                raise exception.ShareSizeExceedsAvailableQuota()
            elif 'shares' in overs:
                LOG.warn(_LW("Quota exceeded for %(s_pid)s, tried to create "
                             "share (%(d_consumed)d shares "
                             "already consumed)"), {
                                 's_pid': context.project_id,
                                 'd_consumed': _consumed('shares')})
                raise exception.ShareLimitExceeded(allowed=quotas['shares'])

        if availability_zone is None:
            availability_zone = CONF.storage_availability_zone

        try:
            is_public = strutils.bool_from_string(is_public, strict=True)
        except ValueError as e:
            raise exception.InvalidParameterValue(e.message)

        options = {'size': size,
                   'user_id': context.user_id,
                   'project_id': context.project_id,
                   'snapshot_id': snapshot_id,
                   'share_network_id': share_network_id,
                   'availability_zone': availability_zone,
                   'metadata': metadata,
                   'status': "creating",
                   'scheduled_at': timeutils.utcnow(),
                   'display_name': name,
                   'display_description': description,
                   'share_proto': share_proto,
                   'share_type_id': share_type_id,
                   'is_public': is_public,
                   }

        try:
            share = self.db.share_create(context, options)
            QUOTAS.commit(context, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    self.db.share_delete(context, share['id'])
                finally:
                    QUOTAS.rollback(context, reservations)

        request_spec = {
            'share_properties': options,
            'share_proto': share_proto,
            'share_id': share['id'],
            'snapshot_id': snapshot_id,
            'share_type': share_type,
        }
        filter_properties = {}

        if (snapshot and not CONF.use_scheduler_creating_share_from_snapshot):
            # Shares from snapshots with restriction - source host only.
            # It is common situation for different types of backends.
            host = snapshot['share']['host']
            share = self.db.share_update(context, share['id'], {'host': host})
            self.share_rpcapi.create_share(
                context,
                share,
                host,
                request_spec=request_spec,
                filter_properties=filter_properties,
                snapshot_id=snapshot_id,
            )
        else:
            # Shares from scratch and from snapshots when source host is not
            # the only allowed, it is possible, for example, in multibackend
            # installation with Generic drivers only.
            self.scheduler_rpcapi.create_share(
                context,
                CONF.share_topic,
                share['id'],
                snapshot_id,
                request_spec=request_spec,
                filter_properties=filter_properties,
            )

        return share

    def manage(self, context, share_data, driver_options):
        policy.check_policy(context, 'share', 'manage')

        shares = self.get_all(context, {
            'host': share_data['host'],
            'export_location': share_data['export_location'],
            'share_proto': share_data['share_proto']
        })

        share_data.update({
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_MANAGING,
            'scheduled_at': timeutils.utcnow(),
        })

        LOG.debug("Manage: Found shares %s" % len(shares))

        retry_states = (constants.STATUS_MANAGE_ERROR,)

        export_location = share_data.pop('export_location')

        if len(shares) == 0:
            share = self.db.share_create(context, share_data)
        # NOTE(u_glide): Case when administrator have fixed some problems and
        # tries to manage share again
        elif len(shares) == 1 and shares[0]['status'] in retry_states:
            share = self.db.share_update(context, shares[0]['id'], share_data)
        else:
            msg = _("Share already exists.")
            raise exception.ManilaException(msg)

        self.db.share_export_locations_update(context, share['id'],
                                              export_location)

        self.share_rpcapi.manage_share(context, share, driver_options)
        return self.db.share_get(context, share['id'])

    def unmanage(self, context, share):
        policy.check_policy(context, 'share', 'unmanage')

        update_data = {'status': constants.STATUS_UNMANAGING,
                       'terminated_at': timeutils.utcnow()}
        share_ref = self.db.share_update(context, share['id'], update_data)

        self.share_rpcapi.unmanage_share(context, share_ref)

    @policy.wrap_check_policy('share')
    def delete(self, context, share, force=False):
        """Delete share."""
        if context.is_admin and context.project_id != share['project_id']:
            project_id = share['project_id']
        else:
            project_id = context.project_id

        share_id = share['id']
        if not share['host']:
            try:
                reservations = QUOTAS.reserve(context,
                                              project_id=project_id,
                                              shares=-1,
                                              gigabytes=-share['size'])
            except Exception:
                reservations = None
                LOG.exception(_LE("Failed to update quota for deleting share"))
            self.db.share_delete(context.elevated(), share_id)

            if reservations:
                QUOTAS.commit(context, reservations, project_id=project_id)
            return

        if not (force or share['status'] in ["available", "error"]):
            msg = _("Share status must be available or error")
            raise exception.InvalidShare(reason=msg)

        snapshots = self.db.share_snapshot_get_all_for_share(context, share_id)
        if len(snapshots):
            msg = _("Share still has %d dependent snapshots") % len(snapshots)
            raise exception.InvalidShare(reason=msg)

        now = timeutils.utcnow()
        share = self.db.share_update(context, share_id, {'status': 'deleting',
                                                         'terminated_at': now})

        self.share_rpcapi.delete_share(context, share)

    def delete_share_server(self, context, server):
        """Delete share server."""
        policy.check_policy(context, 'share_server', 'delete', server)
        shares = self.db.share_get_all_by_share_server(context, server['id'])
        if shares:
            raise exception.ShareServerInUse(share_server_id=server['id'])
        # NOTE(vponomaryov): There is no share_server status update here,
        # it is intentional.
        # Status will be changed in manila.share.manager after verification
        # for race condition between share creation on server
        # and server deletion.
        self.share_rpcapi.delete_share_server(context, server)

    def create_snapshot(self, context, share, name, description,
                        force=False):
        policy.check_policy(context, 'share', 'create_snapshot', share)

        if ((not force) and (share['status'] != "available")):
            msg = _("must be available")
            raise exception.InvalidShare(reason=msg)

        size = share['size']

        try:
            reservations = QUOTAS.reserve(
                context, snapshots=1, snapshot_gigabytes=size)
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'snapshot_gigabytes' in overs:
                msg = _LW("Quota exceeded for %(s_pid)s, tried to create "
                          "%(s_size)sG snapshot (%(d_consumed)dG of "
                          "%(d_quota)dG already consumed)")
                LOG.warn(msg, {'s_pid': context.project_id,
                               's_size': size,
                               'd_consumed': _consumed('gigabytes'),
                               'd_quota': quotas['snapshot_gigabytes']})
                raise exception.SnapshotSizeExceedsAvailableQuota()
            elif 'snapshots' in overs:
                msg = _LW("Quota exceeded for %(s_pid)s, tried to create "
                          "snapshot (%(d_consumed)d snapshots "
                          "already consumed)")
                LOG.warn(msg, {'s_pid': context.project_id,
                               'd_consumed': _consumed('snapshots')})
                raise exception.SnapshotLimitExceeded(
                    allowed=quotas['snapshots'])
        options = {'share_id': share['id'],
                   'size': share['size'],
                   'user_id': context.user_id,
                   'project_id': context.project_id,
                   'status': "creating",
                   'progress': '0%',
                   'share_size': share['size'],
                   'display_name': name,
                   'display_description': description,
                   'share_proto': share['share_proto']}

        try:
            snapshot = self.db.share_snapshot_create(context, options)
            QUOTAS.commit(context, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    self.db.snapshot_delete(context, share['id'])
                finally:
                    QUOTAS.rollback(context, reservations)

        self.share_rpcapi.create_snapshot(context, share, snapshot)
        return snapshot

    @policy.wrap_check_policy('share')
    def delete_snapshot(self, context, snapshot, force=False):
        if not (force or snapshot['status'] in ["available", "error"]):
            msg = _("Share Snapshot status must be 'available' or 'error'.")
            raise exception.InvalidShareSnapshot(reason=msg)

        self.db.share_snapshot_update(context, snapshot['id'],
                                      {'status': 'deleting'})
        share = self.db.share_get(context, snapshot['share_id'])
        self.share_rpcapi.delete_snapshot(context, snapshot, share['host'])

    @policy.wrap_check_policy('share')
    def update(self, context, share, fields):
        if 'is_public' in fields:
            try:
                fields['is_public'] = strutils.bool_from_string(
                    fields['is_public'], strict=True)
            except ValueError as e:
                raise exception.InvalidParameterValue(e.message)
        return self.db.share_update(context, share['id'], fields)

    @policy.wrap_check_policy('share')
    def snapshot_update(self, context, snapshot, fields):
        return self.db.share_snapshot_update(context, snapshot['id'], fields)

    def get(self, context, share_id):
        rv = self.db.share_get(context, share_id)
        if not rv['is_public']:
            policy.check_policy(context, 'share', 'get', rv)
        return rv

    def get_all(self, context, search_opts=None, sort_key='created_at',
                sort_dir='desc'):
        policy.check_policy(context, 'share', 'get_all')

        if search_opts is None:
            search_opts = {}

        LOG.debug("Searching for shares by: %s", six.text_type(search_opts))

        # Prepare filters
        filters = {}
        if 'metadata' in search_opts:
            filters['metadata'] = search_opts.pop('metadata')
            if not isinstance(filters['metadata'], dict):
                msg = _("Wrong metadata filter provided: "
                        "%s.") % six.text_type(filters['metadata'])
                raise exception.InvalidInput(reason=msg)
        if 'extra_specs' in search_opts:
            # Verify policy for extra-specs access
            extensions.extension_authorizer(
                'share', 'types_extra_specs')(context)
            filters['extra_specs'] = search_opts.pop('extra_specs')
            if not isinstance(filters['extra_specs'], dict):
                msg = _("Wrong extra specs filter provided: "
                        "%s.") % six.text_type(filters['extra_specs'])
                raise exception.InvalidInput(reason=msg)
        if not (isinstance(sort_key, six.string_types) and sort_key):
            msg = _("Wrong sort_key filter provided: "
                    "'%s'.") % six.text_type(sort_key)
            raise exception.InvalidInput(reason=msg)
        if not (isinstance(sort_dir, six.string_types) and sort_dir):
            msg = _("Wrong sort_dir filter provided: "
                    "'%s'.") % six.text_type(sort_dir)
            raise exception.InvalidInput(reason=msg)

        is_public = search_opts.pop('is_public', False)
        is_public = strutils.bool_from_string(is_public, strict=True)

        # Get filtered list of shares
        if 'share_server_id' in search_opts:
            # NOTE(vponomaryov): this is project_id independent
            policy.check_policy(context, 'share', 'list_by_share_server_id')
            shares = self.db.share_get_all_by_share_server(
                context, search_opts.pop('share_server_id'), filters=filters,
                sort_key=sort_key, sort_dir=sort_dir)
        elif (context.is_admin and 'all_tenants' in search_opts):
            shares = self.db.share_get_all(
                context, filters=filters, sort_key=sort_key, sort_dir=sort_dir)
        else:
            shares = self.db.share_get_all_by_project(
                context, project_id=context.project_id, filters=filters,
                is_public=is_public, sort_key=sort_key, sort_dir=sort_dir)

        # NOTE(vponomaryov): we do not need 'all_tenants' opt anymore
        search_opts.pop('all_tenants', None)

        if search_opts:
            results = []
            for s in shares:
                # values in search_opts can be only strings
                if all(s.get(k, None) == v for k, v in search_opts.items()):
                    results.append(s)
            shares = results
        return shares

    def get_snapshot(self, context, snapshot_id):
        policy.check_policy(context, 'share', 'get_snapshot')
        rv = self.db.share_snapshot_get(context, snapshot_id)
        return dict(six.iteritems(rv))

    def get_all_snapshots(self, context, search_opts=None,
                          sort_key='share_id', sort_dir='desc'):
        policy.check_policy(context, 'share', 'get_all_snapshots')

        search_opts = search_opts or {}
        LOG.debug("Searching for snapshots by: %s", six.text_type(search_opts))

        # Read and remove key 'all_tenants' if was provided
        all_tenants = search_opts.pop('all_tenants', None)

        string_args = {'sort_key': sort_key, 'sort_dir': sort_dir}
        string_args.update(search_opts)
        for k, v in string_args.items():
            if not (isinstance(v, six.string_types) and v):
                msg = _("Wrong '%(k)s' filter provided: "
                        "'%(v)s'.") % {'k': k, 'v': string_args[k]}
                raise exception.InvalidInput(reason=msg)

        if (context.is_admin and all_tenants):
            snapshots = self.db.share_snapshot_get_all(
                context, filters=search_opts,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            snapshots = self.db.share_snapshot_get_all_by_project(
                context, context.project_id, filters=search_opts,
                sort_key=sort_key, sort_dir=sort_dir)

        # Remove key 'usage' if provided
        search_opts.pop('usage', None)

        if search_opts:
            results = []
            not_found = object()
            for snapshot in snapshots:
                for opt, value in six.iteritems(search_opts):
                    if snapshot.get(opt, not_found) != value:
                        break
                else:
                    results.append(snapshot)
            snapshots = results
        return snapshots

    def allow_access(self, ctx, share, access_type, access_to,
                     access_level=None):
        """Allow access to share."""
        if not share['host']:
            msg = _("Share host is None")
            raise exception.InvalidShare(reason=msg)
        if share['status'] not in ["available"]:
            msg = _("Share status must be available")
            raise exception.InvalidShare(reason=msg)
        policy.check_policy(ctx, 'share', 'allow_access')
        values = {
            'share_id': share['id'],
            'access_type': access_type,
            'access_to': access_to,
            'access_level': access_level,
        }
        access = [a for a in self.db.share_access_get_all_by_type_and_access(
            ctx, share['id'], access_type, access_to) if a['state'] != 'error']
        if access:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access_to)
        if access_level not in constants.ACCESS_LEVELS + (None, ):
            msg = _("Invalid share access level: %s.") % access_level
            raise exception.InvalidShareAccess(reason=msg)
        access = self.db.share_access_create(ctx, values)
        self.share_rpcapi.allow_access(ctx, share, access)
        return access

    def deny_access(self, ctx, share, access):
        """Deny access to share."""
        policy.check_policy(ctx, 'share', 'deny_access')
        # First check state of the target share
        if not share['host']:
            msg = _("Share host is None")
            raise exception.InvalidShare(reason=msg)
        if share['status'] not in ["available"]:
            msg = _("Share status must be available")
            raise exception.InvalidShare(reason=msg)

        # Then check state of the access rule
        if access['state'] == access.STATE_ERROR:
            self.db.share_access_delete(ctx, access["id"])
        elif access['state'] == access.STATE_ACTIVE:
            self.db.share_access_update(ctx, access["id"],
                                        {'state': access.STATE_DELETING})
            self.share_rpcapi.deny_access(ctx, share, access)
        else:
            msg = _("Access policy should be active or in error state")
            raise exception.InvalidShareAccess(reason=msg)
            # update share state and send message to manager

    def access_get_all(self, context, share):
        """Returns all access rules for share."""
        policy.check_policy(context, 'share', 'access_get_all')
        rules = self.db.share_access_get_all_for_share(context, share['id'])
        return [{'id': rule.id,
                 'access_type': rule.access_type,
                 'access_to': rule.access_to,
                 'access_level': rule.access_level,
                 'state': rule.state} for rule in rules]

    def access_get(self, context, access_id):
        """Returns access rule with the id."""
        policy.check_policy(context, 'share', 'access_get')
        rule = self.db.share_access_get(context, access_id)
        return rule

    @policy.wrap_check_policy('share')
    def get_share_metadata(self, context, share):
        """Get all metadata associated with a share."""
        rv = self.db.share_metadata_get(context, share['id'])
        return dict(six.iteritems(rv))

    @policy.wrap_check_policy('share')
    def delete_share_metadata(self, context, share, key):
        """Delete the given metadata item from a share."""
        self.db.share_metadata_delete(context, share['id'], key)

    def _check_metadata_properties(self, context, metadata=None):
        if not metadata:
            metadata = {}

        for k, v in six.iteritems(metadata):
            if not k:
                msg = _("Metadata property key is blank")
                LOG.warn(msg)
                raise exception.InvalidShareMetadata(message=msg)
            if len(k) > 255:
                msg = _("Metadata property key is greater than 255 characters")
                LOG.warn(msg)
                raise exception.InvalidShareMetadataSize(message=msg)
            if not v:
                msg = _("Metadata property value is blank")
                LOG.warn(msg)
                raise exception.InvalidShareMetadata(message=msg)
            if len(v) > 1023:
                msg = _("Metadata property value is "
                        "greater than 1023 characters")
                LOG.warn(msg)
                raise exception.InvalidShareMetadataSize(message=msg)

    @policy.wrap_check_policy('share')
    def update_share_metadata(self, context, share, metadata, delete=False):
        """Updates or creates share metadata.

        If delete is True, metadata items that are not specified in the
        `metadata` argument will be deleted.

        """
        orig_meta = self.get_share_metadata(context, share)
        if delete:
            _metadata = metadata
        else:
            _metadata = orig_meta.copy()
            _metadata.update(metadata)

        self._check_metadata_properties(context, _metadata)
        self.db.share_metadata_update(context, share['id'],
                                      _metadata, delete)

        return _metadata

    def get_share_network(self, context, share_net_id):
        return self.db.share_network_get(context, share_net_id)
