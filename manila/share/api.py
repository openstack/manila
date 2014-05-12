# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""
Handles all requests relating to shares.
"""

from manila.db import base
from manila import exception
from manila.openstack.common import excutils
from manila.openstack.common import log as logging
from manila.openstack.common import timeutils
from manila import policy
from manila import quota
from manila.scheduler import rpcapi as scheduler_rpcapi
from manila.share import rpcapi as share_rpcapi

from oslo.config import cfg


CONF = cfg.CONF

LOG = logging.getLogger(__name__)
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
               share_network_id=None, volume_type=None):
        """Create new share."""
        policy.check_policy(context, 'share', 'create')

        self._check_metadata_properties(context, metadata)

        if snapshot is not None:
            if snapshot['status'] != 'available':
                msg = _('status must be available')
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

        if snapshot and volume_type:
            if volume_type['id'] != snapshot['volume_type_id']:
                msg = _("Invalid volume_type provided (requested type "
                        "must match source snapshot, or be omitted). "
                        "You should omit the argument.")
                raise exception.InvalidInput(reason=msg)

        #TODO(rushiagr): Find a suitable place to keep all the allowed
        #                share types so that it becomes easier to add one
        if share_proto.lower() not in ['nfs', 'cifs']:
            msg = (_("Invalid share type provided: %s") % share_proto)
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
                msg = _("Quota exceeded for %(s_pid)s, tried to create "
                        "%(s_size)sG share (%(d_consumed)dG of %(d_quota)dG "
                        "already consumed)")
                LOG.warn(msg % {'s_pid': context.project_id,
                                's_size': size,
                                'd_consumed': _consumed('gigabytes'),
                                'd_quota': quotas['gigabytes']})
                raise exception.ShareSizeExceedsAvailableQuota()
            elif 'shares' in overs:
                msg = _("Quota exceeded for %(s_pid)s, tried to create "
                        "share (%(d_consumed)d shares "
                        "already consumed)")
                LOG.warn(msg % {'s_pid': context.project_id,
                                'd_consumed': _consumed('shares')})
                raise exception.ShareLimitExceeded(allowed=quotas['shares'])

        if availability_zone is None:
            availability_zone = CONF.storage_availability_zone

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
                   'volume_type_id': volume_type['id'] if volume_type else None
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

        request_spec = {'share_properties': options,
                        'share_proto': share_proto,
                        'share_id': share['id'],
                        'snapshot_id': share['snapshot_id'],
                        'volume_type': volume_type
                        }

        filter_properties = {}

        self.scheduler_rpcapi.create_share(
            context,
            CONF.share_topic,
            share['id'],
            snapshot_id,
            request_spec=request_spec,
            filter_properties=filter_properties)

        return share

    @policy.wrap_check_policy('share')
    def delete(self, context, share):
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
                LOG.exception(_("Failed to update quota for deleting share"))
            self.db.share_delete(context.elevated(), share_id)

            if reservations:
                QUOTAS.commit(context, reservations, project_id=project_id)
            return

        if share['status'] not in ["available", "error"]:
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

    def create_snapshot(self, context, share, name, description,
                        force=False):
        policy.check_policy(context, 'share', 'create_snapshot', share)

        if ((not force) and (share['status'] != "available")):
            msg = _("must be available")
            raise exception.InvalidShare(reason=msg)

        size = share['size']

        try:
            reservations = QUOTAS.reserve(context, snapshots=1, gigabytes=size)
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'gigabytes' in overs:
                msg = _("Quota exceeded for %(s_pid)s, tried to create "
                        "%(s_size)sG snapshot (%(d_consumed)dG of "
                        "%(d_quota)dG already consumed)")
                LOG.warn(msg % {'s_pid': context.project_id,
                                's_size': size,
                                'd_consumed': _consumed('gigabytes'),
                                'd_quota': quotas['gigabytes']})
                raise exception.ShareSizeExceedsAvailableQuota()
            elif 'snapshots' in overs:
                msg = _("Quota exceeded for %(s_pid)s, tried to create "
                        "snapshot (%(d_consumed)d snapshots "
                        "already consumed)")
                LOG.warn(msg % {'s_pid': context.project_id,
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
                   'share_proto': share['share_proto'],
                   'export_location': share['export_location']}

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
        if not force and snapshot['status'] not in ["available", "error"]:
            msg = _("Share Snapshot status must be available or ")
            raise exception.InvalidShareSnapshot(reason=msg)

        self.db.share_snapshot_update(context, snapshot['id'],
                                      {'status': 'deleting'})
        share = self.db.share_get(context, snapshot['share_id'])
        self.share_rpcapi.delete_snapshot(context, snapshot, share['host'])

    @policy.wrap_check_policy('share')
    def update(self, context, share, fields):
        return self.db.share_update(context, share['id'], fields)

    @policy.wrap_check_policy('share')
    def snapshot_update(self, context, snapshot, fields):
        return self.db.share_snapshot_update(context, snapshot['id'], fields)

    def get(self, context, share_id):
        rv = self.db.share_get(context, share_id)
        policy.check_policy(context, 'share', 'get', rv)
        return rv

    def get_all(self, context, search_opts={}):
        policy.check_policy(context, 'share', 'get_all')

        search_opts = search_opts or {}

        if (context.is_admin and 'all_tenants' in search_opts):
            # Need to remove all_tenants to pass the filtering below.
            del search_opts['all_tenants']
            shares = self.db.share_get_all(context)
        else:
            shares = self.db.share_get_all_by_project(context,
                                                      context.project_id)

        if search_opts:
            LOG.debug("Searching by: %s" % str(search_opts))

            results = []
            not_found = object()
            for share in shares:
                for opt, value in search_opts.iteritems():
                    if share.get(opt, not_found) != value:
                        break
                else:
                    results.append(share)
            shares = results
        return shares

    def get_snapshot(self, context, snapshot_id):
        policy.check_policy(context, 'share', 'get_snapshot')
        rv = self.db.share_snapshot_get(context, snapshot_id)
        return dict(rv.iteritems())

    def get_all_snapshots(self, context, search_opts=None):
        policy.check_policy(context, 'share', 'get_all_snapshots')

        search_opts = search_opts or {}

        if (context.is_admin and 'all_tenants' in search_opts):
            # Need to remove all_tenants to pass the filtering below.
            del search_opts['all_tenants']
            snapshots = self.db.share_snapshot_get_all(context)
        else:
            snapshots = self.db.share_snapshot_get_all_by_project(
                context, context.project_id)

        if search_opts:
            LOG.debug("Searching by: %s" % str(search_opts))

            results = []
            not_found = object()
            for snapshot in snapshots:
                for opt, value in search_opts.iteritems():
                    if snapshot.get(opt, not_found) != value:
                        break
                else:
                    results.append(snapshot)
            snapshots = results
        return snapshots

    def allow_access(self, ctx, share, access_type, access_to):
        """Allow access to share."""
        if not share['host']:
            msg = _("Share host is None")
            raise exception.InvalidShare(reason=msg)
        if share['status'] not in ["available"]:
            msg = _("Share status must be available")
            raise exception.InvalidShare(reason=msg)
        policy.check_policy(ctx, 'share', 'allow_access')
        values = {'share_id': share['id'],
                  'access_type': access_type,
                  'access_to': access_to}
        access = [a for a in self.db.share_access_get_all_by_type_and_access(
            ctx, share['id'], access_type, access_to) if a['state'] != 'error']
        if access:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access_to)
        access = self.db.share_access_create(ctx, values)
        self.share_rpcapi.allow_access(ctx, share, access)
        return access

    def deny_access(self, ctx, share, access):
        """Deny access to share."""
        policy.check_policy(ctx, 'share', 'deny_access')
        #First check state of the target share
        if not share['host']:
            msg = _("Share host is None")
            raise exception.InvalidShare(reason=msg)
        if share['status'] not in ["available"]:
            msg = _("Share status must be available")
            raise exception.InvalidShare(reason=msg)

        #Then check state of the access rule
        if access['state'] == access.STATE_ERROR:
            self.db.share_access_delete(ctx, access["id"])
        elif access['state'] == access.STATE_ACTIVE:
            self.db.share_access_update(ctx, access["id"],
                                        {'state': access.STATE_DELETING})
            self.share_rpcapi.deny_access(ctx, share, access)
        else:
            msg = _("Access policy should be active or in error state")
            raise exception.InvalidShareAccess(reason=msg)
            #update share state and send message to manager

    def access_get_all(self, context, share):
        """Returns all access rules for share."""
        policy.check_policy(context, 'share', 'access_get_all')
        rules = self.db.share_access_get_all_for_share(context, share['id'])
        return [{'id': rule.id,
                 'access_type': rule.access_type,
                 'access_to': rule.access_to,
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
        return dict(rv.iteritems())

    @policy.wrap_check_policy('share')
    def delete_share_metadata(self, context, share, key):
        """Delete the given metadata item from a share."""
        self.db.share_metadata_delete(context, share['id'], key)

    def _check_metadata_properties(self, context, metadata=None):
        if not metadata:
            metadata = {}

        for k, v in metadata.iteritems():
            if len(k) == 0:
                msg = _("Metadata property key is blank")
                LOG.warn(msg)
                raise exception.InvalidShareMetadata(message=msg)
            if len(k) > 255:
                msg = _("Metadata property key is greater than 255 characters")
                LOG.warn(msg)
                raise exception.InvalidShareMetadataSize(message=msg)
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
