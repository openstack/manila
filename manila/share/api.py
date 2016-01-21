# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
# Copyright (c) 2015 Mirantis Inc.
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
from manila.i18n import _LI
from manila.i18n import _LW
from manila import policy
from manila import quota
from manila.scheduler import rpcapi as scheduler_rpcapi
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types
from manila.share import utils as share_utils
from manila import utils

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
               share_network_id=None, share_type=None, is_public=False,
               consistency_group_id=None, cgsnapshot_member=None):
        """Create new share."""
        policy.check_policy(context, 'share', 'create')

        self._check_metadata_properties(context, metadata)

        if snapshot is not None:
            if snapshot['status'] != constants.STATUS_AVAILABLE:
                msg = _("status must be '%s'") % constants.STATUS_AVAILABLE
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
            availability_zone = source_share['availability_zone']
            if share_type is None:
                share_type_id = source_share['share_type_id']
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
                LOG.warning(_LW("Quota exceeded for %(s_pid)s, "
                                "tried to create "
                                "%(s_size)sG share (%(d_consumed)dG of "
                                "%(d_quota)dG already consumed)."), {
                                    's_pid': context.project_id,
                                    's_size': size,
                                    'd_consumed': _consumed('gigabytes'),
                                    'd_quota': quotas['gigabytes']})
                raise exception.ShareSizeExceedsAvailableQuota()
            elif 'shares' in overs:
                LOG.warning(_LW("Quota exceeded for %(s_pid)s, "
                                "tried to create "
                                "share (%(d_consumed)d shares "
                                "already consumed)."), {
                                    's_pid': context.project_id,
                                    'd_consumed': _consumed('shares')})
                raise exception.ShareLimitExceeded(allowed=quotas['shares'])

        try:
            is_public = strutils.bool_from_string(is_public, strict=True)
            snapshot_support = strutils.bool_from_string(
                share_type.get('extra_specs', {}).get(
                    'snapshot_support', True) if share_type else True,
                strict=True)
        except ValueError as e:
            raise exception.InvalidParameterValue(six.text_type(e))

        consistency_group = None
        if consistency_group_id:
            try:
                consistency_group = self.db.consistency_group_get(
                    context, consistency_group_id)
            except exception.NotFound as e:
                raise exception.InvalidParameterValue(six.text_type(e))

            if (not cgsnapshot_member and
                    not (consistency_group['status'] ==
                         constants.STATUS_AVAILABLE)):
                params = {
                    'avail': constants.STATUS_AVAILABLE,
                    'cg_status': consistency_group['status'],
                }
                msg = _("Consistency group status must be %(avail)s, got"
                        "%(cg_status)s.") % params
                raise exception.InvalidConsistencyGroup(message=msg)

            if share_type_id:
                cg_st_ids = [st['share_type_id'] for st in
                             consistency_group.get('share_types', [])]
                if share_type_id not in cg_st_ids:
                    params = {
                        'type': share_type_id,
                        'cg': consistency_group_id
                    }
                    msg = _("The specified share type (%(type)s) is not "
                            "supported by the specified consistency group "
                            "(%(cg)s).") % params
                    raise exception.InvalidParameterValue(msg)

            if (not consistency_group.get('share_network_id')
                    == share_network_id):
                params = {
                    'net': share_network_id,
                    'cg': consistency_group_id
                }
                msg = _("The specified share network (%(net)s) is not "
                        "supported by the specified consistency group "
                        "(%(cg)s).") % params
                raise exception.InvalidParameterValue(msg)

        options = {'size': size,
                   'user_id': context.user_id,
                   'project_id': context.project_id,
                   'snapshot_id': snapshot_id,
                   'snapshot_support': snapshot_support,
                   'metadata': metadata,
                   'display_name': name,
                   'display_description': description,
                   'share_proto': share_proto,
                   'share_type_id': share_type_id,
                   'is_public': is_public,
                   'consistency_group_id': consistency_group_id,
                   }
        if cgsnapshot_member:
            options['source_cgsnapshot_member_id'] = cgsnapshot_member['id']

        try:
            share = self.db.share_create(context, options,
                                         create_share_instance=False)
            QUOTAS.commit(context, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    self.db.share_delete(context, share['id'])
                finally:
                    QUOTAS.rollback(context, reservations)

        host = None
        if snapshot and not CONF.use_scheduler_creating_share_from_snapshot:
            # Shares from snapshots with restriction - source host only.
            # It is common situation for different types of backends.
            host = snapshot['share']['host']

        self.create_instance(context, share, share_network_id=share_network_id,
                             host=host, availability_zone=availability_zone,
                             consistency_group=consistency_group,
                             cgsnapshot_member=cgsnapshot_member)

        return share

    def create_instance(self, context, share, share_network_id=None,
                        host=None, availability_zone=None,
                        consistency_group=None, cgsnapshot_member=None):
        policy.check_policy(context, 'share', 'create')

        availability_zone_id = None
        if availability_zone:
            availability_zone_id = self.db.availability_zone_get(
                context, availability_zone).id

        # TODO(u_glide): Add here validation that provided share network
        # doesn't conflict with provided availability_zone when Neutron
        # will have AZ support.

        share_instance = self.db.share_instance_create(
            context, share['id'],
            {
                'share_network_id': share_network_id,
                'status': constants.STATUS_CREATING,
                'scheduled_at': timeutils.utcnow(),
                'host': host if host else '',
                'availability_zone_id': availability_zone_id,
            }
        )

        if cgsnapshot_member:
            host = cgsnapshot_member['share']['host']
            share = self.db.share_instance_update(context,
                                                  share_instance['id'],
                                                  {'host': host})
            # NOTE(ameade): Do not cast to driver if creating from cgsnapshot
            return

        share_properties = {
            'size': share['size'],
            'user_id': share['user_id'],
            'project_id': share['project_id'],
            'metadata': self.db.share_metadata_get(context, share['id']),
            'share_server_id': share['share_server_id'],
            'snapshot_support': share['snapshot_support'],
            'share_proto': share['share_proto'],
            'share_type_id': share['share_type_id'],
            'is_public': share['is_public'],
            'consistency_group_id': share['consistency_group_id'],
            'source_cgsnapshot_member_id': share[
                'source_cgsnapshot_member_id'],
            'snapshot_id': share['snapshot_id'],
        }
        share_instance_properties = {
            'availability_zone_id': share_instance['availability_zone_id'],
            'share_network_id': share_instance['share_network_id'],
            'share_server_id': share_instance['share_server_id'],
            'share_id': share_instance['share_id'],
            'host': share_instance['host'],
            'status': share_instance['status'],
        }

        share_type = None
        if share['share_type_id']:
            share_type = self.db.share_type_get(
                context, share['share_type_id'])

        request_spec = {
            'share_properties': share_properties,
            'share_instance_properties': share_instance_properties,
            'share_proto': share['share_proto'],
            'share_id': share['id'],
            'snapshot_id': share['snapshot_id'],
            'share_type': share_type,
            'consistency_group': consistency_group,
        }

        if host:
            self.share_rpcapi.create_share_instance(
                context,
                share_instance,
                host,
                request_spec=request_spec,
                filter_properties={},
                snapshot_id=share['snapshot_id'],
            )
        else:
            # Create share instance from scratch or from snapshot could happen
            # on hosts other than the source host.
            self.scheduler_rpcapi.create_share_instance(
                context, request_spec=request_spec, filter_properties={})

        return share_instance

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

        self.db.share_export_locations_update(context, share.instance['id'],
                                              export_location)

        self.share_rpcapi.manage_share(context, share, driver_options)
        return self.db.share_get(context, share['id'])

    def unmanage(self, context, share):
        policy.check_policy(context, 'share', 'unmanage')

        self._check_is_share_busy(share)

        update_data = {'status': constants.STATUS_UNMANAGING,
                       'terminated_at': timeutils.utcnow()}
        share_ref = self.db.share_update(context, share['id'], update_data)

        self.share_rpcapi.unmanage_share(context, share_ref)

        # NOTE(u_glide): We should update 'updated_at' timestamp of
        # share server here, when manage/unmanage operations will be supported
        # for driver_handles_share_servers=True mode

    @policy.wrap_check_policy('share')
    def delete(self, context, share, force=False):
        """Delete share."""
        share = self.db.share_get(context, share['id'])
        if context.is_admin and context.project_id != share['project_id']:
            project_id = share['project_id']
        else:
            project_id = context.project_id

        share_id = share['id']

        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR,
                    constants.STATUS_INACTIVE)
        if not (force or share['status'] in statuses):
            msg = _("Share status must be one of %(statuses)s") % {
                "statuses": statuses}
            raise exception.InvalidShare(reason=msg)

        snapshots = self.db.share_snapshot_get_all_for_share(context, share_id)
        if len(snapshots):
            msg = _("Share still has %d dependent snapshots") % len(snapshots)
            raise exception.InvalidShare(reason=msg)

        cgsnapshot_members_count = self.db.count_cgsnapshot_members_in_share(
            context, share_id)
        if cgsnapshot_members_count:
            msg = (_("Share still has %d dependent cgsnapshot members") %
                   cgsnapshot_members_count)
            raise exception.InvalidShare(reason=msg)

        self._check_is_share_busy(share)

        try:
            reservations = QUOTAS.reserve(context,
                                          project_id=project_id,
                                          shares=-1,
                                          gigabytes=-share['size'])
        except Exception as e:
            reservations = None
            LOG.exception(
                _LE("Failed to update quota for deleting share: %s"),
                six.text_type(e)
            )

        for share_instance in share.instances:
            if share_instance['host']:
                self.delete_instance(context, share_instance, force=force)
            else:
                self.db.share_instance_delete(context, share_instance['id'])

        if reservations:
            QUOTAS.commit(context, reservations, project_id=project_id)

    def delete_instance(self, context, share_instance, force=False):
        policy.check_policy(context, 'share', 'delete')

        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR,
                    constants.STATUS_INACTIVE)
        if not (force or share_instance['status'] in statuses):
            msg = _("Share instance status must be one of %(statuses)s") % {
                "statuses": statuses}
            raise exception.InvalidShareInstance(reason=msg)

        share_instance = self.db.share_instance_update(
            context, share_instance['id'],
            {'status': constants.STATUS_DELETING,
             'terminated_at': timeutils.utcnow()}
        )

        self.share_rpcapi.delete_share_instance(context, share_instance)

        # NOTE(u_glide): 'updated_at' timestamp is used to track last usage of
        # share server. This is required for automatic share servers cleanup
        # because we should track somehow period of time when share server
        # doesn't have shares (unused). We do this update only on share
        # deletion because share server with shares cannot be deleted, so no
        # need to do this update on share creation or any other share operation
        if share_instance['share_server_id']:
            self.db.share_server_update(
                context,
                share_instance['share_server_id'],
                {'updated_at': timeutils.utcnow()})

    def delete_share_server(self, context, server):
        """Delete share server."""
        policy.check_policy(context, 'share_server', 'delete', server)
        shares = self.db.share_instances_get_all_by_share_server(context,
                                                                 server['id'])

        if shares:
            raise exception.ShareServerInUse(share_server_id=server['id'])

        cgs = self.db.consistency_group_get_all_by_share_server(context,
                                                                server['id'])
        if cgs:
            LOG.error(_LE("share server '%(ssid)s' in use by CGs"),
                      {'ssid': server['id']})
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

        if ((not force) and (share['status'] != constants.STATUS_AVAILABLE)):
            msg = _("Source share status must be "
                    "%s") % constants.STATUS_AVAILABLE
            raise exception.InvalidShare(reason=msg)

        size = share['size']

        self._check_is_share_busy(share)

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
                          "%(d_quota)dG already consumed).")
                LOG.warning(msg, {'s_pid': context.project_id,
                                  's_size': size,
                                  'd_consumed': _consumed('gigabytes'),
                                  'd_quota': quotas['snapshot_gigabytes']})
                raise exception.SnapshotSizeExceedsAvailableQuota()
            elif 'snapshots' in overs:
                msg = _LW("Quota exceeded for %(s_pid)s, tried to create "
                          "snapshot (%(d_consumed)d snapshots "
                          "already consumed).")
                LOG.warning(msg, {'s_pid': context.project_id,
                                  'd_consumed': _consumed('snapshots')})
                raise exception.SnapshotLimitExceeded(
                    allowed=quotas['snapshots'])
        options = {'share_id': share['id'],
                   'size': share['size'],
                   'user_id': context.user_id,
                   'project_id': context.project_id,
                   'status': constants.STATUS_CREATING,
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
    def migrate_share(self, context, share, host, force_host_copy):
        """Migrates share to a new host."""

        policy.check_policy(context, 'share', 'migrate')

        share_instance = share.instance

        # We only handle "available" share for now
        if share_instance['status'] != constants.STATUS_AVAILABLE:
            msg = _('Share instance %(instance_id)s status must be available, '
                    'but current status is: %(instance_status)s.') % {
                'instance_id': share_instance['id'],
                'instance_status': share_instance['status']}
            raise exception.InvalidShare(reason=msg)

        self._check_is_share_busy(share)

        # Make sure the destination host is different than the current one
        if host == share_instance['host']:
            msg = _('Destination host %(dest_host)s must be different '
                    'than the current host %(src_host)s.') % {
                'dest_host': host,
                'src_host': share_instance['host']}
            raise exception.InvalidHost(reason=msg)

        # We only handle shares without snapshots for now
        snaps = self.db.share_snapshot_get_all_for_share(context, share['id'])
        if snaps:
            msg = _("Share %s must not have snapshots.") % share['id']
            raise exception.InvalidShare(reason=msg)

        # Make sure the host is in the list of available hosts
        utils.validate_service_host(context, share_utils.extract_host(host))

        # NOTE(ganso): there is the possibility of an error between here and
        # manager code, which will cause the share to be stuck in
        # MIGRATION_STARTING status. According to Liberty Midcycle discussion,
        # this kind of scenario should not be cleaned up, the administrator
        # should be issued to clear this status before a new migration request
        # is made
        self.update(
            context, share,
            {'task_state': constants.STATUS_TASK_STATE_MIGRATION_STARTING})

        share_type = {}
        share_type_id = share['share_type_id']
        if share_type_id:
            share_type = share_types.get_share_type(context, share_type_id)

        share_properties = {
            'size': share['size'],
            'user_id': share['user_id'],
            'project_id': share['project_id'],
            'share_server_id': share['share_server_id'],
            'snapshot_support': share['snapshot_support'],
            'share_proto': share['share_proto'],
            'share_type_id': share['share_type_id'],
            'is_public': share['is_public'],
            'consistency_group_id': share['consistency_group_id'],
            'source_cgsnapshot_member_id': share[
                'source_cgsnapshot_member_id'],
            'snapshot_id': share['snapshot_id'],
        }
        share_instance_properties = {
            'availability_zone_id': share_instance['availability_zone_id'],
            'share_network_id': share_instance['share_network_id'],
            'share_server_id': share_instance['share_server_id'],
            'share_id': share_instance['share_id'],
            'host': share_instance['host'],
            'status': share_instance['status'],
        }
        request_spec = {'share_properties': share_properties,
                        'share_instance_properties': share_instance_properties,
                        'share_type': share_type,
                        'share_id': share['id']}

        try:
            self.scheduler_rpcapi.migrate_share_to_host(context, share['id'],
                                                        host, force_host_copy,
                                                        request_spec)
        except Exception:
            self.update(
                context, share,
                {'task_state': constants.STATUS_TASK_STATE_MIGRATION_ERROR})
            raise

    @policy.wrap_check_policy('share')
    def delete_snapshot(self, context, snapshot, force=False):
        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
        if not (force or snapshot['status'] in statuses):
            msg = _("Share Snapshot status must be one of %(statuses)s.") % {
                "statuses": statuses}
            raise exception.InvalidShareSnapshot(reason=msg)

        self.db.share_snapshot_update(context, snapshot['id'],
                                      {'status': constants.STATUS_DELETING})
        share = self.db.share_get(context, snapshot['share_id'])
        self.share_rpcapi.delete_snapshot(context, snapshot, share['host'])

    @policy.wrap_check_policy('share')
    def update(self, context, share, fields):
        if 'is_public' in fields:
            try:
                fields['is_public'] = strutils.bool_from_string(
                    fields['is_public'], strict=True)
            except ValueError as e:
                raise exception.InvalidParameterValue(six.text_type(e))
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
        policy.check_policy(context, 'share_snapshot', 'get_snapshot')
        rv = self.db.share_snapshot_get(context, snapshot_id)
        return dict(six.iteritems(rv))

    def get_all_snapshots(self, context, search_opts=None,
                          sort_key='share_id', sort_dir='desc'):
        policy.check_policy(context, 'share_snapshot', 'get_all_snapshots')

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
        policy.check_policy(ctx, 'share', 'allow_access')
        share = self.db.share_get(ctx, share['id'])
        if share['status'] != constants.STATUS_AVAILABLE:
            msg = _("Share status must be %s") % constants.STATUS_AVAILABLE
            raise exception.InvalidShare(reason=msg)
        values = {
            'share_id': share['id'],
            'access_type': access_type,
            'access_to': access_to,
            'access_level': access_level,
        }
        for access in self.db.share_access_get_all_by_type_and_access(
                ctx, share['id'], access_type, access_to):
            if access['state'] != constants.STATUS_ERROR:
                raise exception.ShareAccessExists(access_type=access_type,
                                                  access=access_to)
        if access_level not in constants.ACCESS_LEVELS + (None, ):
            msg = _("Invalid share access level: %s.") % access_level
            raise exception.InvalidShareAccess(reason=msg)
        access = self.db.share_access_create(ctx, values)

        for share_instance in share.instances:
            self.allow_access_to_instance(ctx, share_instance, access)
        return {
            'id': access['id'],
            'share_id': access['share_id'],
            'access_type': access['access_type'],
            'access_to': access['access_to'],
            'access_level': access['access_level'],
            'state': access['state'],
        }

    def allow_access_to_instance(self, context, share_instance, access):
        policy.check_policy(context, 'share', 'allow_access')

        if not share_instance['host']:
            msg = _("Invalid share instance host: %s") % share_instance['host']
            raise exception.InvalidShareInstance(reason=msg)

        self.share_rpcapi.allow_access(context, share_instance, access)

    def deny_access(self, ctx, share, access):
        """Deny access to share."""
        policy.check_policy(ctx, 'share', 'deny_access')
        # First check state of the target share
        share = self.db.share_get(ctx, share['id'])
        if not (share.instances and share.instance['host']):
            msg = _("Share doesn't have any instances")
            raise exception.InvalidShare(reason=msg)
        if share['status'] != constants.STATUS_AVAILABLE:
            msg = _("Share status must be %s") % constants.STATUS_AVAILABLE
            raise exception.InvalidShare(reason=msg)

        # Then check state of the access rule
        if (access['state'] == constants.STATUS_ERROR and not
                self.db.share_instance_access_get_all(ctx, access['id'])):
            self.db.share_access_delete(ctx, access["id"])

        elif access['state'] in [constants.STATUS_ACTIVE,
                                 constants.STATUS_ERROR]:
            for share_instance in share.instances:
                try:
                    self.deny_access_to_instance(ctx, share_instance, access)
                except exception.NotFound:
                    LOG.warning(_LW("Access rule %(access_id)s not found "
                                    "for instance %(instance_id)s.") % {
                                'access_id': access['id'],
                                'instance_id': share_instance['id']})
        else:
            msg = _("Access policy should be %(active)s or in %(error)s "
                    "state") % {"active": constants.STATUS_ACTIVE,
                                "error": constants.STATUS_ERROR}
            raise exception.InvalidShareAccess(reason=msg)
            # update share state and send message to manager

    def deny_access_to_instance(self, context, share_instance, access):
        policy.check_policy(context, 'share', 'deny_access')

        if not share_instance['host']:
            msg = _("Invalid share instance host: %s") % share_instance['host']
            raise exception.InvalidShareInstance(reason=msg)

        access_mapping = self.db.share_instance_access_get(
            context, access['id'], share_instance['id'])
        self.db.share_instance_access_update_state(
            context, access_mapping['id'],
            access_mapping.STATE_DELETING)

        self.share_rpcapi.deny_access(context, share_instance, access)

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

    def _check_is_share_busy(self, share):
        """Raises an exception if share is busy with an active task."""
        if share.is_busy:
            msg = _("Share %(share_id)s is busy as part of an active "
                    "task: %(task)s.") % {
                'share_id': share['id'],
                'task': share['task_state']
            }
            raise exception.ShareBusyException(reason=msg)

    def _check_metadata_properties(self, context, metadata=None):
        if not metadata:
            metadata = {}

        for k, v in six.iteritems(metadata):
            if not k:
                msg = _("Metadata property key is blank.")
                LOG.warning(msg)
                raise exception.InvalidShareMetadata(message=msg)
            if len(k) > 255:
                msg = _("Metadata property key is "
                        "greater than 255 characters.")
                LOG.warning(msg)
                raise exception.InvalidShareMetadataSize(message=msg)
            if not v:
                msg = _("Metadata property value is blank.")
                LOG.warning(msg)
                raise exception.InvalidShareMetadata(message=msg)
            if len(v) > 1023:
                msg = _("Metadata property value is "
                        "greater than 1023 characters.")
                LOG.warning(msg)
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

    def extend(self, context, share, new_size):
        policy.check_policy(context, 'share', 'extend')

        if share['status'] != constants.STATUS_AVAILABLE:
            msg_params = {
                'valid_status': constants.STATUS_AVAILABLE,
                'share_id': share['id'],
                'status': share['status'],
            }
            msg = _("Share %(share_id)s status must be '%(valid_status)s' "
                    "to extend, but current status is: "
                    "%(status)s.") % msg_params
            raise exception.InvalidShare(reason=msg)

        self._check_is_share_busy(share)

        size_increase = int(new_size) - share['size']
        if size_increase <= 0:
            msg = (_("New size for extend must be greater "
                     "than current size. (current: %(size)s, "
                     "extended: %(new_size)s).") % {'new_size': new_size,
                                                    'size': share['size']})
            raise exception.InvalidInput(reason=msg)

        try:
            reservations = QUOTAS.reserve(context,
                                          project_id=share['project_id'],
                                          gigabytes=size_increase)
        except exception.OverQuota as exc:
            usages = exc.kwargs['usages']
            quotas = exc.kwargs['quotas']

            def _consumed(name):
                return usages[name]['reserved'] + usages[name]['in_use']

            msg = _LE("Quota exceeded for %(s_pid)s, tried to extend share "
                      "by %(s_size)sG, (%(d_consumed)dG of %(d_quota)dG "
                      "already consumed).")
            LOG.error(msg, {'s_pid': context.project_id,
                            's_size': size_increase,
                            'd_consumed': _consumed('gigabytes'),
                            'd_quota': quotas['gigabytes']})
            raise exception.ShareSizeExceedsAvailableQuota(
                requested=size_increase,
                consumed=_consumed('gigabytes'),
                quota=quotas['gigabytes'])

        self.update(context, share, {'status': constants.STATUS_EXTENDING})
        self.share_rpcapi.extend_share(context, share, new_size, reservations)
        LOG.info(_LI("Extend share request issued successfully."),
                 resource=share)

    def shrink(self, context, share, new_size):
        policy.check_policy(context, 'share', 'shrink')

        status = six.text_type(share['status']).lower()
        valid_statuses = (constants.STATUS_AVAILABLE,
                          constants.STATUS_SHRINKING_POSSIBLE_DATA_LOSS_ERROR)

        if status not in valid_statuses:
            msg_params = {
                'valid_status': ", ".join(valid_statuses),
                'share_id': share['id'],
                'status': status,
            }
            msg = _("Share %(share_id)s status must in (%(valid_status)s) "
                    "to shrink, but current status is: "
                    "%(status)s.") % msg_params
            raise exception.InvalidShare(reason=msg)

        self._check_is_share_busy(share)

        size_decrease = int(share['size']) - int(new_size)
        if size_decrease <= 0 or new_size <= 0:
            msg = (_("New size for shrink must be less "
                     "than current size and greater than 0 (current: %(size)s,"
                     " new: %(new_size)s)") % {'new_size': new_size,
                                               'size': share['size']})
            raise exception.InvalidInput(reason=msg)

        self.update(context, share, {'status': constants.STATUS_SHRINKING})
        self.share_rpcapi.shrink_share(context, share, new_size)
        LOG.info(_LI("Shrink share (id=%(id)s) request issued successfully."
                     " New size: %(size)s") % {'id': share['id'],
                                               'size': new_size})
