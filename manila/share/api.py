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

from manila.common import constants
from manila.data import rpcapi as data_rpcapi
from manila.db import base
from manila import exception
from manila.i18n import _
from manila import policy
from manila import quota
from manila.scheduler import rpcapi as scheduler_rpcapi
from manila.share import access
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
        super(API, self).__init__(db_driver)
        self.scheduler_rpcapi = scheduler_rpcapi.SchedulerAPI()
        self.share_rpcapi = share_rpcapi.ShareAPI()
        self.access_helper = access.ShareInstanceAccess(self.db, None)

    def create(self, context, share_proto, size, name, description,
               snapshot_id=None, availability_zone=None, metadata=None,
               share_network_id=None, share_type=None, is_public=False,
               share_group_id=None, share_group_snapshot_member=None):
        """Create new share."""
        policy.check_policy(context, 'share', 'create')

        self._check_metadata_properties(context, metadata)

        if snapshot_id is not None:
            snapshot = self.get_snapshot(context, snapshot_id)
            if snapshot['aggregate_status'] != constants.STATUS_AVAILABLE:
                msg = _("status must be '%s'") % constants.STATUS_AVAILABLE
                raise exception.InvalidShareSnapshot(reason=msg)
            if not size:
                size = snapshot['size']
        else:
            snapshot = None

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
            availability_zone = source_share['instance']['availability_zone']
            if share_type is None:
                # Grab the source share's share_type if no new share type
                # has been provided.
                share_type_id = source_share['instance']['share_type_id']
                share_type = share_types.get_share_type(context, share_type_id)
            else:
                share_type_id = share_type['id']
                if share_type_id != source_share['instance']['share_type_id']:
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
            reservations = QUOTAS.reserve(
                context, shares=1, gigabytes=size,
                share_type_id=share_type_id,
            )
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'gigabytes' in overs:
                LOG.warning("Quota exceeded for %(s_pid)s, "
                            "tried to create "
                            "%(s_size)sG share (%(d_consumed)dG of "
                            "%(d_quota)dG already consumed).", {
                                's_pid': context.project_id,
                                's_size': size,
                                'd_consumed': _consumed('gigabytes'),
                                'd_quota': quotas['gigabytes']})
                raise exception.ShareSizeExceedsAvailableQuota()
            elif 'shares' in overs:
                LOG.warning("Quota exceeded for %(s_pid)s, "
                            "tried to create "
                            "share (%(d_consumed)d shares "
                            "already consumed).", {
                                's_pid': context.project_id,
                                'd_consumed': _consumed('shares')})
                raise exception.ShareLimitExceeded(allowed=quotas['shares'])

        try:
            is_public = strutils.bool_from_string(is_public, strict=True)
        except ValueError as e:
            raise exception.InvalidParameterValue(six.text_type(e))

        share_group = None
        if share_group_id:
            try:
                share_group = self.db.share_group_get(context, share_group_id)
            except exception.NotFound as e:
                raise exception.InvalidParameterValue(six.text_type(e))

            if (not share_group_snapshot_member and
                    not (share_group['status'] == constants.STATUS_AVAILABLE)):
                params = {
                    'avail': constants.STATUS_AVAILABLE,
                    'status': share_group['status'],
                }
                msg = _("Share group status must be %(avail)s, got"
                        "%(status)s.") % params
                raise exception.InvalidShareGroup(message=msg)

            if share_type_id:
                share_group_st_ids = [
                    st['share_type_id']
                    for st in share_group.get('share_types', [])]
                if share_type_id not in share_group_st_ids:
                    params = {
                        'type': share_type_id,
                        'group': share_group_id,
                    }
                    msg = _("The specified share type (%(type)s) is not "
                            "supported by the specified share group "
                            "(%(group)s).") % params
                    raise exception.InvalidParameterValue(msg)

            if not share_group.get('share_network_id') == share_network_id:
                params = {
                    'net': share_network_id,
                    'group': share_group_id
                }
                msg = _("The specified share network (%(net)s) is not "
                        "supported by the specified share group "
                        "(%(group)s).") % params
                raise exception.InvalidParameterValue(msg)

        options = {
            'size': size,
            'user_id': context.user_id,
            'project_id': context.project_id,
            'snapshot_id': snapshot_id,
            'metadata': metadata,
            'display_name': name,
            'display_description': description,
            'share_proto': share_proto,
            'is_public': is_public,
            'share_group_id': share_group_id,
        }
        options.update(self.get_share_attributes_from_share_type(share_type))

        if share_group_snapshot_member:
            options['source_share_group_snapshot_member_id'] = (
                share_group_snapshot_member['id'])

        try:
            share = self.db.share_create(context, options,
                                         create_share_instance=False)
            QUOTAS.commit(context, reservations, share_type_id=share_type_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    self.db.share_delete(context, share['id'])
                finally:
                    QUOTAS.rollback(
                        context, reservations, share_type_id=share_type_id)

        host = None
        if snapshot and not CONF.use_scheduler_creating_share_from_snapshot:
            # Shares from snapshots with restriction - source host only.
            # It is common situation for different types of backends.
            host = snapshot['share']['instance']['host']

        elif share_group:
            host = share_group['host']

        self.create_instance(
            context, share, share_network_id=share_network_id, host=host,
            availability_zone=availability_zone, share_group=share_group,
            share_group_snapshot_member=share_group_snapshot_member,
            share_type_id=share_type_id)

        # Retrieve the share with instance details
        share = self.db.share_get(context, share['id'])

        return share

    def get_share_attributes_from_share_type(self, share_type):
        """Determine share attributes from the share type.

        The share type can change any time after shares of that type are
        created, so we copy some share type attributes to the share to
        consistently govern the behavior of that share over its lifespan.
        """

        inferred_map = constants.ExtraSpecs.INFERRED_OPTIONAL_MAP
        snapshot_support_key = constants.ExtraSpecs.SNAPSHOT_SUPPORT
        create_share_from_snapshot_key = (
            constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT)
        revert_to_snapshot_key = (
            constants.ExtraSpecs.REVERT_TO_SNAPSHOT_SUPPORT)
        mount_snapshot_support_key = (
            constants.ExtraSpecs.MOUNT_SNAPSHOT_SUPPORT)

        snapshot_support_default = inferred_map.get(snapshot_support_key)
        create_share_from_snapshot_support_default = inferred_map.get(
            create_share_from_snapshot_key)
        revert_to_snapshot_support_default = inferred_map.get(
            revert_to_snapshot_key)
        mount_snapshot_support_default = inferred_map.get(
            constants.ExtraSpecs.MOUNT_SNAPSHOT_SUPPORT)

        if share_type:
            snapshot_support = share_types.parse_boolean_extra_spec(
                snapshot_support_key,
                share_type.get('extra_specs', {}).get(
                    snapshot_support_key, snapshot_support_default))
            create_share_from_snapshot_support = (
                share_types.parse_boolean_extra_spec(
                    create_share_from_snapshot_key,
                    share_type.get('extra_specs', {}).get(
                        create_share_from_snapshot_key,
                        create_share_from_snapshot_support_default)))
            revert_to_snapshot_support = (
                share_types.parse_boolean_extra_spec(
                    revert_to_snapshot_key,
                    share_type.get('extra_specs', {}).get(
                        revert_to_snapshot_key,
                        revert_to_snapshot_support_default)))
            mount_snapshot_support = share_types.parse_boolean_extra_spec(
                mount_snapshot_support_key, share_type.get(
                    'extra_specs', {}).get(
                    mount_snapshot_support_key,
                    mount_snapshot_support_default))
            replication_type = share_type.get('extra_specs', {}).get(
                'replication_type')
        else:
            snapshot_support = snapshot_support_default
            create_share_from_snapshot_support = (
                create_share_from_snapshot_support_default)
            revert_to_snapshot_support = revert_to_snapshot_support_default
            mount_snapshot_support = mount_snapshot_support_default
            replication_type = None

        return {
            'snapshot_support': snapshot_support,
            'create_share_from_snapshot_support':
                create_share_from_snapshot_support,
            'revert_to_snapshot_support': revert_to_snapshot_support,
            'replication_type': replication_type,
            'mount_snapshot_support': mount_snapshot_support,
        }

    def create_instance(self, context, share, share_network_id=None,
                        host=None, availability_zone=None,
                        share_group=None, share_group_snapshot_member=None,
                        share_type_id=None):
        policy.check_policy(context, 'share', 'create')

        request_spec, share_instance = (
            self.create_share_instance_and_get_request_spec(
                context, share, availability_zone=availability_zone,
                share_group=share_group, host=host,
                share_network_id=share_network_id,
                share_type_id=share_type_id))

        if share_group_snapshot_member:
            # Inherit properties from the share_group_snapshot_member
            member_share_instance = share_group_snapshot_member[
                'share_instance']
            updates = {
                'host': member_share_instance['host'],
                'share_network_id': member_share_instance['share_network_id'],
                'share_server_id': member_share_instance['share_server_id'],
            }
            share = self.db.share_instance_update(context,
                                                  share_instance['id'],
                                                  updates)
            # NOTE(ameade): Do not cast to driver if creating from share group
            # snapshot
            return

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

    def create_share_instance_and_get_request_spec(
            self, context, share, availability_zone=None,
            share_group=None, host=None, share_network_id=None,
            share_type_id=None, cast_rules_to_readonly=False):

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
                'share_type_id': share_type_id,
                'cast_rules_to_readonly': cast_rules_to_readonly,
            }
        )

        share_properties = {
            'id': share['id'],
            'size': share['size'],
            'user_id': share['user_id'],
            'project_id': share['project_id'],
            'metadata': self.db.share_metadata_get(context, share['id']),
            'share_server_id': share_instance['share_server_id'],
            'snapshot_support': share['snapshot_support'],
            'create_share_from_snapshot_support':
                share['create_share_from_snapshot_support'],
            'revert_to_snapshot_support': share['revert_to_snapshot_support'],
            'mount_snapshot_support': share['mount_snapshot_support'],
            'share_proto': share['share_proto'],
            'share_type_id': share_type_id,
            'is_public': share['is_public'],
            'share_group_id': share['share_group_id'],
            'source_share_group_snapshot_member_id': share[
                'source_share_group_snapshot_member_id'],
            'snapshot_id': share['snapshot_id'],
            'replication_type': share['replication_type'],
        }
        share_instance_properties = {
            'id': share_instance['id'],
            'availability_zone_id': share_instance['availability_zone_id'],
            'share_network_id': share_instance['share_network_id'],
            'share_server_id': share_instance['share_server_id'],
            'share_id': share_instance['share_id'],
            'host': share_instance['host'],
            'status': share_instance['status'],
            'replica_state': share_instance['replica_state'],
            'share_type_id': share_instance['share_type_id'],
        }

        share_type = None
        if share_instance['share_type_id']:
            share_type = self.db.share_type_get(
                context, share_instance['share_type_id'])

        request_spec = {
            'share_properties': share_properties,
            'share_instance_properties': share_instance_properties,
            'share_proto': share['share_proto'],
            'share_id': share['id'],
            'snapshot_id': share['snapshot_id'],
            'share_type': share_type,
            'share_group': share_group,
            'availability_zone_id': availability_zone_id,
        }
        return request_spec, share_instance

    def create_share_replica(self, context, share, availability_zone=None,
                             share_network_id=None):

        if not share.get('replication_type'):
            msg = _("Replication not supported for share %s.")
            raise exception.InvalidShare(message=msg % share['id'])

        if share.get('share_group_id'):
            msg = _("Replication not supported for shares in a group.")
            raise exception.InvalidShare(message=msg)

        self._check_is_share_busy(share)

        active_replica = self.db.share_replicas_get_available_active_replica(
            context, share['id'])

        if not active_replica:
            msg = _("Share %s does not have any active replica in available "
                    "state.")
            raise exception.ReplicationException(reason=msg % share['id'])

        if share['replication_type'] == constants.REPLICATION_TYPE_READABLE:
            cast_rules_to_readonly = True
        else:
            cast_rules_to_readonly = False

        request_spec, share_replica = (
            self.create_share_instance_and_get_request_spec(
                context, share, availability_zone=availability_zone,
                share_network_id=share_network_id,
                share_type_id=share['instance']['share_type_id'],
                cast_rules_to_readonly=cast_rules_to_readonly))

        all_replicas = self.db.share_replicas_get_all_by_share(
            context, share['id'])
        all_hosts = [r['host'] for r in all_replicas]

        request_spec['active_replica_host'] = active_replica['host']
        request_spec['all_replica_hosts'] = ','.join(all_hosts)

        self.db.share_replica_update(
            context, share_replica['id'],
            {'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC})

        existing_snapshots = (
            self.db.share_snapshot_get_all_for_share(
                context, share_replica['share_id'])
        )
        snapshot_instance = {
            'status': constants.STATUS_CREATING,
            'progress': '0%',
            'share_instance_id': share_replica['id'],
        }
        for snapshot in existing_snapshots:
            self.db.share_snapshot_instance_create(
                context, snapshot['id'], snapshot_instance)

        self.scheduler_rpcapi.create_share_replica(
            context, request_spec=request_spec, filter_properties={})

        return share_replica

    def delete_share_replica(self, context, share_replica, force=False):
        # Disallow deletion of ONLY active replica, *even* when this
        # operation is forced.
        replicas = self.db.share_replicas_get_all_by_share(
            context, share_replica['share_id'])
        active_replicas = list(filter(
            lambda x: x['replica_state'] == constants.REPLICA_STATE_ACTIVE,
            replicas))
        if (share_replica.get('replica_state') ==
                constants.REPLICA_STATE_ACTIVE and len(active_replicas) == 1):
            msg = _("Cannot delete last active replica.")
            raise exception.ReplicationException(reason=msg)

        LOG.info("Deleting replica %s.", share_replica['id'])

        self.db.share_replica_update(
            context, share_replica['id'],
            {
                'status': constants.STATUS_DELETING,
                'terminated_at': timeutils.utcnow(),
            }
        )

        if not share_replica['host']:
            # Delete any snapshot instances created on the database
            replica_snapshots = (
                self.db.share_snapshot_instance_get_all_with_filters(
                    context, {'share_instance_ids': share_replica['id']})
            )
            for snapshot in replica_snapshots:
                self.db.share_snapshot_instance_delete(context, snapshot['id'])

            # Delete the replica from the database
            self.db.share_replica_delete(context, share_replica['id'])
        else:

            self.share_rpcapi.delete_share_replica(context,
                                                   share_replica,
                                                   force=force)

    def promote_share_replica(self, context, share_replica):

        if share_replica.get('status') != constants.STATUS_AVAILABLE:
            msg = _("Replica %(replica_id)s must be in %(status)s state to be "
                    "promoted.")
            raise exception.ReplicationException(
                reason=msg % {'replica_id': share_replica['id'],
                              'status': constants.STATUS_AVAILABLE})

        replica_state = share_replica['replica_state']

        if (replica_state in (constants.REPLICA_STATE_OUT_OF_SYNC,
                              constants.STATUS_ERROR)
                and not context.is_admin):
            msg = _("Promoting a replica with 'replica_state': %s requires "
                    "administrator privileges.")
            raise exception.AdminRequired(
                message=msg % replica_state)

        self.db.share_replica_update(
            context, share_replica['id'],
            {'status': constants.STATUS_REPLICATION_CHANGE})

        self.share_rpcapi.promote_share_replica(context, share_replica)

        return self.db.share_replica_get(context, share_replica['id'])

    def update_share_replica(self, context, share_replica):

        if not share_replica['host']:
            msg = _("Share replica does not have a valid host.")
            raise exception.InvalidHost(reason=msg)

        self.share_rpcapi.update_share_replica(context, share_replica)

    def manage(self, context, share_data, driver_options):
        policy.check_policy(context, 'share', 'manage')

        shares = self.get_all(context, {
            'host': share_data['host'],
            'export_location': share_data['export_location'],
            'share_proto': share_data['share_proto'],
            'share_type_id': share_data['share_type_id']
        })

        share_type_id = share_data['share_type_id']
        share_type = share_types.get_share_type(context, share_type_id)

        share_data.update({
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_MANAGING,
            'scheduled_at': timeutils.utcnow(),
        })
        share_data.update(
            self.get_share_attributes_from_share_type(share_type))

        LOG.debug("Manage: Found shares %s.", len(shares))

        export_location = share_data.pop('export_location')

        if len(shares) == 0:
            share = self.db.share_create(context, share_data)
        else:
            msg = _("Share already exists.")
            raise exception.InvalidShare(reason=msg)

        self.db.share_export_locations_update(context, share.instance['id'],
                                              export_location)

        request_spec = self._get_request_spec_dict(
            share, share_type, size=0, share_proto=share_data['share_proto'],
            host=share_data['host'])

        # NOTE(ganso): Scheduler is called to validate if share type
        # provided can fit in host provided. It will invoke manage upon
        # successful validation.
        self.scheduler_rpcapi.manage_share(context, share['id'],
                                           driver_options, request_spec)

        return self.db.share_get(context, share['id'])

    def _get_request_spec_dict(self, share, share_type, **kwargs):

        if share is None:
            share = {'instance': {}}

        share_instance = share['instance']

        share_properties = {
            'size': kwargs.get('size', share.get('size')),
            'user_id': kwargs.get('user_id', share.get('user_id')),
            'project_id': kwargs.get('project_id', share.get('project_id')),
            'snapshot_support': kwargs.get(
                'snapshot_support',
                share_type.get('extra_specs', {}).get('snapshot_support')
            ),
            'create_share_from_snapshot_support': kwargs.get(
                'create_share_from_snapshot_support',
                share_type.get('extra_specs', {}).get(
                    'create_share_from_snapshot_support')
            ),
            'revert_to_snapshot_support': kwargs.get(
                'revert_to_snapshot_support',
                share_type.get('extra_specs', {}).get(
                    'revert_to_snapshot_support')
            ),
            'mount_snapshot_support': kwargs.get(
                'mount_snapshot_support',
                share_type.get('extra_specs', {}).get(
                    'mount_snapshot_support')
            ),
            'share_proto': kwargs.get('share_proto', share.get('share_proto')),
            'share_type_id': share_type['id'],
            'is_public': kwargs.get('is_public', share.get('is_public')),
            'share_group_id': kwargs.get(
                'share_group_id', share.get('share_group_id')),
            'source_share_group_snapshot_member_id': kwargs.get(
                'source_share_group_snapshot_member_id',
                share.get('source_share_group_snapshot_member_id')),
            'snapshot_id': kwargs.get('snapshot_id', share.get('snapshot_id')),
        }
        share_instance_properties = {
            'availability_zone_id': kwargs.get(
                'availability_zone_id',
                share_instance.get('availability_zone_id')),
            'share_network_id': kwargs.get(
                'share_network_id', share_instance.get('share_network_id')),
            'share_server_id': kwargs.get(
                'share_server_id', share_instance.get('share_server_id')),
            'share_id': kwargs.get('share_id', share_instance.get('share_id')),
            'host': kwargs.get('host', share_instance.get('host')),
            'status': kwargs.get('status', share_instance.get('status')),
        }

        request_spec = {
            'share_properties': share_properties,
            'share_instance_properties': share_instance_properties,
            'share_type': share_type,
            'share_id': share.get('id'),
        }
        return request_spec

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

    def manage_snapshot(self, context, snapshot_data, driver_options):
        try:
            share = self.db.share_get(context, snapshot_data['share_id'])
        except exception.NotFound:
            raise exception.ShareNotFound(share_id=snapshot_data['share_id'])

        if share['has_replicas']:
            msg = (_("Share %s has replicas. Snapshots of this share cannot "
                     "currently be managed until all replicas are removed.")
                   % share['id'])
            raise exception.InvalidShare(reason=msg)

        existing_snapshots = self.db.share_snapshot_get_all_for_share(
            context, snapshot_data['share_id'])

        for existing_snap in existing_snapshots:
            for inst in existing_snap.get('instances'):
                if (snapshot_data['provider_location'] ==
                        inst['provider_location']):
                    msg = _("A share snapshot %(share_snapshot_id)s is "
                            "already managed for provider location "
                            "%(provider_location)s.") % {
                        'share_snapshot_id': existing_snap['id'],
                        'provider_location':
                            snapshot_data['provider_location'],
                    }
                    raise exception.ManageInvalidShareSnapshot(
                        reason=msg)

        snapshot_data.update({
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_MANAGING,
            'share_size': share['size'],
            'progress': '0%',
            'share_proto': share['share_proto']
        })

        snapshot = self.db.share_snapshot_create(context, snapshot_data)

        self.share_rpcapi.manage_snapshot(context, snapshot, share['host'],
                                          driver_options)
        return snapshot

    def unmanage_snapshot(self, context, snapshot, host):
        update_data = {'status': constants.STATUS_UNMANAGING,
                       'terminated_at': timeutils.utcnow()}
        snapshot_ref = self.db.share_snapshot_update(context,
                                                     snapshot['id'],
                                                     update_data)

        self.share_rpcapi.unmanage_snapshot(context, snapshot_ref, host)

    def revert_to_snapshot(self, context, share, snapshot):
        """Revert a share to a snapshot."""

        reservations = self._handle_revert_to_snapshot_quotas(
            context, share, snapshot)

        try:
            if share.get('has_replicas'):
                self._revert_to_replicated_snapshot(
                    context, share, snapshot, reservations)
            else:
                self._revert_to_snapshot(
                    context, share, snapshot, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                if reservations:
                    QUOTAS.rollback(
                        context, reservations,
                        share_type_id=share['instance']['share_type_id'])

    def _handle_revert_to_snapshot_quotas(self, context, share, snapshot):
        """Reserve extra quota if a revert will result in a larger share."""

        # Note(cknight): This value may be positive or negative.
        size_increase = snapshot['size'] - share['size']
        if not size_increase:
            return None

        try:
            return QUOTAS.reserve(
                context,
                project_id=share['project_id'],
                gigabytes=size_increase,
                user_id=share['user_id'],
                share_type_id=share['instance']['share_type_id'])
        except exception.OverQuota as exc:
            usages = exc.kwargs['usages']
            quotas = exc.kwargs['quotas']
            consumed_gb = (usages['gigabytes']['reserved'] +
                           usages['gigabytes']['in_use'])

            msg = _("Quota exceeded for %(s_pid)s. Reverting share "
                    "%(s_sid)s to snapshot %(s_ssid)s will increase the "
                    "share's size by %(s_size)sG, "
                    "(%(d_consumed)dG of %(d_quota)dG already consumed).")
            msg_args = {
                's_pid': context.project_id,
                's_sid': share['id'],
                's_ssid': snapshot['id'],
                's_size': size_increase,
                'd_consumed': consumed_gb,
                'd_quota': quotas['gigabytes'],
            }
            message = msg % msg_args
            LOG.error(message)
            raise exception.ShareSizeExceedsAvailableQuota(message=message)

    def _revert_to_snapshot(self, context, share, snapshot, reservations):
        """Revert a non-replicated share to a snapshot."""

        # Set status of share to 'reverting'
        self.db.share_update(
            context, snapshot['share_id'],
            {'status': constants.STATUS_REVERTING})

        # Set status of snapshot to 'restoring'
        self.db.share_snapshot_update(
            context, snapshot['id'],
            {'status': constants.STATUS_RESTORING})

        # Send revert API to share host
        self.share_rpcapi.revert_to_snapshot(
            context, share, snapshot, share['instance']['host'], reservations)

    def _revert_to_replicated_snapshot(self, context, share, snapshot,
                                       reservations):
        """Revert a replicated share to a snapshot."""

        # Get active replica
        active_replica = self.db.share_replicas_get_available_active_replica(
            context, share['id'])

        if not active_replica:
            msg = _('Share %s has no active replica in available state.')
            raise exception.ReplicationException(reason=msg % share['id'])

        # Get snapshot instance on active replica
        snapshot_instance_filters = {
            'share_instance_ids': active_replica['id'],
            'snapshot_ids': snapshot['id'],
        }
        snapshot_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, snapshot_instance_filters))
        active_snapshot_instance = (
            snapshot_instances[0] if snapshot_instances else None)

        if not active_snapshot_instance:
            msg = _('Share %(share)s has no snapshot %(snap)s associated with '
                    'its active replica.')
            msg_args = {'share': share['id'], 'snap': snapshot['id']}
            raise exception.ReplicationException(reason=msg % msg_args)

        # Set active replica to 'reverting'
        self.db.share_replica_update(
            context, active_replica['id'],
            {'status': constants.STATUS_REVERTING})

        # Set snapshot instance on active replica to 'restoring'
        self.db.share_snapshot_instance_update(
            context, active_snapshot_instance['id'],
            {'status': constants.STATUS_RESTORING})

        # Send revert API to active replica host
        self.share_rpcapi.revert_to_snapshot(
            context, share, snapshot, active_replica['host'], reservations)

    @policy.wrap_check_policy('share')
    def delete(self, context, share, force=False):
        """Delete share."""
        share = self.db.share_get(context, share['id'])
        share_id = share['id']
        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR,
                    constants.STATUS_INACTIVE)
        if not (force or share['status'] in statuses):
            msg = _("Share status must be one of %(statuses)s") % {
                "statuses": statuses}
            raise exception.InvalidShare(reason=msg)

        # NOTE(gouthamr): If the share has more than one replica,
        # it can't be deleted until the additional replicas are removed.
        if share.has_replicas:
            msg = _("Share %s has replicas. Remove the replicas before "
                    "deleting the share.") % share_id
            raise exception.Conflict(err=msg)

        snapshots = self.db.share_snapshot_get_all_for_share(context, share_id)
        if len(snapshots):
            msg = _("Share still has %d dependent snapshots.") % len(snapshots)
            raise exception.InvalidShare(reason=msg)

        share_group_snapshot_members_count = (
            self.db.count_share_group_snapshot_members_in_share(
                context, share_id))
        if share_group_snapshot_members_count:
            msg = (
                _("Share still has %d dependent share group snapshot "
                  "members.") % share_group_snapshot_members_count)
            raise exception.InvalidShare(reason=msg)

        self._check_is_share_busy(share)
        for share_instance in share.instances:
            if share_instance['host']:
                self.delete_instance(context, share_instance, force=force)
            else:
                self.db.share_instance_delete(
                    context, share_instance['id'], need_to_update_usages=True)

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

        self.share_rpcapi.delete_share_instance(context, share_instance,
                                                force=force)

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

        share_groups = self.db.share_group_get_all_by_share_server(
            context, server['id'])
        if share_groups:
            LOG.error("share server '%(ssid)s' in use by share groups.",
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
                context, snapshots=1, snapshot_gigabytes=size,
                share_type_id=share['instance']['share_type_id'])
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'snapshot_gigabytes' in overs:
                msg = ("Quota exceeded for %(s_pid)s, tried to create "
                       "%(s_size)sG snapshot (%(d_consumed)dG of "
                       "%(d_quota)dG already consumed).")
                LOG.warning(msg, {'s_pid': context.project_id,
                                  's_size': size,
                                  'd_consumed': _consumed('gigabytes'),
                                  'd_quota': quotas['snapshot_gigabytes']})
                raise exception.SnapshotSizeExceedsAvailableQuota()
            elif 'snapshots' in overs:
                msg = ("Quota exceeded for %(s_pid)s, tried to create "
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
            QUOTAS.commit(
                context, reservations,
                share_type_id=share['instance']['share_type_id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    self.db.snapshot_delete(context, share['id'])
                finally:
                    QUOTAS.rollback(
                        context, reservations,
                        share_type_id=share['instance']['share_type_id'])

        # If replicated share, create snapshot instances for each replica
        if share.get('has_replicas'):
            snapshot = self.db.share_snapshot_get(context, snapshot['id'])
            share_instance_id = snapshot['instance']['share_instance_id']
            replicas = self.db.share_replicas_get_all_by_share(
                context, share['id'])
            replicas = [r for r in replicas if r['id'] != share_instance_id]
            snapshot_instance = {
                'status': constants.STATUS_CREATING,
                'progress': '0%',
            }
            for replica in replicas:
                snapshot_instance.update({'share_instance_id': replica['id']})
                self.db.share_snapshot_instance_create(
                    context, snapshot['id'], snapshot_instance)
            self.share_rpcapi.create_replicated_snapshot(
                context, share, snapshot)

        else:
            self.share_rpcapi.create_snapshot(context, share, snapshot)

        return snapshot

    def migration_start(
            self, context, share, dest_host, force_host_assisted_migration,
            preserve_metadata, writable, nondisruptive, preserve_snapshots,
            new_share_network=None, new_share_type=None):
        """Migrates share to a new host."""

        if force_host_assisted_migration and (
                preserve_metadata or writable or nondisruptive or
                preserve_snapshots):
            msg = _('Invalid parameter combination. Cannot set parameters '
                    '"nondisruptive", "writable", "preserve_snapshots" or '
                    '"preserve_metadata" to True when enabling the '
                    '"force_host_assisted_migration" option.')
            LOG.error(msg)
            raise exception.InvalidInput(reason=msg)

        share_instance = share.instance

        # NOTE(gouthamr): Ensure share does not have replicas.
        # Currently share migrations are disallowed for replicated shares.
        if share.has_replicas:
            msg = _('Share %s has replicas. Remove the replicas before '
                    'attempting to migrate the share.') % share['id']
            LOG.error(msg)
            raise exception.Conflict(err=msg)

        # TODO(ganso): We do not support migrating shares in or out of groups
        # for now.
        if share.get('share_group_id'):
            msg = _('Share %s is a member of a group. This operation is not '
                    'currently supported for shares that are members of '
                    'groups.') % share['id']
            LOG.error(msg)
            raise exception.InvalidShare(reason=msg)

        # We only handle "available" share for now
        if share_instance['status'] != constants.STATUS_AVAILABLE:
            msg = _('Share instance %(instance_id)s status must be available, '
                    'but current status is: %(instance_status)s.') % {
                'instance_id': share_instance['id'],
                'instance_status': share_instance['status']}
            raise exception.InvalidShare(reason=msg)

        # Access rules status must not be error
        if share_instance['access_rules_status'] == constants.STATUS_ERROR:
            msg = _('Share instance %(instance_id)s access rules status must '
                    'not be in %(error)s when attempting to start a '
                    'migration.') % {
                'instance_id': share_instance['id'],
                'error': constants.STATUS_ERROR}
            raise exception.InvalidShare(reason=msg)

        self._check_is_share_busy(share)

        if force_host_assisted_migration:
            # We only handle shares without snapshots for
            # host-assisted migration
            snaps = self.db.share_snapshot_get_all_for_share(context,
                                                             share['id'])
            if snaps:
                msg = _("Share %s must not have snapshots when using "
                        "host-assisted migration.") % share['id']
                raise exception.Conflict(err=msg)

        dest_host_host = share_utils.extract_host(dest_host)

        # Make sure the host is in the list of available hosts
        utils.validate_service_host(context, dest_host_host)

        if new_share_type:
            share_type = new_share_type
            new_share_type_id = new_share_type['id']
            dhss = share_type['extra_specs']['driver_handles_share_servers']
            dhss = strutils.bool_from_string(dhss, strict=True)
            if (dhss and not new_share_network and
                    not share_instance['share_network_id']):
                msg = _(
                    "New share network must be provided when share type of"
                    " given share %s has extra_spec "
                    "'driver_handles_share_servers' as True.") % share['id']
                raise exception.InvalidInput(reason=msg)
        else:
            share_type = {}
            share_type_id = share_instance['share_type_id']
            if share_type_id:
                share_type = share_types.get_share_type(context, share_type_id)
            new_share_type_id = share_instance['share_type_id']

        dhss = share_type['extra_specs']['driver_handles_share_servers']
        dhss = strutils.bool_from_string(dhss, strict=True)

        if dhss:
            if new_share_network:
                new_share_network_id = new_share_network['id']
            else:
                new_share_network_id = share_instance['share_network_id']
        else:
            if new_share_network:
                msg = _(
                    "New share network must not be provided when share type of"
                    " given share %s has extra_spec "
                    "'driver_handles_share_servers' as False.") % share['id']
                raise exception.InvalidInput(reason=msg)

            new_share_network_id = None

        # Make sure the destination is different than the source
        if (new_share_network_id == share_instance['share_network_id'] and
                new_share_type_id == share_instance['share_type_id'] and
                dest_host == share_instance['host']):
            msg = ("Destination host (%(dest_host)s), share network "
                   "(%(dest_sn)s) or share type (%(dest_st)s) are the same "
                   "as the current host's '%(src_host)s', '%(src_sn)s' and "
                   "'%(src_st)s' respectively. Nothing to be done.") % {
                       'dest_host': dest_host,
                       'dest_sn': new_share_network_id,
                       'dest_st': new_share_type_id,
                       'src_host': share_instance['host'],
                       'src_sn': share_instance['share_network_id'],
                       'src_st': share_instance['share_type_id'],
                       }
            LOG.info(msg)
            self.db.share_update(
                context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_SUCCESS})
            return 200

        service = self.db.service_get_by_args(
            context, dest_host_host, 'manila-share')

        request_spec = self._get_request_spec_dict(
            share,
            share_type,
            availability_zone_id=service['availability_zone_id'],
            share_network_id=new_share_network_id)

        self.db.share_update(
            context, share['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_STARTING})

        self.db.share_instance_update(context, share_instance['id'],
                                      {'status': constants.STATUS_MIGRATING})

        self.scheduler_rpcapi.migrate_share_to_host(
            context, share['id'], dest_host, force_host_assisted_migration,
            preserve_metadata, writable, nondisruptive, preserve_snapshots,
            new_share_network_id, new_share_type_id, request_spec)

        return 202

    def migration_complete(self, context, share):

        if share['task_state'] not in (
                constants.TASK_STATE_DATA_COPYING_COMPLETED,
                constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE):
            msg = self._migration_validate_error_message(share)
            if msg is None:
                msg = _("First migration phase of share %s not completed"
                        " yet.") % share['id']
            LOG.error(msg)
            raise exception.InvalidShare(reason=msg)

        share_instance_id, new_share_instance_id = (
            self.get_migrating_instances(share))

        share_instance_ref = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        self.share_rpcapi.migration_complete(context, share_instance_ref,
                                             new_share_instance_id)

    def get_migrating_instances(self, share):

        share_instance_id = None
        new_share_instance_id = None

        for instance in share.instances:
            if instance['status'] == constants.STATUS_MIGRATING:
                share_instance_id = instance['id']
            if instance['status'] == constants.STATUS_MIGRATING_TO:
                new_share_instance_id = instance['id']

        if None in (share_instance_id, new_share_instance_id):
            msg = _("Share instances %(instance_id)s and "
                    "%(new_instance_id)s in inconsistent states, cannot"
                    " continue share migration for share %(share_id)s"
                    ".") % {'instance_id': share_instance_id,
                            'new_instance_id': new_share_instance_id,
                            'share_id': share['id']}
            raise exception.ShareMigrationFailed(reason=msg)

        return share_instance_id, new_share_instance_id

    def migration_get_progress(self, context, share):

        if share['task_state'] == (
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):

            share_instance_id, migrating_instance_id = (
                self.get_migrating_instances(share))

            share_instance_ref = self.db.share_instance_get(
                context, share_instance_id, with_share_data=True)

            service_host = share_utils.extract_host(share_instance_ref['host'])

            service = self.db.service_get_by_args(
                context, service_host, 'manila-share')

            if utils.service_is_up(service):
                try:
                    result = self.share_rpcapi.migration_get_progress(
                        context, share_instance_ref, migrating_instance_id)
                except Exception:
                    msg = _("Failed to obtain migration progress of share "
                            "%s.") % share['id']
                    LOG.exception(msg)
                    raise exception.ShareMigrationError(reason=msg)
            else:
                result = None

        elif share['task_state'] == (
                constants.TASK_STATE_DATA_COPYING_IN_PROGRESS):
            data_rpc = data_rpcapi.DataAPI()
            LOG.info("Sending request to get share migration information"
                     " of share %s.", share['id'])

            services = self.db.service_get_all_by_topic(context, 'manila-data')

            if len(services) > 0 and utils.service_is_up(services[0]):

                try:
                    result = data_rpc.data_copy_get_progress(
                        context, share['id'])
                except Exception:
                    msg = _("Failed to obtain migration progress of share "
                            "%s.") % share['id']
                    LOG.exception(msg)
                    raise exception.ShareMigrationError(reason=msg)
            else:
                result = None
        else:
            result = self._migration_get_progress_state(share)

        if not (result and result.get('total_progress') is not None):
            msg = self._migration_validate_error_message(share)
            if msg is None:
                msg = _("Migration progress of share %s cannot be obtained at "
                        "this moment.") % share['id']
            LOG.error(msg)
            raise exception.InvalidShare(reason=msg)

        return result

    def _migration_get_progress_state(self, share):

        task_state = share['task_state']
        if task_state in (constants.TASK_STATE_MIGRATION_SUCCESS,
                          constants.TASK_STATE_DATA_COPYING_ERROR,
                          constants.TASK_STATE_MIGRATION_CANCELLED,
                          constants.TASK_STATE_MIGRATION_COMPLETING,
                          constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
                          constants.TASK_STATE_DATA_COPYING_COMPLETED,
                          constants.TASK_STATE_DATA_COPYING_COMPLETING,
                          constants.TASK_STATE_DATA_COPYING_CANCELLED,
                          constants.TASK_STATE_MIGRATION_ERROR):
            return {'total_progress': 100}
        elif task_state in (constants.TASK_STATE_MIGRATION_STARTING,
                            constants.TASK_STATE_MIGRATION_DRIVER_STARTING,
                            constants.TASK_STATE_DATA_COPYING_STARTING,
                            constants.TASK_STATE_MIGRATION_IN_PROGRESS):
            return {'total_progress': 0}
        else:
            return None

    def _migration_validate_error_message(self, share):

        task_state = share['task_state']
        if task_state == constants.TASK_STATE_MIGRATION_SUCCESS:
            msg = _("Migration of share %s has already "
                    "completed.") % share['id']
        elif task_state in (None, constants.TASK_STATE_MIGRATION_ERROR):
            msg = _("There is no migration being performed for share %s "
                    "at this moment.") % share['id']
        elif task_state == constants.TASK_STATE_MIGRATION_CANCELLED:
            msg = _("Migration of share %s was already "
                    "cancelled.") % share['id']
        elif task_state in (constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
                            constants.TASK_STATE_DATA_COPYING_COMPLETED):
            msg = _("Migration of share %s has already completed first "
                    "phase.") % share['id']
        else:
            return None
        return msg

    def migration_cancel(self, context, share):

        migrating = True
        if share['task_state'] in (
                constants.TASK_STATE_DATA_COPYING_COMPLETED,
                constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):

            share_instance_id, migrating_instance_id = (
                self.get_migrating_instances(share))

            share_instance_ref = self.db.share_instance_get(
                context, share_instance_id, with_share_data=True)

            service_host = share_utils.extract_host(share_instance_ref['host'])

            service = self.db.service_get_by_args(
                context, service_host, 'manila-share')

            if utils.service_is_up(service):
                    self.share_rpcapi.migration_cancel(
                        context, share_instance_ref, migrating_instance_id)
            else:
                migrating = False

        elif share['task_state'] == (
                constants.TASK_STATE_DATA_COPYING_IN_PROGRESS):

            data_rpc = data_rpcapi.DataAPI()
            LOG.info("Sending request to cancel migration of "
                     "share %s.", share['id'])

            services = self.db.service_get_all_by_topic(context, 'manila-data')

            if len(services) > 0 and utils.service_is_up(services[0]):
                try:
                    data_rpc.data_copy_cancel(context, share['id'])
                except Exception:
                    msg = _("Failed to cancel migration of share "
                            "%s.") % share['id']
                    LOG.exception(msg)
                    raise exception.ShareMigrationError(reason=msg)
            else:
                migrating = False

        else:
            migrating = False

        if not migrating:
            msg = self._migration_validate_error_message(share)
            if msg is None:
                msg = _("Migration of share %s cannot be cancelled at this "
                        "moment.") % share['id']
            LOG.error(msg)
            raise exception.InvalidShare(reason=msg)

    @policy.wrap_check_policy('share')
    def delete_snapshot(self, context, snapshot, force=False):
        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
        if not (force or snapshot['aggregate_status'] in statuses):
            msg = _("Share Snapshot status must be one of %(statuses)s.") % {
                "statuses": statuses}
            raise exception.InvalidShareSnapshot(reason=msg)

        share = self.db.share_get(context, snapshot['share_id'])

        snapshot_instances = (
            self.db.share_snapshot_instance_get_all_with_filters(
                context, {'snapshot_ids': snapshot['id']})
        )

        for snapshot_instance in snapshot_instances:
            self.db.share_snapshot_instance_update(
                context, snapshot_instance['id'],
                {'status': constants.STATUS_DELETING})

        if share['has_replicas']:
            self.share_rpcapi.delete_replicated_snapshot(
                context, snapshot, share['instance']['host'],
                share_id=share['id'], force=force)
        else:
            self.share_rpcapi.delete_snapshot(
                context, snapshot, share['instance']['host'], force=force)

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

        LOG.debug("Searching for shares by: %s", search_opts)

        # Prepare filters
        filters = {}
        if 'export_location_id' in search_opts:
            filters['export_location_id'] = search_opts.pop(
                'export_location_id')
        if 'export_location_path' in search_opts:
            filters['export_location_path'] = search_opts.pop(
                'export_location_path')
        if 'metadata' in search_opts:
            filters['metadata'] = search_opts.pop('metadata')
            if not isinstance(filters['metadata'], dict):
                msg = _("Wrong metadata filter provided: "
                        "%s.") % six.text_type(filters['metadata'])
                raise exception.InvalidInput(reason=msg)
        if 'extra_specs' in search_opts:
            # Verify policy for extra-specs access
            policy.check_policy(context, 'share_types_extra_spec', 'index')
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
        if 'host' in search_opts:
            policy.check_policy(context, 'share', 'list_by_host')
        if 'share_server_id' in search_opts:
            # NOTE(vponomaryov): this is project_id independent
            policy.check_policy(context, 'share', 'list_by_share_server_id')
            shares = self.db.share_get_all_by_share_server(
                context, search_opts.pop('share_server_id'), filters=filters,
                sort_key=sort_key, sort_dir=sort_dir)
        elif (context.is_admin and utils.is_all_tenants(search_opts)):
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
                if (all(s.get(k, None) == v or (v in (s.get(k.rstrip('~'))
                        if k.endswith('~') and s.get(k.rstrip('~')) else ()))
                        for k, v in search_opts.items())):
                    results.append(s)
            shares = results
        return shares

    def get_snapshot(self, context, snapshot_id):
        policy.check_policy(context, 'share_snapshot', 'get_snapshot')
        return self.db.share_snapshot_get(context, snapshot_id)

    def get_all_snapshots(self, context, search_opts=None,
                          sort_key='share_id', sort_dir='desc'):
        policy.check_policy(context, 'share_snapshot', 'get_all_snapshots')

        search_opts = search_opts or {}
        LOG.debug("Searching for snapshots by: %s", search_opts)

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
                if (all(snapshot.get(k, not_found) == v or
                        (v in snapshot.get(k.rstrip('~'))
                        if k.endswith('~') and
                        snapshot.get(k.rstrip('~')) else ())
                        for k, v in search_opts.items())):
                    results.append(snapshot)
            snapshots = results
        return snapshots

    def get_latest_snapshot_for_share(self, context, share_id):
        """Get the newest snapshot of a share."""
        return self.db.share_snapshot_get_latest_for_share(context, share_id)

    @staticmethod
    def _is_invalid_share_instance(instance):
        return (instance['host'] is None
                or instance['status'] in constants.
                INVALID_SHARE_INSTANCE_STATUSES_FOR_ACCESS_RULE_UPDATES)

    def allow_access(self, ctx, share, access_type, access_to,
                     access_level=None):
        """Allow access to share."""

        # Access rule validation:
        if access_level not in constants.ACCESS_LEVELS + (None, ):
            msg = _("Invalid share access level: %s.") % access_level
            raise exception.InvalidShareAccess(reason=msg)

        access_exists = self.db.share_access_check_for_existing_access(
            ctx, share['id'], access_type, access_to)

        if access_exists:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access_to)

        # Share instance validation
        if any(instance for instance in share.instances
               if self._is_invalid_share_instance(instance)):
            msg = _("New access rules cannot be applied while the share or "
                    "any of its replicas or migration copies lacks a valid "
                    "host or is in an invalid state.")
            raise exception.InvalidShare(message=msg)

        values = {
            'share_id': share['id'],
            'access_type': access_type,
            'access_to': access_to,
            'access_level': access_level,
        }

        access = self.db.share_access_create(ctx, values)

        for share_instance in share.instances:
            self.allow_access_to_instance(ctx, share_instance)

        return access

    def allow_access_to_instance(self, context, share_instance):
        self._conditionally_transition_share_instance_access_rules_status(
            context, share_instance)
        self.share_rpcapi.update_access(context, share_instance)

    def _conditionally_transition_share_instance_access_rules_status(
            self, context, share_instance):
        conditionally_change = {
            constants.STATUS_ACTIVE: constants.SHARE_INSTANCE_RULES_SYNCING,
        }
        self.access_helper.get_and_update_share_instance_access_rules_status(
            context, conditionally_change=conditionally_change,
            share_instance_id=share_instance['id'])

    def deny_access(self, ctx, share, access):
        """Deny access to share."""

        if any(instance for instance in share.instances if
               self._is_invalid_share_instance(instance)):
            msg = _("Access rules cannot be denied while the share, "
                    "any of its replicas or migration copies lacks a valid "
                    "host or is in an invalid state.")
            raise exception.InvalidShare(message=msg)

        for share_instance in share.instances:
                self.deny_access_to_instance(ctx, share_instance, access)

    def deny_access_to_instance(self, context, share_instance, access):
        self._conditionally_transition_share_instance_access_rules_status(
            context, share_instance)
        updates = {'state': constants.ACCESS_STATE_QUEUED_TO_DENY}
        self.access_helper.get_and_update_share_instance_access_rule(
            context, access['id'], updates=updates,
            share_instance_id=share_instance['id'])

        self.share_rpcapi.update_access(context, share_instance)

    def access_get_all(self, context, share):
        """Returns all access rules for share."""
        policy.check_policy(context, 'share', 'access_get_all')
        rules = self.db.share_access_get_all_for_share(context, share['id'])
        return rules

    def access_get(self, context, access_id):
        """Returns access rule with the id."""
        policy.check_policy(context, 'share', 'access_get')
        rule = self.db.share_access_get(context, access_id)
        return rule

    @policy.wrap_check_policy('share')
    def get_share_metadata(self, context, share):
        """Get all metadata associated with a share."""
        rv = self.db.share_metadata_get(context, share['id'])
        return dict(rv.items())

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

        for k, v in metadata.items():
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
            # we give the user_id of the share, to update the quota usage
            # for the user, who created the share, because on share delete
            # only this quota will be decreased
            reservations = QUOTAS.reserve(
                context,
                project_id=share['project_id'],
                gigabytes=size_increase,
                user_id=share['user_id'],
                share_type_id=share['instance']['share_type_id'])
        except exception.OverQuota as exc:
            usages = exc.kwargs['usages']
            quotas = exc.kwargs['quotas']

            def _consumed(name):
                return usages[name]['reserved'] + usages[name]['in_use']

            msg = ("Quota exceeded for %(s_pid)s, tried to extend share "
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
        LOG.info("Extend share request issued successfully.",
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
        LOG.info("Shrink share (id=%(id)s) request issued successfully."
                 " New size: %(size)s", {'id': share['id'],
                                         'size': new_size})

    def snapshot_allow_access(self, context, snapshot, access_type, access_to):
        """Allow access to a share snapshot."""
        access_exists = self.db.share_snapshot_check_for_existing_access(
            context, snapshot['id'], access_type, access_to)

        if access_exists:
            raise exception.ShareSnapshotAccessExists(access_type=access_type,
                                                      access=access_to)

        values = {
            'share_snapshot_id': snapshot['id'],
            'access_type': access_type,
            'access_to': access_to,
        }

        if any((instance['status'] != constants.STATUS_AVAILABLE) or
               (instance['share_instance']['host'] is None)
               for instance in snapshot.instances):
            msg = _("New access rules cannot be applied while the snapshot or "
                    "any of its replicas or migration copies lacks a valid "
                    "host or is not in %s state.") % constants.STATUS_AVAILABLE

            raise exception.InvalidShareSnapshotInstance(reason=msg)

        access = self.db.share_snapshot_access_create(context, values)

        for snapshot_instance in snapshot.instances:
            self.share_rpcapi.snapshot_update_access(
                context, snapshot_instance)

        return access

    def snapshot_deny_access(self, context, snapshot, access):
        """Deny access to a share snapshot."""
        if any((instance['status'] != constants.STATUS_AVAILABLE) or
               (instance['share_instance']['host'] is None)
               for instance in snapshot.instances):
            msg = _("Access rules cannot be denied while the snapshot or "
                    "any of its replicas or migration copies lacks a valid "
                    "host or is not in %s state.") % constants.STATUS_AVAILABLE

            raise exception.InvalidShareSnapshotInstance(reason=msg)

        for snapshot_instance in snapshot.instances:
            rule = self.db.share_snapshot_instance_access_get(
                context, access['id'], snapshot_instance['id'])
            self.db.share_snapshot_instance_access_update(
                context, rule['access_id'], snapshot_instance['id'],
                {'state': constants.ACCESS_STATE_QUEUED_TO_DENY})
            self.share_rpcapi.snapshot_update_access(
                context, snapshot_instance)

    def snapshot_access_get_all(self, context, snapshot):
        """Returns all access rules for share snapshot."""
        rules = self.db.share_snapshot_access_get_all_for_share_snapshot(
            context, snapshot['id'], {})
        return rules

    def snapshot_access_get(self, context, access_id):
        """Returns snapshot access rule with the id."""
        rule = self.db.share_snapshot_access_get(context, access_id)
        return rule

    def snapshot_export_locations_get(self, context, snapshot):
        return self.db.share_snapshot_export_locations_get(context, snapshot)

    def snapshot_export_location_get(self, context, el_id):
        return self.db.share_snapshot_instance_export_location_get(context,
                                                                   el_id)
