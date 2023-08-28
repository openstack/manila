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
import functools
import json

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import strutils
from oslo_utils import timeutils
from oslo_utils import uuidutils

from manila.api import common as api_common
from manila.common import constants
from manila import context as manila_context
from manila import coordination
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
                     'If set to True, then scheduler will be used.'
                     'When enabling this option make sure that filter '
                     'CreateFromSnapshotFilter is enabled and to have hosts '
                     'reporting replication_domain option.'
                )
]

CONF = cfg.CONF
CONF.register_opts(share_api_opts)

LOG = log.getLogger(__name__)
GB = 1048576 * 1024
QUOTAS = quota.QUOTAS

AFFINITY_HINT = 'same_host'
ANTI_AFFINITY_HINT = 'different_host'
AFFINITY_KEY = "__affinity_same_host"
ANTI_AFFINITY_KEY = "__affinity_different_host"


def locked_security_service_update_operation(operation):
    """Lock decorator for security service operation.

    Takes a named lock prior to executing the operation. The lock is named with
    the ids of the security services.
    """

    def wrapped(*args, **kwargs):
        new_id = kwargs.get('new_security_service_id', '')
        current_id = kwargs.get('current_security_service_id', '')

        @coordination.synchronized(
            'locked-security-service-update-operation-%(new)s-%(curr)s' % {
                'new': new_id,
                'curr': current_id,
            })
        def locked_security_service_operation(*_args, **_kwargs):
            return operation(*_args, **_kwargs)
        return locked_security_service_operation(*args, **kwargs)

    return wrapped


def locked_share_server_update_allocations_operation(operation):
    """Lock decorator for share server update allocations operation.

    Takes a named lock prior to executing the operation. The lock is named with
    the ids of the share network and the region to be updated.
    """

    def wrapped(*args, **kwargs):
        az_id = kwargs.get('availability_zone_id')
        share_net_id = kwargs.get('share_network_id')

        @coordination.synchronized(
            'locked-share-server-update-allocations-operation-%(net)s-%(az)s'
            % {
                'net': share_net_id,
                'az': az_id,
            })
        def locked_share_server_allocations_operation(*_args, **_kwargs):
            return operation(*_args, **_kwargs)
        return locked_share_server_allocations_operation(*args, **kwargs)

    return wrapped


class API(base.Base):
    """API for interacting with the share manager."""

    def __init__(self, db_driver=None):
        super(API, self).__init__(db_driver)
        self.scheduler_rpcapi = scheduler_rpcapi.SchedulerAPI()
        self.share_rpcapi = share_rpcapi.ShareAPI()
        self.access_helper = access.ShareInstanceAccess(self.db, None)
        coordination.LOCK_COORDINATOR.start()

    def prevent_locked_action_on_share(arg):
        """Decorator for preventing a locked method from executing on a share.

        Add this decorator to any API method which takes a RequestContext
        object as a first  parameter and a share object as the second
        parameter.

        Can be used in any of the following forms
        @prevent_locked_action_on_share
        @prevent_locked_action_on_share('my_action_name')

        :param arg: Can either be the function being decorated or a str
        containing the 'action' that we need to check resource locks for.
        If no action name is provided, the function name is assumed to be
        the action name.
        """
        action_name = None

        def check_for_locks(f):
            @functools.wraps(f)
            def wrapper(self, context, share, *args, **kwargs):
                action = action_name or f.__name__
                resource_locks, __ = (
                    self.db.resource_lock_get_all(
                        context.elevated(),
                        filters={'resource_id': share['id'],
                                 'resource_action': action,
                                 'all_projects': True},
                    )
                )
                if resource_locks:
                    msg_payload = {
                        'locks': ', '.join(
                            [lock['id'] for lock in resource_locks]
                        ),
                        'action': action,
                    }
                    msg = (f"Resource lock/s [{msg_payload['locks']}] "
                           f"prevent {action} action.")
                    raise exception.InvalidShare(msg)
                return f(self, context, share, *args, **kwargs)
            return wrapper

        if callable(arg):
            return check_for_locks(arg)
        else:
            action_name = arg
            return check_for_locks

    def _get_all_availability_zones_with_subnets(self, context,
                                                 share_network_id):
        compatible_azs_name = []
        compatible_azs_multiple = {}
        for az in self.db.availability_zone_get_all(context):
            subnets = (
                self.db.share_network_subnets_get_all_by_availability_zone_id(
                    context, share_network_id=share_network_id,
                    availability_zone_id=az['id']))
            if subnets:
                compatible_azs_multiple[az['id']] = len(subnets) > 1
                compatible_azs_name.append(az['name'])
        return compatible_azs_name, compatible_azs_multiple

    @staticmethod
    def check_if_share_quotas_exceeded(context, quota_exception,
                                       share_size, operation='create'):
        overs = quota_exception.kwargs['overs']
        usages = quota_exception.kwargs['usages']
        quotas = quota_exception.kwargs['quotas']

        def _consumed(name):
            return (usages[name]['reserved'] + usages[name]['in_use'])

        if 'gigabytes' in overs:
            LOG.warning("Quota exceeded for %(s_pid)s, "
                        "tried to %(operation)s "
                        "%(s_size)sG share (%(d_consumed)dG of "
                        "%(d_quota)dG already consumed).", {
                            's_pid': context.project_id,
                            's_size': share_size,
                            'd_consumed': _consumed('gigabytes'),
                            'd_quota': quotas['gigabytes'],
                            'operation': operation})
            raise exception.ShareSizeExceedsAvailableQuota()
        elif 'shares' in overs:
            LOG.warning("Quota exceeded for %(s_pid)s, "
                        "tried to %(operation)s "
                        "share (%(d_consumed)d shares "
                        "already consumed).", {
                            's_pid': context.project_id,
                            'd_consumed': _consumed('shares'),
                            'operation': operation})
            raise exception.ShareLimitExceeded(allowed=quotas['shares'])

    @staticmethod
    def check_if_replica_quotas_exceeded(context, quota_exception,
                                         replica_size,
                                         resource_type='share_replica'):
        overs = quota_exception.kwargs['overs']
        usages = quota_exception.kwargs['usages']
        quotas = quota_exception.kwargs['quotas']

        def _consumed(name):
            return (usages[name]['reserved'] + usages[name]['in_use'])

        if 'share_replicas' in overs:
            LOG.warning("Quota exceeded for %(s_pid)s, "
                        "unable to create share-replica (%(d_consumed)d "
                        "of %(d_quota)d already consumed).", {
                            's_pid': context.project_id,
                            'd_consumed': _consumed('share_replicas'),
                            'd_quota': quotas['share_replicas']})
            exception_kwargs = {}
            if resource_type != 'share_replica':
                msg = _("Failed while creating a share with replication "
                        "support. Maximum number of allowed share-replicas "
                        "is exceeded.")
                exception_kwargs['message'] = msg
            raise exception.ShareReplicasLimitExceeded(**exception_kwargs)
        elif 'replica_gigabytes' in overs:
            LOG.warning("Quota exceeded for %(s_pid)s, "
                        "unable to create a share replica size of "
                        "%(s_size)sG (%(d_consumed)dG of "
                        "%(d_quota)dG already consumed).", {
                            's_pid': context.project_id,
                            's_size': replica_size,
                            'd_consumed': _consumed('replica_gigabytes'),
                            'd_quota': quotas['replica_gigabytes']})
            exception_kwargs = {}
            if resource_type != 'share_replica':
                msg = _("Failed while creating a share with replication "
                        "support. Requested share replica exceeds allowed "
                        "project/user or share type gigabytes quota.")
                exception_kwargs['message'] = msg
            raise exception.ShareReplicaSizeExceedsAvailableQuota(
                **exception_kwargs)

    def create(self, context, share_proto, size, name, description,
               snapshot_id=None, availability_zone=None, metadata=None,
               share_network_id=None, share_type=None, is_public=False,
               share_group_id=None, share_group_snapshot_member=None,
               availability_zones=None, scheduler_hints=None,
               az_request_multiple_subnet_support_map=None):
        """Create new share."""

        api_common.check_metadata_properties(metadata)

        if snapshot_id is not None:
            snapshot = self.get_snapshot(context, snapshot_id)
            if snapshot['aggregate_status'] != constants.STATUS_AVAILABLE:
                msg = _("status must be '%s'") % constants.STATUS_AVAILABLE
                raise exception.InvalidShareSnapshot(reason=msg)
            if not size:
                size = snapshot['size']
        else:
            snapshot = None

        if not strutils.is_int_like(size) or int(size) <= 0:
            msg = (_("Share size '%s' must be an integer and greater than 0")
                   % size)
            raise exception.InvalidInput(reason=msg)

        # make sure size has been convert to int.
        size = int(size)
        if snapshot and size < snapshot['size']:
            msg = (_("Share size '%s' must be equal or greater "
                     "than snapshot size") % size)
            raise exception.InvalidInput(reason=msg)

        # ensure we pass the share_type provisioning filter on size
        share_types.provision_filter_on_size(context, share_type, size)

        if snapshot is None:
            share_type_id = share_type['id'] if share_type else None
        else:
            source_share = self.db.share_get(context, snapshot['share_id'])
            source_share_az = source_share['instance']['availability_zone']
            if availability_zone is None:
                availability_zone = source_share_az
            elif (availability_zone != source_share_az
                  and not CONF.use_scheduler_creating_share_from_snapshot):
                LOG.error("The specified availability zone must be the same "
                          "as parent share when you have the configuration "
                          "option 'use_scheduler_creating_share_from_snapshot'"
                          " set to False.")
                msg = _("The specified availability zone must be the same "
                        "as the parent share when creating from snapshot.")
                raise exception.InvalidInput(reason=msg)
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

        self.check_is_share_size_within_per_share_quota_limit(context, size)

        deltas = {'shares': 1, 'gigabytes': size}
        share_type_attributes = self.get_share_attributes_from_share_type(
            share_type)
        share_type_supports_replication = share_type_attributes.get(
            'replication_type', None)
        if share_type_supports_replication:
            deltas.update(
                {'share_replicas': 1, 'replica_gigabytes': size})

        try:
            reservations = QUOTAS.reserve(
                context, share_type_id=share_type_id, **deltas)
        except exception.OverQuota as e:
            self.check_if_share_quotas_exceeded(context, e, size)
            if share_type_supports_replication:
                self.check_if_replica_quotas_exceeded(context, e, size,
                                                      resource_type='share')

        share_group = None
        if share_group_id:
            try:
                share_group = self.db.share_group_get(context, share_group_id)
            except exception.NotFound as e:
                raise exception.InvalidParameterValue(e.message)

            if (not share_group_snapshot_member and
                    not (share_group['status'] == constants.STATUS_AVAILABLE)):
                params = {
                    'avail': constants.STATUS_AVAILABLE,
                    'status': share_group['status'],
                }
                msg = _("Share group status must be %(avail)s, got "
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
        options.update(share_type_attributes)

        if share_group_snapshot_member:
            options['source_share_group_snapshot_member_id'] = (
                share_group_snapshot_member['id'])

        # NOTE(dviroel): If a target availability zone was not provided, the
        # scheduler will receive a list with all availability zones that
        # contains a subnet within the selected share network.
        if share_network_id and not availability_zone:
            compatible_azs_name, compatible_azs_multiple = (
                self._get_all_availability_zones_with_subnets(
                    context, share_network_id))
            if not availability_zones:
                availability_zones = compatible_azs_name
            else:
                availability_zones = (
                    [az for az in availability_zones
                     if az in compatible_azs_name])
            if not availability_zones:
                msg = _(
                    "The share network is not supported within any requested "
                    "availability zone. Check the share type's "
                    "'availability_zones' extra-spec and the availability "
                    "zones of the share network subnets")
                raise exception.InvalidInput(message=msg)
            if az_request_multiple_subnet_support_map:
                az_request_multiple_subnet_support_map.update(
                    compatible_azs_multiple)
            else:
                az_request_multiple_subnet_support_map = (
                    compatible_azs_multiple)

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

        self.save_scheduler_hints(context, share, scheduler_hints)

        host = None
        snapshot_host = None
        if snapshot:
            snapshot_host = snapshot['share']['instance']['host']
            if not CONF.use_scheduler_creating_share_from_snapshot:
                # Shares from snapshots with restriction - source host only.
                # It is common situation for different types of backends.
                host = snapshot['share']['instance']['host']

        if share_group and host is None:
            host = share_group['host']

        self.create_instance(
            context, share, share_network_id=share_network_id, host=host,
            availability_zone=availability_zone, share_group=share_group,
            share_group_snapshot_member=share_group_snapshot_member,
            share_type_id=share_type_id, availability_zones=availability_zones,
            snapshot_host=snapshot_host, scheduler_hints=scheduler_hints,
            az_request_multiple_subnet_support_map=(
                az_request_multiple_subnet_support_map))

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
                        share_type_id=None, availability_zones=None,
                        snapshot_host=None, scheduler_hints=None,
                        az_request_multiple_subnet_support_map=None):
        request_spec, share_instance = (
            self.create_share_instance_and_get_request_spec(
                context, share, availability_zone=availability_zone,
                share_group=share_group, host=host,
                share_network_id=share_network_id,
                share_type_id=share_type_id,
                availability_zones=availability_zones,
                snapshot_host=snapshot_host,
                az_request_multiple_subnet_support_map=(
                    az_request_multiple_subnet_support_map)))

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
                filter_properties={'scheduler_hints': scheduler_hints},
                snapshot_id=share['snapshot_id'],
            )
        else:
            # Create share instance from scratch or from snapshot could happen
            # on hosts other than the source host.
            self.scheduler_rpcapi.create_share_instance(
                context,
                request_spec=request_spec,
                filter_properties={'scheduler_hints': scheduler_hints},
            )

        return share_instance

    def create_share_instance_and_get_request_spec(
            self, context, share, availability_zone=None,
            share_group=None, host=None, share_network_id=None,
            share_type_id=None, cast_rules_to_readonly=False,
            availability_zones=None, snapshot_host=None,
            az_request_multiple_subnet_support_map=None):

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
            'snapshot_host': snapshot_host,
            'share_type': share_type,
            'share_group': share_group,
            'availability_zone_id': availability_zone_id,
            'availability_zones': availability_zones,
            'az_request_multiple_subnet_support_map': (
                az_request_multiple_subnet_support_map),
        }
        return request_spec, share_instance

    def create_share_replica(self, context, share, availability_zone=None,
                             share_network_id=None, scheduler_hints=None):

        parent_share_network_id = share.get('share_network_id')
        if (parent_share_network_id and share_network_id and
                parent_share_network_id != share_network_id):
            parent_security_services = (
                self.db.security_service_get_all_by_share_network(
                    context, parent_share_network_id))
            security_services = (
                self.db.security_service_get_all_by_share_network(
                    context, share_network_id))
            parent_ss = set([s['id'] for s in parent_security_services])
            ss = set([s['id'] for s in security_services])
            if ss != parent_ss:
                msg = _("Share and its replica can't be in "
                        "different authentication domains.")
                raise exception.InvalidInput(reason=msg)

        if not share.get('replication_type'):
            msg = _("Replication not supported for share %s.")
            raise exception.InvalidShare(message=msg % share['id'])

        if share.get('share_group_id'):
            msg = _("Replication not supported for shares in a group.")
            raise exception.InvalidShare(message=msg)

        if scheduler_hints:
            if ('only_host' not in scheduler_hints.keys() or len(
                    scheduler_hints) > 1):
                msg = _("Arg 'scheduler_hints' supports only 'only_host' key.")
                raise exception.InvalidInput(reason=msg)

        self._check_is_share_busy(share)

        active_replica = self.db.share_replicas_get_available_active_replica(
            context, share['id'])

        if not active_replica:
            msg = _("Share %s does not have any active replica in available "
                    "state.")
            raise exception.ReplicationException(reason=msg % share['id'])

        share_type = share_types.get_share_type(
            context, share.instance['share_type_id'])
        type_azs = share_type['extra_specs'].get('availability_zones', '')
        type_azs = [t for t in type_azs.split(',') if type_azs]
        if (availability_zone and type_azs and
                availability_zone not in type_azs):
            msg = _("Share replica cannot be created since the share type "
                    "%(type)s is not supported within the availability zone "
                    "chosen %(az)s.")
            type_name = '%s' % (share_type['name'] or '')
            type_id = '(ID: %s)' % share_type['id']
            payload = {'type': '%s%s' % (type_name, type_id),
                       'az': availability_zone}
            raise exception.InvalidShare(message=msg % payload)

        try:
            reservations = QUOTAS.reserve(
                context, share_replicas=1, replica_gigabytes=share['size'],
                share_type_id=share_type['id']
            )
        except exception.OverQuota as e:
            self.check_if_replica_quotas_exceeded(context, e, share['size'])

        az_request_multiple_subnet_support_map = {}
        if share_network_id:
            if availability_zone:
                try:
                    az = self.db.availability_zone_get(context,
                                                       availability_zone)
                except exception.AvailabilityZoneNotFound:
                    msg = _("Share replica cannot be created because the "
                            "specified availability zone does not exist.")
                    raise exception.InvalidInput(message=msg)
                az_id = az.get('id')
                subnets = (
                    self.db.
                    share_network_subnets_get_all_by_availability_zone_id(
                        context, share_network_id, az_id))
                if not subnets:
                    msg = _("Share replica cannot be created because the "
                            "share network is not available within the "
                            "specified availability zone.")
                    raise exception.InvalidShare(message=msg)
                az_request_multiple_subnet_support_map[az_id] = (
                    len(subnets) > 1)
            else:
                # NOTE(dviroel): If a target availability zone was not
                # provided, the scheduler will receive a list with all
                # availability zones that contains subnets within the
                # selected share network.
                compatible_azs_name, compatible_azs_multiple = (
                    self._get_all_availability_zones_with_subnets(
                        context, share_network_id))
                if not type_azs:
                    type_azs = compatible_azs_name
                else:
                    type_azs = (
                        [az for az in type_azs if az in compatible_azs_name])
                if not type_azs:
                    msg = _(
                        "The share network is not supported within any "
                        "requested  availability zone. Check the share type's "
                        "'availability_zones' extra-spec and the availability "
                        "zones of the share network subnets")
                    raise exception.InvalidInput(message=msg)
                az_request_multiple_subnet_support_map.update(
                    compatible_azs_multiple)

        if share['replication_type'] == constants.REPLICATION_TYPE_READABLE:
            cast_rules_to_readonly = True
        else:
            cast_rules_to_readonly = False

        try:
            request_spec, share_replica = (
                self.create_share_instance_and_get_request_spec(
                    context, share, availability_zone=availability_zone,
                    share_network_id=share_network_id,
                    share_type_id=share['instance']['share_type_id'],
                    cast_rules_to_readonly=cast_rules_to_readonly,
                    availability_zones=type_azs,
                    az_request_multiple_subnet_support_map=(
                        az_request_multiple_subnet_support_map))
            )
            QUOTAS.commit(
                context, reservations, project_id=share['project_id'],
                share_type_id=share_type['id'],
            )
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    self.db.share_replica_delete(
                        context, share_replica['id'],
                        need_to_update_usages=False)
                finally:
                    QUOTAS.rollback(
                        context, reservations, share_type_id=share_type['id'])

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
            context, request_spec=request_spec,
            filter_properties={'scheduler_hints': scheduler_hints})

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

    def promote_share_replica(self, context, share_replica,
                              quiesce_wait_time=None):

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

        self.share_rpcapi.promote_share_replica(
            context, share_replica,
            quiesce_wait_time=quiesce_wait_time)

        return self.db.share_replica_get(context, share_replica['id'])

    def update_share_replica(self, context, share_replica):

        if not share_replica['host']:
            msg = _("Share replica does not have a valid host.")
            raise exception.InvalidHost(reason=msg)

        self.share_rpcapi.update_share_replica(context, share_replica)

    def manage(self, context, share_data, driver_options):

        # Check whether there's a share already with the provided options:
        filters = {
            'export_location_path': share_data['export_location_path'],
            'host': share_data['host'],
        }
        share_server_id = share_data.get('share_server_id')
        if share_server_id:
            filters['share_server_id'] = share_data['share_server_id']

        already_managed = self.db.share_instances_get_all(context,
                                                          filters=filters)

        if already_managed:
            LOG.error("Found an existing share with export location %s!",
                      share_data['export_location_path'])
            msg = _("A share already exists with the export path specified.")
            raise exception.InvalidShare(reason=msg)

        share_type_id = share_data['share_type_id']
        share_type = share_types.get_share_type(context, share_type_id)

        dhss = share_types.parse_boolean_extra_spec(
            'driver_handles_share_servers',
            share_type['extra_specs']['driver_handles_share_servers'])

        if dhss and not share_server_id:
            msg = _("Share Server ID parameter is required when managing a "
                    "share using a share type with "
                    "driver_handles_share_servers extra-spec set to True.")
            raise exception.InvalidInput(reason=msg)
        if not dhss and share_server_id:
            msg = _("Share Server ID parameter is not expected when managing a"
                    " share using a share type with "
                    "driver_handles_share_servers extra-spec set to False.")
            raise exception.InvalidInput(reason=msg)

        if share_server_id:
            try:
                share_server = self.db.share_server_get(
                    context, share_data['share_server_id'])
            except exception.ShareServerNotFound:
                msg = _("Share Server specified was not found.")
                raise exception.InvalidInput(reason=msg)

            if share_server['status'] != constants.STATUS_ACTIVE:
                msg = _("The provided share server is not active.")
                raise exception.InvalidShareServer(reason=msg)
            share_data['share_network_id'] = (
                share_server['share_network_id'])

            try:
                share_network = self.db.share_network_get(
                    context, share_data['share_network_id'])
            except exception.ShareNetworkNotFound:
                msg = _("Share network %s was not found."
                        ) % share_data['share_network_id']
                raise exception.InvalidInput(reason=msg)
            # Check if share network is active, otherwise raise a BadRequest
            api_common.check_share_network_is_active(share_network)

        share_data.update({
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_MANAGING,
            'scheduled_at': timeutils.utcnow(),
        })
        share_data.update(
            self.get_share_attributes_from_share_type(share_type))

        share = self.db.share_create(context, share_data)

        export_location_path = share_data.pop('export_location_path')
        self.db.share_export_locations_update(context, share.instance['id'],
                                              export_location_path)

        request_spec = self._get_request_spec_dict(
            context, share, share_type, size=0,
            share_proto=share_data['share_proto'],
            host=share_data['host'])

        # NOTE(ganso): Scheduler is called to validate if share type
        # provided can fit in host provided. It will invoke manage upon
        # successful validation.
        self.scheduler_rpcapi.manage_share(context, share['id'],
                                           driver_options, request_spec)

        return self.db.share_get(context, share['id'])

    def _get_request_spec_dict(self, context, share, share_type, **kwargs):

        if share is None:
            share = {'instance': {}}

        # NOTE(dviroel): The share object can be a share instance object with
        # share data.
        share_instance = share.get('instance', share)

        share_properties = {
            'size': kwargs.get('size', share.get('size')),
            'user_id': kwargs.get('user_id', share.get('user_id')),
            'project_id': kwargs.get('project_id', share.get('project_id')),
            'metadata': self.db.share_metadata_get(
                context, share_instance.get('share_id')),
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

    @prevent_locked_action_on_share('delete')
    def unmanage(self, context, share):
        policy.check_policy(context, 'share', 'unmanage')

        self._check_is_share_busy(share)

        if share['status'] == constants.STATUS_MANAGE_ERROR:
            update_status = constants.STATUS_MANAGE_ERROR_UNMANAGING
        else:
            update_status = constants.STATUS_UNMANAGING

        update_data = {'status': update_status,
                       'terminated_at': timeutils.utcnow()}
        share_ref = self.db.share_update(context, share['id'], update_data)

        self.delete_scheduler_hints(context, share)
        self.share_rpcapi.unmanage_share(context, share_ref)

        # NOTE(u_glide): We should update 'updated_at' timestamp of
        # share server here, when manage/unmanage operations will be supported
        # for driver_handles_share_servers=True mode

    def manage_snapshot(self, context, snapshot_data, driver_options,
                        share=None):
        if not share:
            try:
                share = self.db.share_get(context, snapshot_data['share_id'])
            except exception.NotFound:
                raise exception.ShareNotFound(
                    share_id=snapshot_data['share_id'])

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
    @prevent_locked_action_on_share('delete')
    def soft_delete(self, context, share):
        """Soft delete share."""
        share_id = share['id']

        if share['is_soft_deleted']:
            msg = _("The share has been soft deleted already")
            raise exception.InvalidShare(reason=msg)

        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR,
                    constants.STATUS_INACTIVE)
        if share['status'] not in statuses:
            msg = _("Share status must be one of %(statuses)s") % {
                "statuses": statuses}
            raise exception.InvalidShare(reason=msg)

        # If the share has more than one replica,
        # it can't be soft deleted until the additional replicas are removed.
        if share.has_replicas:
            msg = _("Share %s has replicas. Remove the replicas before "
                    "soft deleting the share.") % share_id
            raise exception.Conflict(err=msg)

        snapshots = self.db.share_snapshot_get_all_for_share(context, share_id)
        if len(snapshots):
            msg = _("Share still has %d dependent snapshots.") % len(snapshots)
            raise exception.InvalidShare(reason=msg)

        filters = dict(share_id=share_id)
        backups = self.db.share_backups_get_all(context, filters=filters)
        if len(backups):
            msg = _("Share still has %d dependent backups.") % len(backups)
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
        self.db.share_soft_delete(context, share_id)

    @policy.wrap_check_policy('share')
    def restore(self, context, share):
        """Restore share."""
        share_id = share['id']
        self.db.share_restore(context, share_id)

    @policy.wrap_check_policy('share')
    @prevent_locked_action_on_share
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

        filters = dict(share_id=share_id)
        backups = self.db.share_backups_get_all(context, filters=filters)
        if len(backups):
            msg = _("Share still has %d dependent backups.") % len(backups)
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
        self.delete_scheduler_hints(context, share)

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
            msg = _("Share instance status must be  one of %(statuses)s") % {
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

    def manage_share_server(
            self, context, identifier, host, share_net_subnet, driver_opts):
        """Manage a share server."""

        try:
            matched_servers = self.db.share_server_search_by_identifier(
                context, identifier)
        except exception.ShareServerNotFound:
            pass
        else:
            msg = _("Identifier %(identifier)s specified matches existing "
                    "share servers: %(servers)s.") % {
                'identifier': identifier,
                'servers': ', '.join(s['identifier'] for s in matched_servers)
            }
            raise exception.InvalidInput(reason=msg)

        values = {
            'host': host,
            'share_network_subnets': [share_net_subnet],
            'status': constants.STATUS_MANAGING,
            'is_auto_deletable': False,
            'identifier': identifier,
        }

        server = self.db.share_server_create(context, values)

        self.share_rpcapi.manage_share_server(
            context, server, identifier, driver_opts)

        return self.db.share_server_get(context, server['id'])

    def unmanage_share_server(self, context, share_server, force=False):
        """Unmanage a share server."""

        shares = self.db.share_instances_get_all_by_share_server(
            context, share_server['id'])

        if shares:
            raise exception.ShareServerInUse(
                share_server_id=share_server['id'])

        share_groups = self.db.share_group_get_all_by_share_server(
            context, share_server['id'])
        if share_groups:
            LOG.error("share server '%(ssid)s' in use by share groups.",
                      {'ssid': share_server['id']})
            raise exception.ShareServerInUse(
                share_server_id=share_server['id'])

        update_data = {'status': constants.STATUS_UNMANAGING,
                       'terminated_at': timeutils.utcnow()}

        share_server = self.db.share_server_update(
            context, share_server['id'], update_data)

        self.share_rpcapi.unmanage_share_server(
            context, share_server, force=force)

    def transfer_accept(self, context, share, new_user,
                        new_project, clear_rules=False):
        self.share_rpcapi.transfer_accept(context, share,
                                          new_user, new_project,
                                          clear_rules=clear_rules)

    def create_snapshot(self, context, share, name, description,
                        force=False, metadata=None):
        policy.check_policy(context, 'share', 'create_snapshot', share)
        if metadata:
            api_common.check_metadata_properties(metadata)

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
                LOG.warning(msg, {
                    's_pid': context.project_id,
                    's_size': size,
                    'd_consumed': _consumed('snapshot_gigabytes'),
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
        if metadata:
            options.update({"metadata": metadata})

        try:
            snapshot = None
            snapshot = self.db.share_snapshot_create(context, options)
            QUOTAS.commit(
                context, reservations,
                share_type_id=share['instance']['share_type_id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    if snapshot and snapshot['instance']:
                        self.db.share_snapshot_instance_delete(
                            context, snapshot['instance']['id'])
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

    def _modify_quotas_for_share_migration(self, context, share,
                                           new_share_type):
        """Consume quotas for share migration.

        If a share migration was requested and a new share type was provided,
        quotas must be consumed from this share type. If no quotas are
        available for shares, gigabytes, share replicas or replica gigabytes,
        an error will be thrown.
        """

        new_share_type_id = new_share_type['id']

        if new_share_type_id == share['share_type_id']:
            return

        new_type_extra_specs = self.get_share_attributes_from_share_type(
            new_share_type)
        new_type_replication_type = new_type_extra_specs.get(
            'replication_type', None)

        deltas = {}

        # NOTE(carloss): If a new share type with a replication type was
        # specified, there is need to allocate quotas in the new share type.
        # We won't remove the current consumed quotas, since both share
        # instances will co-exist until the migration gets completed,
        # cancelled or it fails.
        if new_type_replication_type:
            deltas['share_replicas'] = 1
            deltas['replica_gigabytes'] = share['size']

        deltas.update({
            'share_type_id': new_share_type_id,
            'shares': 1,
            'gigabytes': share['size']
        })

        try:
            reservations = QUOTAS.reserve(
                context, project_id=share['project_id'],
                user_id=share['user_id'], **deltas)
            QUOTAS.commit(
                context, reservations, project_id=share['project_id'],
                user_id=share['user_id'], share_type_id=new_share_type_id)
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'replica_gigabytes' in overs:
                LOG.warning("Replica gigabytes quota exceeded "
                            "for %(s_pid)s, tried to migrate "
                            "%(s_size)sG share (%(d_consumed)dG of "
                            "%(d_quota)dG already consumed).", {
                                's_pid': context.project_id,
                                's_size': share['size'],
                                'd_consumed': _consumed(
                                    'replica_gigabytes'),
                                'd_quota': quotas['replica_gigabytes']})
                msg = _("Failed while migrating a share with replication "
                        "support. Maximum number of allowed "
                        "replica gigabytes is exceeded.")
                raise exception.ShareReplicaSizeExceedsAvailableQuota(
                    message=msg)

            if 'share_replicas' in overs:
                LOG.warning("Quota exceeded for %(s_pid)s, "
                            "unable to migrate share-replica (%(d_consumed)d "
                            "of %(d_quota)d already consumed).", {
                                's_pid': context.project_id,
                                'd_consumed': _consumed('share_replicas'),
                                'd_quota': quotas['share_replicas']})
                msg = _(
                    "Failed while migrating a share with replication "
                    "support. Maximum number of allowed share-replicas "
                    "is exceeded.")
                raise exception.ShareReplicasLimitExceeded(msg)

            if 'gigabytes' in overs:
                LOG.warning("Quota exceeded for %(s_pid)s, "
                            "tried to migrate "
                            "%(s_size)sG share (%(d_consumed)dG of "
                            "%(d_quota)dG already consumed).", {
                                's_pid': context.project_id,
                                's_size': share['size'],
                                'd_consumed': _consumed('gigabytes'),
                                'd_quota': quotas['gigabytes']})
                raise exception.ShareSizeExceedsAvailableQuota()
            if 'shares' in overs:
                LOG.warning("Quota exceeded for %(s_pid)s, "
                            "tried to migrate "
                            "share (%(d_consumed)d shares "
                            "already consumed).", {
                                's_pid': context.project_id,
                                'd_consumed': _consumed('shares')})
                raise exception.ShareLimitExceeded(allowed=quotas['shares'])

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
            # ensure pass the size limitations in the share type
            size = share['size']
            share_types.provision_filter_on_size(context, share_type, size)
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
            self._modify_quotas_for_share_migration(context, share,
                                                    new_share_type)
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

        type_azs = share_type['extra_specs'].get('availability_zones', '')
        type_azs = [t for t in type_azs.split(',') if type_azs]
        if type_azs and service['availability_zone']['name'] not in type_azs:
            msg = _("Share %(shr)s cannot be migrated to host %(dest)s "
                    "because share type %(type)s is not supported within the "
                    "availability zone (%(az)s) that the host is in.")
            type_name = '%s' % (share_type['name'] or '')
            type_id = '(ID: %s)' % share_type['id']
            payload = {'type': '%s%s' % (type_name, type_id),
                       'az': service['availability_zone']['name'],
                       'shr': share['id'],
                       'dest': dest_host}
            raise exception.InvalidShare(reason=msg % payload)

        request_spec = self._get_request_spec_dict(
            context,
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
                except exception.InvalidShare:
                    # reload to get the latest task_state
                    share = self.db.share_get(context, share['id'])
                    result = self._migration_get_progress_state(share)
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
                          constants.TASK_STATE_MIGRATION_CANCEL_IN_PROGRESS,
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

    def _migration_validate_error_message(self, resource,
                                          resource_type='share'):
        task_state = resource['task_state']
        if task_state == constants.TASK_STATE_MIGRATION_SUCCESS:
            msg = _("Migration of %(resource_type)s %(resource_id)s has "
                    "already completed.") % {
                'resource_id': resource['id'],
                'resource_type': resource_type}
        elif task_state in (None, constants.TASK_STATE_MIGRATION_ERROR):
            msg = _("There is no migration being performed for "
                    "%(resource_type)s %(resource_id)s at this moment.") % {
                'resource_id': resource['id'],
                'resource_type': resource_type}
        elif task_state == constants.TASK_STATE_MIGRATION_CANCELLED:
            msg = _("Migration of %(resource_type)s %(resource_id)s was "
                    "already cancelled.") % {
                'resource_id': resource['id'],
                'resource_type': resource_type}
        elif task_state in (constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
                            constants.TASK_STATE_DATA_COPYING_COMPLETED):
            msg = _("Migration of %(resource_type)s %(resource_id)s has "
                    "already completed first phase.") % {
                'resource_id': resource['id'],
                'resource_type': resource_type}
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
        return self.db.share_update(context, share['id'], fields)

    @policy.wrap_check_policy('share')
    def snapshot_update(self, context, snapshot, fields):
        return self.db.share_snapshot_update(context, snapshot['id'], fields)

    def get(self, context, share_id):
        rv = self.db.share_get(context, share_id)
        if not rv['is_public']:
            authorized = policy.check_policy(
                context, 'share', 'get', rv, do_raise=False)
            if not authorized:
                raise exception.NotFound()
        return rv

    def get_all(self, context, search_opts=None, sort_key='created_at',
                sort_dir='desc'):
        return self._get_all(context, search_opts=search_opts,
                             sort_key=sort_key, sort_dir=sort_dir)

    def get_all_with_count(self, context, search_opts=None,
                           sort_key='created_at', sort_dir='desc'):
        return self._get_all(context, search_opts=search_opts,
                             sort_key=sort_key, sort_dir=sort_dir,
                             show_count=True)

    def _get_all(self, context, search_opts=None, sort_key='created_at',
                 sort_dir='desc', show_count=False):
        policy.check_policy(context, 'share', 'get_all')

        if search_opts is None:
            search_opts = {}

        LOG.debug("Searching for shares by: %s", search_opts)

        # Prepare filters
        filters = {}

        filter_keys = [
            'display_name', 'share_group_id', 'display_name~',
            'display_description', 'display_description~', 'snapshot_id',
            'status', 'share_type_id', 'project_id', 'export_location_id',
            'export_location_path', 'limit', 'offset', 'host',
            'share_network_id', 'is_soft_deleted']

        for key in filter_keys:
            if key in search_opts:
                filters[key] = search_opts.pop(key)

        if 'metadata' in search_opts:
            filters['metadata'] = search_opts.pop('metadata')
            if not isinstance(filters['metadata'], dict):
                msg = _("Wrong metadata filter provided: "
                        "%s.") % filters['metadata']
                raise exception.InvalidInput(reason=msg)
        if 'extra_specs' in search_opts:
            # Verify policy for extra-specs access
            policy.check_policy(context, 'share_types_extra_spec', 'index')
            filters['extra_specs'] = search_opts.pop('extra_specs')
            if not isinstance(filters['extra_specs'], dict):
                msg = _("Wrong extra specs filter provided: "
                        "%s.") % filters['extra_specs']
                raise exception.InvalidInput(reason=msg)

        if not (isinstance(sort_key, str) and sort_key):
            msg = _("Wrong sort_key filter provided: "
                    "'%s'.") % sort_key
            raise exception.InvalidInput(reason=msg)
        if not (isinstance(sort_dir, str) and sort_dir):
            msg = _("Wrong sort_dir filter provided: "
                    "'%s'.") % sort_dir
            raise exception.InvalidInput(reason=msg)

        is_public = search_opts.pop('is_public', False)
        is_public = strutils.bool_from_string(is_public, strict=True)

        get_methods = {
            'get_by_share_server': (
                self.db.share_get_all_by_share_server_with_count
                if show_count else self.db.share_get_all_by_share_server),
            'get_all': (
                self.db.share_get_all_with_count
                if show_count else self.db.share_get_all),
            'get_all_by_project': (
                self.db.share_get_all_by_project_with_count
                if show_count else self.db.share_get_all_by_project)}

        # Get filtered list of shares
        if 'host' in filters:
            policy.check_policy(context, 'share', 'list_by_host')
        if 'share_server_id' in search_opts:
            # NOTE(vponomaryov): this is project_id independent
            policy.check_policy(context, 'share', 'list_by_share_server_id')
            result = get_methods['get_by_share_server'](
                context, search_opts.pop('share_server_id'), filters=filters,
                sort_key=sort_key, sort_dir=sort_dir)
        elif context.is_admin and utils.is_all_tenants(search_opts):
            result = get_methods['get_all'](
                context, filters=filters, sort_key=sort_key, sort_dir=sort_dir)
        else:
            result = get_methods['get_all_by_project'](
                context, project_id=context.project_id, filters=filters,
                is_public=is_public, sort_key=sort_key, sort_dir=sort_dir)

        if show_count:
            count = result[0]
            shares = result[1]
        else:
            shares = result

        result = (count, shares) if show_count else shares

        return result

    def get_snapshot(self, context, snapshot_id):
        policy.check_policy(context, 'share_snapshot', 'get_snapshot')
        return self.db.share_snapshot_get(context, snapshot_id)

    def get_all_snapshots(self, context, search_opts=None, limit=None,
                          offset=None, sort_key='share_id', sort_dir='desc'):
        return self._get_all_snapshots(context, search_opts=search_opts,
                                       limit=limit, offset=offset,
                                       sort_key=sort_key, sort_dir=sort_dir)

    def get_all_snapshots_with_count(self, context, search_opts=None,
                                     limit=None, offset=None,
                                     sort_key='share_id', sort_dir='desc'):
        return self._get_all_snapshots(context, search_opts=search_opts,
                                       limit=limit, offset=offset,
                                       sort_key=sort_key, sort_dir=sort_dir,
                                       show_count=True)

    def _get_all_snapshots(self, context, search_opts=None, limit=None,
                           offset=None, sort_key='share_id', sort_dir='desc',
                           show_count=False):
        policy.check_policy(context, 'share_snapshot', 'get_all_snapshots')

        search_opts = search_opts or {}
        LOG.debug("Searching for snapshots by: %s", search_opts)

        # Read and remove key 'all_tenants' if was provided
        all_tenants = search_opts.pop('all_tenants', None)

        string_args = {'sort_key': sort_key, 'sort_dir': sort_dir}
        string_args.update(search_opts)
        for k, v in string_args.items():
            if not (isinstance(v, str) and v) and k != 'metadata':
                msg = _("Wrong '%(k)s' filter provided: "
                        "'%(v)s'.") % {'k': k, 'v': string_args[k]}
                raise exception.InvalidInput(reason=msg)

        get_methods = {
            'get_all': (
                self.db.share_snapshot_get_all_with_count
                if show_count else self.db.share_snapshot_get_all),
            'get_all_by_project': (
                self.db.share_snapshot_get_all_by_project_with_count
                if show_count else self.db.share_snapshot_get_all_by_project)}

        if context.is_admin and all_tenants:
            result = get_methods['get_all'](
                context, filters=search_opts, limit=limit, offset=offset,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            result = get_methods['get_all_by_project'](
                context, context.project_id, filters=search_opts,
                limit=limit, offset=offset, sort_key=sort_key,
                sort_dir=sort_dir)

        if show_count:
            count = result[0]
            snapshots = result[1]
        else:
            snapshots = result

        result = (count, snapshots) if show_count else snapshots
        return result

    def get_latest_snapshot_for_share(self, context, share_id):
        """Get the newest snapshot of a share."""
        return self.db.share_snapshot_get_latest_for_share(context, share_id)

    @staticmethod
    def _any_invalid_share_instance(share, allow_on_error_state=False):
        invalid_states = (
            constants.INVALID_SHARE_INSTANCE_STATUSES_FOR_ACCESS_RULE_UPDATES)
        if not allow_on_error_state:
            invalid_states += (constants.STATUS_ERROR,)

        for instance in share.instances:
            if (not instance['host'] or instance['status'] in invalid_states):
                return True
        return False

    def allow_access(self, ctx, share, access_type, access_to,
                     access_level=None, metadata=None,
                     allow_on_error_state=False):
        """Allow access to share."""

        # Access rule validation:
        if access_level not in constants.ACCESS_LEVELS + (None, ):
            msg = _("Invalid share access level: %s.") % access_level
            raise exception.InvalidShareAccess(reason=msg)

        api_common.check_metadata_properties(metadata)
        access_exists = self.db.share_access_check_for_existing_access(
            ctx, share['id'], access_type, access_to)

        if access_exists:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access_to)

        if self._any_invalid_share_instance(share, allow_on_error_state):
            msg = _("New access rules cannot be applied while the share or "
                    "any of its replicas or migration copies lacks a valid "
                    "host or is in an invalid state.")
            raise exception.InvalidShare(message=msg)

        values = {
            'share_id': share['id'],
            'access_type': access_type,
            'access_to': access_to,
            'access_level': access_level,
            'metadata': metadata,
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

    def deny_access(self, ctx, share, access, allow_on_error_state=False):
        """Deny access to share."""

        if self._any_invalid_share_instance(share, allow_on_error_state):
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

    def access_get_all(self, context, share, filters=None):
        """Returns all access rules for share."""
        policy.check_policy(context, 'share', 'access_get_all')
        rules = self.db.share_access_get_all_for_share(
            context, share['id'], filters=filters)
        return rules

    def access_get(self, context, access_id):
        """Returns access rule with the id."""
        policy.check_policy(context, 'share', 'access_get')
        rule = self.db.share_access_get(context, access_id)
        # NOTE(gouthamr): Check if the caller has access to the share that
        # the rule belongs to:
        self.get(context, rule['share_id'])

        return rule

    def _validate_scheduler_hints(self, context, share, share_uuids):
        for uuid in share_uuids:
            if not uuidutils.is_uuid_like(uuid):
                raise exception.InvalidUUID(uuid=uuid)
            try:
                self.get(context, uuid)
            except (exception.NotFound, exception.PolicyNotAuthorized):
                raise exception.ShareNotFound(share_id=uuid)

    def _save_scheduler_hints(self, context, share, share_uuids, key):
        share_uuids = share_uuids.split(",")

        self._validate_scheduler_hints(context, share, share_uuids)
        val_uuids = None
        for uuid in share_uuids:
            try:
                result = self.db.share_metadata_get_item(context, uuid, key)
            except exception.MetadataItemNotFound:
                item = {key: share['id']}
            else:
                existing_uuids = result.get(key, "")
                item = {key:
                        ','.join(existing_uuids.split(',') + [share['id']])}
            self.db.share_metadata_update_item(context, uuid, item)
            if not val_uuids:
                val_uuids = uuid
            else:
                val_uuids = val_uuids + "," + uuid

        if val_uuids:
            item = {key: val_uuids}
            self.db.share_metadata_update_item(context, share['id'], item)

    def save_scheduler_hints(self, context, share, scheduler_hints=None):
        if scheduler_hints is None:
            return

        same_host_uuids = scheduler_hints.get(AFFINITY_HINT, None)
        different_host_uuids = scheduler_hints.get(ANTI_AFFINITY_HINT, None)

        if same_host_uuids:
            self._save_scheduler_hints(context, share, same_host_uuids,
                                       AFFINITY_KEY)
        if different_host_uuids:
            self._save_scheduler_hints(context, share, different_host_uuids,
                                       ANTI_AFFINITY_KEY)

    def _delete_scheduler_hints(self, context, share, key):
        try:
            result = self.db.share_metadata_get_item(context, share['id'],
                                                     key)
        except exception.MetadataItemNotFound:
            return

        share_uuids = result.get(key, "").split(",")
        for uuid in share_uuids:
            try:
                result = self.db.share_metadata_get_item(context, uuid, key)
            except exception.MetadataItemNotFound:
                continue

            new_val_uuids = [val_uuid for val_uuid
                             in result.get(key, "").split(",")
                             if val_uuid != share['id']]
            if not new_val_uuids:
                self.db.share_metadata_delete(context, uuid, key)
            else:
                item = {key: ','.join(new_val_uuids)}
                self.db.share_metadata_update_item(context, uuid, item)
        self.db.share_metadata_delete(context, share['id'], key)

    def delete_scheduler_hints(self, context, share):
        self._delete_scheduler_hints(context, share, AFFINITY_KEY)
        self._delete_scheduler_hints(context, share, ANTI_AFFINITY_KEY)

    def _check_is_share_busy(self, share):
        """Raises an exception if share is busy with an active task."""
        if share.is_busy:
            msg = _("Share %(share_id)s is busy as part of an active "
                    "task: %(task)s.") % {
                'share_id': share['id'],
                'task': share['task_state']
            }
            raise exception.ShareBusyException(reason=msg)

    @staticmethod
    def check_is_share_size_within_per_share_quota_limit(context, size):
        """Raises an exception if share size above per share quota limit."""
        try:
            values = {'per_share_gigabytes': size}
            QUOTAS.limit_check(context, project_id=context.project_id,
                               **values)
        except exception.OverQuota as e:
            quotas = e.kwargs['quotas']
            raise exception.ShareSizeExceedsLimit(
                size=size, limit=quotas['per_share_gigabytes'])

    def update_share_access_metadata(self, context, access_id, metadata):
        """Updates share access metadata."""
        try:
            api_common.check_metadata_properties(metadata)
        except exception.InvalidMetadata:
            raise exception.InvalidMetadata()
        except exception.InvalidMetadataSize:
            raise exception.InvalidMetadataSize()
        return self.db.share_access_metadata_update(
            context, access_id, metadata)

    def get_share_network(self, context, share_net_id):
        return self.db.share_network_get(context, share_net_id)

    def extend(self, context, share, new_size, force=False):
        if force:
            policy.check_policy(context, 'share', 'force_extend')
        else:
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

        self.check_is_share_size_within_per_share_quota_limit(context,
                                                              new_size)

        # ensure we pass the share_type provisioning filter on size
        try:
            share_type = share_types.get_share_type(
                context, share['instance']['share_type_id'])
        except (exception.InvalidShareType, exception.ShareTypeNotFound):
            share_type = None

        allowed_to_extend_past_max_share_size = policy.check_policy(
            context, 'share', constants.POLICY_EXTEND_BEYOND_MAX_SHARE_SIZE,
            target_obj=share, do_raise=False)
        if allowed_to_extend_past_max_share_size:
            share_types.provision_filter_on_size(context, share_type,
                                                 new_size,
                                                 operation='admin-extend')
        else:
            share_types.provision_filter_on_size(context, share_type,
                                                 new_size, operation='extend')

        replicas = self.db.share_replicas_get_all_by_share(
            context, share['id'])
        supports_replication = len(replicas) > 0

        deltas = {
            'project_id': share['project_id'],
            'gigabytes': size_increase,
            'user_id': share['user_id'],
            'share_type_id': share['instance']['share_type_id']
        }

        # NOTE(carloss): If the share type supports replication, we must get
        # all the replicas that pertain to the share and calculate the final
        # size (size to increase * amount of replicas), since all the replicas
        # are going to be extended when the driver sync them.
        if supports_replication:
            replica_gigs_to_increase = len(replicas) * size_increase
            deltas.update({'replica_gigabytes': replica_gigs_to_increase})

        try:
            # we give the user_id of the share, to update the quota usage
            # for the user, who created the share, because on share delete
            # only this quota will be decreased
            reservations = QUOTAS.reserve(context, **deltas)
        except exception.OverQuota as exc:
            # Check if the exceeded quota was 'gigabytes'
            self.check_if_share_quotas_exceeded(context, exc, share['size'],
                                                operation='extend')
            # NOTE(carloss): Check if the exceeded quota is
            # 'replica_gigabytes'. If so the failure could be caused due to
            # lack of quotas to extend the share's replicas, then the
            # 'check_if_replica_quotas_exceeded' method can't be reused here
            # since the error message must be different from the default one.
            if supports_replication:
                overs = exc.kwargs['overs']
                usages = exc.kwargs['usages']
                quotas = exc.kwargs['quotas']

                def _consumed(name):
                    return (usages[name]['reserved'] + usages[name]['in_use'])

                if 'replica_gigabytes' in overs:
                    LOG.warning("Replica gigabytes quota exceeded "
                                "for %(s_pid)s, tried to extend "
                                "%(s_size)sG share (%(d_consumed)dG of "
                                "%(d_quota)dG already consumed).", {
                                    's_pid': context.project_id,
                                    's_size': share['size'],
                                    'd_consumed': _consumed(
                                        'replica_gigabytes'),
                                    'd_quota': quotas['replica_gigabytes']})
                    msg = _("Failed while extending a share with replication "
                            "support. There is no available quota to extend "
                            "the share and its %(count)d replicas. Maximum "
                            "number of allowed replica_gigabytes is "
                            "exceeded.") % {'count': len(replicas)}
                    raise exception.ShareReplicaSizeExceedsAvailableQuota(
                        message=msg)

        self.update(context, share, {'status': constants.STATUS_EXTENDING})
        if force:
            self.share_rpcapi.extend_share(context, share,
                                           new_size, reservations)
        else:
            share_type = share_types.get_share_type(
                context, share['instance']['share_type_id'])
            request_spec = self._get_request_spec_dict(context, share,
                                                       share_type)
            request_spec.update({'is_share_extend': True})
            self.scheduler_rpcapi.extend_share(context, share['id'], new_size,
                                               reservations, request_spec)
        LOG.info("Extend share request issued successfully.",
                 resource=share)

    def shrink(self, context, share, new_size):
        policy.check_policy(context, 'share', 'shrink')

        status = str(share['status']).lower()
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

        # ensure we pass the share_type provisioning filter on size
        try:
            share_type = share_types.get_share_type(
                context, share['instance']['share_type_id'])
        except (exception.InvalidShareType, exception.ShareTypeNotFound):
            share_type = None
        share_types.provision_filter_on_size(context, share_type, new_size,
                                             operation='shrink')

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

    def share_server_migration_get_destination(self, context, source_server_id,
                                               status=None):
        filters = {'source_share_server_id': source_server_id}
        if status:
            filters.update({'status': status})

        dest_share_servers = self.db.share_server_get_all_with_filters(
            context, filters=filters)
        if not dest_share_servers:
            msg = _("A destination share server wasn't found for source "
                    "share server %s.") % source_server_id
            raise exception.InvalidShareServer(reason=msg)
        if len(dest_share_servers) > 1:
            msg = _("More than one destination share server was found for "
                    "source share server %s. Aborting...") % source_server_id
            raise exception.InvalidShareServer(reason=msg)

        return dest_share_servers[0]

    def get_share_server_migration_request_spec_dict(
            self, context, share_instances, snapshot_instances, **kwargs):
        """Returns request specs related to share server and all its shares."""

        shares_total_size = sum([instance.get('size', 0)
                                 for instance in share_instances])
        snapshots_total_size = sum([instance.get('size', 0)
                                    for instance in snapshot_instances])

        shares_req_spec = []
        for share_instance in share_instances:
            share_type_id = share_instance['share_type_id']
            share_type = share_types.get_share_type(context, share_type_id)
            req_spec = self._get_request_spec_dict(context, share_instance,
                                                   share_type,
                                                   **kwargs)
            shares_req_spec.append(req_spec)

        server_request_spec = {
            'shares_size': shares_total_size,
            'snapshots_size': snapshots_total_size,
            'shares_req_spec': shares_req_spec,
        }
        return server_request_spec

    def _migration_initial_checks(self, context, share_server, dest_host,
                                  new_share_network):
        shares = self.db.share_get_all_by_share_server(
            context, share_server['id'])

        shares_in_recycle_bin = (
            self.db.get_shares_in_recycle_bin_by_share_server(
                context, share_server['id']))

        if len(shares) == 0:
            msg = _("Share server %s does not have shares."
                    % share_server['id'])
            raise exception.InvalidShareServer(reason=msg)

        if shares_in_recycle_bin:
            msg = _("Share server %s has at least one share that has "
                    "been soft deleted." % share_server['id'])
            raise exception.InvalidShareServer(reason=msg)

        # We only handle "active" share servers for now
        if share_server['status'] != constants.STATUS_ACTIVE:
            msg = _('Share server %(server_id)s status must be active, '
                    'but current status is: %(server_status)s.') % {
                        'server_id': share_server['id'],
                        'server_status': share_server['status']}
            raise exception.InvalidShareServer(reason=msg)

        share_groups_related_to_share_server = (
            self.db.share_group_get_all_by_share_server(
                context, share_server['id']))

        if share_groups_related_to_share_server:
            msg = _("The share server %s can not be migrated because it is "
                    "related to a share group.") % share_server['id']
            raise exception.InvalidShareServer(reason=msg)

        # Same backend and same network, nothing changes
        src_backend = share_utils.extract_host(share_server['host'],
                                               level='backend_name')
        dest_backend = share_utils.extract_host(dest_host,
                                                level='backend_name')
        current_share_network_id = shares[0]['instance']['share_network_id']
        if (src_backend == dest_backend and
                (new_share_network is None or
                 new_share_network['id'] == current_share_network_id)):
            msg = _('There is no difference between source and destination '
                    'backends and between source and destination share '
                    'networks. Share server migration will not proceed.')
            raise exception.InvalidShareServer(reason=msg)

        filters = {'source_share_server_id': share_server['id'],
                   'status': constants.STATUS_SERVER_MIGRATING_TO}
        dest_share_servers = self.db.share_server_get_all_with_filters(
            context, filters=filters)
        if len(dest_share_servers):
            msg = _("There is at least one destination share server pointing "
                    "to this source share server. Clean up your environment "
                    "before starting a new migration.")
            raise exception.InvalidShareServer(reason=msg)

        dest_service_host = share_utils.extract_host(dest_host)
        # Make sure the host is in the list of available hosts
        utils.validate_service_host(context, dest_service_host)

        service = self.db.service_get_by_args(
            context, dest_service_host, 'manila-share')

        # Get all share types
        type_ids = set([share['instance']['share_type_id']
                        for share in shares])
        types = [share_types.get_share_type(context, type_id)
                 for type_id in type_ids]

        # Check if share type azs are supported by the destination host
        for share_type in types:
            azs = share_type['extra_specs'].get('availability_zones', '')
            if azs and service['availability_zone']['name'] not in azs:
                msg = _("Share server %(server)s cannot be migrated to host "
                        "%(dest)s because the share type %(type)s is used by "
                        "one of the shares, and this share type is not "
                        "supported within the availability zone (%(az)s) that "
                        "the host is in.")
                type_name = '%s' % (share_type['name'] or '')
                type_id = '(ID: %s)' % share_type['id']
                payload = {'type': '%s%s' % (type_name, type_id),
                           'az': service['availability_zone']['name'],
                           'server': share_server['id'],
                           'dest': dest_host}
                raise exception.InvalidShareServer(reason=msg % payload)

        if new_share_network:
            new_share_network_id = new_share_network['id']
        else:
            new_share_network_id = shares[0]['instance']['share_network_id']
        # NOTE(carloss): check if the new or old share network has a subnet
        # that spans the availability zone of the destination host, otherwise
        # we should deny this operation.
        dest_az = self.db.availability_zone_get(
            context, service['availability_zone']['name'])
        compatible_subnets = (
            self.db.share_network_subnets_get_all_by_availability_zone_id(
                context, new_share_network_id, dest_az['id']))

        if not compatible_subnets:
            msg = _("The share network %(network)s does not have a subnet "
                    "that spans the destination host availability zone.")
            payload = {'network': new_share_network_id}
            raise exception.InvalidShareServer(reason=msg % payload)

        net_changes_identified = False
        if new_share_network:
            net_changes_identified = not share_utils.is_az_subnets_compatible(
                share_server['share_network_subnets'], compatible_subnets)

        # NOTE(carloss): Refreshing the list of shares since something could've
        # changed from the initial list.
        shares = self.db.share_get_all_by_share_server(
            context, share_server['id'])
        for share in shares:
            if share['status'] != constants.STATUS_AVAILABLE:
                msg = _('Share %(share_id)s status must be available, '
                        'but current status is: %(share_status)s.') % {
                            'share_id': share['id'],
                            'share_status': share['status']}
                raise exception.InvalidShareServer(reason=msg)

            if share.has_replicas:
                msg = _('Share %s has replicas. Remove the replicas of all '
                        'shares in the share server before attempting to '
                        'migrate it.') % share['id']
                LOG.error(msg)
                raise exception.InvalidShareServer(reason=msg)

            # NOTE(carloss): Not validating the flag preserve_snapshots at this
            # point, considering that even if the admin set the value to False,
            # the driver can still support preserving snapshots and the
            # snapshots would be copied anyway. So the share/manager will be
            # responsible for checking if the driver does not support snapshot
            # preservation, and if there are snapshots in the share server.
            share_snapshots = self.db.share_snapshot_get_all_for_share(
                context, share['id'])
            all_snapshots_are_available = all(
                [snapshot['status'] == constants.STATUS_AVAILABLE
                 for snapshot in share_snapshots])
            if not all_snapshots_are_available:
                msg = _(
                    "All snapshots must have '%(status)s' status to be "
                    "migrated by the driver along with share "
                    "%(resource_id)s.") % {
                        'resource_id': share['id'],
                        'status': constants.STATUS_AVAILABLE,
                }
                LOG.error(msg)
                raise exception.InvalidShareServer(reason=msg)

            if share.get('share_group_id'):
                msg = _('Share %s is a member of a group. This operation is '
                        'not currently supported for share servers that '
                        'contain shares members of  groups.') % share['id']
                LOG.error(msg)
                raise exception.InvalidShareServer(reason=msg)

            share_instance = share['instance']
            # Access rules status must not be error
            if share_instance['access_rules_status'] == constants.STATUS_ERROR:
                msg = _(
                    'Share instance %(instance_id)s access rules status must '
                    'not be in %(error)s when attempting to start a share '
                    'server migration.') % {
                        'instance_id': share_instance['id'],
                        'error': constants.STATUS_ERROR}
                raise exception.InvalidShareServer(reason=msg)
            try:
                self._check_is_share_busy(share)
            except exception.ShareBusyException as e:
                raise exception.InvalidShareServer(reason=e.msg)

        return (
            shares, types, service, new_share_network_id,
            net_changes_identified)

    def share_server_migration_check(self, context, share_server, dest_host,
                                     writable, nondisruptive,
                                     preserve_snapshots,
                                     new_share_network=None):
        """Migrates share server to a new host."""
        shares, types, service, new_share_network_id, net_params_changed = (
            self._migration_initial_checks(context, share_server, dest_host,
                                           new_share_network))

        # If a nondisruptive migration was requested and different neutron net
        # id and neutron subnet ids were identified
        if net_params_changed and nondisruptive:
            result = {
                'compatible': False,
                'writable': False,
                'nondisruptive': False,
                'preserve_snapshots': False,
                'migration_cancel': False,
                'migration_get_progress': False,
                'share_network_id': new_share_network_id
            }
            return result

        # NOTE(dviroel): Service is up according to validations made on initial
        # checks
        result = self.share_rpcapi.share_server_migration_check(
            context, share_server['id'], dest_host, writable, nondisruptive,
            preserve_snapshots, new_share_network_id)

        # NOTE(carloss): In case users haven't requested a nondisruptive
        # migration and a network change was identified, we must get the
        # driver's check result and  if there is need to, manipulate it.
        # The result is provided by the driver and based on the back end
        # possibility to perform a nondisruptive migration or not. If
        # a network change was provided, we know that the migration will be
        # disruptive, so in order to do not confuse the user, we must present
        # the share server migration as disruptive
        if result.get('nondisruptive') and net_params_changed:
            result['nondisruptive'] = False

        return result

    def share_server_migration_start(
            self, context, share_server, dest_host, writable, nondisruptive,
            preserve_snapshots, new_share_network=None):
        """Migrates share server to a new host."""

        shares, types, service, new_share_network_id, net_params_changed = (
            self._migration_initial_checks(context, share_server,
                                           dest_host,
                                           new_share_network))

        if nondisruptive and net_params_changed:
            msg = _("Nondisruptive migration would only be feasible when the "
                    "current and new share networks carry the same "
                    "'neutron_net_id' and 'neutron_subnet_id', or when no "
                    "network changes are occurring.")
            raise exception.InvalidInput(reason=msg)

        # Updates the share server status to migration starting
        self.db.share_server_update(
            context, share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_STARTING,
             'status': constants.STATUS_SERVER_MIGRATING})

        share_snapshots = [
            self.db.share_snapshot_get_all_for_share(context, share['id'])
            for share in shares]
        snapshot_instance_ids = []
        for snapshot_list in share_snapshots:
            for snapshot in snapshot_list:
                snapshot_instance_ids.append(snapshot['instance']['id'])
        share_instance_ids = [share['instance']['id'] for share in shares]

        # Updates all shares and snapshot instances
        self.db.share_and_snapshot_instances_status_update(
            context, {'status': constants.STATUS_SERVER_MIGRATING},
            share_instance_ids=share_instance_ids,
            snapshot_instance_ids=snapshot_instance_ids,
            current_expected_status=constants.STATUS_AVAILABLE
        )

        # NOTE(dviroel): Service is up according to validations made on initial
        # checks
        self.share_rpcapi.share_server_migration_start(
            context, share_server, dest_host, writable, nondisruptive,
            preserve_snapshots, new_share_network_id)

    def share_server_migration_complete(self, context, share_server):
        """Invokes 2nd phase of share server migration."""
        if share_server['status'] != constants.STATUS_SERVER_MIGRATING:
            msg = _("Share server %s is not migrating") % share_server['id']
            LOG.error(msg)
            raise exception.InvalidShareServer(reason=msg)
        if (share_server['task_state'] !=
                constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE):
            msg = _("The first phase of migration has to finish to "
                    "request the completion of server %s's "
                    "migration.") % share_server['id']
            LOG.error(msg)
            raise exception.InvalidShareServer(reason=msg)

        dest_share_server = self.share_server_migration_get_destination(
            context, share_server['id'],
            status=constants.STATUS_SERVER_MIGRATING_TO
        )

        dest_host = share_utils.extract_host(dest_share_server['host'])
        utils.validate_service_host(context, dest_host)

        self.share_rpcapi.share_server_migration_complete(
            context, dest_share_server['host'], share_server,
            dest_share_server)

        return {
            'destination_share_server_id': dest_share_server['id']
        }

    def share_server_migration_cancel(self, context, share_server):
        """Attempts to cancel share server migration."""
        if share_server['status'] != constants.STATUS_SERVER_MIGRATING:
            msg = _("Migration of share server %s cannot be cancelled because "
                    "the provided share server is not being migrated."
                    % (share_server['id']))
            LOG.error(msg)
            raise exception.InvalidShareServer(reason=msg)

        if share_server['task_state'] in (
                constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):

            dest_share_server = self.share_server_migration_get_destination(
                context, share_server['id'],
                status=constants.STATUS_SERVER_MIGRATING_TO
            )

            dest_host = share_utils.extract_host(dest_share_server['host'])
            utils.validate_service_host(context, dest_host)

            self.share_rpcapi.share_server_migration_cancel(
                context, dest_share_server['host'], share_server,
                dest_share_server)
        else:
            msg = self._migration_validate_error_message(
                share_server, resource_type='share_server')
            if msg is None:
                msg = _("Migration of share server %s can be cancelled only "
                        "after the driver already started the migration, or "
                        "when the first phase of the migration gets "
                        "completed.") % share_server['id']
            LOG.error(msg)
            raise exception.InvalidShareServer(reason=msg)

    def share_server_migration_get_progress(self, context,
                                            src_share_server_id):
        """Retrieve migration progress for a given share server."""
        try:
            share_server = self.db.share_server_get(context,
                                                    src_share_server_id)
        except exception.ShareServerNotFound:
            msg = _('Share server %s was not found. We will search for a '
                    'successful migration') % src_share_server_id
            LOG.debug(msg)
            # Search for a successful migration, raise an error if not found
            dest_share_server = self.share_server_migration_get_destination(
                context, src_share_server_id,
                status=constants.STATUS_ACTIVE
            )
            return {
                'total_progress': 100,
                'destination_share_server_id': dest_share_server['id'],
                'task_state': dest_share_server['task_state'],
            }
        # Source server still exists so it must be in 'server_migrating' status
        if share_server['status'] != constants.STATUS_SERVER_MIGRATING:
            msg = _("Migration progress of share server %s cannot be "
                    "obtained. The provided share server is not being "
                    "migrated.") % share_server['id']
            LOG.error(msg)
            raise exception.InvalidShareServer(reason=msg)

        dest_share_server = self.share_server_migration_get_destination(
            context, share_server['id'],
            status=constants.STATUS_SERVER_MIGRATING_TO
        )

        if (share_server['task_state'] ==
                constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS):

            dest_host = share_utils.extract_host(dest_share_server['host'])
            utils.validate_service_host(context, dest_host)

            try:
                result = (
                    self.share_rpcapi.share_server_migration_get_progress(
                        context, dest_share_server['host'],
                        share_server, dest_share_server))
            except Exception:
                msg = _("Failed to obtain migration progress of share "
                        "server %s.") % share_server['id']
                LOG.exception(msg)
                raise exception.ShareServerMigrationError(reason=msg)

        else:
            result = self._migration_get_progress_state(share_server)

        if not (result and result.get('total_progress') is not None):
            msg = self._migration_validate_error_message(
                share_server, resource_type='share_server')
            if msg is None:
                msg = _("Migration progress of share server %s cannot be "
                        "obtained at this moment.") % share_server['id']
            LOG.error(msg)
            raise exception.InvalidShareServer(reason=msg)

        result.update({
            'destination_share_server_id': dest_share_server['id'],
            'task_state': dest_share_server['task_state']
        })
        return result

    def _share_network_update_initial_checks(self, context, share_network,
                                             new_security_service,
                                             current_security_service=None):
        api_common.check_share_network_is_active(share_network)

        if not current_security_service:
            # Since we are adding a new security service, we can't have one
            # of the same type already associated with this share network
            for attached_service in share_network['security_services']:
                if attached_service['type'] == new_security_service['type']:
                    msg = _("Cannot add security service to share network. "
                            "Security service with '%(ss_type)s' type already "
                            "added to '%(sn_id)s' share network") % {
                        'ss_type': new_security_service['type'],
                        'sn_id': share_network['id']
                    }
                    raise exception.InvalidSecurityService(reason=msg)
        else:
            # Validations needed only for update operation
            current_service_is_associated = (
                self.db.share_network_security_service_association_get(
                    context, share_network['id'],
                    current_security_service['id']))

            if not current_service_is_associated:
                msg = _("The specified current security service %(service)s "
                        "is not associated to the share network %(network)s."
                        ) % {
                    'service': current_security_service['id'],
                    'network': share_network['id']
                }
                raise exception.InvalidSecurityService(reason=msg)

            if (current_security_service['type'] !=
                    new_security_service['type']):
                msg = _("A security service can only be replaced by one of "
                        "the same type. The current security service type is "
                        "'%(ss_type)s' and the new security service type is "
                        "'%(new_ss_type)s'") % {
                    'ss_type': current_security_service['type'],
                    'new_ss_type': new_security_service['type'],
                    'sn_id': share_network['id']
                }
                raise exception.InvalidSecurityService(reason=msg)

        share_servers = set()
        for subnet in share_network['share_network_subnets']:
            if subnet['share_servers']:
                share_servers.update(subnet['share_servers'])

        backend_hosts = set()
        if share_servers:
            if not share_network['security_service_update_support']:
                msg = _("Updating security services is not supported on this "
                        "share network (%(sn_id)s) while it has shares. "
                        "See the capability "
                        "'security_service_update_support'.") % {
                    "sn_id": share_network["id"]
                }
                raise exception.InvalidShareNetwork(reason=msg)

            # We can only handle "active" share servers for now
            for share_server in share_servers:
                if share_server['status'] != constants.STATUS_ACTIVE:
                    msg = _('Some resources exported on share network '
                            '%(shar_net_id)s are not currently available.') % {
                        'shar_net_id': share_network['id']
                    }
                    raise exception.InvalidShareNetwork(reason=msg)
                # Create a set of backend hosts
                backend_hosts.add(share_server['host'])

            for backend_host in backend_hosts:
                # We need an admin context to validate these hosts
                admin_ctx = manila_context.get_admin_context()
                # Make sure the host is in the list of available hosts
                utils.validate_service_host(admin_ctx, backend_host)

            shares_in_recycle_bin = (
                self.db.get_shares_in_recycle_bin_by_network(
                    context, share_network['id']))
            if shares_in_recycle_bin:
                msg = _("Some shares with share network %(sn_id)s have "
                        "been soft deleted.") % {'sn_id': share_network['id']}
                raise exception.InvalidShareNetwork(reason=msg)

            shares = self.get_all(
                context, search_opts={'share_network_id': share_network['id']})
            shares_not_available = [
                share['id'] for share in shares if
                share['status'] != constants.STATUS_AVAILABLE]

            if shares_not_available:
                msg = _("Some shares exported on share network %(sn_id)s are "
                        "not available: %(share_ids)s.") % {
                    'sn_id': share_network['id'],
                    'share_ids': shares_not_available,
                }
                raise exception.InvalidShareNetwork(reason=msg)

            shares_rules_not_available = [
                share['id'] for share in shares if
                share['instance'][
                    'access_rules_status'] != constants.STATUS_ACTIVE]

            if shares_rules_not_available:
                msg = _(
                    "Either these shares or one of their replicas or "
                    "migration copies exported on share network %(sn_id)s "
                    "are not available: %(share_ids)s.") % {
                    'sn_id': share_network['id'],
                    'share_ids': shares_rules_not_available,
                }
                raise exception.InvalidShareNetwork(reason=msg)

            busy_shares = []
            for share in shares:
                try:
                    self._check_is_share_busy(share)
                except exception.ShareBusyException:
                    busy_shares.append(share['id'])
            if busy_shares:
                msg = _("Some shares exported on share network %(sn_id)s "
                        "are busy: %(share_ids)s.") % {
                    'sn_id': share_network['id'],
                    'share_ids': busy_shares,
                }
                raise exception.InvalidShareNetwork(reason=msg)

        return list(share_servers), list(backend_hosts)

    def get_security_service_update_key(
            self, operation, new_security_service_id,
            current_security_service_id=None):
        if current_security_service_id:
            return ('share_network_sec_service_update_' +
                    current_security_service_id + '_' +
                    new_security_service_id + '_' + operation)
        else:
            return ('share_network_sec_service_add_' +
                    new_security_service_id + '_' + operation)

    @locked_security_service_update_operation
    def _security_service_update_validate_hosts(
            self, context, share_network,
            backend_hosts, share_servers,
            new_security_service_id=None,
            current_security_service_id=None):

        # create a key based on users request
        update_key = self.get_security_service_update_key(
            'hosts_check', new_security_service_id,
            current_security_service_id=current_security_service_id)

        return self._do_update_validate_hosts(
            context, share_network['id'], backend_hosts, update_key,
            new_security_service_id=new_security_service_id,
            current_security_service_id=current_security_service_id)

    def _do_update_validate_hosts(
            self, context, share_network_id,
            backend_hosts, update_key, new_share_network_subnet=None,
            new_security_service_id=None, current_security_service_id=None):

        # check if there is an entry being processed.
        update_value = self.db.async_operation_data_get(
            context, share_network_id, update_key)
        if not update_value:
            # Create a new entry, send all asynchronous rpcs and return.
            hosts_to_validate = {}
            for host in backend_hosts:
                hosts_to_validate[host] = None
            self.db.async_operation_data_update(
                context, share_network_id,
                {update_key: json.dumps(hosts_to_validate)})
            for host in backend_hosts:
                if new_share_network_subnet:
                    (self.share_rpcapi.
                        check_update_share_server_network_allocations(
                            context, host, share_network_id,
                            new_share_network_subnet))
                else:
                    (self.share_rpcapi.
                        check_update_share_network_security_service(
                            context, host, share_network_id,
                            new_security_service_id,
                            current_security_service_id=(
                                current_security_service_id)))
            return None, hosts_to_validate

        else:
            # process current existing hosts and update them if needed.
            current_hosts = json.loads(update_value)
            hosts_to_include = (
                set(backend_hosts).difference(set(current_hosts.keys())))
            hosts_to_validate = {}
            for host in backend_hosts:
                hosts_to_validate[host] = current_hosts.get(host, None)

            # Check if there is any unsupported host.
            if any(hosts_to_validate[host] is False for host in backend_hosts):
                return False, hosts_to_validate

            # Update the list of hosts to be validated.
            if hosts_to_include:
                self.db.async_operation_data_update(
                    context, share_network_id,
                    {update_key: json.dumps(hosts_to_validate)})

                for host in hosts_to_include:
                    # send asynchronous check only for new backend hosts.
                    if new_share_network_subnet:
                        (self.share_rpcapi.
                            check_update_share_server_network_allocations(
                                context, host, share_network_id,
                                new_share_network_subnet))
                    else:
                        (self.share_rpcapi.
                            check_update_share_network_security_service(
                                context, host, share_network_id,
                                new_security_service_id,
                                current_security_service_id=(
                                    current_security_service_id)))

                return None, hosts_to_validate

            if all(hosts_to_validate[host] for host in backend_hosts):
                return True, hosts_to_validate

            return None, current_hosts

    def check_share_network_security_service_update(
            self, context, share_network, new_security_service,
            current_security_service=None, reset_operation=False):
        share_servers, backend_hosts = (
            self._share_network_update_initial_checks(
                context, share_network, new_security_service,
                current_security_service=current_security_service))

        if not backend_hosts:
            # There is no backend host to validate. Operation is supported.
            return {
                'compatible': True,
                'hosts_check_result': {},
            }
        curr_sec_serv_id = (
            current_security_service['id']
            if current_security_service else None)
        key = self.get_security_service_update_key(
            'hosts_check', new_security_service['id'],
            current_security_service_id=curr_sec_serv_id)
        if reset_operation:
            self.db.async_operation_data_delete(context, share_network['id'],
                                                key)
        try:
            compatible, hosts_info = (
                self._security_service_update_validate_hosts(
                    context, share_network, backend_hosts, share_servers,
                    new_security_service_id=new_security_service['id'],
                    current_security_service_id=curr_sec_serv_id))
        except Exception as e:
            LOG.error(e)
            # Due to an internal error, we will delete the entry
            self.db.async_operation_data_delete(
                context, share_network['id'], key)
            msg = _(
                'The share network %(share_net_id)s cannot be updated '
                'since at least one of its backend hosts do not support '
                'this operation.') % {
                    'share_net_id': share_network['id']}
            raise exception.InvalidShareNetwork(reason=msg)

        return {
            'compatible': compatible,
            'hosts_check_result': hosts_info
        }

    def update_share_network_security_service(self, context, share_network,
                                              new_security_service,
                                              current_security_service=None):
        share_servers, backend_hosts = (
            self._share_network_update_initial_checks(
                context, share_network, new_security_service,
                current_security_service=current_security_service))
        if not backend_hosts:
            # There is no backend host to validate or update.
            return

        curr_sec_serv_id = (
            current_security_service['id']
            if current_security_service else None)

        update_key = self.get_security_service_update_key(
            'hosts_check', new_security_service['id'],
            current_security_service_id=curr_sec_serv_id)
        # check if there is an entry being processed at this moment
        update_value = self.db.async_operation_data_get(
            context, share_network['id'], update_key)
        if not update_value:
            msg = _(
                'The share network %(share_net_id)s cannot start the update '
                'process since no check operation was found. Before starting '
                'the update operation, a "check" operation must be triggered '
                'to validate if all backend hosts support the provided '
                'configuration paramaters.') % {
                'share_net_id': share_network['id']
            }
            raise exception.InvalidShareNetwork(reason=msg)

        try:
            result, __ = self._security_service_update_validate_hosts(
                context, share_network, backend_hosts, share_servers,
                new_security_service_id=new_security_service['id'],
                current_security_service_id=curr_sec_serv_id)
        except Exception:
            # Due to an internal error, we will delete the entry
            self.db.async_operation_data_delete(
                context, share_network['id'], update_key)
            msg = _(
                'The share network %(share_net_id)s cannot be updated '
                'since at least one of its backend hosts do not support '
                'this operation.') % {
                    'share_net_id': share_network['id']}
            raise exception.InvalidShareNetwork(reason=msg)

        if result is False:
            msg = _(
                'The share network %(share_net_id)s cannot be updated '
                'since at least one of its backend hosts do not support '
                'this operation.') % {
                    'share_net_id': share_network['id']}
            raise exception.InvalidShareNetwork(reason=msg)
        elif result is None:
            msg = _(
                'Not all of the validation has been completed yet. A '
                'validation check is in progress. This operation can be '
                'retried.')
            raise exception.InvalidShareNetwork(reason=msg)

        self.db.share_network_update(
            context, share_network['id'],
            {'status': constants.STATUS_NETWORK_CHANGE})

        # NOTE(dviroel): We want to change the status for all share servers to
        # identify when all modifications are made, and update share network
        # status to 'active' again.
        share_servers_ids = [ss.id for ss in share_servers]
        self.db.share_servers_update(
            context, share_servers_ids,
            {'status': constants.STATUS_SERVER_NETWORK_CHANGE})

        for backend_host in backend_hosts:
            self.share_rpcapi.update_share_network_security_service(
                context, backend_host, share_network['id'],
                new_security_service['id'],
                current_security_service_id=curr_sec_serv_id)

        # Erase db entry, since we won't need it anymore
        self.db.async_operation_data_delete(
            context, share_network['id'], update_key)

        LOG.info('Security service update has been started for share network '
                 '%(share_net_id)s.', {'share_net_id': share_network['id']})

    @locked_share_server_update_allocations_operation
    def _share_server_update_allocations_validate_hosts(
            self, context, backend_hosts, update_key, share_network_id=None,
            neutron_net_id=None, neutron_subnet_id=None,
            availability_zone_id=None):

        new_share_network_subnet = {
            'neutron_net_id': neutron_net_id,
            'neutron_subnet_id': neutron_subnet_id,
            'availability_zone_id': availability_zone_id,
        }
        return self._do_update_validate_hosts(
            context, share_network_id, backend_hosts, update_key,
            new_share_network_subnet=new_share_network_subnet)

    def get_share_server_update_allocations_key(
            self, share_network_id, availability_zone_id):
        return ('share_server_update_allocations_' + share_network_id + '_' +
                str(availability_zone_id) + '_' + 'hosts_check')

    def _share_server_update_allocations_initial_checks(
            self, context, share_network, share_servers):

        api_common.check_share_network_is_active(share_network)
        if not share_network['network_allocation_update_support']:
            msg = _("Updating network allocations is not supported on this "
                    "share network (%(sn_id)s) while it has shares. "
                    "See the capability 'network_allocation_update_support'."
                    ) % {"sn_id": share_network["id"]}
            raise exception.InvalidShareNetwork(reason=msg)

        backend_hosts = set()
        for share_server in share_servers:
            share_server_id = share_server['id']
            if share_server['status'] != constants.STATUS_ACTIVE:
                msg = _('The share server %(server)s in the specified '
                        'availability zone subnet is not currently '
                        'available.') % {'server': share_server_id}
                raise exception.InvalidShareNetwork(reason=msg)

            # We need an admin context to validate these hosts.
            admin_ctx = manila_context.get_admin_context()
            # Make sure the host is in the list of available hosts.
            utils.validate_service_host(admin_ctx, share_server['host'])

            # Create a set of backend hosts.
            backend_hosts.add(share_server['host'])

            shares = self.db.share_get_all_by_share_server(
                context, share_server_id)
            shares_not_available = [
                share['id']
                for share in shares if
                share['status'] != constants.STATUS_AVAILABLE]

            if shares_not_available:
                msg = _("The share server (%(server_id)s) in the specified "
                        "availability zone subnet has some shares that are "
                        "not available: "
                        "%(share_ids)s.") % {
                    'server_id': share_server_id,
                    'share_ids': shares_not_available,
                }
                raise exception.InvalidShareNetwork(reason=msg)

            shares_rules_not_available = [
                share['id'] for share in shares if
                share['instance'][
                    'access_rules_status'] != constants.STATUS_ACTIVE]

            if shares_rules_not_available:
                msg = _("The share server (%(server_id)s) in the specified "
                        "availability zone subnet has either these shares or "
                        "one of their replicas or migration copies that are "
                        "not available: %(share_ids)s.") % {
                    'server_id': share_server_id,
                    'share_ids': shares_rules_not_available,
                }
                raise exception.InvalidShareNetwork(reason=msg)

            busy_shares = []
            for share in shares:
                try:
                    self._check_is_share_busy(share)
                except exception.ShareBusyException:
                    busy_shares.append(share['id'])
            if busy_shares:
                msg = _("The share server (%(server_id)s) in the specified "
                        "availability zone subnet has some shares that are "
                        "busy as part of an active task: "
                        "%(share_ids)s.") % {
                    'server_id': share_server_id,
                    'share_ids': busy_shares,
                }
                raise exception.InvalidShareNetwork(reason=msg)

        return backend_hosts

    def check_update_share_server_network_allocations(
            self, context, share_network, new_share_network_subnet,
            reset_operation):

        backend_hosts = self._share_server_update_allocations_initial_checks(
            context, share_network, new_share_network_subnet['share_servers'])

        update_key = self.get_share_server_update_allocations_key(
            share_network['id'],
            new_share_network_subnet['availability_zone_id'])
        if reset_operation:
            self.db.async_operation_data_delete(context, share_network['id'],
                                                update_key)
        try:
            compatible, hosts_info = (
                self._share_server_update_allocations_validate_hosts(
                    context, backend_hosts, update_key,
                    share_network_id=share_network['id'],
                    neutron_net_id=(
                        new_share_network_subnet.get('neutron_net_id')),
                    neutron_subnet_id=(
                        new_share_network_subnet.get('neutron_subnet_id')),
                    availability_zone_id=new_share_network_subnet.get(
                        "availability_zone_id")))
        except Exception as e:
            LOG.exception(e)
            # Due to an internal error, we will delete the entry.
            self.db.async_operation_data_delete(
                context, share_network['id'], update_key)
            msg = _(
                "The server's allocations cannot be updated on availability "
                "zone %(zone_id)s of the share network %(share_net_id)s, "
                "since at least one of its backend hosts do not support this "
                "operation.") % {
                'share_net_id': share_network['id'],
                'zone_id': new_share_network_subnet['availability_zone_id']}
            raise exception.InvalidShareNetwork(reason=msg)

        return {
            'compatible': compatible,
            'hosts_check_result': hosts_info
        }

    def update_share_server_network_allocations(
            self, context, share_network, new_share_network_subnet):

        backend_hosts = self._share_server_update_allocations_initial_checks(
            context, share_network, new_share_network_subnet['share_servers'])

        update_key = self.get_share_server_update_allocations_key(
            share_network['id'],
            new_share_network_subnet['availability_zone_id'])

        # check if there is an entry being processed at this moment.
        update_value = self.db.async_operation_data_get(
            context, share_network['id'], update_key)
        if not update_value:
            msg = _(
                'The share network %(share_net_id)s cannot start the update '
                'process since no check operation was found. Before starting '
                'the update operation, a "check" operation must be triggered '
                'to validate if all backend hosts support the provided '
                'configuration paramaters.') % {
                    'share_net_id': share_network['id']
                }
            raise exception.InvalidShareNetwork(reason=msg)

        subnet_info = {
            'availability_zone_id':
                new_share_network_subnet.get("availability_zone_id"),
            'neutron_net_id':
                new_share_network_subnet.get('neutron_net_id'),
            'neutron_subnet_id':
                new_share_network_subnet.get('neutron_subnet_id'),
        }
        try:
            result, __ = self._share_server_update_allocations_validate_hosts(
                context, backend_hosts, update_key,
                share_network_id=share_network['id'],
                neutron_net_id=(
                    new_share_network_subnet.get('neutron_net_id')),
                neutron_subnet_id=(
                    new_share_network_subnet.get('neutron_subnet_id')),
                availability_zone_id=new_share_network_subnet.get(
                    "availability_zone_id"))
        except Exception:
            # Due to an internal error, we will delete the entry.
            self.db.async_operation_data_delete(
                context, share_network['id'], update_key)
            msg = _(
                "The server's allocations cannot be updated on availability "
                "zone %(zone_id)s of the share network %(share_net_id)s, "
                "since an internal error occurred."
                "operation.") % {
                    'share_net_id': share_network['id'],
                    'zone_id': subnet_info['availability_zone_id']
                }
            raise exception.InvalidShareNetwork(reason=msg)

        if result is False:
            msg = _(
                "The server's allocations cannot be updated on availability "
                "zone %(zone_id)s of the share network %(share_net_id)s, "
                "since at least one of its backend hosts do not support this "
                "operation.") % {
                    'share_net_id': share_network['id'],
                    'zone_id': subnet_info['availability_zone_id']
                }
            raise exception.InvalidShareNetwork(reason=msg)
        elif result is None:
            msg = _(
                'Not all of the validation has been completed yet. A '
                'validation check is in progress. This operation can be '
                'retried.')
            raise exception.InvalidShareNetwork(reason=msg)

        # change db to start the update.
        self.db.share_network_update(
            context, share_network['id'],
            {'status': constants.STATUS_NETWORK_CHANGE})
        share_servers_ids = [ss['id'] for ss in
                             new_share_network_subnet['share_servers']]
        self.db.share_servers_update(
            context, share_servers_ids,
            {'status': constants.STATUS_SERVER_NETWORK_CHANGE})

        # create the new subnet.
        new_share_network_subnet_db = self.db.share_network_subnet_create(
            context, new_share_network_subnet)

        # triggering the actual update.
        for backend_host in backend_hosts:
            self.share_rpcapi.update_share_server_network_allocations(
                context, backend_host, share_network['id'],
                new_share_network_subnet_db['id'])

        # Erase db entry, since we won't need it anymore.
        self.db.async_operation_data_delete(
            context, share_network['id'], update_key)

        LOG.info('Share servers allocations update have been started for '
                 'share network %(share_net_id)s on its availability zone '
                 '%(az_id)s with new subnet %(subnet_id)s.',
                 {
                     'share_net_id': share_network['id'],
                     'az_id': new_share_network_subnet['availability_zone_id'],
                     'subnet_id': new_share_network_subnet_db['id'],
                 })
        return new_share_network_subnet_db

    def create_share_backup(self, context, share, backup):
        share_id = share['id']
        self._check_is_share_busy(share)

        if share['status'] != constants.STATUS_AVAILABLE:
            msg_args = {'share_id': share_id, 'state': share['status']}
            msg = (_("Share %(share_id)s is in '%(state)s' state, but it must "
                     "be in 'available' state to create a backup.") % msg_args)
            raise exception.InvalidShare(message=msg)

        snapshots = self.db.share_snapshot_get_all_for_share(context, share_id)
        if snapshots:
            msg = _("Cannot backup share %s while it has snapshots.")
            raise exception.InvalidShare(message=msg % share_id)

        if share.has_replicas:
            msg = _("Cannot backup share %s while it has replicas.")
            raise exception.InvalidShare(message=msg % share_id)

        # Reserve a quota before setting share status and backup status
        try:
            reservations = QUOTAS.reserve(
                context, backups=1, backup_gigabytes=share['size'])
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(resource_name):
                return (usages[resource_name]['reserved'] +
                        usages[resource_name]['in_use'])

            for over in overs:
                if 'backup_gigabytes' in over:
                    msg = ("Quota exceeded for %(s_pid)s, tried to create "
                           "%(s_size)sG backup, but (%(d_consumed)dG of "
                           "%(d_quota)dG already consumed.)")
                    LOG.warning(msg, {'s_pid': context.project_id,
                                      's_size': share['size'],
                                      'd_consumed': _consumed(over),
                                      'd_quota': quotas[over]})
                    raise exception.ShareBackupSizeExceedsAvailableQuota(
                        requested=share['size'],
                        consumed=_consumed('backup_gigabytes'),
                        quota=quotas['backup_gigabytes'])
                elif 'backups' in over:
                    msg = ("Quota exceeded for %(s_pid)s, tried to create "
                           "backup, but (%(d_consumed)d of %(d_quota)d "
                           "backups already consumed.)")
                    LOG.warning(msg, {'s_pid': context.project_id,
                                      'd_consumed': _consumed(over),
                                      'd_quota': quotas[over]})
                    raise exception.BackupLimitExceeded(
                        allowed=quotas[over])

        backup_ref = {}
        try:
            backup_ref = self.db.share_backup_create(
                context, share['id'],
                {
                    'user_id': context.user_id,
                    'project_id': context.project_id,
                    'progress': '0',
                    'restore_progress': '0',
                    'status': constants.STATUS_CREATING,
                    'display_description': backup.get('description'),
                    'display_name': backup.get('name'),
                    'size': share['size'],
                    'availability_zone': share['instance']['availability_zone']
                }
            )
            QUOTAS.commit(context, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                QUOTAS.rollback(context, reservations)

        self.db.share_update(
            context, share_id,
            {'status': constants.STATUS_BACKUP_CREATING})

        backup_ref['backup_options'] = backup.get('backup_options', {})
        backup_values = {}
        if backup_ref['backup_options']:
            topic = CONF.share_topic
            backup_ref['host'] = share_utils.extract_host(share['host'])
            backup_values.update({'host': backup_ref['host']})
        else:
            topic = CONF.data_topic

        backup_values.update({'topic': topic})
        self.db.share_backup_update(context, backup_ref['id'], backup_values)

        if topic == CONF.share_topic:
            self.share_rpcapi.create_backup(context, backup_ref)
        elif topic == CONF.data_topic:
            data_rpc = data_rpcapi.DataAPI()
            data_rpc.create_backup(context, backup_ref)
        return backup_ref

    def delete_share_backup(self, context, backup):
        """Make the RPC call to delete a share backup.

        :param context: request context
        :param backup: the model of backup that is retrieved from DB.
        :raises: InvalidBackup
        :raises: BackupDriverException
        :raises: ServiceNotFound
        """
        if backup.status not in [constants.STATUS_AVAILABLE,
                                 constants.STATUS_ERROR]:
            msg = (_('Backup %s status must be available or error.')
                   % backup['id'])
            raise exception.InvalidBackup(reason=msg)

        self.db.share_backup_update(
            context, backup['id'], {'status': constants.STATUS_DELETING})

        if backup['topic'] == CONF.share_topic:
            self.share_rpcapi.delete_backup(context, backup)
        elif backup['topic'] == CONF.data_topic:
            data_rpc = data_rpcapi.DataAPI()
            data_rpc.delete_backup(context, backup)

    def restore_share_backup(self, context, backup):
        """Make the RPC call to restore a backup."""
        backup_id = backup['id']
        if backup['status'] != constants.STATUS_AVAILABLE:
            msg = (_('Backup %s status must be available.') % backup['id'])
            raise exception.InvalidBackup(reason=msg)

        share = self.get(context, backup['share_id'])
        share_id = share['id']
        if share['status'] != constants.STATUS_AVAILABLE:
            msg = _('Share to be restored to must be available.')
            raise exception.InvalidShare(reason=msg)

        backup_size = backup['size']
        LOG.debug('Checking backup size %(backup_size)s against share size '
                  '%(share_size)s.', {'backup_size': backup_size,
                                      'share_size': share['size']})
        if backup_size > share['size']:
            msg = (_('Share size %(share_size)d is too small to restore '
                     'backup of size %(size)d.') %
                   {'share_size': share['size'], 'size': backup_size})
            raise exception.InvalidShare(reason=msg)

        LOG.info("Overwriting share %(share_id)s with restore of "
                 "backup %(backup_id)s.",
                 {'share_id': share_id, 'backup_id': backup_id})

        self.db.share_backup_update(
            context, backup_id,
            {'status': constants.STATUS_RESTORING})
        self.db.share_update(
            context, share_id,
            {'status': constants.STATUS_BACKUP_RESTORING,
             'source_backup_id': backup_id})

        if backup['topic'] == CONF.share_topic:
            self.share_rpcapi.restore_backup(context, backup, share_id)
        elif backup['topic'] == CONF.data_topic:
            data_rpc = data_rpcapi.DataAPI()
            data_rpc.restore_backup(context, backup, share_id)

        restore_info = {'backup_id': backup_id, 'share_id': share_id}
        return restore_info

    def update_share_backup(self, context, backup, fields):
        return self.db.share_backup_update(context, backup['id'], fields)
