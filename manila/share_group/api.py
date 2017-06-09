# Copyright (c) 2015 Alex Meade
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
Handles all requests relating to share groups.
"""

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import strutils
import six

from manila.common import constants
from manila.db import base
from manila import exception
from manila.i18n import _
from manila import quota
from manila.scheduler import rpcapi as scheduler_rpcapi
from manila import share
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types

CONF = cfg.CONF
LOG = log.getLogger(__name__)
QUOTAS = quota.QUOTAS


class API(base.Base):
    """API for interacting with the share manager."""

    def __init__(self, db_driver=None):
        self.scheduler_rpcapi = scheduler_rpcapi.SchedulerAPI()
        self.share_rpcapi = share_rpcapi.ShareAPI()
        self.share_api = share.API()
        super(API, self).__init__(db_driver)

    def create(self, context, name=None, description=None,
               share_type_ids=None, source_share_group_snapshot_id=None,
               share_network_id=None, share_group_type_id=None,
               availability_zone_id=None):
        """Create new share group."""

        share_group_snapshot = None
        original_share_group = None
        # NOTE(gouthamr): share_server_id is inherited from the
        # parent share group if a share group snapshot is specified,
        # else, it will be set in the share manager.
        share_server_id = None
        if source_share_group_snapshot_id:
            share_group_snapshot = self.db.share_group_snapshot_get(
                context, source_share_group_snapshot_id)
            if share_group_snapshot['status'] != constants.STATUS_AVAILABLE:
                msg = (_("Share group snapshot status must be %s.")
                       % constants.STATUS_AVAILABLE)
                raise exception.InvalidShareGroupSnapshot(reason=msg)

            original_share_group = self.db.share_group_get(
                context, share_group_snapshot['share_group_id'])
            share_type_ids = [
                s['share_type_id']
                for s in original_share_group['share_types']]
            share_network_id = original_share_group['share_network_id']
            share_server_id = original_share_group['share_server_id']
            availability_zone_id = original_share_group['availability_zone_id']

        # Get share_type_objects
        share_type_objects = []
        driver_handles_share_servers = None
        for share_type_id in (share_type_ids or []):
            try:
                share_type_object = share_types.get_share_type(
                    context, share_type_id)
            except exception.ShareTypeNotFound:
                msg = _("Share type with id %s could not be found.")
                raise exception.InvalidInput(msg % share_type_id)
            share_type_objects.append(share_type_object)

            extra_specs = share_type_object.get('extra_specs')
            if extra_specs:
                share_type_handle_ss = strutils.bool_from_string(
                    extra_specs.get(
                        constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS))
                if driver_handles_share_servers is None:
                    driver_handles_share_servers = share_type_handle_ss
                elif not driver_handles_share_servers == share_type_handle_ss:
                    # NOTE(ameade): if the share types have conflicting values
                    #  for driver_handles_share_servers then raise bad request
                    msg = _("The specified share_types cannot have "
                            "conflicting values for the "
                            "driver_handles_share_servers extra spec.")
                    raise exception.InvalidInput(reason=msg)

                if (not share_type_handle_ss) and share_network_id:
                    msg = _("When using a share types with the "
                            "driver_handles_share_servers extra spec as "
                            "False, a share_network_id must not be provided.")
                    raise exception.InvalidInput(reason=msg)

        try:
            if share_network_id:
                self.db.share_network_get(context, share_network_id)
        except exception.ShareNetworkNotFound:
            msg = _("The specified share network does not exist.")
            raise exception.InvalidInput(reason=msg)

        if (driver_handles_share_servers and
                not (source_share_group_snapshot_id or share_network_id)):
            msg = _("When using a share type with the "
                    "driver_handles_share_servers extra spec as "
                    "True, a share_network_id must be provided.")
            raise exception.InvalidInput(reason=msg)

        try:
            share_group_type = self.db.share_group_type_get(
                context, share_group_type_id)
        except exception.ShareGroupTypeNotFound:
            msg = _("The specified share group type %s does not exist.")
            raise exception.InvalidInput(reason=msg % share_group_type_id)

        supported_share_types = set(
            [x['share_type_id'] for x in share_group_type['share_types']])

        if not set(share_type_ids or []) <= supported_share_types:
            msg = _("The specified share types must be a subset of the share "
                    "types supported by the share group type.")
            raise exception.InvalidInput(reason=msg)

        try:
            reservations = QUOTAS.reserve(context, share_groups=1)
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'share_groups' in overs:
                msg = ("Quota exceeded for '%(s_uid)s' user in '%(s_pid)s' "
                       "project. (%(d_consumed)d of "
                       "%(d_quota)d already consumed).")
                LOG.warning(msg, {
                    's_pid': context.project_id,
                    's_uid': context.user_id,
                    'd_consumed': _consumed('share_groups'),
                    'd_quota': quotas['share_groups'],
                })
            raise exception.ShareGroupsLimitExceeded()

        options = {
            'share_group_type_id': share_group_type_id,
            'source_share_group_snapshot_id': source_share_group_snapshot_id,
            'share_network_id': share_network_id,
            'share_server_id': share_server_id,
            'availability_zone_id': availability_zone_id,
            'name': name,
            'description': description,
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_CREATING,
            'share_types': share_type_ids or supported_share_types
        }
        if original_share_group:
            options['host'] = original_share_group['host']

        share_group = None
        try:
            share_group = self.db.share_group_create(context, options)
            if share_group_snapshot:
                members = self.db.share_group_snapshot_members_get_all(
                    context, source_share_group_snapshot_id)
                for member in members:
                    share_instance = self.db.share_instance_get(
                        context, member['share_instance_id'])
                    share_type = share_types.get_share_type(
                        context, share_instance['share_type_id'])
                    self.share_api.create(
                        context,
                        member['share_proto'],
                        member['size'],
                        None,
                        None,
                        share_group_id=share_group['id'],
                        share_group_snapshot_member=member,
                        share_type=share_type,
                        availability_zone=availability_zone_id,
                        share_network_id=share_network_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                if share_group:
                    self.db.share_group_destroy(
                        context.elevated(), share_group['id'])
                QUOTAS.rollback(context, reservations)

        try:
            QUOTAS.commit(context, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                QUOTAS.rollback(context, reservations)

        request_spec = {'share_group_id': share_group['id']}
        request_spec.update(options)
        request_spec['share_types'] = share_type_objects
        request_spec['resource_type'] = share_group_type

        if share_group_snapshot and original_share_group:
            self.share_rpcapi.create_share_group(
                context, share_group, original_share_group['host'])
        else:
            self.scheduler_rpcapi.create_share_group(
                context, share_group_id=share_group['id'],
                request_spec=request_spec, filter_properties={})

        return share_group

    def delete(self, context, share_group):
        """Delete share group."""

        share_group_id = share_group['id']
        if not share_group['host']:
            self.db.share_group_destroy(context.elevated(), share_group_id)
            return

        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
        if not share_group['status'] in statuses:
            msg = (_("Share group status must be one of %(statuses)s")
                   % {"statuses": statuses})
            raise exception.InvalidShareGroup(reason=msg)

        # NOTE(ameade): check for group_snapshots in the group
        if self.db.count_share_group_snapshots_in_share_group(
                context, share_group_id):
            msg = (_("Cannot delete a share group with snapshots"))
            raise exception.InvalidShareGroup(reason=msg)

        # NOTE(ameade): check for shares in the share group
        if self.db.count_shares_in_share_group(context, share_group_id):
            msg = (_("Cannot delete a share group with shares"))
            raise exception.InvalidShareGroup(reason=msg)

        share_group = self.db.share_group_update(
            context, share_group_id, {'status': constants.STATUS_DELETING})

        try:
            reservations = QUOTAS.reserve(
                context,
                share_groups=-1,
                project_id=share_group['project_id'],
                user_id=share_group['user_id'],
            )
        except exception.OverQuota as e:
            reservations = None
            LOG.exception(
                ("Failed to update quota for deleting share group: %s"), e)

        try:
            self.share_rpcapi.delete_share_group(context, share_group)
        except Exception:
            with excutils.save_and_reraise_exception():
                QUOTAS.rollback(context, reservations)

        if reservations:
            QUOTAS.commit(
                context, reservations,
                project_id=share_group['project_id'],
                user_id=share_group['user_id'],
            )

    def update(self, context, group, fields):
        return self.db.share_group_update(context, group['id'], fields)

    def get(self, context, share_group_id):
        return self.db.share_group_get(context, share_group_id)

    def get_all(self, context, detailed=True, search_opts=None, sort_key=None,
                sort_dir=None):

        if search_opts is None:
            search_opts = {}

        LOG.debug("Searching for share_groups by: %s",
                  six.text_type(search_opts))

        # Get filtered list of share_groups
        if search_opts.pop('all_tenants', 0) and context.is_admin:
            share_groups = self.db.share_group_get_all(
                context, detailed=detailed, filters=search_opts,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            share_groups = self.db.share_group_get_all_by_project(
                context, context.project_id, detailed=detailed,
                filters=search_opts, sort_key=sort_key, sort_dir=sort_dir)

        return share_groups

    def create_share_group_snapshot(self, context, name=None, description=None,
                                    share_group_id=None):
        """Create new share group snapshot."""
        options = {
            'share_group_id': share_group_id,
            'name': name,
            'description': description,
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_CREATING,
        }
        share_group = self.db.share_group_get(context, share_group_id)
        # Check status of group, must be active
        if not share_group['status'] == constants.STATUS_AVAILABLE:
            msg = (_("Share group status must be %s")
                   % constants.STATUS_AVAILABLE)
            raise exception.InvalidShareGroup(reason=msg)

        # Create members for every share in the group
        shares = self.db.share_get_all_by_share_group_id(
            context, share_group_id)

        # Check status of all shares, they must be active in order to snap
        # the group
        for s in shares:
            if not s['status'] == constants.STATUS_AVAILABLE:
                msg = (_("Share %(s)s in share group must have status "
                         "of %(status)s in order to create a group snapshot")
                       % {"s": s['id'],
                          "status": constants.STATUS_AVAILABLE})
                raise exception.InvalidShareGroup(reason=msg)

        try:
            reservations = QUOTAS.reserve(context, share_group_snapshots=1)
        except exception.OverQuota as e:
            overs = e.kwargs['overs']
            usages = e.kwargs['usages']
            quotas = e.kwargs['quotas']

            def _consumed(name):
                return (usages[name]['reserved'] + usages[name]['in_use'])

            if 'share_group_snapshots' in overs:
                msg = ("Quota exceeded for '%(s_uid)s' user in '%(s_pid)s' "
                       "project. (%(d_consumed)d of "
                       "%(d_quota)d already consumed).")
                LOG.warning(msg, {
                    's_pid': context.project_id,
                    's_uid': context.user_id,
                    'd_consumed': _consumed('share_group_snapshots'),
                    'd_quota': quotas['share_group_snapshots'],
                })
            raise exception.ShareGroupSnapshotsLimitExceeded()

        snap = None
        try:
            snap = self.db.share_group_snapshot_create(context, options)
            members = []
            for s in shares:
                member_options = {
                    'share_group_snapshot_id': snap['id'],
                    'user_id': context.user_id,
                    'project_id': context.project_id,
                    'status': constants.STATUS_CREATING,
                    'size': s['size'],
                    'share_proto': s['share_proto'],
                    'share_instance_id': s.instance['id']
                }
                member = self.db.share_group_snapshot_member_create(
                    context, member_options)
                members.append(member)

            # Cast to share manager
            self.share_rpcapi.create_share_group_snapshot(
                context, snap, share_group['host'])
        except Exception:
            with excutils.save_and_reraise_exception():
                # This will delete the snapshot and all of it's members
                if snap:
                    self.db.share_group_snapshot_destroy(context, snap['id'])
                QUOTAS.rollback(context, reservations)

        try:
            QUOTAS.commit(context, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                QUOTAS.rollback(context, reservations)

        return snap

    def delete_share_group_snapshot(self, context, snap):
        """Delete share group snapshot."""
        snap_id = snap['id']
        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
        share_group = self.db.share_group_get(context, snap['share_group_id'])
        if not snap['status'] in statuses:
            msg = (_("Share group snapshot status must be one of"
                     " %(statuses)s") % {"statuses": statuses})
            raise exception.InvalidShareGroupSnapshot(reason=msg)

        self.db.share_group_snapshot_update(
            context, snap_id, {'status': constants.STATUS_DELETING})

        try:
            reservations = QUOTAS.reserve(
                context,
                share_group_snapshots=-1,
                project_id=snap['project_id'],
                user_id=snap['user_id'],
            )
        except exception.OverQuota as e:
            reservations = None
            LOG.exception(
                ("Failed to update quota for deleting share group snapshot: "
                 "%s"), e)

        # Cast to share manager
        self.share_rpcapi.delete_share_group_snapshot(
            context, snap, share_group['host'])

        if reservations:
            QUOTAS.commit(
                context, reservations,
                project_id=snap['project_id'],
                user_id=snap['user_id'],
            )

    def update_share_group_snapshot(self, context, share_group_snapshot,
                                    fields):
        return self.db.share_group_snapshot_update(
            context, share_group_snapshot['id'], fields)

    def get_share_group_snapshot(self, context, snapshot_id):
        return self.db.share_group_snapshot_get(context, snapshot_id)

    def get_all_share_group_snapshots(self, context, detailed=True,
                                      search_opts=None, sort_key=None,
                                      sort_dir=None):
        if search_opts is None:
            search_opts = {}
        LOG.debug("Searching for share group snapshots by: %s",
                  six.text_type(search_opts))

        # Get filtered list of share group snapshots
        if search_opts.pop('all_tenants', 0) and context.is_admin:
            share_group_snapshots = self.db.share_group_snapshot_get_all(
                context, detailed=detailed, filters=search_opts,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            share_group_snapshots = (
                self.db.share_group_snapshot_get_all_by_project(
                    context, context.project_id, detailed=detailed,
                    filters=search_opts, sort_key=sort_key, sort_dir=sort_dir,
                )
            )
        return share_group_snapshots

    def get_all_share_group_snapshot_members(self, context,
                                             share_group_snapshot_id):
        members = self.db.share_group_snapshot_members_get_all(
            context,  share_group_snapshot_id)
        return members
