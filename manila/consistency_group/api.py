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
Handles all requests relating to consistency groups.
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
from manila.scheduler import rpcapi as scheduler_rpcapi
from manila import share
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types


CONF = cfg.CONF

LOG = log.getLogger(__name__)


class API(base.Base):
    """API for interacting with the share manager."""

    def __init__(self, db_driver=None):
        self.scheduler_rpcapi = scheduler_rpcapi.SchedulerAPI()
        self.share_rpcapi = share_rpcapi.ShareAPI()
        self.share_api = share.API()
        super(API, self).__init__(db_driver)

    def create(self, context, name=None, description=None,
               share_type_ids=None, source_cgsnapshot_id=None,
               share_network_id=None):
        """Create new consistency group."""

        cgsnapshot = None
        original_cg = None
        if source_cgsnapshot_id:
            cgsnapshot = self.db.cgsnapshot_get(context, source_cgsnapshot_id)
            if cgsnapshot['status'] != constants.STATUS_AVAILABLE:
                msg = (_("Consistency group snapshot status must be %s")
                       % constants.STATUS_AVAILABLE)
                raise exception.InvalidCGSnapshot(reason=msg)

            original_cg = self.db.consistency_group_get(context, cgsnapshot[
                'consistency_group_id'])
            share_type_ids = [s['share_type_id'] for s in original_cg[
                'share_types']]

        # Get share_type_objects
        share_type_objects = []
        driver_handles_share_servers = None
        for share_type_id in (share_type_ids or []):
            try:
                share_type_object = share_types.get_share_type(
                    context, share_type_id)
            except exception.ShareTypeNotFound:
                msg = _("Share type with id %s could not be found")
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
                not (source_cgsnapshot_id or share_network_id)):
            msg = _("When using a share type with the "
                    "driver_handles_share_servers extra spec as "
                    "True, a share_network_id must be provided.")
            raise exception.InvalidInput(reason=msg)

        options = {
            'source_cgsnapshot_id': source_cgsnapshot_id,
            'share_network_id': share_network_id,
            'name': name,
            'description': description,
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_CREATING,
            'share_types': share_type_ids
        }
        if original_cg:
            options['host'] = original_cg['host']

        cg = self.db.consistency_group_create(context, options)

        try:
            if cgsnapshot:
                members = self.db.cgsnapshot_members_get_all(
                    context, source_cgsnapshot_id)
                for member in members:
                    share_type = share_types.get_share_type(
                        context, member['share_type_id'])
                    member['share'] = self.db.share_instance_get(
                        context, member['share_instance_id'],
                        with_share_data=True)
                    self.share_api.create(context, member['share_proto'],
                                          member['size'], None, None,
                                          consistency_group_id=cg['id'],
                                          cgsnapshot_member=member,
                                          share_type=share_type,
                                          share_network_id=share_network_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.consistency_group_destroy(context.elevated(), cg['id'])

        request_spec = {'consistency_group_id': cg['id']}
        request_spec.update(options)
        request_spec['share_types'] = share_type_objects

        if cgsnapshot and original_cg:
            self.share_rpcapi.create_consistency_group(
                context, cg, original_cg['host'])
        else:
            self.scheduler_rpcapi.create_consistency_group(
                context, cg_id=cg['id'], request_spec=request_spec,
                filter_properties={})

        return cg

    def delete(self, context, cg):
        """Delete consistency group."""

        cg_id = cg['id']
        if not cg['host']:
            self.db.consistency_group_destroy(context.elevated(), cg_id)
            return

        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
        if not cg['status'] in statuses:
            msg = (_("Consistency group status must be one of %(statuses)s")
                   % {"statuses": statuses})
            raise exception.InvalidConsistencyGroup(reason=msg)

        # NOTE(ameade): check for cgsnapshots in the CG
        if self.db.count_cgsnapshots_in_consistency_group(context, cg_id):
            msg = (_("Cannot delete a consistency group with cgsnapshots"))
            raise exception.InvalidConsistencyGroup(reason=msg)

        # NOTE(ameade): check for shares in the CG
        if self.db.count_shares_in_consistency_group(context, cg_id):
            msg = (_("Cannot delete a consistency group with shares"))
            raise exception.InvalidConsistencyGroup(reason=msg)

        cg = self.db.consistency_group_update(
            context, cg_id, {'status': constants.STATUS_DELETING})

        self.share_rpcapi.delete_consistency_group(context, cg)

    def update(self, context, cg, fields):
        return self.db.consistency_group_update(context, cg['id'], fields)

    def get(self, context, cg_id):
        return self.db.consistency_group_get(context, cg_id)

    def get_all(self, context, detailed=True, search_opts=None):

        if search_opts is None:
            search_opts = {}

        LOG.debug("Searching for consistency_groups by: %s",
                  six.text_type(search_opts))

        # Get filtered list of consistency_groups
        if context.is_admin and search_opts.get('all_tenants'):
            consistency_groups = self.db.consistency_group_get_all(
                context, detailed=detailed)
        else:
            consistency_groups = self.db.consistency_group_get_all_by_project(
                context, context.project_id, detailed=detailed)

        return consistency_groups

    def create_cgsnapshot(self, context, name=None, description=None,
                          consistency_group_id=None):
        """Create new cgsnapshot."""

        options = {
            'consistency_group_id': consistency_group_id,
            'name': name,
            'description': description,
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_CREATING,
        }

        cg = self.db.consistency_group_get(context, consistency_group_id)
        # Check status of CG, must be active
        if not cg['status'] == constants.STATUS_AVAILABLE:
            msg = (_("Consistency group status must be %s")
                   % constants.STATUS_AVAILABLE)
            raise exception.InvalidConsistencyGroup(reason=msg)

        # Create members for every share in the CG
        shares = self.db.share_get_all_by_consistency_group_id(
            context, consistency_group_id)

        # Check status of all shares, they must be active in order to snap
        # the CG
        for s in shares:
            if not s['status'] == constants.STATUS_AVAILABLE:
                msg = (_("Share %(s)s in consistency group must have status "
                         "of %(status)s in order to create a CG snapshot")
                       % {"s": s['id'],
                          "status": constants.STATUS_AVAILABLE})
                raise exception.InvalidConsistencyGroup(reason=msg)

        snap = self.db.cgsnapshot_create(context, options)

        try:
            members = []
            for s in shares:
                member_options = {
                    'cgsnapshot_id': snap['id'],
                    'user_id': context.user_id,
                    'project_id': context.project_id,
                    'status': constants.STATUS_CREATING,
                    'size': s['size'],
                    'share_proto': s['share_proto'],
                    'share_type_id': s['share_type_id'],
                    'share_id': s['id'],
                    'share_instance_id': s.instance['id']
                }
                member = self.db.cgsnapshot_member_create(context,
                                                          member_options)
                members.append(member)

            # Cast to share manager
            self.share_rpcapi.create_cgsnapshot(context, snap, cg['host'])
        except Exception:
            with excutils.save_and_reraise_exception():
                # This will delete the snapshot and all of it's members
                self.db.cgsnapshot_destroy(context, snap['id'])

        return snap

    def delete_cgsnapshot(self, context, snap):
        """Delete consistency group snapshot."""

        snap_id = snap['id']

        cg = self.db.consistency_group_get(context,
                                           snap['consistency_group_id'])

        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
        if not snap['status'] in statuses:
            msg = (_("Consistency group snapshot status must be one of"
                     " %(statuses)s")
                   % {"statuses": statuses})
            raise exception.InvalidCGSnapshot(reason=msg)

        self.db.cgsnapshot_update(context, snap_id,
                                  {'status': constants.STATUS_DELETING})

        # Cast to share manager
        self.share_rpcapi.delete_cgsnapshot(context, snap, cg['host'])

    def update_cgsnapshot(self, context, cg, fields):
        return self.db.cgsnapshot_update(context, cg['id'], fields)

    def get_cgsnapshot(self, context, snapshot_id):
        return self.db.cgsnapshot_get(context, snapshot_id)

    def get_all_cgsnapshots(self, context, detailed=True, search_opts=None):

        if search_opts is None:
            search_opts = {}

        LOG.debug("Searching for consistency group snapshots by: %s",
                  six.text_type(search_opts))

        # Get filtered list of consistency_groups
        if context.is_admin and search_opts.get('all_tenants'):
            cgsnapshots = self.db.cgsnapshot_get_all(
                context, detailed=detailed)
        else:
            cgsnapshots = self.db.cgsnapshot_get_all_by_project(
                context, context.project_id, detailed=detailed)

        return cgsnapshots

    def get_all_cgsnapshot_members(self, context, cgsnapshot_id):
        members = self.db.cgsnapshot_members_get_all(context,
                                                     cgsnapshot_id)

        return members
