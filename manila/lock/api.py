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
Handles all requests related to resource locks.
"""

from oslo_log import log as logging

from manila.common import constants
from manila.db import base
from manila import exception
from manila import policy

LOG = logging.getLogger(__name__)


class API(base.Base):
    """API for handling resource locks."""

    resource_get = {
        "share": "share_get",
    }

    def _get_lock_context(self, context):
        if context.is_service:
            lock_context = 'service'
        elif context.is_admin:
            lock_context = 'admin'
        else:
            lock_context = 'user'
        return {
            'lock_context': lock_context,
            'user_id': context.user_id,
            'project_id': context.project_id,
        }

    def _check_allow_lock_manipulation(self, context, resource_lock):
        """Lock owners may not manipulate a lock if lock_context disallows

        The logic enforced by this method is that user created locks can be
        manipulated by all roles, service created locks can be manipulated
        by service and admin roles, while admin created locks can only be
        manipulated by admin role:

        +------------+------------+--------------+---------+
        | Requester  | Lock Owner | Lock Context | Allowed |
        +------------+------------+--------------+---------+
        | user       | user       | user         | yes     |
        | user       | user       | service      | no      |
        | user       | admin      | admin        | no      |
        | admin      | user       | user         | yes     |
        | admin      | user       | service      | yes     |
        | admin      | admin      | admin        | yes     |
        | service    | user       | user         | yes     |
        | service    | user       | service      | yes     |
        | service    | admin      | admin        | no      |
        +------------+------------+--------------+---------+
        """
        locked_by = resource_lock['lock_context']
        update_requested_by = self._get_lock_context(context)['lock_context']
        if ((locked_by == 'admin' and update_requested_by != 'admin')
                or (locked_by == 'service' and update_requested_by == 'user')):
            raise exception.NotAuthorized("Resource lock cannot be "
                                          "manipulated by user. Please "
                                          "contact the administrator.")

    def get(self, context, lock_id):
        """Return resource lock with the specified id."""
        return self.db.resource_lock_get(context, lock_id)

    def get_all(self, context, search_opts=None, limit=None,
                offset=None, sort_key="created_at", sort_dir="desc",
                show_count=False):
        """Return resource locks for the given context."""
        LOG.debug("Searching for locks by: %s", search_opts)

        search_opts = search_opts or {}
        if 'all_projects' in search_opts:
            allow_all_projects = policy.check_policy(
                context,
                'resource_lock',
                'get_all_projects',
                do_raise=False
            )
            LOG.warning("User %s not allowed to query locks across "
                        "all projects.", context.user_id)
            if not allow_all_projects:
                search_opts.pop('all_projects')
                search_opts.pop('project_id', None)

        locks, count = self.db.resource_lock_get_all(
            context,
            filters=search_opts,
            limit=limit, offset=offset,
            sort_key=sort_key,
            sort_dir=sort_dir,
            show_count=show_count,
        )

        return locks, count

    def create(self, context, resource_id=None, resource_type=None,
               resource_action=None, lock_reason=None):
        """Create a resource lock with the specified information."""
        get_res_method = getattr(self.db, self.resource_get[resource_type])
        resource = get_res_method(context, resource_id)
        policy.check_policy(context, 'resource_lock', 'create', resource)
        self._check_resource_state_for_locking(resource_action, resource)
        lock_context_data = self._get_lock_context(context)
        resource_lock = lock_context_data.copy()
        resource_lock.update({
            'resource_id': resource_id,
            'resource_action': resource_action,
            'lock_reason': lock_reason,
        })
        return self.db.resource_lock_create(context, resource_lock)

    def _check_resource_state_for_locking(self, resource_action, resource):
        """Check if resource is in a "disallowed" state for locking.

        For example, deletion lock on a "deleting" resource would be futile.
        """
        resource_state = resource.get('status', resource.get('state', ''))
        disallowed_statuses = ()
        if resource_action == 'delete':
            disallowed_statuses = (
                constants.STATUS_DELETING,
                constants.STATUS_ERROR_DELETING,
                constants.STATUS_UNMANAGING,
                constants.STATUS_MANAGE_ERROR_UNMANAGING,
                constants.STATUS_UNMANAGE_ERROR,
                constants.STATUS_UNMANAGED,  # not possible, future proofing
                constants.STATUS_DELETED,  # not possible, future proofing
            )
        if resource_state in disallowed_statuses:
            msg = "Resource status not suitable for locking"
            raise exception.InvalidInput(reason=msg)
        resource_is_soft_deleted = resource.get('is_soft_deleted', False)
        if resource_is_soft_deleted:
            msg = "Resource cannot be locked since it has been soft deleted."
            raise exception.InvalidInput(reason=msg)

    def update(self, context, lock_id, updates):
        """Update a resource lock with the specified information."""
        resource_lock = self.db.resource_lock_get(context, lock_id)
        policy.check_policy(context, 'resource_lock', 'update', resource_lock)
        self._check_allow_lock_manipulation(context, resource_lock)
        if 'resource_action' in updates:
            get_res_method = getattr(
                self.db,
                self.resource_get[resource_lock['resource_type']],
            )
            resource = get_res_method(context, resource_lock['resource_id'])
            self._check_resource_state_for_locking(
                updates['resource_action'], resource)
        return self.db.resource_lock_update(context, lock_id, updates)

    def delete(self, context, lock_id):
        """Delete resource lock with the specified id."""
        resource_lock = self.db.resource_lock_get(context, lock_id)
        policy.check_policy(context, 'resource_lock', 'delete', resource_lock)
        self._check_allow_lock_manipulation(context, resource_lock)
        self.db.resource_lock_delete(context, lock_id)
