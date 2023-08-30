# Copyright 2011 OpenStack LLC.
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

"""RequestContext: context for requests that persist through all of manila."""

import copy

from oslo_context import context
from oslo_db.sqlalchemy import enginefacade
from oslo_utils import timeutils

from manila.i18n import _
from manila import policy


@enginefacade.transaction_context_provider
class RequestContext(context.RequestContext):
    """Security context and request information.

    Represents the user taking a given action within the system.

    """

    def __init__(self, user_id=None, project_id=None, is_admin=None,
                 read_deleted="no", project_name=None, remote_address=None,
                 timestamp=None, quota_class=None, service_catalog=None,
                 **kwargs):
        """Initialize RequestContext.

        :param read_deleted: 'no' indicates deleted records are hidden, 'yes'
            indicates deleted records are visible, 'only' indicates that
            *only* deleted records are visible.

        :param kwargs: Extra arguments passed transparently to
            oslo_context.RequestContext.
        """
        kwargs.setdefault('user_id', user_id)
        kwargs.setdefault('project_id', project_id)

        super(RequestContext, self).__init__(is_admin=is_admin, **kwargs)

        self.project_name = project_name
        if self.is_admin is None:
            self.is_admin = policy.check_is_admin(self)
        elif self.is_admin and 'admin' not in self.roles:
            self.roles.append('admin')
        # a "service" user's token will contain "service_roles"
        self.is_service = kwargs.get('service_roles') or False
        self.read_deleted = read_deleted
        self.remote_address = remote_address
        if not timestamp:
            timestamp = timeutils.utcnow()
        elif isinstance(timestamp, str):
            timestamp = timeutils.parse_isotime(timestamp)
        self.timestamp = timestamp
        self.quota_class = quota_class
        if service_catalog:
            self.service_catalog = [s for s in service_catalog
                                    if s.get('type') in ('compute', 'volume')]
        else:
            self.service_catalog = []

    def _get_read_deleted(self):
        return self._read_deleted

    def _set_read_deleted(self, read_deleted):
        if read_deleted not in ('no', 'yes', 'only'):
            raise ValueError(_("read_deleted can only be one of 'no', "
                               "'yes' or 'only', not %r") % read_deleted)
        self._read_deleted = read_deleted

    def _del_read_deleted(self):
        del self._read_deleted

    read_deleted = property(_get_read_deleted, _set_read_deleted,
                            _del_read_deleted)

    def to_dict(self):
        values = super(RequestContext, self).to_dict()
        values['user_id'] = self.user_id
        values['project_id'] = self.project_id
        values['project_name'] = self.project_name
        values['domain_id'] = self.domain_id
        values['read_deleted'] = self.read_deleted
        values['remote_address'] = self.remote_address
        values['timestamp'] = self.timestamp.isoformat()
        values['quota_class'] = self.quota_class
        values['service_catalog'] = self.service_catalog
        values['request_id'] = self.request_id
        return values

    @classmethod
    def from_dict(cls, values):
        return cls(
            user_id=values.get('user_id'),
            project_id=values.get('project_id'),
            project_name=values.get('project_name'),
            domain_id=values.get('domain_id'),
            read_deleted=values.get('read_deleted', 'no'),
            remote_address=values.get('remote_address'),
            timestamp=values.get('timestamp'),
            quota_class=values.get('quota_class'),
            service_catalog=values.get('service_catalog'),
            request_id=values.get('request_id'),
            is_admin=values.get('is_admin'),
            roles=values.get('roles'),
            auth_token=values.get('auth_token'),
            user_domain_id=values.get('user_domain_id'),
            project_domain_id=values.get('project_domain_id')
        )

    def elevated(self, read_deleted=None, overwrite=False):
        """Return a version of this context with admin flag set."""
        ctx = copy.deepcopy(self)
        ctx.is_admin = True

        if 'admin' not in ctx.roles:
            ctx.roles.append('admin')

        if read_deleted is not None:
            ctx.read_deleted = read_deleted

        return ctx

    def to_policy_values(self):
        policy = super(RequestContext, self).to_policy_values()
        policy['is_admin'] = self.is_admin
        return policy


def get_admin_context(read_deleted="no"):
    return RequestContext(user_id=None,
                          project_id=None,
                          is_admin=True,
                          read_deleted=read_deleted,
                          overwrite=False)
