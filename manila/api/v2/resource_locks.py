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

"""The resource_locks API controller module.

This module handles the following requests:
GET /resource-locks
GET /resource-locks/{lock_id}
POST /resource-locks
PUT /resource-locks/{lock_id}
DELETE /resource-locks/{lock_id}
"""

from http import client as http_client

from oslo_utils import timeutils
from oslo_utils import uuidutils
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import resource_locks as resource_locks_view
from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.lock import api as resource_locks
from manila import utils

RESOURCE_LOCKS_MIN_API_VERSION = '2.81'


class ResourceLocksController(wsgi.Controller):
    """The Resource Locks API controller for the OpenStack API."""

    _view_builder_class = resource_locks_view.ViewBuilder
    resource_name = 'resource_lock'

    def _check_body(self, body, lock_to_update=None):
        if 'resource_lock' not in body:
            raise exc.HTTPBadRequest(
                explanation="Malformed request body.")
        lock_data = body['resource_lock']
        resource_type = (
            lock_to_update['resource_type']
            if lock_to_update
            else lock_data.get('resource_type', constants.SHARE_RESOURCE_TYPE)
        )
        resource_id = lock_data.get('resource_id') or ''
        resource_action = (lock_data.get('resource_action') or
                           constants.RESOURCE_ACTION_DELETE)
        lock_reason = lock_data.get('lock_reason') or ''

        if len(lock_reason) > 1023:
            msg = _("'lock_reason' can contain a maximum of 1023 characters.")
            raise exc.HTTPBadRequest(explanation=msg)
        if resource_type not in constants.RESOURCE_LOCK_RESOURCE_TYPES:
            msg = _("'resource_type' is required and must be one "
                    "of %(resource_types)s") % {
                'resource_types': constants.RESOURCE_LOCK_RESOURCE_TYPES
            }
            raise exc.HTTPBadRequest(explanation=msg)
        resource_type_lock_actions = (
            constants.RESOURCE_LOCK_ACTIONS_MAPPING[resource_type])
        if resource_action not in resource_type_lock_actions:
            msg = _("'resource_action' can only be one of %(actions)s" %
                    {'actions': resource_type_lock_actions})
            raise exc.HTTPBadRequest(explanation=msg)

        if lock_to_update:
            if set(lock_data.keys()) - {'resource_action', 'lock_reason'}:
                msg = _("Only 'resource_action' and 'lock_reason' "
                        "can be updated.")
                raise exc.HTTPBadRequest(explanation=msg)
        else:
            if not uuidutils.is_uuid_like(resource_id):
                msg = _("Resource ID is required and must be in uuid format.")
                raise exc.HTTPBadRequest(explanation=msg)

    def __init__(self):
        self.resource_locks_api = resource_locks.API()
        super(ResourceLocksController, self).__init__()

    @wsgi.Controller.api_version(RESOURCE_LOCKS_MIN_API_VERSION)
    @wsgi.Controller.authorize('get_all')
    def index(self, req):
        """Returns a list of locks, transformed through view builder."""
        context = req.environ['manila.context']
        filters = req.params.copy()

        params = common.get_pagination_params(req)
        limit, offset = [params.pop('limit', None), params.pop('offset', None)]
        sort_key, sort_dir = common.get_sort_params(filters)
        for key in ('limit', 'offset'):
            filters.pop(key, None)

        show_count = utils.get_bool_from_api_params(
            'with_count', {'with_count': filters.pop('with_count', False)})

        for time_comparison_filter in ['created_since', 'created_before']:
            if time_comparison_filter in filters:
                time_str = filters.get(time_comparison_filter)
                try:
                    parsed_time = timeutils.parse_isotime(time_str)
                    filters[time_comparison_filter] = parsed_time
                except ValueError:
                    msg = _('Invalid value specified for the query '
                            'key: %s') % time_comparison_filter
                    raise exc.HTTPBadRequest(explanation=msg)

        locks, count = self.resource_locks_api.get_all(context,
                                                       search_opts=filters,
                                                       limit=limit,
                                                       offset=offset,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir,
                                                       show_count=show_count)

        return self._view_builder.index(req,
                                        locks,
                                        count=count)

    @wsgi.Controller.api_version(RESOURCE_LOCKS_MIN_API_VERSION)
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Return an existing resource lock by ID."""
        context = req.environ['manila.context']
        try:
            resource_lock = self.resource_locks_api.get(context, id)
        except exception.ResourceLockNotFound as error:
            raise exc.HTTPNotFound(explanation=error.msg)
        return self._view_builder.detail(req, resource_lock)

    @wsgi.Controller.api_version(RESOURCE_LOCKS_MIN_API_VERSION)
    @wsgi.Controller.authorize
    @wsgi.action("delete")
    def delete(self, req, id):
        """Delete an existing resource lock."""
        context = req.environ['manila.context']
        try:
            self.resource_locks_api.delete(context, id)
        except exception.ResourceLockNotFound as error:
            raise exc.HTTPNotFound(explanation=error.msg)
        return webob.Response(status_int=http_client.NO_CONTENT)

    @wsgi.Controller.api_version(RESOURCE_LOCKS_MIN_API_VERSION)
    @wsgi.Controller.authorize
    def create(self, req, body):
        """Create a resource lock."""
        context = req.environ['manila.context']
        self._check_body(body)
        lock_data = body['resource_lock']
        try:
            resource_lock = self.resource_locks_api.create(
                context,
                resource_id=lock_data['resource_id'],
                resource_type=lock_data['resource_type'],
                resource_action=(lock_data.get('resource_action') or
                                 constants.RESOURCE_ACTION_DELETE),
                lock_reason=lock_data.get('lock_reason')
            )
        except exception.NotFound:
            raise exc.HTTPBadRequest(
                explanation="No such resource found.")
        except exception.InvalidInput as error:
            raise exc.HTTPConflict(explanation=error.msg)
        except exception.ResourceVisibilityLockExists:
            raise exc.HTTPConflict(
                "Resource's visibility is already locked by other user.")
        return self._view_builder.detail(req, resource_lock)

    @wsgi.Controller.api_version(RESOURCE_LOCKS_MIN_API_VERSION)
    @wsgi.Controller.authorize
    def update(self, req, id, body):
        """Update an existing resource lock."""
        context = req.environ['manila.context']
        try:
            resource_lock = self.resource_locks_api.get(context, id)
        except exception.NotFound as e:
            raise exc.HTTPNotFound(explanation=e.msg)

        self._check_body(body, lock_to_update=resource_lock)
        lock_data = body['resource_lock']
        try:
            resource_lock = self.resource_locks_api.update(
                context,
                resource_lock,
                lock_data,
            )
        except exception.InvalidInput as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        return self._view_builder.detail(req, resource_lock)


def create_resource():
    return wsgi.Resource(ResourceLocksController())
