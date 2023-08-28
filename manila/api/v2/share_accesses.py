# Copyright 2018 Huawei Corporation.
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

"""The share accesses api."""

import ast

import webob

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import share_accesses as share_access_views
from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.lock import api as resource_locks
from manila import share


class ShareAccessesController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The Share accesses API V2 controller for the OpenStack API."""

    resource_name = 'share_access_rule'
    _view_builder_class = share_access_views.ViewBuilder

    def __init__(self):
        super(ShareAccessesController, self).__init__()
        self.share_api = share.API()
        self.resource_locks_api = resource_locks.API()

    @wsgi.Controller.api_version('2.45')
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Return data about the given share access rule."""
        context = req.environ['manila.context']
        share_access = self._get_share_access(context, id)
        restricted = self._is_rule_restricted(context, id)
        if restricted:
            share_access['restricted'] = True
        return self._view_builder.view(req, share_access)

    def _is_rule_restricted(self, context, id):
        search_opts = {
            'resource_id': id,
            'resource_action': constants.RESOURCE_ACTION_SHOW,
            'resource_type': 'access_rule'
        }
        locks, count = self.resource_locks_api.get_all(
            context, search_opts, show_count=True)

        if count:
            return self.resource_locks_api.access_is_restricted(context,
                                                                locks[0])
        return False

    def _get_share_access(self, context, share_access_id):
        try:
            return self.share_api.access_get(context, share_access_id)
        except exception.NotFound:
            msg = _("Share access rule %s not found.") % share_access_id
            raise webob.exc.HTTPNotFound(explanation=msg)

    def _validate_search_opts(self, req, search_opts):
        """Check if search opts parameters are valid."""
        access_type = search_opts.get('access_type', None)
        access_to = search_opts.get('access_to', None)

        if access_type and access_type not in ['ip', 'user', 'cert', 'cephx']:
            raise exception.InvalidShareAccessType(type=access_type)

        # If access_to is present but access type is not, it gets tricky to
        # validate its content
        if access_to and not access_type:
            msg = _("'access_type' parameter must be provided when specifying "
                    "'access_to'.")
            raise exception.InvalidInput(reason=msg)

        if access_type and access_to:
            common.validate_access(access_type=access_type,
                                   access_to=access_to,
                                   enable_ceph=True,
                                   enable_ipv6=True)

        access_level = search_opts.get('access_level', None)
        if access_level and access_level not in constants.ACCESS_LEVELS:
            raise exception.InvalidShareAccessLevel(level=access_level)

    @wsgi.Controller.authorize('index')
    def _index(self, req, support_for_access_filters=False):
        """Returns the list of access rules for a given share."""
        context = req.environ['manila.context']
        search_opts = {}
        search_opts.update(req.GET)
        if 'share_id' not in search_opts:
            msg = _("The field 'share_id' has to be specified.")
            raise webob.exc.HTTPBadRequest(explanation=msg)
        share_id = search_opts.pop('share_id', None)

        if 'metadata' in search_opts:
            search_opts['metadata'] = ast.literal_eval(
                search_opts['metadata'])
        if support_for_access_filters:
            try:
                self._validate_search_opts(req, search_opts)
            except (exception.InvalidShareAccessLevel,
                    exception.InvalidShareAccessType) as e:
                raise webob.exc.HTTPBadRequest(explanation=e.msg)
        try:
            share = self.share_api.get(context, share_id)
        except exception.NotFound:
            msg = _("Share %s not found.") % share_id
            raise webob.exc.HTTPBadRequest(explanation=msg)
        access_rules = self.share_api.access_get_all(
            context, share, search_opts)
        rule_list = []
        for rule in access_rules:
            restricted = self._is_rule_restricted(context, rule['id'])
            rule['restricted'] = restricted
            if (('access_to' in search_opts or 'access_key' in search_opts)
                    and restricted):
                continue
            rule_list.append(rule)

        return self._view_builder.list_view(req, rule_list)

    @wsgi.Controller.api_version('2.45', '2.81')
    def index(self, req):
        return self._index(req)

    @wsgi.Controller.api_version('2.82')
    def index(self, req): # pylint: disable=function-redefined  # noqa F811
        return self._index(req, support_for_access_filters=True)


def create_resource():
    return wsgi.Resource(ShareAccessesController())
