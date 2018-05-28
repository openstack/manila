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

from manila.api.openstack import wsgi
from manila.api.views import share_accesses as share_access_views
from manila import exception
from manila.i18n import _
from manila import share


class ShareAccessesController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The Share accesses API V2 controller for the OpenStack API."""

    resource_name = 'share_access_rule'
    _view_builder_class = share_access_views.ViewBuilder

    def __init__(self):
        super(ShareAccessesController, self).__init__()
        self.share_api = share.API()

    @wsgi.Controller.api_version('2.45')
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Return data about the given share access rule."""
        context = req.environ['manila.context']
        share_access = self._get_share_access(context, id)
        return self._view_builder.view(req, share_access)

    def _get_share_access(self, context, share_access_id):
        try:
            return self.share_api.access_get(context, share_access_id)
        except exception.NotFound:
            msg = _("Share access rule %s not found.") % share_access_id
            raise webob.exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.api_version('2.45')
    @wsgi.Controller.authorize
    def index(self, req):
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
        try:
            share = self.share_api.get(context, share_id)
        except exception.NotFound:
            msg = _("Share %s not found.") % share_id
            raise webob.exc.HTTPBadRequest(explanation=msg)
        access_rules = self.share_api.access_get_all(
            context, share, search_opts)

        return self._view_builder.list_view(req, access_rules)


def create_resource():
    return wsgi.Resource(ShareAccessesController())
