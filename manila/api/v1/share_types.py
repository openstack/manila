# Copyright (c) 2014 NetApp, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""The share type & share types extra specs extension."""

from oslo_utils import strutils
import six
from webob import exc

from manila.api.openstack import wsgi
from manila.api.views import types as views_types
from manila import exception
from manila.i18n import _
from manila import policy
from manila.share import share_types

RESOURCE_NAME = 'share_type'


class ShareTypesController(wsgi.Controller):
    """The share types API controller for the OpenStack API."""

    _view_builder_class = views_types.ViewBuilder

    def index(self, req):
        """Returns the list of share types."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'index')

        limited_types = self._get_share_types(req)
        req.cache_db_share_types(limited_types)
        return self._view_builder.index(req, limited_types)

    def show(self, req, id):
        """Return a single share type item."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'show')

        try:
            share_type = share_types.get_share_type(context, id)
        except exception.NotFound:
            msg = _("Share type not found.")
            raise exc.HTTPNotFound(explanation=msg)

        share_type['id'] = six.text_type(share_type['id'])
        req.cache_db_share_type(share_type)
        return self._view_builder.show(req, share_type)

    def default(self, req):
        """Return default volume type."""
        context = req.environ['manila.context']
        policy.check_policy(context, RESOURCE_NAME, 'default')

        try:
            share_type = share_types.get_default_share_type(context)
        except exception.NotFound:
            msg = _("Share type not found")
            raise exc.HTTPNotFound(explanation=msg)

        if not share_type:
            msg = _("Default share type not found")
            raise exc.HTTPNotFound(explanation=msg)

        share_type['id'] = six.text_type(share_type['id'])
        return self._view_builder.show(req, share_type)

    def _get_share_types(self, req):
        """Helper function that returns a list of type dicts."""
        filters = {}
        context = req.environ['manila.context']
        if context.is_admin:
            # Only admin has query access to all share types
            filters['is_public'] = self._parse_is_public(
                req.params.get('is_public'))
        else:
            filters['is_public'] = True
        limited_types = share_types.get_all_types(
            context, search_opts=filters).values()
        return list(limited_types)

    @staticmethod
    def _parse_is_public(is_public):
        """Parse is_public into something usable.

        * True: API should list public share types only
        * False: API should list private share types only
        * None: API should list both public and private share types
        """
        if is_public is None:
            # preserve default value of showing only public types
            return True
        elif six.text_type(is_public).lower() == "all":
            return None
        else:
            try:
                return strutils.bool_from_string(is_public, strict=True)
            except ValueError:
                msg = _('Invalid is_public filter [%s]') % is_public
                raise exc.HTTPBadRequest(explanation=msg)


def create_resource():
    return wsgi.Resource(ShareTypesController())
