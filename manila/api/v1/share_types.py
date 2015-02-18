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

import six
from webob import exc

from manila.api.openstack import wsgi
from manila.api.views import types as views_types
from manila import exception
from manila.i18n import _
from manila.share import share_types


class ShareTypesController(wsgi.Controller):
    """The share types API controller for the OpenStack API."""

    _view_builder_class = views_types.ViewBuilder

    def index(self, req):
        """Returns the list of share types."""
        context = req.environ['manila.context']
        shr_types = share_types.get_all_types(context).values()
        return self._view_builder.index(req, shr_types)

    def show(self, req, id):
        """Return a single share type item."""
        context = req.environ['manila.context']

        try:
            share_type = share_types.get_share_type(context, id)
        except exception.NotFound:
            msg = _("Share type not found.")
            raise exc.HTTPNotFound(explanation=msg)

        share_type['id'] = six.text_type(share_type['id'])
        return self._view_builder.show(req, share_type)

    def default(self, req):
        """Return default volume type."""
        context = req.environ['manila.context']

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


def create_resource():
    return wsgi.Resource(ShareTypesController())
