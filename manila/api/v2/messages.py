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

"""The messages API controller module.

This module handles the following requests:
GET /messages
GET /messages/<message_id>
DELETE /messages/<message_id>
"""

import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import messages as messages_view
from manila import exception
from manila.message import api as message_api

MESSAGES_BASE_MICRO_VERSION = '2.37'


class MessagesController(wsgi.Controller):
    """The User Messages API controller for the OpenStack API."""

    _view_builder_class = messages_view.ViewBuilder
    resource_name = 'message'

    def __init__(self):
        self.message_api = message_api.API()
        super(MessagesController, self).__init__()

    @wsgi.Controller.api_version(MESSAGES_BASE_MICRO_VERSION)
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Return the given message."""
        context = req.environ['manila.context']

        try:
            message = self.message_api.get(context, id)
        except exception.MessageNotFound as error:
            raise exc.HTTPNotFound(explanation=error.msg)

        return self._view_builder.detail(req, message)

    @wsgi.Controller.api_version(MESSAGES_BASE_MICRO_VERSION)
    @wsgi.Controller.authorize
    @wsgi.action("delete")
    def delete(self, req, id):
        """Delete a message."""
        context = req.environ['manila.context']

        try:
            message = self.message_api.get(context, id)
            self.message_api.delete(context, message)
        except exception.MessageNotFound as error:
            raise exc.HTTPNotFound(explanation=error.msg)

        return webob.Response(status_int=204)

    @wsgi.Controller.api_version(MESSAGES_BASE_MICRO_VERSION)
    @wsgi.Controller.authorize('get_all')
    def index(self, req):
        """Returns a list of messages, transformed through view builder."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # Remove keys that are not related to message attrs
        search_opts.pop('limit', None)
        search_opts.pop('marker', None)
        sort_key = search_opts.pop('sort_key', 'created_at')
        sort_dir = search_opts.pop('sort_dir', 'desc')

        messages = self.message_api.get_all(
            context, search_opts=search_opts, sort_dir=sort_dir,
            sort_key=sort_key)
        limited_list = common.limited(messages, req)

        return self._view_builder.index(req, limited_list)


def create_resource():
    return wsgi.Resource(MessagesController())
