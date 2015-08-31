# Copyright 2015 Mirantis Inc.
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

from webob import exc

from manila.api.openstack import wsgi
from manila.api.views import share_instance as instance_view
from manila import db
from manila import exception
from manila import policy
from manila import share


class ShareInstancesController(wsgi.Controller):
    """The share instances API controller for the OpenStack API."""

    resource_name = 'share_instance'
    _view_builder_class = instance_view.ViewBuilder

    def __init__(self):
        self.share_api = share.API()
        super(ShareInstancesController, self).__init__()

    def _authorize(self, context, action):
        try:
            policy.check_policy(context, self.resource_name, action)
        except exception.PolicyNotAuthorized:
            raise exc.HTTPForbidden()

    @wsgi.Controller.api_version("1.4")
    def index(self, req):
        context = req.environ['manila.context']
        self._authorize(context, 'index')

        instances = db.share_instances_get_all(context)
        return self._view_builder.detail_list(req, instances)

    @wsgi.Controller.api_version("1.4")
    def show(self, req, id):
        context = req.environ['manila.context']
        self._authorize(context, 'show')

        try:
            instance = db.share_instance_get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, instance)

    @wsgi.Controller.api_version("1.4")
    def get_share_instances(self, req, share_id):
        context = req.environ['manila.context']
        self._authorize(context, 'index')

        try:
            share = self.share_api.get(context, share_id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        view = instance_view.ViewBuilder()
        return view.detail_list(req, share.instances)


def create_resource():
    return wsgi.Resource(ShareInstancesController())