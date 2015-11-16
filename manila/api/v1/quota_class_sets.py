# Copyright 2012 OpenStack LLC.
# Copyright (c) 2015 Mirantis inc.
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

import webob

from manila.api.openstack import wsgi
from manila.api.views import quota_class_sets as quota_class_sets_views
from manila import db
from manila import exception
from manila import quota

QUOTAS = quota.QUOTAS


class QuotaClassSetsController(wsgi.Controller):

    resource_name = "quota_class_set"
    _view_builder_class = quota_class_sets_views.ViewBuilder

    @wsgi.Controller.authorize
    def show(self, req, id):
        context = req.environ['manila.context']
        try:
            db.authorize_quota_class_context(context, id)
        except exception.NotAuthorized:
            raise webob.exc.HTTPForbidden()

        return self._view_builder.detail_list(
            QUOTAS.get_class_quotas(context, id), id)

    @wsgi.Controller.authorize
    def update(self, req, id, body):
        context = req.environ['manila.context']
        quota_class = id
        for key in body.get(self.resource_name, {}).keys():
            if key in QUOTAS:
                value = int(body[self.resource_name][key])
                try:
                    db.quota_class_update(context, quota_class, key, value)
                except exception.QuotaClassNotFound:
                    db.quota_class_create(context, quota_class, key, value)
                except exception.AdminRequired:
                    raise webob.exc.HTTPForbidden()
        return self._view_builder.detail_list(
            QUOTAS.get_class_quotas(context, quota_class))


def create_resource():
    return wsgi.Resource(QuotaClassSetsController())
