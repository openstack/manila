# Copyright 2016 Huawei Inc.
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
from manila.api.views import share_snapshot_instances as instance_view
from manila import db
from manila import exception
from manila.i18n import _
from manila import share


class ShareSnapshotInstancesController(wsgi.Controller,
                                       wsgi.AdminActionsMixin):
    """The share snapshot instances API controller for the OpenStack API."""

    resource_name = 'share_snapshot_instance'
    _view_builder_class = instance_view.ViewBuilder

    def __init__(self):
        self.share_api = share.API()
        super(self.__class__, self).__init__()

    @wsgi.Controller.api_version('2.19')
    @wsgi.Controller.authorize
    def show(self, req, id):
        context = req.environ['manila.context']
        try:
            snapshot_instance = db.share_snapshot_instance_get(
                context, id)
        except exception.ShareSnapshotInstanceNotFound:
            msg = (_("Snapshot instance %s not found.") % id)
            raise exc.HTTPNotFound(explanation=msg)
        return self._view_builder.detail(req, snapshot_instance)

    @wsgi.Controller.api_version('2.19')
    @wsgi.Controller.authorize
    def index(self, req):
        """Return a summary list of snapshot instances."""
        return self._get_instances(req)

    @wsgi.Controller.api_version('2.19')
    @wsgi.Controller.authorize
    def detail(self, req):
        """Returns a detailed list of snapshot instances."""
        return self._get_instances(req, is_detail=True)

    def _get_instances(self, req, is_detail=False):
        """Returns list of snapshot instances."""
        context = req.environ['manila.context']
        snapshot_id = req.params.get('snapshot_id')

        instances = db.share_snapshot_instance_get_all_with_filters(
            context, {'snapshot_ids': snapshot_id})

        if is_detail:
            instances = self._view_builder.detail_list(req, instances)
        else:
            instances = self._view_builder.summary_list(req, instances)
        return instances

    @wsgi.Controller.api_version('2.19')
    @wsgi.action('reset_status')
    def reset_status(self, req, id, body):
        """Reset the 'status' attribute in the database."""
        return self._reset_status(req, id, body)

    def _update(self, *args, **kwargs):
        db.share_snapshot_instance_update(*args, **kwargs)


def create_resource():
    return wsgi.Resource(ShareSnapshotInstancesController())
