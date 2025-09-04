# Copyright 2013 NetApp
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

"""The share snapshots api."""

from oslo_log import log

from manila.api.openstack import wsgi
from manila.api.v2 import share_snapshots
from manila.api.views import share_snapshots as snapshot_views
from manila import share

LOG = log.getLogger(__name__)


class ShareSnapshotsController(
    share_snapshots.ShareSnapshotMixin, wsgi.Controller,
    wsgi.AdminActionsMixin
):
    """The Share Snapshots API controller for the OpenStack API."""

    resource_name = 'share_snapshot'
    _view_builder_class = snapshot_views.ViewBuilder

    def __init__(self):
        super(ShareSnapshotsController, self).__init__()
        self.share_api = share.API()

    @wsgi.action('os-reset_status')
    def snapshot_reset_status_legacy(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.action('os-force_delete')
    def snapshot_force_delete_legacy(self, req, id, body):
        return self._force_delete(req, id, body)


def create_resource():
    return wsgi.Resource(ShareSnapshotsController())
