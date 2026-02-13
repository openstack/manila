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

"""The shares api."""

from oslo_log import log

from manila.api.openstack import wsgi
from manila.api.v2 import shares
from manila.api.views import share_accesses as share_access_views
from manila.api.views import shares as share_views
from manila.lock import api as resource_locks
from manila import share

LOG = log.getLogger(__name__)


class ShareController(
    wsgi.Controller, shares.ShareMixin, wsgi.AdminActionsMixin
):
    """The Shares API v1 controller for the OpenStack API."""
    resource_name = 'share'
    _view_builder_class = share_views.ViewBuilder

    def __init__(self):
        super(ShareController, self).__init__()
        self.share_api = share.API()
        self.resource_locks_api = resource_locks.API()
        self._access_view_builder = share_access_views.ViewBuilder()

    @wsgi.action('os-reset_status')
    def share_reset_status(self, req, id, body):
        """Reset status of a share."""
        return self._reset_status(req, id, body)

    @wsgi.action('os-force_delete')
    def share_force_delete(self, req, id, body):
        """Delete a share, bypassing the check for status."""
        return self._force_delete(req, id, body)

    @wsgi.action('os-allow_access')
    def allow_access(self, req, id, body):
        """Add share access rule."""
        return self._allow_access(req, id, body)

    @wsgi.action('os-deny_access')
    def deny_access(self, req, id, body):
        """Remove share access rule."""
        return self._deny_access(req, id, body)

    @wsgi.action('os-access_list')
    def access_list(self, req, id, body):
        """List share access rules."""
        return self._access_list(req, id, body)

    @wsgi.action('os-extend')
    def extend(self, req, id, body):
        """Extend size of a share."""
        return self._extend(req, id, body)

    @wsgi.action('os-shrink')
    def shrink(self, req, id, body):
        """Shrink size of a share."""
        return self._shrink(req, id, body)


def create_resource():
    return wsgi.Resource(ShareController())
