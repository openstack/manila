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

from manila.api.openstack import wsgi
from manila.api.v1 import share_manage
from manila.api.v1 import share_unmanage
from manila.api.v1 import shares
from manila.api.views import shares as share_views
from manila import share


class ShareController(shares.ShareMixin,
                      share_manage.ShareManageMixin,
                      share_unmanage.ShareUnmanageMixin,
                      wsgi.Controller,
                      wsgi.AdminActionsMixin):
    """The Shares API v2 controller for the OpenStack API."""

    resource_name = 'share'
    _view_builder_class = share_views.ViewBuilder

    def __init__(self):
        super(self.__class__, self).__init__()
        self.share_api = share.API()

    @wsgi.Controller.api_version("2.4")
    def create(self, req, body):
        return self._create(req, body)

    @wsgi.Controller.api_version("2.0", "2.3")  # noqa
    def create(self, req, body):  # pylint: disable=E0102
        # Remove consistency group attributes
        body.get('share', {}).pop('consistency_group_id', None)
        share = self._create(req, body)
        return share

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-reset_status')
    def share_reset_status_legacy(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('reset_status')
    def share_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-force_delete')
    def share_force_delete_legacy(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('force_delete')
    def share_force_delete(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.5', '2.6', experimental=True)
    @wsgi.action("os-migrate_share")
    def migrate_share_legacy(self, req, id, body):
        return self._migrate_share(req, id, body)

    @wsgi.Controller.api_version('2.7', experimental=True)
    @wsgi.action("migrate_share")
    def migrate_share(self, req, id, body):
        return self._migrate_share(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-allow_access')
    def allow_access_legacy(self, req, id, body):
        """Add share access rule."""
        return self._allow_access(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('allow_access')
    def allow_access(self, req, id, body):
        """Add share access rule."""
        return self._allow_access(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-deny_access')
    def deny_access_legacy(self, req, id, body):
        """Remove share access rule."""
        return self._deny_access(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('deny_access')
    def deny_access(self, req, id, body):
        """Remove share access rule."""
        return self._deny_access(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-access_list')
    def access_list_legacy(self, req, id, body):
        """List share access rules."""
        return self._access_list(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('access_list')
    def access_list(self, req, id, body):
        """List share access rules."""
        return self._access_list(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-extend')
    def extend_legacy(self, req, id, body):
        """Extend size of a share."""
        return self._extend(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('extend')
    def extend(self, req, id, body):
        """Extend size of a share."""
        return self._extend(req, id, body)

    @wsgi.Controller.api_version('2.0', '2.6')
    @wsgi.action('os-shrink')
    def shrink_legacy(self, req, id, body):
        """Shrink size of a share."""
        return self._shrink(req, id, body)

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('shrink')
    def shrink(self, req, id, body):
        """Shrink size of a share."""
        return self._shrink(req, id, body)

    @wsgi.Controller.api_version('2.7', '2.7')
    def manage(self, req, body):
        body.get('share', {}).pop('is_public', None)
        detail = self._manage(req, body)
        return detail

    @wsgi.Controller.api_version("2.8")  # noqa
    def manage(self, req, body):  # pylint: disable=E0102
        detail = self._manage(req, body)
        return detail

    @wsgi.Controller.api_version('2.7')
    @wsgi.action('unmanage')
    def unmanage(self, req, id, body=None):
        return self._unmanage(req, id, body)


def create_resource():
    return wsgi.Resource(ShareController())
