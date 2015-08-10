#   Copyright 2012 OpenStack Foundation
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

from oslo_log import log
import six
import webob
from webob import exc

from manila.api import extensions
from manila.api.openstack import wsgi
from manila.common import constants
from manila import db
from manila import exception
from manila import share

LOG = log.getLogger(__name__)


class AdminController(wsgi.Controller):
    """Abstract base class for AdminControllers."""

    collection = None

    valid_status = set([
        constants.STATUS_CREATING,
        constants.STATUS_AVAILABLE,
        constants.STATUS_DELETING,
        constants.STATUS_ERROR,
        constants.STATUS_ERROR_DELETING,
    ])

    def __init__(self, *args, **kwargs):
        super(AdminController, self).__init__(*args, **kwargs)
        self.resource_name = self.collection.rstrip('s')
        self.share_api = share.API()

    def _update(self, *args, **kwargs):
        raise NotImplementedError()

    def _get(self, *args, **kwargs):
        raise NotImplementedError()

    def _delete(self, *args, **kwargs):
        raise NotImplementedError()

    def validate_update(self, body):
        update = {}
        try:
            update['status'] = body['status']
        except (TypeError, KeyError):
            raise exc.HTTPBadRequest(explanation="Must specify 'status'")
        if update['status'] not in self.valid_status:
            expl = "Invalid state. Valid states: " +\
                   ', '.join(self.valid_status) + '.'
            raise exc.HTTPBadRequest(explanation=expl)
        return update

    def authorize(self, context, action_name):
        action = '%s_admin_actions:%s' % (self.resource_name, action_name)
        extensions.extension_authorizer('share', action)(context)

    @wsgi.action('os-reset_status')
    def _reset_status(self, req, id, body):
        """Reset status on the resource."""
        context = req.environ['manila.context']
        self.authorize(context, 'reset_status')
        update = self.validate_update(body['os-reset_status'])
        msg = "Updating %(resource)s '%(id)s' with '%(update)r'"
        LOG.debug(msg, {'resource': self.resource_name, 'id': id,
                        'update': update})
        try:
            self._update(context, id, update)
        except exception.NotFound as e:
            raise exc.HTTPNotFound(six.text_type(e))
        return webob.Response(status_int=202)

    @wsgi.action('os-force_delete')
    def _force_delete(self, req, id, body):
        """Delete a resource, bypassing the check for status."""
        context = req.environ['manila.context']
        self.authorize(context, 'force_delete')
        try:
            resource = self._get(context, id)
        except exception.NotFound as e:
            raise exc.HTTPNotFound(six.text_type(e))
        self._delete(context, resource, force=True)
        return webob.Response(status_int=202)


class ShareAdminController(AdminController):
    """AdminController for Shares."""

    collection = 'shares'

    def _update(self, *args, **kwargs):
        db.share_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return self.share_api.get(*args, **kwargs)

    def _delete(self, *args, **kwargs):
        return self.share_api.delete(*args, **kwargs)


class SnapshotAdminController(AdminController):
    """AdminController for Snapshots."""

    collection = 'snapshots'

    def _update(self, *args, **kwargs):
        db.share_snapshot_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return self.share_api.get_snapshot(*args, **kwargs)

    def _delete(self, *args, **kwargs):
        return self.share_api.delete_snapshot(*args, **kwargs)


class Admin_actions(extensions.ExtensionDescriptor):
    """Enable admin actions."""

    name = "AdminActions"
    alias = "os-admin-actions"
    updated = "2012-08-25T00:00:00+00:00"

    def get_controller_extensions(self):
        exts = []
        for class_ in (ShareAdminController, SnapshotAdminController):
            controller = class_()
            extension = extensions.ControllerExtension(
                self, class_.collection, controller)
            exts.append(extension)
        return exts
