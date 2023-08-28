# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""The Share Backups API."""

import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import share_backups as backup_view
from manila import db
from manila import exception
from manila.i18n import _
from manila import policy
from manila import share


MIN_SUPPORTED_API_VERSION = '2.80'


class ShareBackupController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The Share Backup API controller for the OpenStack API."""

    resource_name = 'share_backup'
    _view_builder_class = backup_view.BackupViewBuilder

    def __init__(self):
        super(ShareBackupController, self).__init__()
        self.share_api = share.API()

    def _update(self, *args, **kwargs):
        db.share_backup_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return db.share_backup_get(*args, **kwargs)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    def index(self, req):
        """Return a summary list of backups."""
        return self._get_backups(req)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    def detail(self, req):
        """Returns a detailed list of backups."""
        return self._get_backups(req, is_detail=True)

    @wsgi.Controller.authorize('get_all')
    def _get_backups(self, req, is_detail=False):
        """Returns list of backups."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)
        params = common.get_pagination_params(req)
        limit, offset = [params.get('limit'), params.get('offset')]

        search_opts.pop('limit', None)
        search_opts.pop('offset', None)
        sort_key, sort_dir = common.get_sort_params(search_opts)
        key_dict = {"name": "display_name",
                    "description": "display_description"}
        for key in key_dict:
            if sort_key == key:
                sort_key = key_dict[key]

        if 'name' in search_opts:
            search_opts['display_name'] = search_opts.pop('name')
        if 'description' in search_opts:
            search_opts['display_description'] = search_opts.pop(
                'description')

        # like filter
        for key, db_key in (('name~', 'display_name~'),
                            ('description~', 'display_description~')):
            if key in search_opts:
                search_opts[db_key] = search_opts.pop(key)

        common.remove_invalid_options(context, search_opts,
                                      self._get_backups_search_options())

        # Read and remove key 'all_tenants' if was provided
        search_opts['project_id'] = context.project_id
        all_tenants = search_opts.pop('all_tenants',
                                      search_opts.pop('all_projects', None))
        if all_tenants:
            allowed_to_list_all_tenants = policy.check_policy(
                context, 'share_backup', 'get_all_project', do_raise=False)
            if allowed_to_list_all_tenants:
                search_opts.pop('project_id')

        share_id = req.params.get('share_id')
        if share_id:
            try:
                self.share_api.get(context, share_id)
                search_opts.update({'share_id': share_id})
            except exception.NotFound:
                msg = _("No share exists with ID %s.")
                raise exc.HTTPBadRequest(explanation=msg % share_id)

        backups = db.share_backups_get_all(context,
                                           filters=search_opts,
                                           limit=limit,
                                           offset=offset,
                                           sort_key=sort_key,
                                           sort_dir=sort_dir)
        if is_detail:
            backups = self._view_builder.detail_list(req, backups)
        else:
            backups = self._view_builder.summary_list(req, backups)

        return backups

    def _get_backups_search_options(self):
        """Return share backup search options allowed by non-admin."""
        return ('display_name', 'status', 'share_id', 'topic', 'display_name~',
                'display_description~', 'display_description')

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Return data about the given backup."""
        context = req.environ['manila.context']

        try:
            backup = db.share_backup_get(context, id)
        except exception.ShareBackupNotFound:
            msg = _("No backup exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        return self._view_builder.detail(req, backup)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize
    @wsgi.response(202)
    def create(self, req, body):
        """Add a backup to an existing share."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share_backup'):
            msg = _("Body does not contain 'share_backup' information.")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        backup = body.get('share_backup')
        share_id = backup.get('share_id')

        if not share_id:
            msg = _("'share_id' is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            share = self.share_api.get(context, share_id)
        except exception.NotFound:
            msg = _("No share exists with ID %s.")
            raise exc.HTTPBadRequest(explanation=msg % share_id)
        if share.get('is_soft_deleted'):
            msg = _("Backup can not be created for share '%s' "
                    "since it has been soft deleted.") % share_id
            raise exc.HTTPForbidden(explanation=msg)

        try:
            backup = self.share_api.create_share_backup(context, share, backup)
        except (exception.InvalidBackup,
                exception.InvalidShare) as e:
            raise exc.HTTPBadRequest(explanation=e.msg)
        except exception.ShareBusyException as e:
            raise exc.HTTPConflict(explanation=e.msg)

        return self._view_builder.detail(req, backup)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize
    def delete(self, req, id):
        """Delete a backup."""
        context = req.environ['manila.context']

        try:
            backup = db.share_backup_get(context, id)
        except exception.ShareBackupNotFound:
            msg = _("No backup exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        try:
            self.share_api.delete_share_backup(context, backup)
        except exception.InvalidBackup as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        return webob.Response(status_int=202)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('restore')
    @wsgi.Controller.authorize
    @wsgi.response(202)
    def restore(self, req, id, body):
        """Restore an existing backup to a share."""
        context = req.environ['manila.context']

        try:
            backup = db.share_backup_get(context, id)
        except exception.ShareBackupNotFound:
            msg = _("No backup exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        try:
            restored = self.share_api.restore_share_backup(context, backup)
        except (exception.InvalidShare,
                exception.InvalidBackup) as e:
            raise exc.HTTPBadRequest(explanation=e.msg)

        retval = self._view_builder.restore_summary(req, restored)
        return retval

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize
    @wsgi.response(200)
    def update(self, req, id, body):
        """Update a backup."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share_backup'):
            msg = _("Body does not contain 'share_backup' information.")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        try:
            backup = db.share_backup_get(context, id)
        except exception.ShareBackupNotFound:
            msg = _("No backup exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        backup_update = body.get('share_backup')
        update_dict = {}
        if 'name' in backup_update:
            update_dict['display_name'] = backup_update.pop('name')
        if 'description' in backup_update:
            update_dict['display_description'] = (
                backup_update.pop('description'))

        backup = self.share_api.update_share_backup(context, backup,
                                                    update_dict)
        return self._view_builder.detail(req, backup)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('reset_status')
    def backup_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)


def create_resource():
    return wsgi.Resource(ShareBackupController())
