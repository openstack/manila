# Copyright 2015 Alex Meade
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

"""The consistency groups snapshot API."""

from oslo_log import log
from oslo_utils import uuidutils
import six
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
import manila.api.views.cgsnapshots as cg_views
import manila.consistency_group.api as cg_api
from manila import db
from manila import exception
from manila.i18n import _
from manila.i18n import _LI

LOG = log.getLogger(__name__)


class CGSnapshotController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The Consistency Group Snapshots API controller for the OpenStack API."""

    resource_name = 'cgsnapshot'
    _view_builder_class = cg_views.CGSnapshotViewBuilder

    def __init__(self):
        super(CGSnapshotController, self).__init__()
        self.cg_api = cg_api.API()

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize('get_cgsnapshot')
    def show(self, req, id):
        """Return data about the given cgsnapshot."""
        context = req.environ['manila.context']

        try:
            cg = self.cg_api.get_cgsnapshot(context, id)
        except exception.NotFound:
            msg = _("Consistency group snapshot %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)

        return self._view_builder.detail(req, cg)

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize
    def delete(self, req, id):
        """Delete a cgsnapshot."""
        context = req.environ['manila.context']

        LOG.info(_LI("Delete consistency group snapshot with id: %s"), id,
                 context=context)

        try:
            snap = self.cg_api.get_cgsnapshot(context, id)
        except exception.NotFound:
            msg = _("Consistency group snapshot %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)

        try:
            self.cg_api.delete_cgsnapshot(context, snap)
        except exception.InvalidCGSnapshot as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))

        return webob.Response(status_int=202)

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize('get_all')
    def index(self, req):
        """Returns a summary list of cgsnapshots."""
        return self._get_cgs(req, is_detail=False)

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize('get_all')
    def detail(self, req):
        """Returns a detailed list of cgsnapshots."""
        return self._get_cgs(req, is_detail=True)

    def _get_cgs(self, req, is_detail):
        """Returns a list of cgsnapshots."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # Remove keys that are not related to cg attrs
        search_opts.pop('limit', None)
        search_opts.pop('offset', None)

        snaps = self.cg_api.get_all_cgsnapshots(
            context, detailed=is_detail, search_opts=search_opts)

        limited_list = common.limited(snaps, req)

        if is_detail:
            snaps = self._view_builder.detail_list(req, limited_list)
        else:
            snaps = self._view_builder.summary_list(req, limited_list)
        return snaps

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize
    def update(self, req, id, body):
        """Update a cgsnapshot."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'cgsnapshot'):
            msg = _("'cgsnapshot' is missing from the request body")
            raise exc.HTTPBadRequest(explanation=msg)

        cg_data = body['cgsnapshot']
        valid_update_keys = {
            'name',
            'description',
        }
        invalid_fields = set(cg_data.keys()) - valid_update_keys
        if invalid_fields:
            msg = _("The fields %s are invalid or not allowed to be updated.")
            raise exc.HTTPBadRequest(explanation=msg % invalid_fields)

        try:
            cg = self.cg_api.get_cgsnapshot(context, id)
        except exception.NotFound:
            msg = _("Consistency group snapshot %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)

        cg = self.cg_api.update_cgsnapshot(context, cg, cg_data)
        return self._view_builder.detail(req, cg)

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def create(self, req, body):
        """Creates a new cgsnapshot."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'cgsnapshot'):
            msg = _("'cgsnapshot' is missing from the request body")
            raise exc.HTTPBadRequest(explanation=msg)

        cgsnapshot = body.get('cgsnapshot')

        if not cgsnapshot.get('consistency_group_id'):
            msg = _("Must supply 'consistency_group_id' attribute.")
            raise exc.HTTPBadRequest(explanation=msg)

        consistency_group_id = cgsnapshot.get('consistency_group_id')
        if (consistency_group_id and
                not uuidutils.is_uuid_like(consistency_group_id)):
            msg = _("The 'consistency_group_id' attribute must be a uuid.")
            raise exc.HTTPBadRequest(explanation=six.text_type(msg))

        kwargs = {"consistency_group_id": consistency_group_id}

        if 'name' in cgsnapshot:
            kwargs['name'] = cgsnapshot.get('name')
        if 'description' in cgsnapshot:
            kwargs['description'] = cgsnapshot.get('description')

        try:
            new_snapshot = self.cg_api.create_cgsnapshot(context, **kwargs)
        except exception.ConsistencyGroupNotFound as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))
        except exception.InvalidConsistencyGroup as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))

        return self._view_builder.detail(req, dict(six.iteritems(
                                         new_snapshot)))

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize('get_cgsnapshot')
    def members(self, req, id):
        """Returns a list of cgsnapshot members."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # Remove keys that are not related to cg attrs
        search_opts.pop('limit', None)
        search_opts.pop('offset', None)

        snaps = self.cg_api.get_all_cgsnapshot_members(context, id)

        limited_list = common.limited(snaps, req)

        snaps = self._view_builder.member_list(req, limited_list)
        return snaps

    def _update(self, *args, **kwargs):
        db.cgsnapshot_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return self.cg_api.get_cgsnapshot(*args, **kwargs)

    def _delete(self, context, resource, force=True):
        db.cgsnapshot_destroy(context.elevated(), resource['id'])

    @wsgi.Controller.api_version('2.4', '2.6', experimental=True)
    @wsgi.action('os-reset_status')
    def cgsnapshot_reset_status_legacy(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.7', experimental=True)
    @wsgi.action('reset_status')
    def cgsnapshot_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.4', '2.6', experimental=True)
    @wsgi.action('os-force_delete')
    def cgsnapshot_force_delete_legacy(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.7', experimental=True)
    @wsgi.action('force_delete')
    def cgsnapshot_force_delete(self, req, id, body):
        return self._force_delete(req, id, body)


def create_resource():
    return wsgi.Resource(CGSnapshotController())
