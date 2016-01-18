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

"""The consistency groups API."""

from oslo_log import log
from oslo_utils import uuidutils
import six
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
import manila.api.views.consistency_groups as cg_views
import manila.consistency_group.api as cg_api
from manila import db
from manila import exception
from manila.i18n import _
from manila.i18n import _LI
from manila.share import share_types

LOG = log.getLogger(__name__)


class CGController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The Consistency Groups API controller for the OpenStack API."""

    resource_name = 'consistency_group'
    _view_builder_class = cg_views.CGViewBuilder
    resource_name = 'consistency_group'

    def __init__(self):
        super(CGController, self).__init__()
        self.cg_api = cg_api.API()

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Return data about the given CG."""
        context = req.environ['manila.context']

        try:
            cg = self.cg_api.get(context, id)
        except exception.NotFound:
            msg = _("Consistency group %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)

        return self._view_builder.detail(req, cg)

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize
    def delete(self, req, id):
        """Delete a CG."""
        context = req.environ['manila.context']

        LOG.info(_LI("Delete consistency group with id: %s"), id,
                 context=context)

        try:
            cg = self.cg_api.get(context, id)
        except exception.NotFound:
            msg = _("Consistency group %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)

        try:
            self.cg_api.delete(context, cg)
        except exception.InvalidConsistencyGroup as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))

        return webob.Response(status_int=202)

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize('get_all')
    def index(self, req):
        """Returns a summary list of shares."""
        return self._get_cgs(req, is_detail=False)

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize('get_all')
    def detail(self, req):
        """Returns a detailed list of shares."""
        return self._get_cgs(req, is_detail=True)

    def _get_cgs(self, req, is_detail):
        """Returns a list of shares, transformed through view builder."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # Remove keys that are not related to cg attrs
        search_opts.pop('limit', None)
        search_opts.pop('offset', None)

        cgs = self.cg_api.get_all(
            context, detailed=is_detail, search_opts=search_opts)

        limited_list = common.limited(cgs, req)

        if is_detail:
            cgs = self._view_builder.detail_list(req, limited_list)
        else:
            cgs = self._view_builder.summary_list(req, limited_list)
        return cgs

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.Controller.authorize
    def update(self, req, id, body):
        """Update a share."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'consistency_group'):
            msg = _("'consistency_group' is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        cg_data = body['consistency_group']
        valid_update_keys = {
            'name',
            'description',
        }
        invalid_fields = set(cg_data.keys()) - valid_update_keys
        if invalid_fields:
            msg = _("The fields %s are invalid or not allowed to be updated.")
            raise exc.HTTPBadRequest(explanation=msg % invalid_fields)

        try:
            cg = self.cg_api.get(context, id)
        except exception.NotFound:
            msg = _("Consistency group %s not found.") % id
            raise exc.HTTPNotFound(explanation=msg)

        cg = self.cg_api.update(context, cg, cg_data)
        return self._view_builder.detail(req, cg)

    @wsgi.Controller.api_version('2.4', experimental=True)
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def create(self, req, body):
        """Creates a new share."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'consistency_group'):
            msg = _("'consistency_group' is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        cg = body['consistency_group']

        valid_fields = {'name', 'description', 'share_types',
                        'source_cgsnapshot_id', 'share_network_id'}
        invalid_fields = set(cg.keys()) - valid_fields
        if invalid_fields:
            msg = _("The fields %s are invalid.") % invalid_fields
            raise exc.HTTPBadRequest(explanation=msg)

        if 'share_types' in cg and 'source_cgsnapshot_id' in cg:
            msg = _("Cannot supply both 'share_types' and "
                    "'source_cgsnapshot_id' attributes.")
            raise exc.HTTPBadRequest(explanation=msg)

        if not cg.get('share_types') and 'source_cgsnapshot_id' not in cg:
            default_share_type = share_types.get_default_share_type()
            if default_share_type:
                cg['share_types'] = [default_share_type['id']]
            else:
                msg = _("Must specify at least one share type as a default "
                        "share type has not been configured.")
                raise exc.HTTPBadRequest(explanation=msg)

        kwargs = {}

        if 'name' in cg:
            kwargs['name'] = cg.get('name')
        if 'description' in cg:
            kwargs['description'] = cg.get('description')

        _share_types = cg.get('share_types')
        if _share_types:
            if not all([uuidutils.is_uuid_like(st) for st in _share_types]):
                msg = _("The 'share_types' attribute must be a list of uuids")
                raise exc.HTTPBadRequest(explanation=msg)
            kwargs['share_type_ids'] = _share_types

        if 'source_cgsnapshot_id' in cg:
            source_cgsnapshot_id = cg.get('source_cgsnapshot_id')
            if not uuidutils.is_uuid_like(source_cgsnapshot_id):
                msg = _("The 'source_cgsnapshot_id' attribute must be a uuid.")
                raise exc.HTTPBadRequest(explanation=six.text_type(msg))
            kwargs['source_cgsnapshot_id'] = source_cgsnapshot_id

        if 'share_network_id' in cg:
            share_network_id = cg.get('share_network_id')
            if not uuidutils.is_uuid_like(share_network_id):
                msg = _("The 'share_network_id' attribute must be a uuid.")
                raise exc.HTTPBadRequest(explanation=six.text_type(msg))
            kwargs['share_network_id'] = share_network_id

        try:
            new_cg = self.cg_api.create(context, **kwargs)
        except exception.InvalidCGSnapshot as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))
        except (exception.CGSnapshotNotFound, exception.InvalidInput) as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))

        return self._view_builder.detail(req, dict(new_cg.items()))

    def _update(self, *args, **kwargs):
        db.consistency_group_update(*args, **kwargs)

    def _get(self, *args, **kwargs):
        return self.cg_api.get(*args, **kwargs)

    def _delete(self, context, resource, force=True):
        db.consistency_group_destroy(context.elevated(), resource['id'])

    @wsgi.Controller.api_version('2.4', '2.6', experimental=True)
    @wsgi.action('os-reset_status')
    def cg_reset_status_legacy(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.7', experimental=True)
    @wsgi.action('reset_status')
    def cg_reset_status(self, req, id, body):
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version('2.4', '2.6', experimental=True)
    @wsgi.action('os-force_delete')
    def cg_force_delete_legacy(self, req, id, body):
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version('2.7', experimental=True)
    @wsgi.action('force_delete')
    def cg_force_delete(self, req, id, body):
        return self._force_delete(req, id, body)


def create_resource():
    return wsgi.Resource(CGController())
