# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""The group type API controller module."""
import ast

from http import client as http_client
from oslo_utils import uuidutils
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.views import share_group_types as views
from manila import exception
from manila.i18n import _
from manila.share_group import share_group_types

SG_GRADUATION_VERSION = '2.55'


class ShareGroupTypesController(wsgi.Controller):
    """The share group types API controller for the OpenStack API."""

    resource_name = 'share_group_type'
    _view_builder_class = views.ShareGroupTypeViewBuilder

    def _check_body(self, body, action_name):
        if not self.is_valid_body(body, action_name):
            raise webob.exc.HTTPBadRequest()
        access = body[action_name]
        project = access.get('project')
        if not uuidutils.is_uuid_like(project):
            msg = _("Project value (%s) must be in uuid format.") % project
            raise webob.exc.HTTPBadRequest(explanation=msg)

    @wsgi.Controller.authorize('index')
    def _index(self, req):
        """Returns the list of share group types."""
        limited_types = self._get_share_group_types(req)
        return self._view_builder.index(req, limited_types)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def index(self, req):
        return self._index(req)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def index(self, req):  # pylint: disable=function-redefined  # noqa F811
        return self._index(req)

    @wsgi.Controller.authorize('show')
    def _show(self, req, id):
        """Return a single share group type item."""
        context = req.environ['manila.context']
        try:
            share_group_type = share_group_types.get(context, id)
        except exception.NotFound:
            msg = _("Share group type with id %s not found.")
            raise exc.HTTPNotFound(explanation=msg % id)

        share_group_type['id'] = str(share_group_type['id'])
        return self._view_builder.show(req, share_group_type)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def show(self, req, id):
        return self._show(req, id)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def show(self, req, id):  # pylint: disable=function-redefined  # noqa F811
        return self._show(req, id)

    @wsgi.Controller.authorize('default')
    def _default(self, req):
        """Return default share group type."""
        context = req.environ['manila.context']
        share_group_type = share_group_types.get_default(context)
        if not share_group_type:
            msg = _("Default share group type not found.")
            raise exc.HTTPNotFound(explanation=msg)

        share_group_type['id'] = str(share_group_type['id'])
        return self._view_builder.show(req, share_group_type)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def default(self, req):
        return self._default(req)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def default(self, req):  # pylint: disable=function-redefined  # noqa F811
        return self._default(req)

    def _get_share_group_types(self, req):
        """Helper function that returns a list of share group type dicts."""
        filters = {}
        context = req.environ['manila.context']
        if context.is_admin:
            # Only admin has query access to all group types
            filters['is_public'] = common.parse_is_public(
                req.params.get('is_public'))
        else:
            filters['is_public'] = True

        group_specs = req.params.get('group_specs', {})
        group_specs_disallowed = (req.api_version_request <
                                  api_version.APIVersionRequest("2.66"))

        if group_specs and group_specs_disallowed:
            msg = _("Filter by 'group_specs' is not supported by this "
                    "microversion. Use 2.66 or greater microversion to "
                    "be able to use filter search by 'group_specs.")
            raise webob.exc.HTTPBadRequest(explanation=msg)
        elif group_specs:
            filters['group_specs'] = ast.literal_eval(group_specs)

        limited_types = share_group_types.get_all(
            context, search_opts=filters).values()
        return list(limited_types)

    @wsgi.Controller.authorize('create')
    def _create(self, req, body):
        """Creates a new share group type."""
        context = req.environ['manila.context']
        if not self.is_valid_body(body, 'share_group_type'):
            raise webob.exc.HTTPBadRequest()

        share_group_type = body['share_group_type']
        name = share_group_type.get('name')
        specs = share_group_type.get('group_specs', {})
        is_public = share_group_type.get('is_public', True)

        if not share_group_type.get('share_types'):
            msg = _("Supported share types must be provided.")
            raise webob.exc.HTTPBadRequest(explanation=msg)
        share_types = share_group_type.get('share_types')

        if name is None or name == "" or len(name) > 255:
            msg = _("Share group type name is not valid.")
            raise webob.exc.HTTPBadRequest(explanation=msg)
        if not (specs is None or isinstance(specs, dict)):
            msg = _("Group specs can be either of 'None' or 'dict' types.")
            raise webob.exc.HTTPBadRequest(explanation=msg)
        if specs:
            for element in list(specs.keys()) + list(specs.values()):
                if not isinstance(element, str):
                    msg = _("Group specs keys and values should be strings.")
                    raise webob.exc.HTTPBadRequest(explanation=msg)
        try:
            share_group_types.create(
                context, name, share_types, specs, is_public)
            share_group_type = share_group_types.get_by_name(
                context, name)
        except exception.ShareGroupTypeExists as err:
            raise webob.exc.HTTPConflict(explanation=err.message)
        except exception.ShareTypeDoesNotExist as err:
            raise webob.exc.HTTPNotFound(explanation=err.message)
        except exception.NotFound:
            raise webob.exc.HTTPNotFound()
        return self._view_builder.show(req, share_group_type)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    @wsgi.action("create")
    def create(self, req, body):
        return self._create(req, body)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    @wsgi.action("create")
    def create(self, req, body):  # pylint: disable=function-redefined  # noqa F811
        return self._create(req, body)

    @wsgi.Controller.authorize('delete')
    def _delete(self, req, id):
        """Deletes an existing group type."""
        context = req.environ['manila.context']
        try:
            share_group_type = share_group_types.get(context, id)
            share_group_types.destroy(context, share_group_type['id'])
        except exception.ShareGroupTypeInUse:
            msg = _('Target share group type with id %s is still in use.')
            raise webob.exc.HTTPBadRequest(explanation=msg % id)
        except exception.NotFound:
            raise webob.exc.HTTPNotFound()
        return webob.Response(status_int=http_client.NO_CONTENT)

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    @wsgi.action("delete")
    def delete(self, req, id):
        return self._delete(req, id)

    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    @wsgi.action("delete")
    def delete(self, req, id):  # pylint: disable=function-redefined  # noqa F811
        return self._delete(req, id)

    @wsgi.Controller.authorize('list_project_access')
    def _share_group_type_access(self, req, id):
        context = req.environ['manila.context']
        try:
            share_group_type = share_group_types.get(
                context, id, expected_fields=['projects'])
        except exception.ShareGroupTypeNotFound:
            explanation = _("Share group type %s not found.") % id
            raise webob.exc.HTTPNotFound(explanation=explanation)

        if share_group_type['is_public']:
            expl = _("Access list not available for public share group types.")
            raise webob.exc.HTTPNotFound(explanation=expl)

        projects = []
        for project_id in share_group_type['projects']:
            projects.append(
                {'share_group_type_id': share_group_type['id'],
                 'project_id': project_id}
            )
        return {'share_group_type_access': projects}

    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    def share_group_type_access(self, req, id):
        return self._share_group_type_access(req, id)

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    def share_group_type_access(self, req, id):  # noqa F811
        return self._share_group_type_access(req, id)

    @wsgi.Controller.authorize('add_project_access')
    def _add_project_access(self, req, id, body):
        context = req.environ['manila.context']
        self._check_body(body, 'addProjectAccess')
        project = body['addProjectAccess']['project']
        self._assert_non_public_share_group_type(context, id)
        try:
            share_group_types.add_share_group_type_access(
                context, id, project)
        except exception.ShareGroupTypeAccessExists as err:
            raise webob.exc.HTTPConflict(explanation=err.message)
        return webob.Response(status_int=http_client.ACCEPTED)

    # pylint: enable=function-redefined
    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    @wsgi.action('addProjectAccess')
    def add_project_access(self, req, id, body):
        return self._add_project_access(req, id, body)

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    @wsgi.action('addProjectAccess')
    def add_project_access(self, req, id, body):  # noqa F811
        return self._add_project_access(req, id, body)

    @wsgi.Controller.authorize('remove_project_access')
    def _remove_project_access(self, req, id, body):
        context = req.environ['manila.context']
        self._check_body(body, 'removeProjectAccess')
        project = body['removeProjectAccess']['project']
        self._assert_non_public_share_group_type(context, id)
        try:
            share_group_types.remove_share_group_type_access(
                context, id, project)
        except exception.ShareGroupTypeAccessNotFound as err:
            raise webob.exc.HTTPNotFound(explanation=err.message)
        return webob.Response(status_int=http_client.ACCEPTED)

    # pylint: enable=function-redefined
    @wsgi.Controller.api_version('2.31', '2.54', experimental=True)
    @wsgi.action('removeProjectAccess')
    def remove_project_access(self, req, id, body):
        return self._remove_project_access(req, id, body)

    # pylint: disable=function-redefined
    @wsgi.Controller.api_version(SG_GRADUATION_VERSION)  # noqa
    @wsgi.action('removeProjectAccess')
    def remove_project_access(self, req, id, body):  # noqa F811
        return self._remove_project_access(req, id, body)

    def _assert_non_public_share_group_type(self, context, type_id):
        try:
            share_group_type = share_group_types.get(
                context, type_id)
            if share_group_type['is_public']:
                msg = _("Type access modification is not applicable to "
                        "public share group type.")
                raise webob.exc.HTTPConflict(explanation=msg)
        except exception.ShareGroupTypeNotFound as err:
            raise webob.exc.HTTPNotFound(explanation=err.message)


def create_resource():
    return wsgi.Resource(ShareGroupTypesController())
