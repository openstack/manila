# Copyright (c) 2011 OpenStack Foundation
# Copyright (c) 2014 NetApp, Inc.
#
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

"""The share type API controller module.."""

from oslo_log import log
from oslo_utils import strutils
from oslo_utils import uuidutils
import six
import webob
from webob import exc

from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.views import types as views_types
from manila.common import constants
from manila import exception
from manila.i18n import _
from manila import rpc
from manila.share import share_types


LOG = log.getLogger(__name__)


class ShareTypesController(wsgi.Controller):
    """The share types API controller for the OpenStack API."""

    resource_name = 'share_type'
    _view_builder_class = views_types.ViewBuilder

    def __getattr__(self, key):
        if key == 'os-share-type-access':
            return self.share_type_access
        return super(self.__class__, self).__getattr__(key)

    def _notify_share_type_error(self, context, method, payload):
        rpc.get_notifier('shareType').error(context, method, payload)

    def _check_body(self, body, action_name):
        if not self.is_valid_body(body, action_name):
            raise webob.exc.HTTPBadRequest()
        access = body[action_name]
        project = access.get('project')
        if not uuidutils.is_uuid_like(project):
            msg = _("Bad project format: "
                    "project is not in proper format (%s)") % project
            raise webob.exc.HTTPBadRequest(explanation=msg)

    @wsgi.Controller.authorize
    def index(self, req):
        """Returns the list of share types."""

        limited_types = self._get_share_types(req)
        req.cache_db_share_types(limited_types)
        return self._view_builder.index(req, limited_types)

    @wsgi.Controller.authorize
    def show(self, req, id):
        """Return a single share type item."""
        context = req.environ['manila.context']
        try:
            share_type = self._show_share_type_details(context, id)
        except exception.NotFound:
            msg = _("Share type not found.")
            raise exc.HTTPNotFound(explanation=msg)

        share_type['id'] = six.text_type(share_type['id'])
        req.cache_db_share_type(share_type)
        return self._view_builder.show(req, share_type)

    def _show_share_type_details(self, context, id):
        share_type = share_types.get_share_type(context, id)
        required_extra_specs = {}
        try:
            required_extra_specs = share_types.get_valid_required_extra_specs(
                share_type['extra_specs'])
        except exception.InvalidExtraSpec:
            LOG.exception('Share type %(share_type_id)s has invalid required'
                          ' extra specs.', {'share_type_id': id})

        share_type['required_extra_specs'] = required_extra_specs
        return share_type

    @wsgi.Controller.authorize
    def default(self, req):
        """Return default volume type."""
        context = req.environ['manila.context']

        try:
            share_type = share_types.get_default_share_type(context)
        except exception.NotFound:
            msg = _("Share type not found")
            raise exc.HTTPNotFound(explanation=msg)

        if not share_type:
            msg = _("Default share type not found")
            raise exc.HTTPNotFound(explanation=msg)

        share_type['id'] = six.text_type(share_type['id'])
        return self._view_builder.show(req, share_type)

    def _get_share_types(self, req):
        """Helper function that returns a list of type dicts."""
        filters = {}
        context = req.environ['manila.context']
        if context.is_admin:
            # Only admin has query access to all share types
            filters['is_public'] = self._parse_is_public(
                req.params.get('is_public'))
        else:
            filters['is_public'] = True
        limited_types = share_types.get_all_types(
            context, search_opts=filters).values()
        return list(limited_types)

    @staticmethod
    def _parse_is_public(is_public):
        """Parse is_public into something usable.

        * True: API should list public share types only
        * False: API should list private share types only
        * None: API should list both public and private share types
        """
        if is_public is None:
            # preserve default value of showing only public types
            return True
        elif six.text_type(is_public).lower() == "all":
            return None
        else:
            try:
                return strutils.bool_from_string(is_public, strict=True)
            except ValueError:
                msg = _('Invalid is_public filter [%s]') % is_public
                raise exc.HTTPBadRequest(explanation=msg)

    @wsgi.Controller.api_version("1.0", "2.23")
    @wsgi.action("create")
    def create(self, req, body):
        return self._create(req, body, set_defaults=True)

    @wsgi.Controller.api_version("2.24")  # noqa
    @wsgi.action("create")
    def create(self, req, body):  # pylint: disable=E0102
        return self._create(req, body, set_defaults=False)

    @wsgi.Controller.authorize('create')
    def _create(self, req, body, set_defaults=False):
        """Creates a new share type."""
        context = req.environ['manila.context']

        if (not self.is_valid_body(body, 'share_type') and
                not self.is_valid_body(body, 'volume_type')):
            raise webob.exc.HTTPBadRequest()

        elif self.is_valid_body(body, 'share_type'):
            share_type = body['share_type']
        else:
            share_type = body['volume_type']
        name = share_type.get('name')
        specs = share_type.get('extra_specs', {})
        description = share_type.get('description')
        if (description and req.api_version_request
                < api_version.APIVersionRequest("2.41")):
            msg = _("'description' key is not supported by this "
                    "microversion. Use 2.41 or greater microversion "
                    "to be able to use 'description' in share type.")
            raise webob.exc.HTTPBadRequest(explanation=msg)
        is_public = share_type.get(
            'os-share-type-access:is_public',
            share_type.get('share_type_access:is_public', True),
        )

        if (name is None or name == "" or len(name) > 255
                or (description and len(description) > 255)):
            msg = _("Type name or description is not valid.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        # Note(cknight): Set the default extra spec value for snapshot_support
        # for API versions before it was required.
        if set_defaults:
            if constants.ExtraSpecs.SNAPSHOT_SUPPORT not in specs:
                specs[constants.ExtraSpecs.SNAPSHOT_SUPPORT] = True

        try:
            required_extra_specs = (
                share_types.get_valid_required_extra_specs(specs)
            )
            share_types.create(context, name, specs, is_public,
                               description=description)
            share_type = share_types.get_share_type_by_name(context, name)
            share_type['required_extra_specs'] = required_extra_specs
            req.cache_db_share_type(share_type)
            notifier_info = dict(share_types=share_type)
            rpc.get_notifier('shareType').info(
                context, 'share_type.create', notifier_info)

        except exception.InvalidExtraSpec as e:
            raise webob.exc.HTTPBadRequest(explanation=six.text_type(e))
        except exception.ShareTypeExists as err:
            notifier_err = dict(share_types=share_type,
                                error_message=six.text_type(err))
            self._notify_share_type_error(context, 'share_type.create',
                                          notifier_err)

            raise webob.exc.HTTPConflict(explanation=six.text_type(err))
        except exception.NotFound as err:
            notifier_err = dict(share_types=share_type,
                                error_message=six.text_type(err))
            self._notify_share_type_error(context, 'share_type.create',
                                          notifier_err)
            raise webob.exc.HTTPNotFound()

        return self._view_builder.show(req, share_type)

    @wsgi.action("delete")
    @wsgi.Controller.authorize('delete')
    def _delete(self, req, id):
        """Deletes an existing share type."""
        context = req.environ['manila.context']

        try:
            share_type = share_types.get_share_type(context, id)
            share_types.destroy(context, share_type['id'])
            notifier_info = dict(share_types=share_type)
            rpc.get_notifier('shareType').info(
                context, 'share_type.delete', notifier_info)
        except exception.ShareTypeInUse as err:
            notifier_err = dict(id=id, error_message=six.text_type(err))
            self._notify_share_type_error(context, 'share_type.delete',
                                          notifier_err)
            msg = 'Target share type is still in use.'
            raise webob.exc.HTTPBadRequest(explanation=msg)
        except exception.NotFound as err:
            notifier_err = dict(id=id, error_message=six.text_type(err))
            self._notify_share_type_error(context, 'share_type.delete',
                                          notifier_err)

            raise webob.exc.HTTPNotFound()

        return webob.Response(status_int=202)

    @wsgi.Controller.authorize('list_project_access')
    def share_type_access(self, req, id):
        context = req.environ['manila.context']

        try:
            share_type = share_types.get_share_type(
                context, id, expected_fields=['projects'])
        except exception.ShareTypeNotFound:
            explanation = _("Share type %s not found.") % id
            raise webob.exc.HTTPNotFound(explanation=explanation)

        if share_type['is_public']:
            expl = _("Access list not available for public share types.")
            raise webob.exc.HTTPNotFound(explanation=expl)

        # TODO(vponomaryov): move to views.
        rval = []
        for project_id in share_type['projects']:
            rval.append(
                {'share_type_id': share_type['id'], 'project_id': project_id}
            )
        return {'share_type_access': rval}

    @wsgi.action('addProjectAccess')
    @wsgi.Controller.authorize('add_project_access')
    def _add_project_access(self, req, id, body):
        context = req.environ['manila.context']
        self._check_body(body, 'addProjectAccess')
        project = body['addProjectAccess']['project']

        self._verify_if_non_public_share_type(context, id)

        try:
            share_types.add_share_type_access(context, id, project)
        except exception.ShareTypeAccessExists as err:
            raise webob.exc.HTTPConflict(explanation=six.text_type(err))

        return webob.Response(status_int=202)

    @wsgi.action('removeProjectAccess')
    @wsgi.Controller.authorize('remove_project_access')
    def _remove_project_access(self, req, id, body):
        context = req.environ['manila.context']
        self._check_body(body, 'removeProjectAccess')
        project = body['removeProjectAccess']['project']

        self._verify_if_non_public_share_type(context, id)

        try:
            share_types.remove_share_type_access(context, id, project)
        except exception.ShareTypeAccessNotFound as err:
            raise webob.exc.HTTPNotFound(explanation=six.text_type(err))
        return webob.Response(status_int=202)

    def _verify_if_non_public_share_type(self, context, share_type_id):
        try:
            share_type = share_types.get_share_type(context, share_type_id)

            if share_type['is_public']:
                msg = _("Type access modification is not applicable to "
                        "public share type.")
                raise webob.exc.HTTPConflict(explanation=msg)

        except exception.ShareTypeNotFound as err:
            raise webob.exc.HTTPNotFound(explanation=six.text_type(err))


def create_resource():
    return wsgi.Resource(ShareTypesController())
