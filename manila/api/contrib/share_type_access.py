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

"""The share type access extension."""

from oslo_utils import uuidutils
import six
import webob


from manila.api import extensions
from manila.api.openstack import wsgi
from manila import exception
from manila.i18n import _
from manila.share import share_types


soft_authorize = extensions.soft_extension_authorizer('share',
                                                      'share_type_access')
authorize = extensions.extension_authorizer('share', 'share_type_access')


def _marshall_share_type_access(share_type):
    rval = []
    for project_id in share_type['projects']:
        rval.append({'share_type_id': share_type['id'],
                     'project_id': project_id})

    return {'share_type_access': rval}


class ShareTypeAccessController(object):
    """The share type access API controller for the OpenStack API."""

    def index(self, req, type_id):
        context = req.environ['manila.context']
        authorize(context)

        try:
            share_type = share_types.get_share_type(
                context, type_id, expected_fields=['projects'])
        except exception.ShareTypeNotFound:
            explanation = _("Share type %s not found.") % type_id
            raise webob.exc.HTTPNotFound(explanation=explanation)

        if share_type['is_public']:
            expl = _("Access list not available for public share types.")
            raise webob.exc.HTTPNotFound(explanation=expl)

        return _marshall_share_type_access(share_type)


class ShareTypeActionController(wsgi.Controller):
    """The share type access API controller for the OpenStack API."""

    def _check_body(self, body, action_name):
        if not self.is_valid_body(body, action_name):
            raise webob.exc.HTTPBadRequest()
        access = body[action_name]
        project = access.get('project')
        if not uuidutils.is_uuid_like(project):
            msg = _("Bad project format: "
                    "project is not in proper format (%s)") % project
            raise webob.exc.HTTPBadRequest(explanation=msg)

    def _extend_share_type(self, share_type_rval, share_type_ref):
        if share_type_ref:
            key = "%s:is_public" % (Share_type_access.alias)
            share_type_rval[key] = share_type_ref.get('is_public', True)

    @wsgi.extends
    def show(self, req, resp_obj, id):
        context = req.environ['manila.context']
        if soft_authorize(context):
            share_type = req.get_db_share_type(id)
            self._extend_share_type(resp_obj.obj['share_type'], share_type)

    @wsgi.extends
    def index(self, req, resp_obj):
        context = req.environ['manila.context']
        if soft_authorize(context):
            for share_type_rval in list(resp_obj.obj['share_types']):
                type_id = share_type_rval['id']
                share_type = req.get_db_share_type(type_id)
                self._extend_share_type(share_type_rval, share_type)

    @wsgi.extends(action='create')
    def create(self, req, body, resp_obj):
        context = req.environ['manila.context']
        if soft_authorize(context):
            type_id = resp_obj.obj['share_type']['id']
            share_type = req.get_db_share_type(type_id)
            self._extend_share_type(resp_obj.obj['share_type'], share_type)

    @wsgi.action('addProjectAccess')
    def _addProjectAccess(self, req, id, body):
        context = req.environ['manila.context']
        authorize(context, action="addProjectAccess")
        self._check_body(body, 'addProjectAccess')
        project = body['addProjectAccess']['project']

        try:
            share_type = share_types.get_share_type(context, id)

            if share_type['is_public']:
                msg = _("You cannot add project to public share_type.")
                raise webob.exc.HTTPForbidden(explanation=msg)

        except exception.ShareTypeNotFound as err:
            raise webob.exc.HTTPNotFound(explanation=six.text_type(err))

        try:
            share_types.add_share_type_access(context, id, project)
        except exception.ShareTypeAccessExists as err:
            raise webob.exc.HTTPConflict(explanation=six.text_type(err))

        return webob.Response(status_int=202)

    @wsgi.action('removeProjectAccess')
    def _removeProjectAccess(self, req, id, body):
        context = req.environ['manila.context']
        authorize(context, action="removeProjectAccess")
        self._check_body(body, 'removeProjectAccess')
        project = body['removeProjectAccess']['project']

        try:
            share_types.remove_share_type_access(context, id, project)
        except (exception.ShareTypeNotFound,
                exception.ShareTypeAccessNotFound) as err:
            raise webob.exc.HTTPNotFound(explanation=six.text_type(err))
        return webob.Response(status_int=202)


class Share_type_access(extensions.ExtensionDescriptor):
    """share type access support."""

    name = "ShareTypeAccess"
    alias = "os-share-type-access"
    updated = "2015-03-02T00:00:00Z"

    def get_resources(self):
        resources = []
        res = extensions.ResourceExtension(
            Share_type_access.alias,
            ShareTypeAccessController(),
            parent=dict(member_name='type', collection_name='types'))
        resources.append(res)
        return resources

    def get_controller_extensions(self):
        controller = ShareTypeActionController()
        extension = extensions.ControllerExtension(self, 'types', controller)
        return [extension]
