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

import copy
import six
import webob

from manila.api import common
from manila.api.openstack import wsgi
from manila import db
from manila import exception
from manila.i18n import _
from manila.share_group import share_group_types


class ShareGroupTypeSpecsController(wsgi.Controller):
    """The share group type specs API controller for the OpenStack API."""

    resource_name = 'share_group_types_spec'

    def _get_group_specs(self, context, type_id):
        specs = db.share_group_type_specs_get(context, type_id)
        return {"group_specs": copy.deepcopy(specs)}

    def _assert_share_group_type_exists(self, context, type_id):
        try:
            share_group_types.get(context, type_id)
        except exception.NotFound as ex:
            raise webob.exc.HTTPNotFound(explanation=ex.msg)

    def _verify_group_specs(self, group_specs):

        def is_valid_string(v):
            return isinstance(v, six.string_types) and len(v) in range(1, 256)

        def is_valid_spec(k, v):
            valid_spec_key = is_valid_string(k)
            valid_type = is_valid_string(v) or isinstance(v, bool)
            return valid_spec_key and valid_type

        for k, v in group_specs.items():
            if is_valid_string(k) and isinstance(v, dict):
                self._verify_group_specs(v)
            elif not is_valid_spec(k, v):
                expl = _('Invalid extra_spec: %(key)s: %(value)s') % {
                    'key': k, 'value': v
                }
                raise webob.exc.HTTPBadRequest(explanation=expl)

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize
    def index(self, req, id):
        """Returns the list of group specs for a given share group type."""

        context = req.environ['manila.context']
        self._assert_share_group_type_exists(context, id)
        return self._get_group_specs(context, id)

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize
    def create(self, req, id, body=None):
        context = req.environ['manila.context']
        if not self.is_valid_body(body, 'group_specs'):
            raise webob.exc.HTTPBadRequest()

        self._assert_share_group_type_exists(context, id)
        specs = body['group_specs']
        self._verify_group_specs(specs)
        self._check_key_names(specs.keys())
        db.share_group_type_specs_update_or_create(context, id, specs)
        return body

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize
    def update(self, req, id, key, body=None):
        context = req.environ['manila.context']
        if not body:
            expl = _('Request body empty.')
            raise webob.exc.HTTPBadRequest(explanation=expl)
        self._assert_share_group_type_exists(context, id)
        if key not in body:
            expl = _('Request body and URI mismatch.')
            raise webob.exc.HTTPBadRequest(explanation=expl)
        if len(body) > 1:
            expl = _('Request body contains too many items.')
            raise webob.exc.HTTPBadRequest(explanation=expl)
        self._verify_group_specs(body)
        db.share_group_type_specs_update_or_create(context, id, body)
        return body

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize
    def show(self, req, id, key):
        """Return a single group spec item."""
        context = req.environ['manila.context']
        self._assert_share_group_type_exists(context, id)
        specs = self._get_group_specs(context, id)
        if key in specs['group_specs']:
            return {key: specs['group_specs'][key]}
        else:
            raise webob.exc.HTTPNotFound()

    @wsgi.Controller.api_version('2.31', experimental=True)
    @wsgi.Controller.authorize
    def delete(self, req, id, key):
        """Deletes an existing group spec."""
        context = req.environ['manila.context']
        self._assert_share_group_type_exists(context, id)
        try:
            db.share_group_type_specs_delete(context, id, key)
        except exception.ShareGroupTypeSpecsNotFound as error:
            raise webob.exc.HTTPNotFound(explanation=error.msg)
        return webob.Response(status_int=204)

    def _check_key_names(self, keys):
        if not common.validate_key_names(keys):
            expl = _('Key names can only contain alphanumeric characters, '
                     'underscores, periods, colons and hyphens.')

            raise webob.exc.HTTPBadRequest(explanation=expl)


def create_resource():
    return wsgi.Resource(ShareGroupTypeSpecsController())
