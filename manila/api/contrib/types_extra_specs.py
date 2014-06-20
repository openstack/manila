# Copyright (c) 2011 Zadara Storage Inc.
# Copyright (c) 2011 OpenStack Foundation
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

"""The volume types extra specs extension"""

import webob

from manila.api import common
from manila.api import extensions
from manila.api.openstack import wsgi
from manila import db
from manila import exception
from manila import rpc
from manila.share import volume_types

authorize = extensions.extension_authorizer('share', 'types_extra_specs')


class VolumeTypeExtraSpecsController(wsgi.Controller):
    """The volume type extra specs API controller for the OpenStack API."""

    def _get_extra_specs(self, context, type_id):
        extra_specs = db.volume_type_extra_specs_get(context, type_id)
        specs_dict = {}
        for key, value in extra_specs.iteritems():
            specs_dict[key] = value
        return dict(extra_specs=specs_dict)

    def _check_type(self, context, type_id):
        try:
            volume_types.get_volume_type(context, type_id)
        except exception.NotFound as ex:
            raise webob.exc.HTTPNotFound(explanation=ex.msg)

    def _verify_extra_specs(self, extra_specs):
        # keys and values in extra_specs can be only strings
        # with length in range(1, 256)
        is_valid = True
        for k, v in extra_specs.iteritems():
            if not (isinstance(k, basestring) and len(k) in range(1, 256)):
                is_valid = False
                break
            if isinstance(v, dict):
                self._verify_extra_specs(v)
            elif isinstance(v, basestring):
                if len(v) not in range(1, 256):
                    is_valid = False
                    break
            else:
                is_valid = False
                break
        if not is_valid:
            expl = _('Invalid request body')
            raise webob.exc.HTTPBadRequest(explanation=expl)

    def index(self, req, type_id):
        """Returns the list of extra specs for a given volume type."""
        context = req.environ['manila.context']
        authorize(context)
        self._check_type(context, type_id)
        return self._get_extra_specs(context, type_id)

    def create(self, req, type_id, body=None):
        context = req.environ['manila.context']
        authorize(context)

        if not self.is_valid_body(body, 'extra_specs'):
            raise webob.exc.HTTPBadRequest()

        self._check_type(context, type_id)
        self._verify_extra_specs(body)
        specs = body['extra_specs']
        self._check_key_names(specs.keys())
        db.volume_type_extra_specs_update_or_create(context,
                                                    type_id,
                                                    specs)
        notifier_info = dict(type_id=type_id, specs=specs)
        notifier = rpc.get_notifier('volumeTypeExtraSpecs')
        notifier.info(context, 'volume_type_extra_specs.create', notifier_info)
        return body

    def update(self, req, type_id, id, body=None):
        context = req.environ['manila.context']
        authorize(context)
        if not body:
            expl = _('Request body empty')
            raise webob.exc.HTTPBadRequest(explanation=expl)
        self._check_type(context, type_id)
        if id not in body:
            expl = _('Request body and URI mismatch')
            raise webob.exc.HTTPBadRequest(explanation=expl)
        if len(body) > 1:
            expl = _('Request body contains too many items')
            raise webob.exc.HTTPBadRequest(explanation=expl)
        self._verify_extra_specs(body)
        db.volume_type_extra_specs_update_or_create(context,
                                                    type_id,
                                                    body)
        notifier_info = dict(type_id=type_id, id=id)
        notifier = rpc.get_notifier('volumeTypeExtraSpecs')
        notifier.info(context, 'volume_type_extra_specs.update', notifier_info)
        return body

    def show(self, req, type_id, id):
        """Return a single extra spec item."""
        context = req.environ['manila.context']
        authorize(context)
        self._check_type(context, type_id)
        specs = self._get_extra_specs(context, type_id)
        if id in specs['extra_specs']:
            return {id: specs['extra_specs'][id]}
        else:
            raise webob.exc.HTTPNotFound()

    def delete(self, req, type_id, id):
        """Deletes an existing extra spec."""
        context = req.environ['manila.context']
        self._check_type(context, type_id)
        authorize(context)

        try:
            db.volume_type_extra_specs_delete(context, type_id, id)
        except exception.VolumeTypeExtraSpecsNotFound as error:
            raise webob.exc.HTTPNotFound(explanation=error.msg)

        notifier_info = dict(type_id=type_id, id=id)
        notifier = rpc.get_notifier('volumeTypeExtraSpecs')
        notifier.info(context, 'volume_type_extra_specs.delete', notifier_info)
        return webob.Response(status_int=202)

    def _check_key_names(self, keys):
        if not common.validate_key_names(keys):
            expl = _('Key names can only contain alphanumeric characters, '
                     'underscores, periods, colons and hyphens.')

            raise webob.exc.HTTPBadRequest(explanation=expl)


class Types_extra_specs(extensions.ExtensionDescriptor):
    """Type extra specs support."""

    name = "TypesExtraSpecs"
    alias = "os-types-extra-specs"
    namespace = "http://docs.openstack.org/share/ext/types-extra-specs/api/v1"
    updated = "2011-08-24T00:00:00+00:00"

    def get_resources(self):
        resources = []
        res = extensions.ResourceExtension(
            'extra_specs',
            VolumeTypeExtraSpecsController(),
            parent=dict(member_name='type',
                        collection_name='types')
        )
        resources.append(res)

        return resources
