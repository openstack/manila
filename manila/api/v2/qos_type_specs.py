# Copyright 2026 SAP SE.
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

from http import client as http_client

import webob

from manila.api import common
from manila.api.openstack import wsgi
from manila import db
from manila import exception
from manila.i18n import _
from manila import rpc


MIN_SUPPORTED_API_VERSION = '2.94'


class QosTypeSpecsController(wsgi.Controller):
    """The qos type specs API controller for the OpenStack API."""

    resource_name = 'qos_type_specs'

    def __init__(self):
        super(QosTypeSpecsController, self).__init__()

    def _get_specs(self, context, qos_type_id):
        specs = db.qos_type_specs_get(context, qos_type_id)
        specs_dict = {}
        for key, value in specs.items():
            specs_dict[key] = value
        return dict(specs=specs_dict)

    def _assert_qos_type_exists(self, context, qos_type_id):
        try:
            db.qos_type_get(context, qos_type_id)
        except exception.QosTypeNotFound as ex:
            raise webob.exc.HTTPNotFound(explanation=ex.msg)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    def index(self, req, id):
        """Returns the list of specs for a given qos type."""
        context = req.environ['manila.context']
        self._assert_qos_type_exists(context, id)
        return self._get_specs(context, id)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    def show(self, req, id, key):
        """Return a single qos type spec item."""
        context = req.environ['manila.context']
        self._assert_qos_type_exists(context, id)
        specs = self._get_specs(context, id)
        if key in specs['specs']:
            return {key: specs['specs'][key]}
        else:
            raise webob.exc.HTTPNotFound()

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    @wsgi.response(200)
    def create(self, req, id, body=None):
        """Create qos type spec."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'specs'):
            raise webob.exc.HTTPBadRequest()

        self._assert_qos_type_exists(context, id)

        specs = body['specs']
        common.verify_specs(specs)

        self._check_key_names(specs.keys())
        db.qos_type_specs_update_or_create(context, id, specs)
        notifier_info = dict(qos_type_id=id, specs=specs)
        notifier = rpc.get_notifier('qosTypeSpecs')
        notifier.info(context, 'qos_type_specs.create', notifier_info)
        return body

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    @wsgi.response(200)
    def update(self, req, id, key, body=None):
        """Update qos type spec item."""
        context = req.environ['manila.context']
        if not body:
            expl = _('Request body empty')
            raise webob.exc.HTTPBadRequest(explanation=expl)

        self._assert_qos_type_exists(context, id)
        if key not in body:
            expl = _('Request body and URI mismatch')
            raise webob.exc.HTTPBadRequest(explanation=expl)
        if len(body) > 1:
            expl = _('Request body contains too many items')
            raise webob.exc.HTTPBadRequest(explanation=expl)

        common.verify_specs(body)

        db.qos_type_specs_update_or_create(context, id, body)
        notifier_info = dict(qos_type_id=id, key=key)
        notifier = rpc.get_notifier('qosTypeSpecs')
        notifier.info(context, 'qos_type_specs.update', notifier_info)
        return body

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    def delete(self, req, id, key):
        """Deletes an existing qos type spec."""
        context = req.environ['manila.context']
        self._assert_qos_type_exists(context, id)

        try:
            db.qos_type_specs_delete(context, id, key)
        except exception.QosTypeSpecsNotFound as error:
            raise webob.exc.HTTPNotFound(explanation=error.message)

        notifier_info = dict(qos_type_id=id, key=key)
        notifier = rpc.get_notifier('qosTypeSpecs')
        notifier.info(context, 'qos_type_specs.delete', notifier_info)
        return webob.Response(status_int=http_client.NO_CONTENT)

    def _check_key_names(self, keys):
        if not common.validate_key_names(keys):
            expl = _('Key names can only contain alphanumeric characters, '
                     'underscores, periods, colons and hyphens.')
            raise webob.exc.HTTPBadRequest(explanation=expl)


def create_resource():
    return wsgi.Resource(QosTypeSpecsController())
