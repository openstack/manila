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


"""The qos types API.

This module handles the following requests:
GET /qos-types
GET /qos-types/{qos_type_id}
POST /qos-types
PUT /qos-types/{qos_type_id}
DELETE /qos-types/{qos_type_id}
"""

from http import client as http_client

import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import qos_types as qos_type_view
from manila.db import api as db_api
from manila import exception
from manila.i18n import _
from manila import rpc
from manila import share


MIN_SUPPORTED_API_VERSION = '2.94'


class QosTypesController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The Qos Type API controller for the OpenStack API."""

    resource_name = 'qos_type'
    _view_builder_class = qos_type_view.ViewBuilder

    def __init__(self):
        super(QosTypesController, self).__init__()
        self.share_api = share.API()

    def _notify_qos_type_error(self, context, method, payload):
        rpc.get_notifier('qosType').error(context, method, payload)

    def _notify_qos_type_info(self, context, method, qos_type):
        payload = dict(qos_types=qos_type)
        rpc.get_notifier('qosType').info(context, method, payload)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    def index(self, req):
        """Returns list of qos_types."""
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)
        params = common.get_pagination_params(req)
        limit, offset = [params.get('limit'), params.get('offset')]

        search_opts.pop('limit', None)
        search_opts.pop('offset', None)
        sort_key, sort_dir = common.get_sort_params(search_opts)

        common.remove_invalid_options(context, search_opts,
                                      self._get_qos_types_search_options())

        qos_types = db_api.qos_type_get_all(context,
                                            filters=search_opts,
                                            limit=limit,
                                            offset=offset,
                                            sort_key=sort_key,
                                            sort_dir=sort_dir)
        qos_types = list(qos_types.values())
        return self._view_builder.index(req, qos_types)

    def _get_qos_types_search_options(self):
        """Return qos_type search options allowed by non-admin."""
        return ('name', 'name~', 'description~', 'description')

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    def show(self, req, id):
        """Return data about the given qos_type."""

        context = req.environ['manila.context']
        try:
            qos_type = db_api.qos_type_get(context, id)
        except exception.QosTypeNotFound:
            msg = _("No QoS Type exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)
        return self._view_builder.show(req, qos_type)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    def create(self, req, body):
        """Add a qos_type."""

        context = req.environ['manila.context']
        if not self.is_valid_body(body, 'qos_type'):
            msg = _("Body does not contain 'qos_type' information.")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        data = body.get('qos_type')
        name = data.get('name')
        if not name:
            msg = _("QoS Type must have name. Name will be used as template "
                    "by backend drivers to create QoS policy name.")
            raise exc.HTTPBadRequest(explanation=msg)

        existing_qos = None
        try:
            existing_qos = db_api.qos_type_get_by_name(context, name)
        except exception.QosTypeNotFoundByName:
            pass

        if existing_qos:
            msg = _("QoS Type with name %s already exist.")
            raise exc.HTTPConflict(explanation=msg % name)

        description = data.get('description')
        specs = data.get('specs', {})
        common.verify_specs(specs)
        qos_type_data = dict(name=name, description=description, specs=specs)
        try:
            qos_type = self.share_api.create_qos_type(context, qos_type_data)
            self._notify_qos_type_info(
                context, 'qos_type.create', qos_type)
        except exception.QosTypeExists as err:
            notifier_err = dict(qos_types=qos_type_data,
                                error_message=err.msg)
            self._notify_qos_type_error(context, 'qos_type.create',
                                        notifier_err)
            raise exc.HTTPConflict(explanation=err.msg)
        return self._view_builder.show(req, qos_type)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    def delete(self, req, id):
        """Delete a qos_type."""

        context = req.environ['manila.context']
        try:
            qos_type = db_api.qos_type_get(context, id)
            self.share_api.delete_qos_type(context, qos_type)
            self._notify_qos_type_info(
                context, 'qos_type.delete', qos_type)
        except exception.QosTypeNotFound as err:
            notifier_err = dict(id=id, error_message=err.msg)
            self._notify_qos_type_error(context, 'qos_type.delete',
                                        notifier_err)
            msg = _("No QoS Type exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)
        except exception.QosTypeInUse as err:
            notifier_err = dict(id=id, error_message=err.msg)
            self._notify_qos_type_error(context, 'qos_type.delete',
                                        notifier_err)
            raise exc.HTTPBadRequest(explanation=err.msg)
        return webob.Response(status_int=http_client.NO_CONTENT)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION)
    @wsgi.Controller.authorize
    @wsgi.response(200)
    def update(self, req, id, body):
        """Update a qos_type."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'qos_type'):
            msg = _("Body does not contain 'qos_type' information.")
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        data = body.get('qos_type')
        valid_update_keys = ['description']
        update_dict = {key: data[key]
                       for key in valid_update_keys
                       if key in data}

        try:
            qos_type = db_api.qos_type_get(context, id)
            if update_dict:
                qos_type = self.share_api.update_qos_type(context, qos_type,
                                                          update_dict)
                self._notify_qos_type_info(
                    context, 'qos_type.update', qos_type)
        except exception.QosTypeNotFound as err:
            notifier_err = dict(id=id, error_message=err.msg)
            self._notify_qos_type_error(
                context, 'qos_type.update', notifier_err)
            msg = _("No qos_type exists with ID %s.")
            raise exc.HTTPNotFound(explanation=msg % id)

        return self._view_builder.show(req, qos_type)


def create_resource():
    return wsgi.Resource(QosTypesController())
