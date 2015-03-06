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

"""The share types manage extension."""

import six
import webob

from manila.api import extensions
from manila.api.openstack import wsgi
from manila.api.views import types as views_types
from manila import exception
from manila.i18n import _
from manila import rpc
from manila.share import share_types


authorize = extensions.extension_authorizer('share', 'types_manage')


class ShareTypesManageController(wsgi.Controller):
    """The share types API controller for the OpenStack API."""

    _view_builder_class = views_types.ViewBuilder

    def _notify_share_type_error(self, context, method, payload):
        rpc.get_notifier('shareType').error(context, method, payload)

    @wsgi.action("create")
    def _create(self, req, body):
        """Creates a new share type."""
        context = req.environ['manila.context']
        authorize(context)

        if not self.is_valid_body(body, 'share_type') and \
                not self.is_valid_body(body, 'volume_type'):
            raise webob.exc.HTTPBadRequest()

        elif self.is_valid_body(body, 'share_type'):
            share_type = body['share_type']
        else:
            share_type = body['volume_type']
        name = share_type.get('name', None)
        specs = share_type.get('extra_specs', {})

        if name is None or name == "" or len(name) > 255:
            msg = _("Type name is not valid.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        try:
            required_extra_specs = (
                share_types.get_valid_required_extra_specs(specs)
            )
        except exception.InvalidExtraSpec as e:
            raise webob.exc.HTTPBadRequest(explanation=six.text_type(e))

        try:
            share_types.create(context, name, specs)
            share_type = share_types.get_share_type_by_name(context, name)
            share_type['required_extra_specs'] = required_extra_specs
            notifier_info = dict(share_types=share_type)
            rpc.get_notifier('shareType').info(
                context, 'share_type.create', notifier_info)

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
    def _delete(self, req, id):
        """Deletes an existing share type."""
        context = req.environ['manila.context']
        authorize(context)

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


class Types_manage(extensions.ExtensionDescriptor):
    """Types manage support."""

    name = "TypesManage"
    alias = "os-types-manage"
    namespace = "http://docs.openstack.org/share/ext/types-manage/api/v1"
    updated = "2011-08-24T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = ShareTypesManageController()
        extension = extensions.ControllerExtension(self, 'types', controller)
        return [extension]
