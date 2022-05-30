# Copyright (c) 2022 China Telecom Digital Intelligence.
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

"""The share transfer api."""

from http import client as http_client

from oslo_log import log as logging
from oslo_utils import strutils
from oslo_utils import uuidutils
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import transfers as transfer_view
from manila import exception
from manila.i18n import _
from manila.transfer import api as transfer_api

LOG = logging.getLogger(__name__)
SHARE_TRANSFER_VERSION = "2.77"


class ShareTransferController(wsgi.Controller):
    """The Share Transfer API controller for the OpenStack API."""

    resource_name = 'share_transfer'
    _view_builder_class = transfer_view.ViewBuilder

    def __init__(self):
        self.transfer_api = transfer_api.API()
        super(ShareTransferController, self).__init__()

    @wsgi.Controller.authorize('get')
    @wsgi.Controller.api_version(SHARE_TRANSFER_VERSION)
    def show(self, req, id):
        """Return data about active transfers."""
        context = req.environ['manila.context']

        # Not found exception will be handled at the wsgi level
        transfer = self.transfer_api.get(context, transfer_id=id)

        return self._view_builder.detail(req, transfer)

    @wsgi.Controller.api_version(SHARE_TRANSFER_VERSION)
    def index(self, req):
        """Returns a summary list of transfers."""
        return self._get_transfers(req, is_detail=False)

    @wsgi.Controller.api_version(SHARE_TRANSFER_VERSION)
    def detail(self, req):
        """Returns a detailed list of transfers."""
        return self._get_transfers(req, is_detail=True)

    @wsgi.Controller.authorize('get_all')
    def _get_transfers(self, req, is_detail):
        """Returns a list of transfers, transformed through view builder."""
        context = req.environ['manila.context']
        params = req.params.copy()
        pagination_params = common.get_pagination_params(req)
        limit, offset = [pagination_params.pop('limit', None),
                         pagination_params.pop('offset', None)]
        sort_key, sort_dir = common.get_sort_params(params)

        filters = params
        key_map = {'name': 'display_name', 'name~': 'display_name~'}
        for k in key_map:
            if k in filters:
                filters[key_map[k]] = filters.pop(k)
        LOG.debug('Listing share transfers.')

        transfers = self.transfer_api.get_all(context,
                                              limit=limit,
                                              sort_key=sort_key,
                                              sort_dir=sort_dir,
                                              filters=filters,
                                              offset=offset)

        if is_detail:
            transfers = self._view_builder.detail_list(req, transfers)
        else:
            transfers = self._view_builder.summary_list(req, transfers)

        return transfers

    @wsgi.response(http_client.ACCEPTED)
    @wsgi.Controller.api_version(SHARE_TRANSFER_VERSION)
    @wsgi.Controller.authorize('create')
    def create(self, req, body):
        """Create a new share transfer."""
        LOG.debug('Creating new share transfer %s', body)
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'transfer'):
            msg = _("'transfer' is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        transfer = body.get('transfer', {})

        share_id = transfer.get('share_id')
        if not share_id:
            msg = _("Must supply 'share_id' attribute.")
            raise exc.HTTPBadRequest(explanation=msg)
        if not uuidutils.is_uuid_like(share_id):
            msg = _("The 'share_id' attribute must be a uuid.")
            raise exc.HTTPBadRequest(explanation=msg)

        transfer_name = transfer.get('name')
        if transfer_name is not None:
            transfer_name = transfer_name.strip()

        LOG.debug("Creating transfer of share %s", share_id)

        try:
            new_transfer = self.transfer_api.create(context, share_id,
                                                    transfer_name)
        except exception.Invalid as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

        transfer = self._view_builder.create(req,
                                             dict(new_transfer))
        return transfer

    @wsgi.response(http_client.ACCEPTED)
    @wsgi.Controller.api_version(SHARE_TRANSFER_VERSION)
    @wsgi.Controller.authorize('accept')
    def accept(self, req, id, body):
        """Accept a new share transfer."""
        transfer_id = id
        LOG.debug('Accepting share transfer %s', transfer_id)
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'accept'):
            msg = _("'accept' is missing from the request body.")
            raise exc.HTTPBadRequest(explanation=msg)

        accept = body.get('accept', {})
        auth_key = accept.get('auth_key')
        if not auth_key:
            msg = _("Must supply 'auth_key' while accepting a "
                    "share transfer.")
            raise exc.HTTPBadRequest(explanation=msg)

        clear_rules = accept.get('clear_access_rules', False)
        if clear_rules:
            try:
                clear_rules = strutils.bool_from_string(clear_rules,
                                                        strict=True)
            except (ValueError, TypeError):
                msg = (_('Invalid boolean clear_access_rules : %(value)s') %
                       {'value': accept['clear_access_rules']})
                raise exc.HTTPBadRequest(explanation=msg)

        LOG.debug("Accepting transfer %s", transfer_id)

        try:
            self.transfer_api.accept(
                context, transfer_id, auth_key, clear_rules=clear_rules)
        except (exception.ShareSizeExceedsLimit,
                exception.ShareLimitExceeded,
                exception.ShareSizeExceedsAvailableQuota,
                exception.ShareReplicasLimitExceeded,
                exception.ShareReplicaSizeExceedsAvailableQuota,
                exception.SnapshotSizeExceedsAvailableQuota,
                exception.SnapshotLimitExceeded) as e:
            raise exc.HTTPRequestEntityTooLarge(explanation=e.msg,
                                                headers={'Retry-After': '0'})
        except (exception.InvalidShare,
                exception.InvalidSnapshot,
                exception.InvalidAuthKey,
                exception.TransferNotFound) as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

    @wsgi.Controller.api_version(SHARE_TRANSFER_VERSION)
    @wsgi.Controller.authorize('delete')
    def delete(self, req, id):
        """Delete a transfer."""
        context = req.environ['manila.context']

        LOG.debug("Delete transfer with id: %s", id)

        # Not found exception will be handled at the wsgi level
        self.transfer_api.delete(context, transfer_id=id)
        return webob.Response(status_int=http_client.OK)


def create_resource():
    return wsgi.Resource(ShareTransferController())
