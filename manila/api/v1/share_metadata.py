# Copyright 2011 OpenStack Foundation
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

from http import client as http_client
from oslo_log import log
import webob
from webob import exc

from manila.api import common as api_common
from manila.api.openstack import wsgi
from manila.common import constants
from manila import db
from manila import exception
from manila.i18n import _
from manila import policy
from manila import share


LOG = log.getLogger(__name__)


class ShareMetadataController(object):
    """The share metadata API controller for the OpenStack API."""

    def __init__(self):
        self.share_api = share.API()
        super(ShareMetadataController, self).__init__()

    def _get_metadata(self, context, share_id):
        try:
            share = self.share_api.get(context, share_id)
            rv = db.share_metadata_get(context, share['id'])
            meta = dict(rv.items())
        except exception.NotFound:
            msg = _('share does not exist')
            raise exc.HTTPNotFound(explanation=msg)
        return meta

    def index(self, req, share_id):
        """Returns the list of metadata for a given share."""
        context = req.environ['manila.context']
        return {'metadata': self._get_metadata(context, share_id)}

    def create(self, req, share_id, body):
        try:
            metadata = body['metadata']
        except (KeyError, TypeError):
            msg = _("Malformed request body")
            raise exc.HTTPBadRequest(explanation=msg)

        context = req.environ['manila.context']

        new_metadata = self._update_share_metadata(context,
                                                   share_id,
                                                   metadata,
                                                   delete=False)
        return {'metadata': new_metadata}

    def update(self, req, share_id, id, body):
        try:
            meta_item = body['meta']
        except (TypeError, KeyError):
            expl = _('Malformed request body')
            raise exc.HTTPBadRequest(explanation=expl)

        if id not in meta_item:
            expl = _('Request body and URI mismatch')
            raise exc.HTTPBadRequest(explanation=expl)

        if len(meta_item) > 1:
            expl = _('Request body contains too many items')
            raise exc.HTTPBadRequest(explanation=expl)

        context = req.environ['manila.context']
        self._update_share_metadata(context,
                                    share_id,
                                    meta_item,
                                    delete=False)

        return {'meta': meta_item}

    def update_all(self, req, share_id, body):
        try:
            metadata = body['metadata']
        except (TypeError, KeyError):
            expl = _('Malformed request body')
            raise exc.HTTPBadRequest(explanation=expl)

        context = req.environ['manila.context']

        new_metadata = self._update_share_metadata(
            context, share_id, metadata, delete=True)
        return {'metadata': new_metadata}

    def _update_share_metadata(self, context,
                               share_id, metadata,
                               delete=False):
        ignore_keys = constants.AdminOnlyMetadata.SCHEDULER_FILTERS
        try:
            share = self.share_api.get(context, share_id)
            if set(metadata).intersection(set(ignore_keys)):
                try:
                    policy.check_policy(
                        context, 'share', 'update_admin_only_metadata')
                except exception.PolicyNotAuthorized:
                    msg = _("Cannot set or update admin only metadata.")
                    LOG.exception(msg)
                    raise exc.HTTPForbidden(explanation=msg)
                ignore_keys = []

            rv = db.share_metadata_get(context, share['id'])
            orig_meta = dict(rv.items())
            if delete:
                _metadata = metadata
                for key in ignore_keys:
                    if key in orig_meta:
                        _metadata[key] = orig_meta[key]
            else:
                metadata_copy = metadata.copy()
                for key in ignore_keys:
                    metadata_copy.pop(key, None)
                _metadata = orig_meta.copy()
                _metadata.update(metadata_copy)

            api_common.check_metadata_properties(_metadata)
            db.share_metadata_update(context, share['id'],
                                     _metadata, delete)

            return _metadata
        except exception.NotFound:
            msg = _('share does not exist')
            raise exc.HTTPNotFound(explanation=msg)

        except (ValueError, AttributeError):
            msg = _("Malformed request body")
            raise exc.HTTPBadRequest(explanation=msg)

        except exception.InvalidMetadata as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

        except exception.InvalidMetadataSize as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

    def show(self, req, share_id, id):
        """Return a single metadata item."""
        context = req.environ['manila.context']
        data = self._get_metadata(context, share_id)

        try:
            return {'meta': {id: data[id]}}
        except KeyError:
            msg = _("Metadata item was not found")
            raise exc.HTTPNotFound(explanation=msg)

    def delete(self, req, share_id, id):
        """Deletes an existing metadata."""
        context = req.environ['manila.context']

        metadata = self._get_metadata(context, share_id)

        if id not in metadata:
            msg = _("Metadata item was not found")
            raise exc.HTTPNotFound(explanation=msg)

        try:
            share = self.share_api.get(context, share_id)
            if id in constants.AdminOnlyMetadata.SCHEDULER_FILTERS:
                policy.check_policy(context, 'share',
                                    'update_admin_only_metadata')
            db.share_metadata_delete(context, share['id'], id)
        except exception.NotFound:
            msg = _('share does not exist')
            raise exc.HTTPNotFound(explanation=msg)
        except exception.PolicyNotAuthorized:
            msg = _("Cannot delete admin only metadata.")
            LOG.exception(msg)
            raise exc.HTTPForbidden(explanation=msg)
        return webob.Response(status_int=http_client.OK)


def create_resource():
    return wsgi.Resource(ShareMetadataController())
