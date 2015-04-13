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

import webob
from webob import exc

from manila.api.openstack import wsgi
from manila import exception
from manila.i18n import _
from manila import share


class ShareMetadataController(object):
    """The share metadata API controller for the OpenStack API."""

    def __init__(self):
        self.share_api = share.API()
        super(ShareMetadataController, self).__init__()

    def _get_metadata(self, context, share_id):
        try:
            share = self.share_api.get(context, share_id)
            meta = self.share_api.get_share_metadata(context, share)
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
        new_metadata = self._update_share_metadata(context, share_id,
                                                   metadata, delete=True)
        return {'metadata': new_metadata}

    def _update_share_metadata(self, context,
                               share_id, metadata,
                               delete=False):
        try:
            share = self.share_api.get(context, share_id)
            return self.share_api.update_share_metadata(context,
                                                        share,
                                                        metadata,
                                                        delete)
        except exception.NotFound:
            msg = _('share does not exist')
            raise exc.HTTPNotFound(explanation=msg)

        except (ValueError, AttributeError):
            msg = _("Malformed request body")
            raise exc.HTTPBadRequest(explanation=msg)

        except exception.InvalidShareMetadata as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

        except exception.InvalidShareMetadataSize as error:
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
            self.share_api.delete_share_metadata(context, share, id)
        except exception.NotFound:
            msg = _('share does not exist')
            raise exc.HTTPNotFound(explanation=msg)
        return webob.Response(status_int=200)


def create_resource():
    return wsgi.Resource(ShareMetadataController())
