# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila import db
from manila import exception
from manila.i18n import _
from manila import policy


class MetadataController(object):
    """An abstract metadata controller resource."""

    # From db, ensure it exists
    resource_get = {
        "share": "share_get",
        "share_snapshot": "share_snapshot_get",
        "share_network_subnet": "share_network_subnet_get",
    }

    resource_metadata_get = {
        "share": "share_metadata_get",
        "share_snapshot": "share_snapshot_metadata_get",
        "share_network_subnet": "share_network_subnet_metadata_get",
    }

    resource_metadata_get_item = {
        "share": "share_metadata_get_item",
        "share_snapshot": "share_snapshot_metadata_get_item",
        "share_network_subnet": "share_network_subnet_metadata_get_item",
    }

    resource_metadata_update = {
        "share": "share_metadata_update",
        "share_snapshot": "share_snapshot_metadata_update",
        "share_network_subnet": "share_network_subnet_metadata_update",
    }

    resource_metadata_update_item = {
        "share": "share_metadata_update_item",
        "share_snapshot": "share_snapshot_metadata_update_item",
        "share_network_subnet": "share_network_subnet_metadata_update_item",
    }

    resource_metadata_delete = {
        "share": "share_metadata_delete",
        "share_snapshot": "share_snapshot_metadata_delete",
        "share_network_subnet": "share_network_subnet_metadata_delete",
    }

    resource_policy_get = {
        'share': 'get',
        'share_snapshot': 'get_snapshot',
        'share_network_subnet': 'show',
    }

    def __init__(self):
        super(MetadataController, self).__init__()
        self.resource_name = None

    def _get_resource(self, context, resource_id,
                      for_modification=False, parent_id=None):
        if self.resource_name in ['share', 'share_network_subnet']:
            # we would allow retrieving some "public" resources
            # across project namespaces excpet share snaphots,
            # project_only=True is hard coded
            kwargs = {}
        else:
            kwargs = {'project_only': True}
        try:
            get_res_method = getattr(
                db, self.resource_get[self.resource_name])
            if parent_id is not None:
                kwargs["parent_id"] = parent_id
            res = get_res_method(context, resource_id, **kwargs)

            get_policy = self.resource_policy_get[self.resource_name]
            if res.get('is_public') is False or for_modification:
                policy.check_policy(context, self.resource_name,
                                    get_policy, res)

        except exception.NotFound:
            msg = _('%s not found.' % self.resource_name.capitalize())
            raise exc.HTTPNotFound(explanation=msg)
        return res

    def _get_metadata(self, context, resource_id, parent_id=None):

        self._get_resource(context, resource_id, parent_id=parent_id)
        get_metadata_method = getattr(
            db, self.resource_metadata_get[self.resource_name])

        result = get_metadata_method(context, resource_id)

        return result

    @wsgi.response(200)
    def _index_metadata(self, req, resource_id, parent_id=None):
        context = req.environ['manila.context']
        metadata = self._get_metadata(context, resource_id,
                                      parent_id=parent_id)

        return {'metadata': metadata}

    @wsgi.response(200)
    def _create_metadata(self, req, resource_id, body, parent_id=None):
        """Returns the new metadata item created."""

        context = req.environ['manila.context']
        try:
            metadata = body['metadata']
            common.check_metadata_properties(metadata)
        except (KeyError, TypeError):
            msg = _("Malformed request body")
            raise exc.HTTPBadRequest(explanation=msg)
        except exception.InvalidMetadata as error:
            raise exc.HTTPBadRequest(explanation=error.msg)
        except exception.InvalidMetadataSize as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

        self._get_resource(context, resource_id,
                           for_modification=True, parent_id=parent_id)

        create_metadata_method = getattr(
            db, self.resource_metadata_update[self.resource_name])
        result = create_metadata_method(context, resource_id, metadata,
                                        delete='False')

        return {'metadata': result}

    def _update_metadata_item(self, req, resource_id, body, key,
                              parent_id=None):
        """Updates the specified metadata item."""

        context = req.environ['manila.context']
        try:
            meta_item = body['metadata']
            common.check_metadata_properties(meta_item)
        except (TypeError, KeyError):
            expl = _('Malformed request body')
            raise exc.HTTPBadRequest(explanation=expl)
        except exception.InvalidMetadata as error:
            raise exc.HTTPBadRequest(explanation=error.msg)
        except exception.InvalidMetadataSize as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

        if key not in meta_item:
            expl = _('Request body and URI mismatch')
            raise exc.HTTPBadRequest(explanation=expl)
        if len(meta_item) > 1:
            expl = _('Request body contains too many items')
            raise exc.HTTPBadRequest(explanation=expl)
        self._get_resource(context, resource_id,
                           for_modification=True, parent_id=parent_id)

        update_metadata_item_method = getattr(
            db, self.resource_metadata_update_item[self.resource_name])
        result = update_metadata_item_method(context, resource_id, meta_item)

        return {'metadata': result}

    @wsgi.response(200)
    def _update_all_metadata(self, req, resource_id, body, parent_id=None):
        """Deletes existing metadata, and returns the updated metadata."""

        context = req.environ['manila.context']
        try:
            metadata = body['metadata']
            common.check_metadata_properties(metadata)
        except (TypeError, KeyError):
            expl = _('Malformed request body')
            raise exc.HTTPBadRequest(explanation=expl)
        except exception.InvalidMetadata as error:
            raise exc.HTTPBadRequest(explanation=error.msg)
        except exception.InvalidMetadataSize as error:
            raise exc.HTTPBadRequest(explanation=error.msg)

        self._get_resource(context, resource_id,
                           for_modification=True, parent_id=parent_id)
        meta_ref = self._get_metadata(context, resource_id,
                                      parent_id=parent_id)

        for key in meta_ref:
            delete_metadata_method = getattr(
                db, self.resource_metadata_delete[self.resource_name])
            delete_metadata_method(context, resource_id, key)

        update_metadata_method = getattr(
            db, self.resource_metadata_update[self.resource_name])
        new_metadata = update_metadata_method(context, resource_id,
                                              metadata, delete='False')
        return {'metadata': new_metadata}

    @wsgi.response(200)
    def _show_metadata(self, req, resource_id, key, parent_id=None):
        """Return metadata item."""

        context = req.environ['manila.context']
        self._get_resource(context, resource_id,
                           for_modification=False, parent_id=parent_id)
        get_metadata_item_method = getattr(
            db, self.resource_metadata_get_item[self.resource_name])
        item = get_metadata_item_method(context, resource_id, key)

        return {'meta': {key: item[key]}}

    @wsgi.response(200)
    def _delete_metadata(self, req, resource_id, key, parent_id=None):
        """Deletes existing metadata item."""

        context = req.environ['manila.context']
        self._get_resource(context, resource_id,
                           for_modification=True, parent_id=parent_id)

        get_metadata_item_method = getattr(
            db, self.resource_metadata_get_item[self.resource_name])
        get_metadata_item_method(context, resource_id, key)

        delete_metadata_method = getattr(
            db, self.resource_metadata_delete[self.resource_name])
        delete_metadata_method(context, resource_id, key)
