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

import uuid

from oslo.config import cfg
import webob

from manila.api.v1 import share_metadata
from manila.api.v1 import shares
import manila.db
from manila import exception
from manila.openstack.common import jsonutils
from manila import test
from manila.tests.api import fakes


CONF = cfg.CONF


def return_create_share_metadata_max(context, share_id, metadata, delete):
    return stub_max_share_metadata()


def return_create_share_metadata(context, share_id, metadata, delete):
    return stub_share_metadata()


def return_share_metadata(context, share_id):
    if not isinstance(share_id, str) or not len(share_id) == 36:
        msg = 'id %s must be a uuid in return share metadata' % share_id
        raise Exception(msg)
    return stub_share_metadata()


def return_empty_share_metadata(context, share_id):
    return {}


def delete_share_metadata(context, share_id, key):
    pass


def stub_share_metadata():
    metadata = {
        "key1": "value1",
        "key2": "value2",
        "key3": "value3",
    }
    return metadata


def stub_max_share_metadata():
    metadata = {"metadata": {}}
    for num in range(CONF.quota_metadata_items):
        metadata['metadata']['key%i' % num] = "blah"
    return metadata


def return_share(context, share_id):
    return {'id': '0cc3346e-9fef-4445-abe6-5d2b2690ec64',
            'name': 'fake',
            'metadata': {}}


def return_share_nonexistent(context, share_id):
    raise exception.NotFound('bogus test message')


def fake_update_share_metadata(self, context, share, diff):
    pass


class ShareMetaDataTest(test.TestCase):

    def setUp(self):
        super(ShareMetaDataTest, self).setUp()
        self.share_api = manila.share.api.API()
        fakes.stub_out_key_pair_funcs(self.stubs)
        self.stubs.Set(manila.db, 'share_get', return_share)
        self.stubs.Set(manila.db, 'share_metadata_get',
                       return_share_metadata)

        self.stubs.Set(self.share_api, 'update_share_metadata',
                       fake_update_share_metadata)

        self.share_controller = shares.ShareController()
        self.controller = share_metadata.ShareMetadataController()
        self.req_id = str(uuid.uuid4())
        self.url = '/shares/%s/metadata' % self.req_id

        sh = {"size": 1,
              "name": "Share Test Name",
              "share_proto": "nfs",
              "display_name": "Updated Desc",
              "display_description": "Share Test Desc",
              "metadata": {}}
        body = {"share": sh}
        req = fakes.HTTPRequest.blank('/shares')
        self.share_controller.create(req, body)

    def test_index(self):
        req = fakes.HTTPRequest.blank(self.url)
        res_dict = self.controller.index(req, self.req_id)

        expected = {
            'metadata': {
                'key1': 'value1',
                'key2': 'value2',
                'key3': 'value3',
            },
        }
        self.assertEqual(expected, res_dict)

    def test_index_nonexistent_share(self):
        self.stubs.Set(manila.db, 'share_metadata_get',
                       return_share_nonexistent)
        req = fakes.HTTPRequest.blank(self.url)
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.index, req, self.url)

    def test_index_no_data(self):
        self.stubs.Set(manila.db, 'share_metadata_get',
                       return_empty_share_metadata)
        req = fakes.HTTPRequest.blank(self.url)
        res_dict = self.controller.index(req, self.req_id)
        expected = {'metadata': {}}
        self.assertEqual(expected, res_dict)

    def test_show(self):
        req = fakes.HTTPRequest.blank(self.url + '/key2')
        res_dict = self.controller.show(req, self.req_id, 'key2')
        expected = {'meta': {'key2': 'value2'}}
        self.assertEqual(expected, res_dict)

    def test_show_nonexistent_share(self):
        self.stubs.Set(manila.db, 'share_metadata_get',
                       return_share_nonexistent)
        req = fakes.HTTPRequest.blank(self.url + '/key2')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show, req, self.req_id, 'key2')

    def test_show_meta_not_found(self):
        self.stubs.Set(manila.db, 'share_metadata_get',
                       return_empty_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key6')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show, req, self.req_id, 'key6')

    def test_delete(self):
        self.stubs.Set(manila.db, 'share_metadata_get',
                       return_share_metadata)
        self.stubs.Set(manila.db, 'share_metadata_delete',
                       delete_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key2')
        req.method = 'DELETE'
        res = self.controller.delete(req, self.req_id, 'key2')

        self.assertEqual(200, res.status_int)

    def test_delete_nonexistent_share(self):
        self.stubs.Set(manila.db, 'share_get',
                       return_share_nonexistent)
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'DELETE'
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.delete, req, self.req_id, 'key1')

    def test_delete_meta_not_found(self):
        self.stubs.Set(manila.db, 'share_metadata_get',
                       return_empty_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key6')
        req.method = 'DELETE'
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.delete, req, self.req_id, 'key6')

    def test_create(self):
        self.stubs.Set(manila.db, 'share_metadata_get',
                       return_empty_share_metadata)
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)

        req = fakes.HTTPRequest.blank('/v1/share_metadata')
        req.method = 'POST'
        req.content_type = "application/json"
        body = {"metadata": {"key9": "value9"}}
        req.body = jsonutils.dumps(body)
        res_dict = self.controller.create(req, self.req_id, body)
        self.assertEqual(body, res_dict)

    def test_create_empty_body(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'POST'
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.req_id, None)

    def test_create_item_empty_key(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"": "value1"}}
        req.body = jsonutils.dumps(body)
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.req_id, body)

    def test_create_item_key_too_long(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {("a" * 260): "value1"}}
        req.body = jsonutils.dumps(body)
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create,
                          req, self.req_id, body)

    def test_create_nonexistent_share(self):
        self.stubs.Set(manila.db, 'share_get',
                       return_share_nonexistent)
        self.stubs.Set(manila.db, 'share_metadata_get',
                       return_share_metadata)
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)

        req = fakes.HTTPRequest.blank('/v1/share_metadata')
        req.method = 'POST'
        req.content_type = "application/json"
        body = {"metadata": {"key9": "value9"}}
        req.body = jsonutils.dumps(body)
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.create, req, self.req_id, body)

    def test_update_all(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        expected = {
            'metadata': {
                'key10': 'value10',
                'key99': 'value99',
            },
        }
        req.body = jsonutils.dumps(expected)
        res_dict = self.controller.update_all(req, self.req_id, expected)

        self.assertEqual(expected, res_dict)

    def test_update_all_empty_container(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        expected = {'metadata': {}}
        req.body = jsonutils.dumps(expected)
        res_dict = self.controller.update_all(req, self.req_id, expected)

        self.assertEqual(expected, res_dict)

    def test_update_all_malformed_container(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        expected = {'meta': {}}
        req.body = jsonutils.dumps(expected)

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update_all, req, self.req_id,
                          expected)

    def test_update_all_malformed_data(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        expected = {'metadata': ['asdf']}
        req.body = jsonutils.dumps(expected)

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update_all, req, self.req_id,
                          expected)

    def test_update_all_nonexistent_share(self):
        self.stubs.Set(manila.db, 'share_get', return_share_nonexistent)
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        body = {'metadata': {'key10': 'value10'}}
        req.body = jsonutils.dumps(body)

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.update_all, req, '100', body)

    def test_update_item(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"key1": "value1"}}
        req.body = jsonutils.dumps(body)
        req.headers["content-type"] = "application/json"
        res_dict = self.controller.update(req, self.req_id, 'key1', body)
        expected = {'meta': {'key1': 'value1'}}
        self.assertEqual(expected, res_dict)

    def test_update_item_nonexistent_share(self):
        self.stubs.Set(manila.db, 'share_get',
                       return_share_nonexistent)
        req = fakes.HTTPRequest.blank('/v1.1/fake/shares/asdf/metadata/key1')
        req.method = 'PUT'
        body = {"meta": {"key1": "value1"}}
        req.body = jsonutils.dumps(body)
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.update, req, self.req_id, 'key1',
                          body)

    def test_update_item_empty_body(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, self.req_id, 'key1',
                          None)

    def test_update_item_empty_key(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"": "value1"}}
        req.body = jsonutils.dumps(body)
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, self.req_id, '', body)

    def test_update_item_key_too_long(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {("a" * 260): "value1"}}
        req.body = jsonutils.dumps(body)
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update,
                          req, self.req_id, ("a" * 260), body)

    def test_update_item_value_too_long(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"key1": ("a" * 1025)}}
        req.body = jsonutils.dumps(body)
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update,
                          req, self.req_id, "key1", body)

    def test_update_item_too_many_keys(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"key1": "value1", "key2": "value2"}}
        req.body = jsonutils.dumps(body)
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, self.req_id, 'key1',
                          body)

    def test_update_item_body_uri_mismatch(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url + '/bad')
        req.method = 'PUT'
        body = {"meta": {"key1": "value1"}}
        req.body = jsonutils.dumps(body)
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, self.req_id, 'bad',
                          body)

    def test_invalid_metadata_items_on_create(self):
        self.stubs.Set(manila.db, 'share_metadata_update',
                       return_create_share_metadata)
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'POST'
        req.headers["content-type"] = "application/json"

        # test for long key
        data = {"metadata": {"a" * 260: "value1"}}
        req.body = jsonutils.dumps(data)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.req_id, data)

        # test for long value
        data = {"metadata": {"key": "v" * 1025}}
        req.body = jsonutils.dumps(data)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.req_id, data)

        # test for empty key.
        data = {"metadata": {"": "value1"}}
        req.body = jsonutils.dumps(data)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.req_id, data)
