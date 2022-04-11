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

from unittest import mock

import ddt
import webob

from manila.api.v2 import metadata
from manila import context
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils


@ddt.ddt
class MetadataAPITest(test.TestCase):

    def _get_request(self, version="2.65", use_admin_context=True):
        req = fakes.HTTPRequest.blank(
            '/v2/shares/{resource_id}/metadata',
            version=version, use_admin_context=use_admin_context)
        return req

    def setUp(self):
        super(MetadataAPITest, self).setUp()
        self.controller = (
            metadata.MetadataController())
        self.controller.resource_name = 'share'
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.resource = db_utils.create_share(size=1)

    def test_create_index_metadata(self):
        url = self._get_request()
        body = {'metadata': {'test_key1': 'test_v1', 'test_key2': 'test_v2'}}
        update = self.controller._create_metadata(
            url, self.resource['id'], body=body)

        get = self.controller._index_metadata(url, self.resource['id'])

        self.assertEqual(2, len(get['metadata']))
        self.assertEqual(update['metadata'], get['metadata'])

    @ddt.data(({'metadata': {'key1': 'v1'}}, 'key1'),
              ({'metadata': {'test_key1': 'test_v1'}}, 'test_key1'),
              ({'metadata': {'key1': 'v2'}}, 'key1'))
    @ddt.unpack
    def test_update_get_metadata_item(self, body, key):
        url = self._get_request()
        update = self.controller._update_metadata_item(
            url, self.resource['id'], body=body, key=key)
        self.assertEqual(body, update)

        get = self.controller._index_metadata(url, self.resource['id'])

        self.assertEqual(1, len(get))
        self.assertEqual(body['metadata'], get['metadata'])

        get_item = self.controller._show_metadata(url, self.resource['id'],
                                                  key=key)
        self.assertEqual({'meta': body['metadata']}, get_item)

    @ddt.data({'metadata': {'key1': 'v1', 'key2': 'v2'}},
              {'metadata': {'test_key1': 'test_v1'}},
              {'metadata': {'key1': 'v2'}})
    def test_update_all_metadata(self, body):
        url = self._get_request()
        update = self.controller._update_all_metadata(
            url, self.resource['id'], body=body)
        self.assertEqual(body, update)

        get = self.controller._index_metadata(url, self.resource['id'])

        self.assertEqual(len(body['metadata']), len(get['metadata']))
        self.assertEqual(body['metadata'], get['metadata'])

    def test_delete_metadata(self):
        body = {'metadata': {'test_key3': 'test_v3', 'testkey': 'testval'}}
        url = self._get_request()
        self.controller._create_metadata(url, self.resource['id'], body=body)

        self.controller._delete_metadata(url, self.resource['id'],
                                         'test_key3')
        show_result = self.controller._index_metadata(url, self.resource[
            'id'])

        self.assertEqual(1, len(show_result['metadata']))
        self.assertNotIn('test_key3', show_result['metadata'])

    def test_update_metadata_with_resource_id_not_found(self):
        url = self._get_request()
        id = 'invalid_id'
        body = {'metadata': {'key1': 'v1'}}

        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller._create_metadata,
            url, id, body)

    def test_update_metadata_with_body_error(self):
        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller._create_metadata,
            self._get_request(), self.resource['id'],
            {'metadata_error': {'key1': 'v1'}})

    @ddt.data({'metadata': {'key1': 'v1', 'key2': None}},
              {'metadata': {None: 'v1', 'key2': 'v2'}},
              {'metadata': {'k' * 256: 'v2'}},
              {'metadata': {'key1': 'v' * 1024}})
    @ddt.unpack
    def test_update_metadata_with_invalid_metadata(self, metadata):
        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller._create_metadata,
            self._get_request(), self.resource['id'],
            {'metadata': metadata})

    def test_delete_metadata_not_found(self):
        body = {'metadata': {'test_key_exist': 'test_v_exist'}}
        update = self.controller._update_all_metadata(
            self._get_request(), self.resource['id'], body=body)
        self.assertEqual(body, update)
        self.assertRaises(
            exception.MetadataItemNotFound,
            self.controller._delete_metadata,
            self._get_request(), self.resource['id'], 'key1')
