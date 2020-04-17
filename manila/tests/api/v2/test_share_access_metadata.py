# Copyright (c) 2018 Huawei Inc.
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

from unittest import mock

import ddt
import webob

from manila.api.v2 import share_access_metadata
from manila.api.v2 import share_accesses
from manila import context
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils
from oslo_utils import uuidutils


@ddt.ddt
class ShareAccessesMetadataAPITest(test.TestCase):

    def _get_request(self, version="2.45", use_admin_context=True):
        req = fakes.HTTPRequest.blank(
            '/v2/share-access-rules',
            version=version, use_admin_context=use_admin_context)
        return req

    def setUp(self):
        super(ShareAccessesMetadataAPITest, self).setUp()
        self.controller = (
            share_access_metadata.ShareAccessMetadataController())
        self.access_controller = (
            share_accesses.ShareAccessesController())
        self.resource_name = self.controller.resource_name
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.share = db_utils.create_share()
        self.access = db_utils.create_share_access(
            id=uuidutils.generate_uuid(),
            share_id=self.share['id'])

    @ddt.data({'body': {'metadata': {'key1': 'v1'}}},
              {'body': {'metadata': {'test_key1': 'test_v1'}}},
              {'body': {'metadata': {'key1': 'v2'}}})
    @ddt.unpack
    def test_update_metadata(self, body):
        url = self._get_request()
        update = self.controller.update(url, self.access['id'], body=body)
        self.assertEqual(body, update)

        show_result = self.access_controller.show(url, self.access['id'])

        self.assertEqual(1, len(show_result))
        self.assertIn(self.access['id'], show_result['access']['id'])
        self.assertEqual(body['metadata'], show_result['access']['metadata'])

    def test_delete_metadata(self):
        body = {'metadata': {'test_key3': 'test_v3'}}
        url = self._get_request()
        self.controller.update(url, self.access['id'], body=body)

        self.controller.delete(url, self.access['id'], 'test_key3')
        show_result = self.access_controller.show(url, self.access['id'])

        self.assertEqual(1, len(show_result))
        self.assertIn(self.access['id'], show_result['access']['id'])
        self.assertNotIn('test_key3', show_result['access']['metadata'])

    def test_update_access_metadata_with_access_id_not_found(self):
        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.update,
            self._get_request(), 'not_exist_access_id',
            {'metadata': {'key1': 'v1'}})

    def test_update_access_metadata_with_body_error(self):
        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            self._get_request(), self.access['id'],
            {'metadata_error': {'key1': 'v1'}})

    @ddt.data({'metadata': {'key1': 'v1', 'key2': None}},
              {'metadata': {None: 'v1', 'key2': 'v2'}},
              {'metadata': {'k' * 256: 'v2'}},
              {'metadata': {'key1': 'v' * 1024}})
    @ddt.unpack
    def test_update_metadata_with_invalid_metadata(self, metadata):
        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.update,
            self._get_request(), self.access['id'],
            {'metadata': metadata})

    def test_delete_access_metadata_not_found(self):
        body = {'metadata': {'test_key_exist': 'test_v_exsit'}}
        update = self.controller.update(
            self._get_request(), self.access['id'], body=body)
        self.assertEqual(body, update)
        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.delete,
            self._get_request(), self.access['id'], 'key1')

    @ddt.data('1.0', '2.0', '2.8', '2.44')
    def test_update_metadata_unsupported_version(self, version):
        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            self.controller.update,
            self._get_request(version=version), self.access['id'],
            {'metadata': {'key1': 'v1'}})

    @ddt.data('1.0', '2.0', '2.43')
    def test_delete_metadata_with_unsupported_version(self, version):
        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            self.controller.delete,
            self._get_request(version=version), self.access['id'], 'key1')
