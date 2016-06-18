# Copyright 2016 Nexenta Systems, Inc.
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

from mock import patch
from oslo_serialization import jsonutils
import requests

from manila import exception
from manila.share.drivers.nexenta.ns5 import jsonrpc
from manila import test

PATH_TO_RPC = 'manila.share.drivers.nexenta.ns5.jsonrpc.NexentaJSONProxy'


class TestNexentaJSONProxy(test.TestCase):

    def __init__(self, method):
        super(self.__class__, self).__init__(method)

    def setUp(self):
        super(self.__class__, self).setUp()
        self.nef_get = jsonrpc.NexentaJSONProxy(
            'http', '1.1.1.1', '8080', 'user', 'pass', 'get')
        self.nef_post = jsonrpc.NexentaJSONProxy(
            'https', '1.1.1.1', '8080', 'user', 'pass', 'post')

    @patch('requests.Response.close')
    @patch('requests.Session.get')
    def test_call_get_data(self, get, close):
        data = {'key': 'value'}
        get.return_value = requests.Response()
        get.return_value.__setstate__(
            {'status_code': 200, '_content': jsonutils.dumps(data)})

        self.assertEqual({'key': 'value'}, self.nef_get('url'))

    @patch('requests.Response.close')
    @patch('requests.Session.get')
    def test_call_get_created(self, get, close):
        get.return_value = requests.Response()
        get.return_value.__setstate__({
            'status_code': 201, '_content': ''})

        self.assertIsNone(self.nef_get('url'))

    @patch('requests.Response.close')
    @patch('requests.Session.post')
    def test_call_post_success(self, post, close):
        data = {'key': 'value'}
        post.return_value = requests.Response()
        post.return_value.__setstate__({
            'status_code': 200, '_content': ''})
        self.assertIsNone(self.nef_post('url', data))

    @patch('time.sleep')
    @patch('requests.Response.close')
    @patch('requests.Session.get')
    @patch('requests.Session.post')
    def test_call_post_202(self, post, get, close, sleep):
        data = {'key': 'value'}
        data2 = {'links': [{'href': 'redirect_url'}]}

        get.return_value = requests.Response()
        post.return_value = requests.Response()
        post.return_value.__setstate__({
            'status_code': 202, '_content': jsonutils.dumps(data2)})
        get.return_value.__setstate__({
            'status_code': 200, '_content': jsonutils.dumps(data)})

        self.assertEqual({'key': 'value'}, self.nef_post('url'))

    @patch('requests.Response.close')
    @patch('requests.Session.get')
    def test_call_get_not_exist(self, get, close):
        get.return_value = requests.Response()
        get.return_value.__setstate__({
            'status_code': 400,
            '_content': jsonutils.dumps({'code': 'ENOENT'})})

        self.assertRaises(
            exception.NexentaException, lambda: self.nef_get('url'))

    @patch('requests.Response.close')
    @patch('requests.Session.get')
    def test_call_get_unauthorized(self, get, close):
        get.return_value = requests.Response()
        get.return_value.__setstate__({
            'status_code': 401,
            '_content': jsonutils.dumps({'code': 'unauthorized'})})

        self.assertRaises(
            exception.NexentaException, lambda: self.nef_get('url'))

    @patch('%s.https_auth' % PATH_TO_RPC)
    @patch('requests.Response.close')
    @patch('requests.Session.post')
    def test_call_post_bad_token(self, post, close, auth):
        post.return_value = requests.Response()
        auth.return_value = {'token': 'tok'}
        post.return_value.__setstate__({
            'status_code': 401,
            '_content': jsonutils.dumps({'code': 'unauthorized'})})

        self.assertRaises(
            exception.NexentaException, lambda: self.nef_post('url'))

    @patch('requests.Response.close')
    @patch('requests.Session.post')
    def test_auth(self, post, close):
        httpsdata = {'token': 'tok'}
        post.return_value = requests.Response()
        post.return_value.__setstate__({
            'status_code': 200, '_content': jsonutils.dumps(httpsdata)})
        nef_get = jsonrpc.NexentaJSONProxy(
            'http', '1.1.1.1', '8080', 'user', 'pass', method='get')
        https_auth = nef_get.https_auth()
        self.assertEqual('tok', https_auth)
