# Copyright (c) 2015 Quobyte, Inc.
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

import requests
from requests import auth
from requests import exceptions
import tempfile
import time

import mock
import six

from manila import exception
from manila.share.drivers.quobyte import jsonrpc
from manila import test


class FakeResponse(object):
    def __init__(self, status, body):
        self.status_code = status
        self.reason = "HTTP reason"
        self.body = body
        self.text = six.text_type(body)

    def json(self):
        return self.body


class QuobyteJsonRpcTestCase(test.TestCase):

    def setUp(self):
        super(QuobyteJsonRpcTestCase, self).setUp()
        self.rpc = jsonrpc.JsonRpc(url="http://test",
                                   user_credentials=("me", "team"))
        self.mock_object(time, 'sleep')

    @mock.patch.object(requests, 'post',
                       return_value=FakeResponse(200, {"result": "yes"}))
    def test_request_generation_and_basic_auth(self, req_get_mock):
        self.rpc.call('method', {'param': 'value'})

        req_get_mock.assert_called_once_with(
            url='http://test',
            auth=auth.HTTPBasicAuth("me", "team"),
            json=mock.ANY)

    def test_jsonrpc_init_with_ca(self):
        foofile = tempfile.TemporaryFile()
        fake_url = "https://foo.bar/"
        fake_credentials = ('fakeuser', 'fakepwd')
        fake_cert_file = tempfile.TemporaryFile()
        fake_key_file = tempfile.TemporaryFile()
        self.rpc = jsonrpc.JsonRpc(url=fake_url,
                                   user_credentials=fake_credentials,
                                   ca_file=foofile,
                                   key_file=fake_key_file,
                                   cert_file=fake_cert_file)

        self.assertEqual("https", self.rpc._url_scheme)
        self.assertEqual(fake_url, self.rpc._url)
        self.assertEqual(foofile, self.rpc._ca_file)
        self.assertEqual(fake_cert_file, self.rpc._cert_file)
        self.assertEqual(fake_key_file, self.rpc._key_file)

    @mock.patch.object(jsonrpc.LOG, "warning")
    def test_jsonrpc_init_without_ca(self, mock_warning):
        self.rpc = jsonrpc.JsonRpc("https://foo.bar/",
                                   ('fakeuser', 'fakepwd'),
                                   None)

        mock_warning.assert_called_once_with(
            "Will not verify the server certificate of the API service"
            " because the CA certificate is not available.")

    def test_jsonrpc_init_no_ssl(self):
        self.rpc = jsonrpc.JsonRpc("http://foo.bar/",
                                   ('fakeuser', 'fakepwd'))

        self.assertEqual("http", self.rpc._url_scheme)

    @mock.patch.object(requests, "post",
                       return_value=FakeResponse(
                           200, {"result": "Sweet gorilla of Manila"}))
    def test_successful_call(self, mock_req_get):
        result = self.rpc.call('method', {'param': 'value'})

        mock_req_get.assert_called_once_with(
            url=self.rpc._url,
            json=mock.ANY,  # not checking here as of undefined order in dict
            auth=self.rpc._credentials)
        self.assertEqual("Sweet gorilla of Manila", result)

    @mock.patch.object(requests, "post",
                       return_value=FakeResponse(
                           200, {"result": "Sweet gorilla of Manila"}))
    def test_https_call_with_cert(self, mock_req_get):
        fake_cert_file = tempfile.TemporaryFile()
        fake_key_file = tempfile.TemporaryFile()
        self.rpc = jsonrpc.JsonRpc(url="https://test",
                                   user_credentials=("me", "team"),
                                   cert_file=fake_cert_file,
                                   key_file=fake_key_file)

        result = self.rpc.call('method', {'param': 'value'})

        mock_req_get.assert_called_once_with(
            url=self.rpc._url,
            json=mock.ANY,  # not checking here as of undefined order in dict
            auth=self.rpc._credentials,
            verify=False,
            cert=(fake_cert_file, fake_key_file))
        self.assertEqual("Sweet gorilla of Manila", result)

    @mock.patch.object(requests, "post",
                       return_value=FakeResponse(
                           200, {"result": "Sweet gorilla of Manila"}))
    def test_https_call_verify(self, mock_req_get):
        fake_ca_file = tempfile.TemporaryFile()
        self.rpc = jsonrpc.JsonRpc(url="https://test",
                                   user_credentials=("me", "team"),
                                   ca_file=fake_ca_file)

        result = self.rpc.call('method', {'param': 'value'})

        mock_req_get.assert_called_once_with(
            url=self.rpc._url,
            json=mock.ANY,  # not checking here as of undefined order in dict
            auth=self.rpc._credentials,
            verify=fake_ca_file)
        self.assertEqual("Sweet gorilla of Manila", result)

    @mock.patch.object(jsonrpc.JsonRpc, "_checked_for_application_error",
                       return_value="Sweet gorilla of Manila")
    @mock.patch.object(requests, "post",
                       return_value=FakeResponse(
                           200, {"result": "Sweet gorilla of Manila"}))
    def test_https_call_verify_expected_error(self, mock_req_get, mock_check):
        fake_ca_file = tempfile.TemporaryFile()
        self.rpc = jsonrpc.JsonRpc(url="https://test",
                                   user_credentials=("me", "team"),
                                   ca_file=fake_ca_file)

        result = self.rpc.call('method', {'param': 'value'},
                               expected_errors=[42])

        mock_req_get.assert_called_once_with(
            url=self.rpc._url,
            json=mock.ANY,  # not checking here as of undefined order in dict
            auth=self.rpc._credentials,
            verify=fake_ca_file)
        mock_check.assert_called_once_with(
            {'result': 'Sweet gorilla of Manila'}, [42])
        self.assertEqual("Sweet gorilla of Manila", result)

    @mock.patch.object(requests, "post", side_effect=exceptions.HTTPError)
    def test_jsonrpc_call_http_exception(self, req_get_mock):
        self.assertRaises(exceptions.HTTPError,
                          self.rpc.call,
                          'method', {'param': 'value'})
        req_get_mock.assert_called_once_with(
            url=self.rpc._url,
            json=mock.ANY,  # not checking here as of undefined order in dict
            auth=self.rpc._credentials)

    @mock.patch.object(requests, "post",
                       return_value=FakeResponse(
                           200,
                           {"error": {"code": 28, "message": "text"}}))
    def test_application_error(self, req_get_mock):
        self.assertRaises(exception.QBRpcException,
                          self.rpc.call, 'method', {'param': 'value'})
        req_get_mock.assert_called_once_with(
            url=self.rpc._url,
            json=mock.ANY,  # not checking here as of undefined order in dict
            auth=self.rpc._credentials)

    def test_checked_for_application_error(self):
        resultdict = {"result": "Sweet gorilla of Manila"}
        self.assertEqual("Sweet gorilla of Manila",
                         (self.rpc._checked_for_application_error(
                             result=resultdict)))

    def test_checked_for_application_error_enf(self):
        resultdict = {"result": "Sweet gorilla of Manila",
                      "error": {"message": "No Gorilla",
                                "code": jsonrpc.ERROR_ENTITY_NOT_FOUND}}
        self.assertIsNone(
            self.rpc._checked_for_application_error(
                result=resultdict,
                expected_errors=[jsonrpc.ERROR_ENTITY_NOT_FOUND]))

    def test_checked_for_application_error_no_entry(self):
        resultdict = {"result": "Sweet gorilla of Manila",
                      "error": {"message": "No Gorilla",
                                "code": jsonrpc.ERROR_ENOENT}}
        self.assertIsNone(
            self.rpc._checked_for_application_error(
                result=resultdict, expected_errors=[jsonrpc.ERROR_ENOENT]))

    def test_checked_for_application_error_exception(self):
        self.assertRaises(exception.QBRpcException,
                          self.rpc._checked_for_application_error,
                          {"result": "Sweet gorilla of Manila",
                           "error": {"message": "No Gorilla",
                                     "code": 666
                                     }
                           }
                          )
