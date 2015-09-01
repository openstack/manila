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

import socket
import ssl
import tempfile
import time

import mock
from oslo_serialization import jsonutils
import six
from six.moves import http_client

from manila import exception
from manila.share.drivers.quobyte import jsonrpc
from manila import test


class FakeResponse(object):
    def __init__(self, status, body):
        self.status = status
        self.reason = "HTTP reason"
        self._body = body

    def read(self):
        return self._body


class QuobyteBasicAuthCredentialsTestCase(test.TestCase):

    def test_get_authorization_header(self):
        creds = jsonrpc.BasicAuthCredentials('fakeuser', 'fakepwd')

        self.assertEqual('BASIC ZmFrZXVzZXI6ZmFrZXB3ZA==',
                         creds.get_authorization_header())


class QuobyteHttpsConnectionWithCaVerificationTestCase(test.TestCase):

    @mock.patch.object(socket, "create_connection",
                       return_value="fake_socket")
    @mock.patch.object(ssl, "wrap_socket")
    def test_https_with_ca_connect(self, mock_ssl, mock_cc):
        key_file = tempfile.TemporaryFile()
        cert_file = tempfile.gettempdir()
        ca_file = tempfile.gettempdir()
        mycon = (jsonrpc.
                 HTTPSConnectionWithCaVerification(host="localhost",
                                                   key_file=key_file,
                                                   cert_file=cert_file,
                                                   ca_file=ca_file,
                                                   port=1234,
                                                   timeout=999))

        mycon.connect()

        mock_cc.assert_called_once_with(("localhost", 1234), 999)
        mock_ssl.assert_called_once_with("fake_socket",
                                         keyfile=key_file,
                                         certfile=cert_file,
                                         ca_certs=ca_file,
                                         cert_reqs=mock.ANY)

    @mock.patch.object(http_client.HTTPConnection, "_tunnel")
    @mock.patch.object(socket, "create_connection",
                       return_value="fake_socket")
    @mock.patch.object(ssl, "wrap_socket")
    def test_https_with_ca_connect_tunnel(self,
                                          mock_ssl,
                                          mock_cc,
                                          mock_tunnel):
        key_file = tempfile.TemporaryFile()
        cert_file = tempfile.gettempdir()
        ca_file = tempfile.gettempdir()
        mycon = (jsonrpc.
                 HTTPSConnectionWithCaVerification(host="localhost",
                                                   key_file=key_file,
                                                   cert_file=cert_file,
                                                   ca_file=ca_file,
                                                   port=1234,
                                                   timeout=999))
        mycon._tunnel_host = "fake_tunnel_host"

        mycon.connect()

        mock_tunnel.assert_called_once_with()
        mock_cc.assert_called_once_with(("localhost", 1234), 999)
        mock_ssl.assert_called_once_with("fake_socket",
                                         keyfile=key_file,
                                         certfile=cert_file,
                                         ca_certs=ca_file,
                                         cert_reqs=mock.ANY)


class QuobyteJsonRpcTestCase(test.TestCase):

    def setUp(self):
        super(QuobyteJsonRpcTestCase, self).setUp()
        self.rpc = jsonrpc.JsonRpc(url="http://test",
                                   user_credentials=("me", "team"))
        self.mock_object(self.rpc, '_connection')
        self.mock_object(time, 'sleep')

    def test_request_generation_and_basic_auth(self):
        self.mock_object(
            self.rpc._connection,
            'getresponse',
            mock.Mock(return_value=FakeResponse(200, '{"result":"yes"}')))

        self.rpc.call('method', {'param': 'value'})

        self.rpc._connection.request.assert_called_once_with(
            'POST', 'http://test/',
            jsonutils.dumps({'jsonrpc': '2.0',
                             'method': 'method',
                             'params': {'retry': 'INFINITELY',
                                        'param': 'value'},
                             'id': '1'}),
            dict(Authorization=jsonrpc.BasicAuthCredentials("me", "team")
                 .get_authorization_header()))

    @mock.patch.object(jsonrpc.HTTPSConnectionWithCaVerification,
                       '__init__',
                       return_value=None)
    def test_jsonrpc_init_with_ca(self, mock_init):
        foofile = tempfile.TemporaryFile()
        self.rpc = jsonrpc.JsonRpc("https://foo.bar/",
                                   ('fakeuser', 'fakepwd'),
                                   foofile)

        mock_init.assert_called_once_with("foo.bar",
                                          ca_file=foofile.name)

    @mock.patch.object(jsonrpc.LOG, "warning")
    def test_jsonrpc_init_without_ca(self, mock_warning):
        self.rpc = jsonrpc.JsonRpc("https://foo.bar/",
                                   ('fakeuser', 'fakepwd'),
                                   None)

        mock_warning.assert_called_once_with(
            "Will not verify the server certificate of the API service"
            " because the CA certificate is not available.")

    @mock.patch.object(http_client.HTTPConnection,
                       '__init__',
                       return_value=None)
    def test_jsonrpc_init_no_ssl(self, mock_init):
        self.rpc = jsonrpc.JsonRpc("http://foo.bar/",
                                   ('fakeuser', 'fakepwd'))

        mock_init.assert_called_once_with("foo.bar")

    def test_successful_call(self):
        self.mock_object(
            self.rpc._connection, 'getresponse',
            mock.Mock(return_value=FakeResponse(
                200, '{"result":"Sweet gorilla of Manila"}')))

        result = self.rpc.call('method', {'param': 'value'})

        self.rpc._connection.connect.assert_called_once_with()
        self.assertEqual("Sweet gorilla of Manila", result)

    @mock.patch('six.moves.http_client.HTTPSConnection')
    def test_jsonrpc_call_ssl_disable(self, mock_connection):
        mock_connection.return_value = self.rpc._connection
        self.mock_object(
            self.rpc._connection,
            'request',
            mock.Mock(side_effect=ssl.SSLError))
        self.mock_object(
            self.rpc._connection,
            'getresponse',
            mock.Mock(return_value=FakeResponse(
                403, '{"error":{"code":28,"message":"text"}}')))
        self.mock_object(jsonrpc.LOG, 'warning')

        self.assertRaises(exception.QBException,
                          self.rpc.call,
                          'method', {'param': 'value'})

        self.assertTrue(self.rpc._disabled_cert_verification)
        jsonrpc.LOG.warning.assert_called_once_with(
            "Could not verify server certificate of "
            "API service against CA.")

    def test_jsonrpc_call_ssl_error(self):
        """This test succeeds if a specific exception is thrown.

        Throwing a different exception or none at all
        is a failure in this specific test case.
        """
        self.mock_object(
            self.rpc._connection,
            'request',
            mock.Mock(side_effect=ssl.SSLError))
        self.rpc._disabled_cert_verification = True

        try:
            self.rpc.call('method', {'param': 'value'})
        except exception.QBException as me:
            self.rpc._connection.connect.assert_called_once_with()
            (self.assertTrue(six.text_type(me).startswith
                             ('Client SSL subsystem returned error:')))

        except Exception as e:
            self.fail('Unexpected exception thrown: %s' % e)
        else:
            self.fail('Expected exception not thrown')

    def test_jsonrpc_call_bad_status_line(self):
        self.mock_object(
            self.rpc._connection,
            'getresponse',
            mock.Mock(side_effect=http_client.BadStatusLine("fake_line")))

        self.assertRaises(exception.QBException,
                          self.rpc.call,
                          'method', {'param': 'value'})

    def test_jsonrpc_call_http_exception(self):
        self.mock_object(
            self.rpc._connection,
            'getresponse',
            mock.Mock(side_effect=http_client.HTTPException))
        self.mock_object(jsonrpc.LOG, 'warning')

        self.assertRaises(exception.QBException,
                          self.rpc.call,
                          'method', {'param': 'value'})
        self.rpc._connection.connect.assert_called_once_with()
        jsonrpc.LOG.warning.assert_has_calls([])

    def test_jsonrpc_call_http_exception_retry(self):
        self.mock_object(
            self.rpc._connection,
            'getresponse',
            mock.Mock(side_effect=http_client.HTTPException))
        self.mock_object(jsonrpc.LOG, 'warning')
        self.rpc._fail_fast = False

        self.assertRaises(exception.QBException,
                          self.rpc.call,
                          'method', {'param': 'value'})
        self.rpc._connection.connect.assert_called_once_with()
        jsonrpc.LOG.warning.assert_called_with(
            "Encountered error, retrying: %s", "")

    def test_jsonrpc_call_no_connect(self):
        orig_retries = jsonrpc.CONNECTION_RETRIES
        jsonrpc.CONNECTION_RETRIES = 0

        try:
            self.rpc.call('method', {'param': 'value'})
        except exception.QBException as me:
            self.rpc._connection.connect.assert_called_once_with()
            self.assertEqual("Unable to connect to backend after 0 retries",
                             six.text_type(me))
        else:
            self.fail('Expected exception not thrown')
        finally:
            jsonrpc.CONNECTION_RETRIES = orig_retries

    def test_http_error_401(self):
        self.mock_object(
            self.rpc._connection,
            'getresponse',
            mock.Mock(return_value=FakeResponse(401, '')))

        self.assertRaises(exception.QBException,
                          self.rpc.call, 'method', {'param': 'value'})
        self.rpc._connection.connect.assert_called_once_with()

    def test_http_error_other(self):
        self.mock_object(
            self.rpc._connection,
            'getresponse',
            mock.Mock(return_value=FakeResponse(300, '')))

        self.assertRaises(exception.QBException,
                          self.rpc.call, 'method', {'param': 'value'})
        self.rpc._connection.connect.assert_called_once_with()
        self.assertTrue(self.rpc._connection.getresponse.called)

    def test_application_error(self):
        self.mock_object(
            self.rpc._connection,
            'getresponse',
            mock.Mock(return_value=FakeResponse(
                200, '{"error":{"code":28,"message":"text"}}')))

        self.assertRaises(exception.QBRpcException,
                          self.rpc.call, 'method', {'param': 'value'})
        self.rpc._connection.connect.assert_called_once_with()
        self.assertTrue(self.rpc._connection.getresponse.called)

    def test_broken_application_error(self):
        self.mock_object(
            self.rpc._connection,
            'getresponse',
            mock.Mock(return_value=FakeResponse(
                200, '{"error":{"code":28,"message":"text"}}')))

        self.assertRaises(exception.QBRpcException,
                          self.rpc.call, 'method', {'param': 'value'})
        self.rpc._connection.connect.assert_called_once_with()
        self.assertTrue(self.rpc._connection.getresponse.called)

    def test_checked_for_application_error(self):
        resultdict = {"result": "Sweet gorilla of Manila"}
        self.assertEqual("Sweet gorilla of Manila",
                         (self.rpc.
                          _checked_for_application_error(result=resultdict))
                         )

    def test_checked_for_application_error_no_entry(self):
        resultdict = {"result": "Sweet gorilla of Manila",
                      "error": {"message": "No Gorilla",
                                "code": jsonrpc.ERROR_ENOENT}}
        self.assertIsNone(
            self.rpc._checked_for_application_error(result=resultdict))

    def test_checked_for_application_error_exception(self):
        self.assertRaises(exception.QBRpcException,
                          self.rpc._checked_for_application_error,
                          {"result": "Sweet gorilla of Manila",
                           "error": {"message": "No Gorilla",
                                     "code": 666
                                     }
                           }
                          )
