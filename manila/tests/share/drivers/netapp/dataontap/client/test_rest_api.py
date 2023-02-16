# Copyright 2022 NetApp, Inc.
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
"""
Tests for NetApp REST API layer
"""

from unittest import mock

import ddt
from oslo_serialization import jsonutils
import requests
from requests import auth

from manila.share.drivers.netapp.dataontap.client import api as legacy_api
from manila.share.drivers.netapp.dataontap.client import rest_api as netapp_api
from manila import test
from manila.tests.share.drivers.netapp.dataontap.client import fakes as fake


@ddt.ddt
class NetAppRestApiServerTests(test.TestCase):
    """Test case for NetApp REST API server methods."""
    def setUp(self):
        self.rest_client = netapp_api.RestNaServer('127.0.0.1')
        super(NetAppRestApiServerTests, self).setUp()

    @ddt.data(None, 'my_cert')
    def test__init__ssl_verify(self, ssl_cert_path):
        client = netapp_api.RestNaServer('127.0.0.1',
                                         ssl_cert_path=ssl_cert_path)

        if ssl_cert_path:
            self.assertEqual(ssl_cert_path, client._ssl_verify)
        else:
            self.assertTrue(client._ssl_verify)

    @ddt.data(None, 'ftp')
    def test_set_transport_type_value_error(self, transport_type):
        self.assertRaises(ValueError, self.rest_client.set_transport_type,
                          transport_type)

    @ddt.data('!&', '80na', '')
    def test_set_port__value_error(self, port):
        self.assertRaises(ValueError, self.rest_client.set_port, port)

    @ddt.data(
        {'port': None, 'protocol': 'http', 'expected_port': '80'},
        {'port': None, 'protocol': 'https', 'expected_port': '443'},
        {'port': '111', 'protocol': None, 'expected_port': '111'}
    )
    @ddt.unpack
    def test_set_port(self, port, protocol, expected_port):
        self.rest_client._protocol = protocol

        self.rest_client.set_port(port=port)

        self.assertEqual(expected_port, self.rest_client._port)

    @ddt.data('!&', '80na', '')
    def test_set_timeout_value_error(self, timeout):
        self.assertRaises(ValueError, self.rest_client.set_timeout, timeout)

    @ddt.data({'params': {'major': 1, 'minor': '20a'}},
              {'params': {'major': '20a', 'minor': 1}},
              {'params': {'major': '!*', 'minor': '20a'}})
    @ddt.unpack
    def test_set_api_version_value_error(self, params):
        self.assertRaises(ValueError, self.rest_client.set_api_version,
                          **params)

    def test_set_api_version_valid(self):
        args = {'major': '20', 'minor': 1}

        self.rest_client.set_api_version(**args)

        self.assertEqual(self.rest_client._api_major_version, 20)
        self.assertEqual(self.rest_client._api_minor_version, 1)
        self.assertEqual(self.rest_client._api_version, "20.1")

    def test_invoke_successfully_naapi_error(self):
        self.mock_object(self.rest_client, '_build_headers')
        self.mock_object(self.rest_client, '_get_base_url',
                         mock.Mock(return_value=''))
        self.mock_object(
            self.rest_client, 'send_http_request',
            mock.Mock(return_value=(10, fake.ERROR_RESPONSE_REST)))

        self.assertRaises(legacy_api.NaApiError,
                          self.rest_client.invoke_successfully,
                          fake.FAKE_ACTION_URL, 'get')

    @ddt.data(None, {'fields': 'fake_fields'})
    def test_invoke_successfully(self, query):
        mock_build_header = self.mock_object(
            self.rest_client, '_build_headers',
            mock.Mock(return_value=fake.FAKE_HTTP_HEADER))
        mock_base = self.mock_object(
            self.rest_client, '_get_base_url',
            mock.Mock(return_value=fake.FAKE_BASE_URL))
        mock_add_query = self.mock_object(
            self.rest_client, '_add_query_params_to_url',
            mock.Mock(return_value=fake.FAKE_ACTION_URL))
        http_code = 200
        mock_send_http = self.mock_object(
            self.rest_client, 'send_http_request',
            mock.Mock(return_value=(http_code, fake.NO_RECORDS_RESPONSE_REST)))

        code, response = self.rest_client.invoke_successfully(
            fake.FAKE_ACTION_URL, 'get', body=fake.FAKE_HTTP_BODY, query=query,
            enable_tunneling=True)

        self.assertEqual(response, fake.NO_RECORDS_RESPONSE_REST)
        self.assertEqual(code, http_code)
        mock_build_header.assert_called_once_with(True)
        mock_base.assert_called_once_with()
        self.assertEqual(bool(query), mock_add_query.called)
        mock_send_http.assert_called_once_with(
            'get',
            fake.FAKE_BASE_URL + fake.FAKE_ACTION_URL, fake.FAKE_HTTP_BODY,
            fake.FAKE_HTTP_HEADER)

    @ddt.data(
        {'error': requests.HTTPError(), 'raised': legacy_api.NaApiError},
        {'error': Exception, 'raised': legacy_api.NaApiError})
    @ddt.unpack
    def test_send_http_request_http_error(self, error, raised):
        self.mock_object(netapp_api, 'LOG')
        self.mock_object(self.rest_client, '_build_session')
        self.rest_client._session = mock.Mock()
        self.mock_object(
            self.rest_client, '_get_request_method', mock.Mock(
                return_value=mock.Mock(side_effect=error)))

        self.assertRaises(raised, self.rest_client.send_http_request,
                          'get', fake.FAKE_ACTION_URL, fake.FAKE_HTTP_BODY,
                          fake.FAKE_HTTP_HEADER)

    @ddt.data(
        {
            'resp_content': fake.NO_RECORDS_RESPONSE_REST,
            'body': fake.FAKE_HTTP_BODY,
            'timeout': 10,
        },
        {
            'resp_content': fake.NO_RECORDS_RESPONSE_REST,
            'body': fake.FAKE_HTTP_BODY,
            'timeout': None,
        },
        {
            'resp_content': fake.NO_RECORDS_RESPONSE_REST,
            'body': None,
            'timeout': None,
        },
        {
            'resp_content': None,
            'body': None,
            'timeout': None,
        }
    )
    @ddt.unpack
    def test_send_http_request(self, resp_content, body, timeout):
        if timeout:
            self.rest_client._timeout = timeout
        self.mock_object(netapp_api, 'LOG')
        mock_json_dumps = self.mock_object(
            jsonutils, 'dumps', mock.Mock(return_value='fake_dump_body'))
        mock_build_session = self.mock_object(
            self.rest_client, '_build_session')
        _mock_session = mock.Mock()
        self.rest_client._session = _mock_session
        response = mock.Mock()
        response.content = resp_content
        response.status_code = 10
        mock_post = mock.Mock(return_value=response)
        mock_get_request_method = self.mock_object(
            self.rest_client, '_get_request_method', mock.Mock(
                return_value=mock_post))
        mock_json_loads = self.mock_object(
            jsonutils, 'loads',
            mock.Mock(return_value='fake_loads_response'))

        code, res = self.rest_client.send_http_request(
            'post', fake.FAKE_ACTION_URL, body, fake.FAKE_HTTP_HEADER)

        expected_res = 'fake_loads_response' if resp_content else {}
        self.assertEqual(expected_res, res)
        self.assertEqual(10, code)
        self.assertEqual(bool(body), mock_json_dumps.called)
        self.assertEqual(bool(resp_content), mock_json_loads.called)
        mock_build_session.assert_called_once_with(fake.FAKE_HTTP_HEADER)
        mock_get_request_method.assert_called_once_with('post', _mock_session)
        expected_data = 'fake_dump_body' if body else {}
        if timeout:
            mock_post.assert_called_once_with(
                fake.FAKE_ACTION_URL, data=expected_data, timeout=timeout)
        else:
            mock_post.assert_called_once_with(fake.FAKE_ACTION_URL,
                                              data=expected_data)

    @ddt.data(
        {'host': '192.168.1.0', 'port': '80', 'protocol': 'http'},
        {'host': '0.0.0.0', 'port': '443', 'protocol': 'https'},
        {'host': '::ffff:8', 'port': '80', 'protocol': 'http'},
        {'host': 'fdf8:f53b:82e4::53', 'port': '443', 'protocol': 'https'})
    @ddt.unpack
    def test__get_base_url(self, host, port, protocol):
        client = netapp_api.RestNaServer(host, port=port,
                                         transport_type=protocol)
        expected_host = f'[{host}]' if ':' in host else host
        expected_url = '%s://%s:%s/api' % (protocol, expected_host, port)

        url = client._get_base_url()

        self.assertEqual(expected_url, url)

    def test__add_query_params_to_url(self):
        formatted_url = self.rest_client._add_query_params_to_url(
            fake.FAKE_ACTION_URL, fake.FAKE_HTTP_QUERY)

        expected_formatted_url = fake.FAKE_ACTION_URL
        expected_formatted_url += fake.FAKE_FORMATTED_HTTP_QUERY
        self.assertEqual(expected_formatted_url, formatted_url)

    @ddt.data('post', 'get', 'put', 'delete', 'patch')
    def test_get_request_method(self, method):
        _mock_session = mock.Mock()
        _mock_session.post = mock.Mock()
        _mock_session.get = mock.Mock()
        _mock_session.put = mock.Mock()
        _mock_session.delete = mock.Mock()
        _mock_session.patch = mock.Mock()

        res = self.rest_client._get_request_method(method, _mock_session)

        expected_method = getattr(_mock_session, method)
        self.assertEqual(expected_method, res)

    def test__str__(self):
        fake_host = 'fake_host'
        client = netapp_api.RestNaServer(fake_host)

        expected_str = "server: %s" % fake_host
        self.assertEqual(expected_str, str(client))

    def test_get_transport_type(self):
        expected_protocol = 'fake_protocol'
        self.rest_client._protocol = expected_protocol

        res = self.rest_client.get_transport_type()

        self.assertEqual(expected_protocol, res)

    @ddt.data(None, ('1', '0'))
    def test_get_api_version(self, api_version):
        if api_version:
            self.rest_client._api_version = str(api_version)
            (self.rest_client._api_major_version, _) = api_version
            (_, self.rest_client._api_minor_version) = api_version

        res = self.rest_client.get_api_version()

        self.assertEqual(api_version, res)

    @ddt.data(None, '9.10')
    def test_get_ontap_version(self, ontap_version):
        if ontap_version:
            self.rest_client._ontap_version = ontap_version

        res = self.rest_client.get_ontap_version()

        self.assertEqual(ontap_version, res)

    def test_set_vserver(self):
        expected_vserver = 'fake_vserver'
        self.rest_client.set_vserver(expected_vserver)

        self.assertEqual(expected_vserver, self.rest_client._vserver)

    def test_get_vserver(self):
        expected_vserver = 'fake_vserver'
        self.rest_client._vserver = expected_vserver

        res = self.rest_client.get_vserver()

        self.assertEqual(expected_vserver, res)

    def test__build_session(self):
        fake_session = mock.Mock()
        mock_requests_session = self.mock_object(
            requests, 'Session', mock.Mock(return_value=fake_session))
        mock_auth = self.mock_object(
            self.rest_client, '_create_basic_auth_handler',
            mock.Mock(return_value='fake_auth'))
        self.rest_client._ssl_verify = 'fake_ssl'

        self.rest_client._build_session(fake.FAKE_HTTP_HEADER)

        self.assertEqual(fake_session, self.rest_client._session)
        self.assertEqual('fake_auth', self.rest_client._session.auth)
        self.assertEqual('fake_ssl', self.rest_client._session.verify)
        self.assertEqual(fake.FAKE_HTTP_HEADER,
                         self.rest_client._session.headers)
        mock_requests_session.assert_called_once_with()
        mock_auth.assert_called_once_with()

    @ddt.data(True, False)
    def test__build_headers(self, enable_tunneling):
        self.rest_client._vserver = fake.VSERVER_NAME

        res = self.rest_client._build_headers(enable_tunneling)

        expected = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if enable_tunneling:
            expected["X-Dot-SVM-Name"] = fake.VSERVER_NAME
        self.assertEqual(expected, res)

    def test__create_basic_auth_handler(self):
        username = 'fake_username'
        password = 'fake_password'
        client = netapp_api.RestNaServer('10.1.1.1', username=username,
                                         password=password)

        res = client._create_basic_auth_handler()

        expected = auth.HTTPBasicAuth(username, password)
        self.assertEqual(expected.__dict__, res.__dict__)
