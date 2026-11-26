# Copyright (c) 2014 Ben Swartzlander.  All rights reserved.
# Copyright (c) 2014 Navneet Singh.  All rights reserved.
# Copyright (c) 2014 Clinton Knight.  All rights reserved.
# Copyright (c) 2014 Alex Meade.  All rights reserved.
# Copyright (c) 2014 Bob Callaway.  All rights reserved.
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
Tests for NetApp API layer
"""

from oslo_serialization import jsonutils
from unittest import mock

import ddt
import requests

from manila import exception
from manila.share.drivers.netapp.dataontap.client import api
from manila.share.drivers.netapp.dataontap.client import rest_endpoints
from manila import test
from manila.tests.share.drivers.netapp.dataontap.client import fakes as fake


class NetAppApiElementTransTests(test.TestCase):
    """Test case for NetApp API element translations."""

    def test_zapi_client_init_ssl_verify_precedence(self):
        no_verify_client = api.ZapiClient(
            'localhost', ssl_cert_verify=False, ssl_cert_path='fake_cert')
        self.assertFalse(no_verify_client._ssl_verify)

        path_verify_client = api.ZapiClient(
            'localhost', ssl_cert_verify=True, ssl_cert_path='fake_cert')
        self.assertEqual('fake_cert', path_verify_client._ssl_verify)

        default_verify_client = api.ZapiClient(
            'localhost', ssl_cert_verify=True, ssl_cert_path=None)
        self.assertTrue(default_verify_client._ssl_verify)

    def test_na_server_init_ssl_verify_plumbed_to_both_clients(self):
        server = api.NaServer('localhost', ssl_cert_verify=False)
        self.assertFalse(server.zapi_client._ssl_verify)
        self.assertFalse(server.rest_client._ssl_verify)

    def test_get_set_system_version(self):
        napi = api.NaServer('localhost')

        # Testing calls before version is set
        version = napi.get_system_version()
        self.assertIsNone(version)
        napi.set_system_version(fake.VERSION_TUPLE)
        version = napi.get_system_version()
        self.assertEqual(fake.VERSION_TUPLE, version)

    def test_translate_struct_dict_unique_key(self):
        """Tests if dict gets properly converted to NaElements."""
        root = api.NaElement('root')
        child = {'e1': 'v1', 'e2': 'v2', 'e3': 'v3'}

        root.translate_struct(child)

        self.assertEqual(3, len(root.get_children()))
        for key, value in child.items():
            self.assertEqual(value, root.get_child_content(key))

    def test_translate_struct_dict_nonunique_key(self):
        """Tests if list/dict gets properly converted to NaElements."""
        root = api.NaElement('root')
        child = [{'e1': 'v1', 'e2': 'v2'}, {'e1': 'v3'}]

        root.translate_struct(child)

        children = root.get_children()
        self.assertEqual(3, len(children))
        for c in children:
            if c.get_name() == 'e1':
                self.assertIn(c.get_content(), ['v1', 'v3'])
            else:
                self.assertEqual('v2', c.get_content())

    def test_translate_struct_list(self):
        """Tests if list gets properly converted to NaElements."""
        root = api.NaElement('root')
        child = ['e1', 'e2']

        root.translate_struct(child)

        self.assertEqual(2, len(root.get_children()))
        self.assertIsNone(root.get_child_content('e1'))
        self.assertIsNone(root.get_child_content('e2'))

    def test_translate_struct_tuple(self):
        """Tests if tuple gets properly converted to NaElements."""
        root = api.NaElement('root')
        child = ('e1', 'e2')

        root.translate_struct(child)

        self.assertEqual(2, len(root.get_children()))
        self.assertIsNone(root.get_child_content('e1'))
        self.assertIsNone(root.get_child_content('e2'))

    def test_translate_invalid_struct(self):
        """Tests if invalid data structure raises exception."""
        root = api.NaElement('root')
        child = 'random child element'
        self.assertRaises(ValueError, root.translate_struct, child)

    def test_setter_builtin_types(self):
        """Tests str, int, float get converted to NaElement."""
        update = dict(e1='v1', e2='1', e3='2.0', e4='8')
        root = api.NaElement('root')

        for key, value in update.items():
            root[key] = value

        for key, value in update.items():
            self.assertEqual(value, root.get_child_content(key))

    def test_setter_na_element(self):
        """Tests na_element gets appended as child."""
        root = api.NaElement('root')
        root['e1'] = api.NaElement('nested')
        self.assertEqual(1, len(root.get_children()))
        e1 = root.get_child_by_name('e1')
        self.assertIsInstance(e1, api.NaElement)
        self.assertIsInstance(e1.get_child_by_name('nested'), api.NaElement)

    def test_setter_child_dict(self):
        """Tests dict is appended as child to root."""
        root = api.NaElement('root')
        root['d'] = {'e1': 'v1', 'e2': 'v2'}
        e1 = root.get_child_by_name('d')
        self.assertIsInstance(e1, api.NaElement)
        sub_ch = e1.get_children()
        self.assertEqual(2, len(sub_ch))
        for c in sub_ch:
            self.assertIn(c.get_name(), ['e1', 'e2'])
            if c.get_name() == 'e1':
                self.assertEqual('v1', c.get_content())
            else:
                self.assertEqual('v2', c.get_content())

    def test_setter_child_list_tuple(self):
        """Tests list/tuple are appended as child to root."""
        root = api.NaElement('root')

        root['l'] = ['l1', 'l2']
        root['t'] = ('t1', 't2')

        li = root.get_child_by_name('l')
        self.assertIsInstance(li, api.NaElement)
        t = root.get_child_by_name('t')
        self.assertIsInstance(t, api.NaElement)

        self.assertEqual(2, len(li.get_children()))
        for le in li.get_children():
            self.assertIn(le.get_name(), ['l1', 'l2'])

        self.assertEqual(2, len(t.get_children()))
        for te in t.get_children():
            self.assertIn(te.get_name(), ['t1', 't2'])

    def test_setter_no_value(self):
        """Tests key with None value."""
        root = api.NaElement('root')
        root['k'] = None
        self.assertIsNone(root.get_child_content('k'))

    def test_setter_invalid_value(self):
        """Tests invalid value raises exception."""
        self.assertRaises(TypeError,
                          api.NaElement('root').__setitem__,
                          'k',
                          api.NaServer('localhost'))

    def test_setter_invalid_key(self):
        """Tests invalid value raises exception."""
        self.assertRaises(KeyError,
                          api.NaElement('root').__setitem__,
                          None,
                          'value')

    def test__build_session_with_basic_auth(self):
        """Tests whether build session works with """
        """default(basic auth) parameters"""
        napi = api.ZapiClient('localhost')
        fake_session = mock.Mock()
        mock_requests_session = self.mock_object(
            requests, 'Session', mock.Mock(return_value=fake_session))
        mock_auth = self.mock_object(napi, '_create_basic_auth_handler',
                                     mock.Mock(return_value='fake_auth'))
        napi._ssl_verify = 'fake_ssl'
        fake_headers = {'Content-Type': 'text/xml'}
        napi._build_session()

        self.assertEqual(fake_session, napi._session)
        self.assertEqual('fake_auth', napi._session.auth)
        self.assertEqual('fake_ssl', napi._session.verify)
        self.assertEqual(fake_headers,
                         napi._session.headers)
        mock_requests_session.assert_called_once_with()
        mock_auth.assert_called_once_with()

    def test__build_session_with_certificate_auth(self):
        """Tests whether build session works with """
        """valid certificate parameters"""
        napi = api.ZapiClient('localhost')
        napi._private_key_file = 'fake_key.pem'
        napi._certificate_file = 'fake_cert.pem'
        napi._certificate_host_validation = False
        cert = napi._certificate_file, napi._private_key_file
        fake_headers = {'Content-Type': 'text/xml'}
        fake_session = mock.Mock()
        napi._session = mock.Mock()
        mock_requests_session = self.mock_object(
            requests, 'Session', mock.Mock(return_value=fake_session))
        res = napi._create_certificate_auth_handler()
        napi._build_session()
        self.assertEqual(fake_session, napi._session)
        self.assertEqual(res,
                         (cert, napi._certificate_host_validation))
        self.assertEqual(fake_headers,
                         napi._session.headers)
        mock_requests_session.assert_called_once_with()

    def test__create_certificate_auth_handler_default(self):
        """Test whether create certificate auth handler """
        """works with default params"""
        napi = api.ZapiClient('localhost')
        napi._private_key_file = 'fake_key.pem'
        napi._certificate_file = 'fake_cert.pem'
        napi._certificate_host_validation = False
        cert = napi._certificate_file, napi._private_key_file
        napi._session = mock.Mock()
        if not napi._certificate_host_validation:
            self.assertFalse(napi._certificate_host_validation)
        res = napi._create_certificate_auth_handler()
        self.assertEqual(res, (cert, napi._certificate_host_validation))

    def test__create_certificate_auth_handler_with_host_validation(self):
        """Test whether create certificate auth handler """
        """works with host validation enabled"""
        napi = api.ZapiClient('localhost')
        napi._private_key_file = 'fake_key.pem'
        napi._certificate_file = 'fake_cert.pem'
        napi._ca_certificate_file = 'fake_ca_cert.crt'
        napi._certificate_host_validation = True
        cert = napi._certificate_file, napi._private_key_file
        napi._session = mock.Mock()
        if napi._certificate_host_validation:
            self.assertTrue(napi._certificate_host_validation)
        res = napi._create_certificate_auth_handler()
        self.assertEqual(res, (cert, napi._ca_certificate_file))


@ddt.ddt
class NetAppApiServerZapiClientTests(test.TestCase):
    """Test case for NetApp API server methods"""
    def setUp(self):
        self.root = api.NaServer('127.0.0.1').zapi_client
        super(NetAppApiServerZapiClientTests, self).setUp()

    @ddt.data(None, fake.FAKE_XML_STR)
    def test_invoke_elem_value_error(self, na_element):
        """Tests whether invalid NaElement parameter causes error"""

        self.assertRaises(ValueError, self.root.invoke_elem, na_element)

    def test_invoke_elem_http_error(self):
        """Tests handling of HTTPError"""
        na_element = fake.FAKE_NA_ELEMENT
        self.mock_object(self.root, '_create_request', mock.Mock(
            return_value=fake.FAKE_NA_ELEMENT))
        self.mock_object(api, 'LOG')
        self.root._session = fake.FAKE_HTTP_SESSION
        self.mock_object(self.root, '_build_session')
        self.mock_object(self.root._session, 'post', mock.Mock(
            side_effect=requests.HTTPError()))

        self.assertRaises(api.NaApiError, self.root.invoke_elem,
                          na_element)

    def test_invoke_elem_urlerror(self):
        """Tests handling of URLError"""
        na_element = fake.FAKE_NA_ELEMENT
        self.mock_object(self.root, '_create_request', mock.Mock(
            return_value=fake.FAKE_NA_ELEMENT))
        self.mock_object(api, 'LOG')
        self.root._session = fake.FAKE_HTTP_SESSION
        self.mock_object(self.root, '_build_session')
        self.mock_object(self.root._session, 'post', mock.Mock(
            side_effect=requests.URLRequired()))

        self.assertRaises(exception.StorageCommunicationException,
                          self.root.invoke_elem,
                          na_element)

    def test_invoke_elem_unknown_exception(self):
        """Tests handling of Unknown Exception"""
        na_element = fake.FAKE_NA_ELEMENT
        self.mock_object(self.root, '_create_request', mock.Mock(
            return_value=fake.FAKE_NA_ELEMENT))
        self.mock_object(api, 'LOG')
        self.root._session = fake.FAKE_HTTP_SESSION
        self.mock_object(self.root, '_build_session')
        self.mock_object(self.root._session, 'post', mock.Mock(
            side_effect=Exception))

        exception = self.assertRaises(api.NaApiError, self.root.invoke_elem,
                                      na_element)
        self.assertEqual('unknown', exception.code)

    @ddt.data({'trace_enabled': False,
               'trace_pattern': '(.*)', 'log': False},
              {'trace_enabled': True,
               'trace_pattern': '(?!(volume)).*', 'log': False},
              {'trace_enabled': True,
               'trace_pattern': '(.*)', 'log': True},
              {'trace_enabled': True,
               'trace_pattern': '^volume-(info|get-iter)$', 'log': True})
    @ddt.unpack
    def test_invoke_elem_valid(self, trace_enabled, trace_pattern, log):
        """Tests the method invoke_elem with valid parameters"""
        na_element = fake.FAKE_NA_ELEMENT
        self.root._trace = trace_enabled
        self.root._api_trace_pattern = trace_pattern
        self.mock_object(self.root, '_create_request', mock.Mock(
            return_value=fake.FAKE_NA_ELEMENT))
        self.mock_object(api, 'LOG')
        self.root._session = fake.FAKE_HTTP_SESSION
        self.mock_object(self.root, '_build_session')
        self.mock_object(self.root, '_get_result', mock.Mock(
            return_value=fake.FAKE_NA_ELEMENT))

        response = mock.Mock()
        response.text = 'res1'
        self.mock_object(
            self.root._session, 'post', mock.Mock(
                return_value=response))

        self.root.invoke_elem(na_element)

        expected_log_count = 2 if log else 0
        self.assertEqual(expected_log_count, api.LOG.debug.call_count)

    @ddt.data('1234', 5678)
    def test_custom_port(self, port):
        root = api.NaServer('127.0.0.1', port=port).zapi_client
        self.assertEqual(str(port), root.get_port())


@ddt.ddt
class NetAppApiServerRestClientTests(test.TestCase):
    """Test case for NetApp API Rest server methods"""
    def setUp(self):
        self.root = api.NaServer('127.0.0.1').rest_client
        super(NetAppApiServerRestClientTests, self).setUp()

    def test_invoke_elem_value_error(self):
        """Tests whether invalid NaElement parameter causes error"""
        na_element = fake.FAKE_REST_CALL_STR
        self.assertRaises(ValueError, self.root.invoke_elem, na_element)

    def _setup_mocks_for_invoke_element(self, mock_post_action):

        self.mock_object(api, 'LOG')
        self.root._session = fake.FAKE_HTTP_SESSION
        self.root._session.post = mock_post_action
        self.mock_object(self.root, '_build_session')
        self.mock_object(
            self.root, '_get_request_info', mock.Mock(
                return_value=(self.root._session.post, fake.FAKE_ACTION_URL)))
        self.mock_object(
            self.root, '_get_base_url',
            mock.Mock(return_value=fake.FAKE_BASE_URL))

        return fake.FAKE_BASE_URL

    def test_invoke_elem_http_error(self):
        """Tests handling of HTTPError"""
        na_element = fake.FAKE_NA_ELEMENT
        element_name = fake.FAKE_NA_ELEMENT.get_name()
        self._setup_mocks_for_invoke_element(
            mock_post_action=mock.Mock(side_effect=requests.HTTPError()))

        self.assertRaises(api.NaApiError, self.root.invoke_elem,
                          na_element)
        self.assertTrue(self.root._get_base_url.called)
        self.root._get_request_info.assert_called_once_with(
            element_name, self.root._session)

    def test_invoke_elem_urlerror(self):
        """Tests handling of URLError"""
        na_element = fake.FAKE_NA_ELEMENT
        element_name = fake.FAKE_NA_ELEMENT.get_name()
        self._setup_mocks_for_invoke_element(
            mock_post_action=mock.Mock(side_effect=requests.URLRequired()))

        self.assertRaises(exception.StorageCommunicationException,
                          self.root.invoke_elem,
                          na_element)

        self.assertTrue(self.root._get_base_url.called)
        self.root._get_request_info.assert_called_once_with(
            element_name, self.root._session)

    def test_invoke_elem_unknown_exception(self):
        """Tests handling of Unknown Exception"""
        na_element = fake.FAKE_NA_ELEMENT
        element_name = fake.FAKE_NA_ELEMENT.get_name()
        self._setup_mocks_for_invoke_element(
            mock_post_action=mock.Mock(side_effect=Exception))

        exception = self.assertRaises(api.NaApiError, self.root.invoke_elem,
                                      na_element)
        self.assertEqual('unknown', exception.code)
        self.assertTrue(self.root._get_base_url.called)
        self.root._get_request_info.assert_called_once_with(
            element_name, self.root._session)

    @ddt.data(
        {'trace_enabled': False,
         'trace_pattern': '(.*)',
         'log': False,
         'query': None,
         'body': fake.FAKE_HTTP_BODY
         },
        {'trace_enabled': True,
         'trace_pattern': '(?!(volume)).*',
         'log': False,
         'query': None,
         'body': fake.FAKE_HTTP_BODY
         },
        {'trace_enabled': True,
         'trace_pattern': '(.*)',
         'log': True,
         'query': fake.FAKE_HTTP_QUERY,
         'body': fake.FAKE_HTTP_BODY
         },
        {'trace_enabled': True,
         'trace_pattern': '^volume-(info|get-iter)$',
         'log': True,
         'query': fake.FAKE_HTTP_QUERY,
         'body': fake.FAKE_HTTP_BODY
         }
    )
    @ddt.unpack
    def test_invoke_elem_valid(self, trace_enabled, trace_pattern, log, query,
                               body):
        """Tests the method invoke_elem with valid parameters"""
        self.root._session = fake.FAKE_HTTP_SESSION
        response = mock.Mock()
        response.content = 'fake_response'
        self.root._session.post = mock.Mock(return_value=response)
        na_element = fake.FAKE_NA_ELEMENT
        element_name = fake.FAKE_NA_ELEMENT.get_name()
        self.root._trace = trace_enabled
        self.root._api_trace_pattern = trace_pattern
        expected_url = fake.FAKE_BASE_URL + fake.FAKE_ACTION_URL

        api_args = {
            "body": body,
            "query": query
        }

        self.mock_object(api, 'LOG')
        mock_build_session = self.mock_object(self.root, '_build_session')
        mock_get_req_info = self.mock_object(
            self.root, '_get_request_info', mock.Mock(
                return_value=(self.root._session.post, fake.FAKE_ACTION_URL)))
        mock_add_query_params = self.mock_object(
            self.root, '_add_query_params_to_url', mock.Mock(
                return_value=fake.FAKE_ACTION_URL))
        mock_get_base_url = self.mock_object(
            self.root, '_get_base_url',
            mock.Mock(return_value=fake.FAKE_BASE_URL))
        mock_json_loads = self.mock_object(
            jsonutils, 'loads', mock.Mock(return_value='fake_response'))
        mock_json_dumps = self.mock_object(
            jsonutils, 'dumps', mock.Mock(return_value=body))

        result = self.root.invoke_elem(na_element, api_args=api_args)

        self.assertEqual('fake_response', result)
        expected_log_count = 2 if log else 0
        self.assertEqual(expected_log_count, api.LOG.debug.call_count)
        self.assertTrue(mock_build_session.called)
        mock_get_req_info.assert_called_once_with(
            element_name, self.root._session)
        if query:
            mock_add_query_params.assert_called_once_with(
                fake.FAKE_ACTION_URL, query)
        self.assertTrue(mock_get_base_url.called)
        self.root._session.post.assert_called_once_with(
            expected_url, data=body)
        mock_json_loads.assert_called_once_with('fake_response')
        mock_json_dumps.assert_called_once_with(body)

    @ddt.data(
        ('svm-migration-start', rest_endpoints.ENDPOINT_MIGRATIONS, 'post'),
        ('svm-migration-complete', rest_endpoints.ENDPOINT_MIGRATION_ACTIONS,
         'patch')
    )
    @ddt.unpack
    def test__get_request_info(self, api_name, expected_url, expected_method):
        self.root._session = fake.FAKE_HTTP_SESSION
        for http_method in ['post', 'get', 'put', 'delete', 'patch']:
            setattr(self.root._session, http_method, mock.Mock())

        method, url = self.root._get_request_info(api_name, self.root._session)

        self.assertEqual(method, getattr(self.root._session, expected_method))
        self.assertEqual(expected_url, url)

    @ddt.data(
        {'is_ipv6': False, 'protocol': 'http', 'port': '80'},
        {'is_ipv6': False, 'protocol': 'https', 'port': '443'},
        {'is_ipv6': True, 'protocol': 'http', 'port': '80'},
        {'is_ipv6': True, 'protocol': 'https', 'port': '443'})
    @ddt.unpack
    def test__get_base_url(self, is_ipv6, protocol, port):
        self.root._host = '10.0.0.3' if not is_ipv6 else 'FF01::1'
        self.root._protocol = protocol
        self.root._port = port

        host_formated_for_url = (
            '[%s]' % self.root._host if is_ipv6 else self.root._host)

        # example of the expected format: http://10.0.0.3:80/api/
        expected_result = (
            protocol + '://' + host_formated_for_url + ':' + port + '/api/')

        base_url = self.root._get_base_url()

        self.assertEqual(expected_result, base_url)

    def test__add_query_params_to_url(self):
        url = 'endpoint/to/get/data'
        filters = "?"
        for k, v in fake.FAKE_HTTP_QUERY.items():
            filters += "%(key)s=%(value)s&" % {"key": k, "value": v}
        expected_formated_url = url + filters

        formatted_url = self.root._add_query_params_to_url(
            url, fake.FAKE_HTTP_QUERY)

        self.assertEqual(expected_formated_url, formatted_url)

    @ddt.data('1234', 5678)
    def test_custom_port(self, port):
        root = api.NaServer('127.0.0.1', port=port).rest_client
        self.assertEqual(str(port), root.get_port())

    @ddt.data({'protocol': 'http', 'expected_port': '80'},
              {'protocol': 'https', 'expected_port': '443'})
    @ddt.unpack
    def test_default_port(self, protocol, expected_port):
        client = api.RestClient('127.0.0.1', transport_type=protocol)

        self.assertEqual(expected_port, client.get_port())

    def test__build_headers(self):
        expected = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self.assertEqual(expected, self.root._build_headers())

    def test_invoke_elem_with_url_params_and_timeout(self):
        """A templated endpoint is filled in before the base URL is joined."""
        self.root._session = mock.Mock()
        self.root._refresh_conn = False
        self.root._timeout = 30
        response = mock.Mock()
        response.content = None
        mock_request = mock.Mock(return_value=response)
        mock_build_session = self.mock_object(self.root, '_build_session')
        self.mock_object(
            self.root, '_get_request_info',
            mock.Mock(return_value=(mock_request, '/svm/svms/%(uuid)s')))
        self.mock_object(self.root, '_get_base_url',
                         mock.Mock(return_value=fake.FAKE_BASE_URL))

        result = self.root.invoke_elem(
            api.NaElement('svm-migration-start'),
            api_args={'url_params': {'uuid': 'fake_uuid'}})

        self.assertIsNone(result)
        mock_build_session.assert_not_called()
        mock_request.assert_called_once_with(
            fake.FAKE_BASE_URL + '/svm/svms/fake_uuid', data=None, timeout=30)

    def test_invoke_successfully(self):
        self.mock_object(self.root, 'invoke_elem',
                         mock.Mock(return_value=fake.NO_RECORDS_RESPONSE_REST))

        result = self.root.invoke_successfully(
            api.NaElement('svm-migration-start'), api_args=None)

        self.assertEqual(fake.NO_RECORDS_RESPONSE_REST, result)

    @ddt.data(
        {'error': {'code': api.EAPIERROR, 'message': 'fake_message'},
         'expected_code': api.EAPIERROR,
         'expected_message': 'fake_message'},
        {'error': {'message': 'fake_message'},
         'expected_code': 'ESTATUSFAILED',
         'expected_message': 'fake_message'},
        {'error': {'code': api.EAPIERROR},
         'expected_code': api.EAPIERROR,
         'expected_message':
             'Execution status is failed due to unknown reason'},
        {'error': {'code': api.ESIS_CLONE_NOT_LICENSED,
                   'message': 'fake_message'},
         'expected_code': api.ESIS_CLONE_NOT_LICENSED,
         'expected_message':
             'Clone operation failed: FlexClone not licensed.'},
    )
    @ddt.unpack
    def test_invoke_successfully_error(self, error, expected_code,
                                       expected_message):
        self.mock_object(self.root, 'invoke_elem',
                         mock.Mock(return_value={'error': error}))

        raised = self.assertRaises(
            api.NaApiError, self.root.invoke_successfully,
            api.NaElement('svm-migration-start'))

        self.assertEqual(expected_code, raised.code)
        self.assertEqual(expected_message, raised.message)


@ddt.ddt
class NetAppApiBaseClientTests(test.TestCase):
    """Test case for the accessors shared by the ZAPI and REST clients."""

    def setUp(self):
        super(NetAppApiBaseClientTests, self).setUp()
        self.client = api.BaseClient('127.0.0.1')

    def test_get_style(self):
        self.assertEqual(api.STYLE_LOGIN_PASSWORD, self.client.get_style())

    def test_set_style(self):
        self.client.set_style(api.STYLE_CERTIFICATE.upper())

        self.assertEqual(api.STYLE_CERTIFICATE, self.client.get_style())

    def test_set_style_invalid(self):
        self.assertRaises(ValueError, self.client.set_style, 'kerberos')

    def test_get_transport_type(self):
        self.assertEqual(api.TRANSPORT_TYPE_HTTPS,
                         self.client.get_transport_type())

    def test_set_transport_type(self):
        self.client._refresh_conn = False

        self.client.set_transport_type('HTTP')

        self.assertEqual(api.TRANSPORT_TYPE_HTTP,
                         self.client.get_transport_type())
        self.assertTrue(self.client._refresh_conn)

    def test_set_transport_type_invalid(self):
        self.assertRaises(ValueError, self.client.set_transport_type, 'ftp')

    def test_get_server_type(self):
        self.client._server_type = api.ZapiClient.SERVER_TYPE_FILER

        self.assertEqual(api.ZapiClient.SERVER_TYPE_FILER,
                         self.client.get_server_type())

    def test_set_server_type_not_implemented(self):
        """The base client leaves the server type to the ZAPI subclass."""
        self.assertRaises(NotImplementedError, self.client.set_server_type,
                          api.ZapiClient.SERVER_TYPE_FILER)

    def test_set_api_version(self):
        self.client._refresh_conn = False

        self.client.set_api_version('1', '20')

        self.assertEqual((1, 20), self.client.get_api_version())
        self.assertEqual('1.20', self.client._api_version)
        self.assertTrue(self.client._refresh_conn)

    @ddt.data(('1', 'a'), ('a', '1'))
    @ddt.unpack
    def test_set_api_version_invalid(self, major, minor):
        self.assertRaises(ValueError, self.client.set_api_version, major,
                          minor)

    def test_get_api_version_not_set(self):
        self.assertIsNone(self.client.get_api_version())

    def test_get_system_version_not_set(self):
        self.assertIsNone(self.client.get_system_version())

    def test_set_system_version(self):
        self.client._refresh_conn = False

        self.client.set_system_version(fake.VERSION_TUPLE)

        self.assertEqual(fake.VERSION_TUPLE, self.client.get_system_version())
        self.assertTrue(self.client._refresh_conn)

    def test_set_port(self):
        self.client._refresh_conn = False

        self.client.set_port(8080)

        self.assertEqual('8080', self.client.get_port())
        self.assertTrue(self.client._refresh_conn)

    def test_set_port_invalid(self):
        self.assertRaises(ValueError, self.client.set_port, 'eighty')

    def test_set_timeout(self):
        self.client.set_timeout('45')

        self.assertEqual(45, self.client.get_timeout())

    def test_set_timeout_invalid(self):
        self.assertRaises(ValueError, self.client.set_timeout, 'soon')

    def test_get_timeout_not_set(self):
        self.assertIsNone(self.client.get_timeout())

    def test_get_set_vserver(self):
        self.client.set_vserver(fake.VSERVER_NAME)

        self.assertEqual(fake.VSERVER_NAME, self.client.get_vserver())

    def test_set_username(self):
        self.client._refresh_conn = False

        self.client.set_username('fake_user')

        self.assertEqual('fake_user', self.client._username)
        self.assertTrue(self.client._refresh_conn)

    def test_set_password(self):
        self.client._refresh_conn = False

        self.client.set_password('fake_password')

        self.assertEqual('fake_password', self.client._password)
        self.assertTrue(self.client._refresh_conn)

    def test_invoke_successfully_is_a_no_op(self):
        """The base client declares the entry point but does not use it."""
        self.assertIsNone(
            self.client.invoke_successfully(api.NaElement('fake')))

    def test__build_headers_not_implemented(self):
        self.assertRaises(NotImplementedError, self.client._build_headers)

    def test__create_certificate_auth_handler_without_both_files(self):
        """Both a cert and a key are needed before the session cert is set."""
        self.client._certificate_file = 'fake_cert.pem'
        self.client._private_key_file = None
        self.client._certificate_host_validation = False
        self.client._session = mock.Mock()
        self.client._session.cert = None

        cert, verify = self.client._create_certificate_auth_handler()

        self.assertIsNone(cert)
        self.assertFalse(verify)

    def test__str__(self):
        self.assertEqual('server: 127.0.0.1', str(self.client))


@ddt.ddt
class NetAppApiZapiClientTests(test.TestCase):
    """Test case for the ZAPI client's ports, tunneling and result parsing."""

    def setUp(self):
        super(NetAppApiZapiClientTests, self).setUp()
        self.client = api.NaServer('127.0.0.1').zapi_client

    @ddt.data(
        {'protocol': 'http', 'server_type': 'filer', 'expected_port': '80'},
        {'protocol': 'http', 'server_type': 'dfm', 'expected_port': '8088'},
        {'protocol': 'https', 'server_type': 'filer', 'expected_port': '443'},
        {'protocol': 'https', 'server_type': 'dfm', 'expected_port': '8488'},
    )
    @ddt.unpack
    def test_default_port(self, protocol, server_type, expected_port):
        client = api.ZapiClient('127.0.0.1', transport_type=protocol,
                                server_type=server_type)

        self.assertEqual(expected_port, client.get_port())

    @ddt.data(
        {'server_type': 'FILER', 'expected_url': api.ZapiClient.URL_FILER},
        {'server_type': 'DFM', 'expected_url': api.ZapiClient.URL_DFM},
    )
    @ddt.unpack
    def test_set_server_type(self, server_type, expected_url):
        self.client._refresh_conn = False

        self.client.set_server_type(server_type)

        self.assertEqual(server_type.lower(), self.client.get_server_type())
        self.assertEqual(expected_url, self.client._url)
        self.assertEqual(api.ZapiClient.NETAPP_NS, self.client._ns)
        self.assertTrue(self.client._refresh_conn)

    def test_set_server_type_invalid(self):
        self.assertRaises(ValueError, self.client.set_server_type, 'vserver')

    def test_get_set_vfiler(self):
        self.client.set_vfiler('fake_vfiler')

        self.assertEqual('fake_vfiler', self.client.get_vfiler())

    def test__get_url(self):
        self.client._host = 'FF01::1'
        self.client._protocol = 'https'
        self.client._port = '443'

        self.assertEqual(
            'https://[FF01::1]:443/%s' % api.ZapiClient.URL_FILER,
            self.client._get_url())

    def test__build_headers(self):
        self.assertEqual({'Content-Type': 'text/xml'},
                         self.client._build_headers())

    def test__enable_tunnel_request_vfiler(self):
        self.client.set_vfiler('fake_vfiler')
        self.client.set_api_version(1, 7)
        element = api.NaElement('netapp')

        self.client._enable_tunnel_request(element)

        self.assertEqual('fake_vfiler', element.get_attr('vfiler'))

    def test__enable_tunnel_request_vserver(self):
        self.client.set_vserver(fake.VSERVER_NAME)
        self.client.set_api_version(1, 15)
        element = api.NaElement('netapp')

        self.client._enable_tunnel_request(element)

        self.assertEqual(fake.VSERVER_NAME, element.get_attr('vfiler'))

    def test__enable_tunnel_request_vfiler_api_too_old(self):
        self.client.set_vfiler('fake_vfiler')
        self.client.set_api_version(1, 6)

        self.assertRaises(ValueError, self.client._enable_tunnel_request,
                          api.NaElement('netapp'))

    def test__enable_tunnel_request_vserver_api_too_old(self):
        self.client.set_vserver(fake.VSERVER_NAME)
        self.client.set_api_version(1, 14)

        self.assertRaises(ValueError, self.client._enable_tunnel_request,
                          api.NaElement('netapp'))

    def test__enable_tunnel_request_without_api_version(self):
        self.client.set_vfiler('fake_vfiler')

        self.assertRaises(ValueError, self.client._enable_tunnel_request,
                          api.NaElement('netapp'))

    def test__enable_tunnel_request_nothing_to_tunnel_through(self):
        element = api.NaElement('netapp')

        self.client._enable_tunnel_request(element)

        self.assertIsNone(element.get_attr('vfiler'))

    def test__create_request(self):
        self.client.set_api_version(1, 20)
        mock_enable_tunnel = self.mock_object(
            self.client, '_enable_tunnel_request')

        result = self.client._create_request(
            api.NaElement('volume-get-iter'), enable_tunneling=True)

        self.assertEqual('netapp', result.get_name())
        self.assertEqual(api.ZapiClient.NETAPP_NS, result.get_attr('xmlns'))
        self.assertEqual('1.20', result.get_attr('version'))
        self.assertIsNotNone(result.get_child_by_name('volume-get-iter'))
        mock_enable_tunnel.assert_called_once_with(result)

    def test__create_request_without_tunneling(self):
        mock_enable_tunnel = self.mock_object(
            self.client, '_enable_tunnel_request')

        self.client._create_request(api.NaElement('volume-get-iter'))

        mock_enable_tunnel.assert_not_called()

    def test__parse_response_no_response(self):
        self.assertRaises(api.NaApiError, self.client._parse_response, None)

    def test__parse_response(self):
        result = self.client._parse_response(
            b'<netapp><results status="passed"/></netapp>')

        self.assertEqual('netapp', result.get_name())

    def test__get_result(self):
        result = self.client._get_result(
            b'<netapp><results status="passed"/></netapp>')

        self.assertEqual('results', result.get_name())
        self.assertEqual('passed', result.get_attr('status'))

    def test_invoke_elem_reuses_an_existing_session(self):
        self.client._session = mock.Mock()
        self.client._refresh_conn = False
        mock_build_session = self.mock_object(self.client, '_build_session')
        self.mock_object(self.client, '_create_request',
                         mock.Mock(return_value=fake.FAKE_NA_ELEMENT))
        self.mock_object(self.client, '_get_result',
                         mock.Mock(return_value=fake.FAKE_NA_ELEMENT))
        response = mock.Mock()
        response.text = 'fake_response'
        self.client._session.post = mock.Mock(return_value=response)

        self.client.invoke_elem(fake.FAKE_NA_ELEMENT)

        mock_build_session.assert_not_called()

    @ddt.data({'timeout': None, 'expected_timeout': 10},
              {'timeout': 30, 'expected_timeout': 30})
    @ddt.unpack
    def test_invoke_elem_with_timeout(self, timeout, expected_timeout):
        """An unset timeout falls back to ten seconds."""
        self.client._timeout = timeout
        self.client._session = mock.Mock()
        self.mock_object(self.client, '_build_session')
        self.mock_object(self.client, '_create_request',
                         mock.Mock(return_value=fake.FAKE_NA_ELEMENT))
        self.mock_object(self.client, '_get_result',
                         mock.Mock(return_value=fake.FAKE_NA_ELEMENT))
        self.mock_object(self.client, '_get_url',
                         mock.Mock(return_value=fake.FAKE_BASE_URL))
        response = mock.Mock()
        response.text = 'fake_response'
        self.client._session.post = mock.Mock(return_value=response)

        self.client.invoke_elem(fake.FAKE_NA_ELEMENT)

        self.client._session.post.assert_called_once_with(
            fake.FAKE_BASE_URL, data=fake.FAKE_NA_ELEMENT.to_string(),
            timeout=expected_timeout)
        self.assertEqual(expected_timeout, self.client._timeout)

    def test_invoke_successfully_passed(self):
        result = api.NaElement('results')
        result.add_attr('status', 'passed')
        self.mock_object(self.client, 'invoke_elem',
                         mock.Mock(return_value=result))

        self.assertEqual(
            result,
            self.client.invoke_successfully(api.NaElement('volume-get-iter')))

    def test_invoke_successfully_translates_api_args(self):
        na_element = api.NaElement('volume-get-iter')
        mock_translate = self.mock_object(na_element, 'translate_struct')
        result = api.NaElement('results')
        result.add_attr('status', 'passed')
        self.mock_object(self.client, 'invoke_elem',
                         mock.Mock(return_value=result))

        self.client.invoke_successfully(na_element,
                                        api_args={'name': 'fake_volume'})

        mock_translate.assert_called_once_with({'name': 'fake_volume'})

    @ddt.data(
        {'attrs': {'errno': api.EAPIERROR, 'reason': 'fake_reason'},
         'children': {},
         'expected_code': api.EAPIERROR,
         'expected_message': 'fake_reason'},
        {'attrs': {},
         'children': {'errorno': api.EAPIERROR, 'reason': 'fake_reason'},
         'expected_code': api.EAPIERROR,
         'expected_message': 'fake_reason'},
        {'attrs': {},
         'children': {},
         'expected_code': 'ESTATUSFAILED',
         'expected_message':
             'Execution status is failed due to unknown reason'},
        {'attrs': {'errno': api.ESIS_CLONE_NOT_LICENSED},
         'children': {},
         'expected_code': api.ESIS_CLONE_NOT_LICENSED,
         'expected_message':
             'Clone operation failed: FlexClone not licensed.'},
    )
    @ddt.unpack
    def test_invoke_successfully_failed(self, attrs, children, expected_code,
                                        expected_message):
        result = api.NaElement('results')
        result.add_attr('status', 'failed')
        for name, value in attrs.items():
            result.add_attr(name, value)
        for name, value in children.items():
            result.add_new_child(name, value)
        self.mock_object(self.client, 'invoke_elem',
                         mock.Mock(return_value=result))

        raised = self.assertRaises(
            api.NaApiError, self.client.invoke_successfully,
            api.NaElement('volume-get-iter'))

        self.assertEqual(expected_code, raised.code)
        self.assertEqual(expected_message, raised.message)


@ddt.ddt
class NetAppApiNaServerDelegationTests(test.TestCase):
    """NaServer is a facade that routes calls to the ZAPI or REST client."""

    def setUp(self):
        super(NetAppApiNaServerDelegationTests, self).setUp()
        self.server = api.NaServer('127.0.0.1')
        self.server.zapi_client = mock.Mock()
        self.server.rest_client = mock.Mock()

    @ddt.data(True, False)
    def test_get_client(self, use_zapi):
        expected = (self.server.zapi_client if use_zapi
                    else self.server.rest_client)

        self.assertEqual(expected, self.server.get_client(use_zapi=use_zapi))

    @ddt.data('get_transport_type', 'get_style', 'get_server_type',
              'get_api_version', 'get_system_version', 'get_port',
              'get_timeout', 'get_vserver')
    def test_getter_reads_the_selected_client(self, method):
        client = mock.Mock()
        getattr(client, method).return_value = mock.sentinel.value
        mock_get_client = self.mock_object(
            self.server, 'get_client', mock.Mock(return_value=client))

        result = getattr(self.server, method)(use_zapi_client=False)

        self.assertEqual(mock.sentinel.value, result)
        mock_get_client.assert_called_once_with(use_zapi=False)
        getattr(client, method).assert_called_once_with()

    @ddt.data(
        ('set_transport_type', (mock.sentinel.transport_type,)),
        ('set_style', (mock.sentinel.style,)),
        ('set_server_type', (mock.sentinel.server_type,)),
        ('set_system_version', (mock.sentinel.system_version,)),
        ('set_port', (mock.sentinel.port,)),
        ('set_timeout', (mock.sentinel.seconds,)),
        ('set_vserver', (mock.sentinel.vserver,)),
        ('set_username', (mock.sentinel.username,)),
        ('set_password', (mock.sentinel.password,)),
    )
    @ddt.unpack
    def test_setter_updates_both_clients(self, method, args):
        getattr(self.server, method)(*args)

        getattr(self.server.zapi_client,
                method).assert_called_once_with(*args)
        getattr(self.server.rest_client,
                method).assert_called_once_with(*args)

    def test_set_api_version_pins_the_rest_client(self):
        """The REST client has no ONTAPI version, so it is pinned to 1.0."""
        self.server.set_api_version('1', '20')

        self.server.zapi_client.set_api_version.assert_called_once_with(
            '1', '20')
        self.server.rest_client.set_api_version.assert_called_once_with(1, 0)

    def test_get_vfiler_is_zapi_only(self):
        self.server.zapi_client.get_vfiler.return_value = mock.sentinel.vfiler

        self.assertEqual(mock.sentinel.vfiler, self.server.get_vfiler())
        self.server.rest_client.get_vfiler.assert_not_called()

    def test_set_vfiler_is_zapi_only(self):
        self.server.set_vfiler(mock.sentinel.vfiler)

        self.server.zapi_client.set_vfiler.assert_called_once_with(
            mock.sentinel.vfiler)
        self.server.rest_client.set_vfiler.assert_not_called()

    @ddt.data(True, False)
    def test_invoke_successfully(self, use_zapi):
        client = (self.server.zapi_client if use_zapi
                  else self.server.rest_client)
        client.invoke_successfully.return_value = mock.sentinel.result

        result = self.server.invoke_successfully(
            mock.sentinel.na_element, api_args=mock.sentinel.api_args,
            enable_tunneling=True, use_zapi=use_zapi)

        self.assertEqual(mock.sentinel.result, result)
        client.invoke_successfully.assert_called_once_with(
            mock.sentinel.na_element, api_args=mock.sentinel.api_args,
            enable_tunneling=True)

    def test__str__(self):
        self.assertEqual('server: 127.0.0.1', str(self.server))


class NetAppApiElementAccessorTests(test.TestCase):
    """Test case for the NaElement attribute and child helpers."""

    def setUp(self):
        super(NetAppApiElementAccessorTests, self).setUp()
        self.element = api.NaElement('root')

    def test_add_attrs(self):
        self.element.add_attrs(one='1', two='2')

        self.assertEqual('1', self.element.get_attr('one'))
        self.assertEqual('2', self.element.get_attr('two'))
        self.assertEqual(['one', 'two'],
                         sorted(self.element.get_attr_names()))

    def test_has_attr(self):
        self.element.add_attr('present', 'yes')

        self.assertTrue(self.element.has_attr('present'))
        self.assertFalse(self.element.has_attr('absent'))

    def test_get_attr_absent(self):
        self.assertIsNone(self.element.get_attr('absent'))

    def test_add_new_child_converting_entity_refs(self):
        self.element.add_new_child('child', '&lt;tag&gt;', convert=True)

        self.assertEqual('<tag>', self.element.get_child_content('child'))

    def test_convert_entity_refs(self):
        result = api.NaElement._convert_entity_refs('&lt;a&gt;&gt;b&lt;')

        self.assertEqual('<a>>b<', result)

    def test_create_node_with_children(self):
        node = api.NaElement.create_node_with_children(
            'node', first='1', second='2')

        self.assertEqual('node', node.get_name())
        self.assertEqual('1', node.get_child_content('first'))
        self.assertEqual('2', node.get_child_content('second'))

    def test_add_node_with_children(self):
        self.element.add_node_with_children('node', first='1')

        child = self.element.get_child_by_name('node')
        self.assertIsNotNone(child)
        self.assertEqual('1', child.get_child_content('first'))

    def test_getitem_returns_element_for_a_child_with_children(self):
        self.element.add_node_with_children('node', first='1')

        result = self.element['node']

        self.assertIsInstance(result, api.NaElement)
        self.assertEqual('1', result.get_child_content('first'))

    def test_getitem_returns_content_for_a_leaf_child(self):
        self.element.add_new_child('leaf', 'value')

        self.assertEqual('value', self.element['leaf'])

    def test_getitem_falls_back_to_an_attribute(self):
        self.element.add_attr('attribute', 'value')

        self.assertEqual('value', self.element['attribute'])

    def test_getitem_unknown_name(self):
        self.assertRaises(KeyError, self.element.__getitem__, 'absent')

    def test_translate_struct_nested_dict(self):
        self.element.translate_struct({'outer': {'inner': 'value'}})

        outer = self.element.get_child_by_name('outer')
        self.assertEqual('value', outer.get_child_content('inner'))

    def test_translate_struct_dict_with_empty_value(self):
        """An empty value yields an element with neither content nor kids."""
        self.element.translate_struct({'empty': None})

        child = self.element.get_child_by_name('empty')
        self.assertIsNotNone(child)
        self.assertIsNone(child.get_content())


@ddt.ddt
class NetAppApiInvokeApiTests(test.TestCase):
    """Test case for the module-level API request helpers."""

    def setUp(self):
        super(NetAppApiInvokeApiTests, self).setUp()
        self.server = api.NaServer('127.0.0.1')

    def test_create_api_request_minimal(self):
        result = api.create_api_request('volume-get-iter')

        self.assertEqual('volume-get-iter', result.get_name())
        self.assertEqual([], result.get_children())

    def test_create_api_request(self):
        result = api.create_api_request(
            'volume-get-iter', query={'name': 'fake_volume'},
            des_result={'name': None}, additional_elems={'extra': 'value'},
            is_iter=True, record_step=10, tag='fake_tag')

        query = result.get_child_by_name('query')
        self.assertEqual('fake_volume', query.get_child_content('name'))
        self.assertIsNotNone(result.get_child_by_name('desired-attributes'))
        self.assertEqual('value', result.get_child_content('extra'))
        self.assertEqual('10', result.get_child_content('max-records'))
        self.assertEqual('fake_tag', result.get_child_content('tag'))

    def test_invoke_api_requires_an_na_server(self):
        generator = api.invoke_api(None, 'volume-get-iter')

        self.assertRaises(exception.InvalidInput, list, generator)

    def test_invoke_api_single_result(self):
        self.mock_object(api.NaServer, 'invoke_successfully',
                         mock.Mock(return_value=mock.sentinel.result))
        mock_set_vserver = self.mock_object(api.NaServer, 'set_vserver')
        mock_set_timeout = self.mock_object(api.NaServer, 'set_timeout')

        results = list(api.invoke_api(self.server, 'volume-get-iter',
                                      timeout=30, tunnel=fake.VSERVER_NAME))

        self.assertEqual([mock.sentinel.result], results)
        mock_set_vserver.assert_called_once_with(fake.VSERVER_NAME)
        mock_set_timeout.assert_called_once_with(30)

    def test_invoke_api_seven_mode_tunnels_through_a_vfiler(self):
        self.mock_object(api.NaServer, 'invoke_successfully',
                         mock.Mock(return_value=mock.sentinel.result))
        mock_set_vfiler = self.mock_object(api.NaServer, 'set_vfiler')

        list(api.invoke_api(self.server, 'volume-list-info',
                            api_family='7m', tunnel='fake_vfiler'))

        mock_set_vfiler.assert_called_once_with('fake_vfiler')

    def test_invoke_api_iterates_until_there_is_no_next_tag(self):
        first = api.NaElement('results')
        first.add_new_child('next-tag', 'fake_tag')
        second = api.NaElement('results')
        self.mock_object(api.NaServer, 'invoke_successfully',
                         mock.Mock(side_effect=[first, second]))
        self.mock_object(api.NaServer, 'set_vserver')

        results = list(api.invoke_api(self.server, 'volume-get-iter',
                                      is_iter=True))

        self.assertEqual([first, second], results)

    def test_invoke_api_stops_at_the_record_limit(self):
        result = api.NaElement('results')
        result.add_new_child('next-tag', 'fake_tag')
        self.mock_object(api.NaServer, 'invoke_successfully',
                         mock.Mock(return_value=result))
        self.mock_object(api.NaServer, 'set_vserver')

        results = list(api.invoke_api(self.server, 'volume-get-iter',
                                      is_iter=True, records=50))

        self.assertEqual([result], results)

    def test_invoke_api_keeps_going_below_the_record_limit(self):
        """Records are fetched 50 at a time, so a limit of 100 takes two."""
        result = api.NaElement('results')
        result.add_new_child('next-tag', 'fake_tag')
        self.mock_object(api.NaServer, 'invoke_successfully',
                         mock.Mock(return_value=result))
        self.mock_object(api.NaServer, 'set_vserver')

        results = list(api.invoke_api(self.server, 'volume-get-iter',
                                      is_iter=True, records=100))

        self.assertEqual([result, result], results)
