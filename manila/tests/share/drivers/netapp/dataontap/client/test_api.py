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
