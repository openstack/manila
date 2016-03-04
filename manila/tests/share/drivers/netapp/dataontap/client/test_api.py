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
import ddt
import mock
from six.moves import urllib

from manila import exception
from manila.share.drivers.netapp.dataontap.client import api
from manila import test
from manila.tests.share.drivers.netapp.dataontap.client import fakes as fake


class NetAppApiElementTransTests(test.TestCase):
    """Test case for NetApp API element translations."""

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

        l = root.get_child_by_name('l')
        self.assertIsInstance(l, api.NaElement)
        t = root.get_child_by_name('t')
        self.assertIsInstance(t, api.NaElement)

        self.assertEqual(2, len(l.get_children()))
        for le in l.get_children():
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
class NetAppApiServerTests(test.TestCase):
    """Test case for NetApp API server methods"""
    def setUp(self):
        self.root = api.NaServer('127.0.0.1')
        super(NetAppApiServerTests, self).setUp()

    @ddt.data(None, fake.FAKE_XML_STR)
    def test_invoke_elem_value_error(self, na_element):
        """Tests whether invalid NaElement parameter causes error"""

        self.assertRaises(ValueError, self.root.invoke_elem, na_element)

    def test_invoke_elem_http_error(self):
        """Tests handling of HTTPError"""
        na_element = fake.FAKE_NA_ELEMENT
        self.mock_object(self.root, '_create_request', mock.Mock(
            return_value=('abc', fake.FAKE_NA_ELEMENT)))
        self.mock_object(api, 'LOG')
        self.root._opener = fake.FAKE_HTTP_OPENER
        self.mock_object(self.root, '_build_opener')
        self.mock_object(self.root._opener, 'open', mock.Mock(
            side_effect=urllib.error.HTTPError(url='', hdrs='',
                                               fp=None, code='401',
                                               msg='httperror')))

        self.assertRaises(api.NaApiError, self.root.invoke_elem,
                          na_element)

    def test_invoke_elem_urlerror(self):
        """Tests handling of URLError"""
        na_element = fake.FAKE_NA_ELEMENT
        self.mock_object(self.root, '_create_request', mock.Mock(
            return_value=('abc', fake.FAKE_NA_ELEMENT)))
        self.mock_object(api, 'LOG')
        self.root._opener = fake.FAKE_HTTP_OPENER
        self.mock_object(self.root, '_build_opener')
        self.mock_object(self.root._opener, 'open', mock.Mock(
            side_effect=urllib.error.URLError(reason='urlerror')))

        self.assertRaises(exception.StorageCommunicationException,
                          self.root.invoke_elem,
                          na_element)

    def test_invoke_elem_unknown_exception(self):
        """Tests handling of Unknown Exception"""
        na_element = fake.FAKE_NA_ELEMENT
        self.mock_object(self.root, '_create_request', mock.Mock(
            return_value=('abc', fake.FAKE_NA_ELEMENT)))
        self.mock_object(api, 'LOG')
        self.root._opener = fake.FAKE_HTTP_OPENER
        self.mock_object(self.root, '_build_opener')
        self.mock_object(self.root._opener, 'open', mock.Mock(
            side_effect=Exception))

        exception = self.assertRaises(api.NaApiError, self.root.invoke_elem,
                                      na_element)
        self.assertEqual('unknown', exception.code)

    def test_invoke_elem_valid(self):
        """Tests the method invoke_elem with valid parameters"""
        na_element = fake.FAKE_NA_ELEMENT
        self.root._trace = True
        self.mock_object(self.root, '_create_request', mock.Mock(
            return_value=('abc', fake.FAKE_NA_ELEMENT)))
        self.mock_object(api, 'LOG')
        self.root._opener = fake.FAKE_HTTP_OPENER
        self.mock_object(self.root, '_build_opener')
        self.mock_object(self.root, '_get_result', mock.Mock(
            return_value=fake.FAKE_NA_ELEMENT))
        opener_mock = self.mock_object(
            self.root._opener, 'open', mock.Mock())
        opener_mock.read.side_effect = ['resp1', 'resp2']

        self.root.invoke_elem(na_element)

        self.assertEqual(2, api.LOG.debug.call_count)
