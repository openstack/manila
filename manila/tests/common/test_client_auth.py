# Copyright 2016 SAP SE
# All Rights Reserved
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

from keystoneauth1 import loading as auth
from keystoneauth1.loading._plugins.identity import v2
from oslo_config import cfg

import mock

from manila.common import client_auth
from manila import exception
from manila import test
from manila.tests import fake_client_exception_class


class ClientAuthTestCase(test.TestCase):
    def setUp(self):
        super(ClientAuthTestCase, self).setUp()
        self.context = mock.Mock()
        self.fake_client = mock.Mock()
        self.execption_mod = fake_client_exception_class
        self.auth = client_auth.AuthClientLoader(
            self.fake_client, self.execption_mod, 'foo_group')

    def test_get_client_admin_true(self):
        mock_load_session = self.mock_object(auth,
                                             'load_session_from_conf_options')

        self.auth.get_client(self.context, admin=True)

        mock_load_session.assert_called_once_with(client_auth.CONF,
                                                  'foo_group')
        self.fake_client.assert_called_once_with(
            session=mock_load_session(),
            auth=auth.load_auth_from_conf_options())

    def test_get_client_admin_false(self):
        self.mock_object(auth, 'load_session_from_conf_options')

        self.assertRaises(exception.ManilaException, self.auth.get_client,
                          self.context, admin=False)

    def test_load_auth_plugin_caching(self):
        self.auth.admin_auth = 'admin obj'
        result = self.auth._load_auth_plugin()

        self.assertEqual(self.auth.admin_auth, result)

    def test_load_auth_plugin_no_auth(self):
        auth.load_auth_from_conf_options.return_value = None

        self.assertRaises(fake_client_exception_class.Unauthorized,
                          self.auth._load_auth_plugin)

    def test_load_auth_plugin_no_auth_deprecated_opts(self):
        auth.load_auth_from_conf_options.return_value = None
        self.auth.deprecated_opts_for_v2 = {"username": "foo"}
        pwd_mock = self.mock_object(v2, 'Password')
        auth_result = mock.Mock()
        auth_result.load_from_options = mock.Mock(return_value='foo_auth')
        pwd_mock.return_value = auth_result

        result = self.auth._load_auth_plugin()

        pwd_mock.assert_called_once_with()
        auth_result.load_from_options.assert_called_once_with(username='foo')
        self.assertEqual(result, 'foo_auth')

    @mock.patch.object(auth, 'get_session_conf_options')
    @mock.patch.object(auth, 'get_auth_common_conf_options')
    @mock.patch.object(auth, 'get_auth_plugin_conf_options')
    def test_list_opts(self, auth_conf, common_conf, session_conf):
        session_conf.return_value = [cfg.StrOpt('username'),
                                     cfg.StrOpt('password')]
        common_conf.return_value = ([cfg.StrOpt('auth_url')])
        auth_conf.return_value = [cfg.StrOpt('password')]

        result = client_auth.AuthClientLoader.list_opts("foo_group")

        self.assertEqual('foo_group', result[0][0])
        for entry in result[0][1]:
            self.assertIn(entry.name, ['username', 'auth_url', 'password'])
        common_conf.assert_called_once_with()
        auth_conf.assert_called_once_with('password')

    @mock.patch.object(auth, 'get_session_conf_options')
    @mock.patch.object(auth, 'get_auth_common_conf_options')
    @mock.patch.object(auth, 'get_auth_plugin_conf_options')
    def test_list_opts_not_found(self, auth_conf, common_conf, session_conf):
        session_conf.return_value = [cfg.StrOpt('username'),
                                     cfg.StrOpt('password')]
        common_conf.return_value = ([cfg.StrOpt('auth_url')])
        auth_conf.return_value = [cfg.StrOpt('tenant')]

        result = client_auth.AuthClientLoader.list_opts("foo_group")

        self.assertEqual('foo_group', result[0][0])
        for entry in result[0][1]:
            self.assertIn(entry.name, ['username', 'auth_url', 'password',
                                       'tenant'])
        common_conf.assert_called_once_with()
        auth_conf.assert_called_once_with('password')
