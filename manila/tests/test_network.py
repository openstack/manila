# Copyright 2015 Mirantis Inc.
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

import ddt
from oslo_config import cfg
from oslo_utils import importutils

from manila import exception
from manila import network
from manila import test

CONF = cfg.CONF


@ddt.ddt
class APITestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.mock_object(importutils, 'import_class')

    def test_init_api_with_default_config_group_name(self):
        network.API()

        importutils.import_class.assert_called_once_with(
            CONF.network_api_class)
        importutils.import_class.return_value.assert_called_once_with(
            config_group_name=None, label='user')

    def test_init_api_with_custom_config_group_name(self):
        group_name = 'FOO_GROUP_NAME'

        network.API(config_group_name=group_name)

        importutils.import_class.assert_called_once_with(
            getattr(CONF, group_name).network_api_class)
        importutils.import_class.return_value.assert_called_once_with(
            config_group_name=group_name, label='user')

    def test_init_api_with_custom_config_group_name_and_label(self):
        group_name = 'FOO_GROUP_NAME'
        label = 'custom_label'

        network.API(config_group_name=group_name, label=label)

        importutils.import_class.assert_called_once_with(
            getattr(CONF, group_name).network_api_class)
        importutils.import_class.return_value.assert_called_once_with(
            config_group_name=group_name, label=label)


@ddt.ddt
class NetworkBaseAPITestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.db_driver = 'fake_driver'
        self.mock_object(importutils, 'import_module')

    def test_inherit_network_base_api_no_redefinitions(self):
        class FakeNetworkAPI(network.NetworkBaseAPI):
            pass

        self.assertRaises(TypeError, FakeNetworkAPI)

    def test_inherit_network_base_api_deallocate_not_redefined(self):
        class FakeNetworkAPI(network.NetworkBaseAPI):
            def allocate_network(self, *args, **kwargs):
                pass

        self.assertRaises(TypeError, FakeNetworkAPI)

    def test_inherit_network_base_api_allocate_not_redefined(self):
        class FakeNetworkAPI(network.NetworkBaseAPI):
            def deallocate_network(self, *args, **kwargs):
                pass

        self.assertRaises(TypeError, FakeNetworkAPI)

    def test_inherit_network_base_api(self):
        class FakeNetworkAPI(network.NetworkBaseAPI):
            def allocate_network(self, *args, **kwargs):
                pass

            def deallocate_network(self, *args, **kwargs):
                pass

        result = FakeNetworkAPI()

        self.assertTrue(hasattr(result, '_verify_share_network'))
        self.assertTrue(hasattr(result, 'allocate_network'))
        self.assertTrue(hasattr(result, 'deallocate_network'))

    def test__verify_share_network_ok(self):
        class FakeNetworkAPI(network.NetworkBaseAPI):
            def allocate_network(self, *args, **kwargs):
                pass

            def deallocate_network(self, *args, **kwargs):
                pass

        result = FakeNetworkAPI()

        result._verify_share_network('foo_id', {'id': 'bar_id'})

    def test__verify_share_network_fail(self):
        class FakeNetworkAPI(network.NetworkBaseAPI):
            def allocate_network(self, *args, **kwargs):
                pass

            def deallocate_network(self, *args, **kwargs):
                pass

        result = FakeNetworkAPI()

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            result._verify_share_network, 'foo_id', None)
