# Copyright 2012 NetApp
# Copyright 2014 Mirantis Inc.
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
"""Unit tests for the Share driver module."""

import time

import mock

from manila import exception
from manila import network
from manila.share import configuration
from manila.share import driver
from manila import test
from manila import utils


def fake_execute_with_raise(*cmd, **kwargs):
    raise exception.ProcessExecutionError


def fake_sleep(duration):
    pass


class ShareDriverTestCase(test.TestCase):

    def setUp(self):
        super(ShareDriverTestCase, self).setUp()
        self.utils = utils
        self.stubs.Set(self.utils, 'execute', fake_execute_with_raise)
        self.time = time
        self.stubs.Set(self.time, 'sleep', fake_sleep)

    def test__try_execute(self):
        execute_mixin = driver.ExecuteMixin(
            configuration=configuration.Configuration(None))
        self.assertRaises(exception.ProcessExecutionError,
                          execute_mixin._try_execute)

    def _instantiate_share_driver(self, network_config_group):
        self.stubs.Set(network, 'API', mock.Mock())
        config = mock.Mock()
        config.append_config_values = mock.Mock()
        config.config_group = 'fake_config_group'
        config.network_config_group = network_config_group

        share_driver = driver.ShareDriver(configuration=config)

        self.assertTrue(hasattr(share_driver, 'configuration'))
        config.append_config_values.assert_called_once_with(driver.share_opts)
        if network_config_group:
            network.API.assert_called_once_with(
                config_group_name=config.network_config_group)
        else:
            network.API.assert_called_once_with(
                config_group_name=config.config_group)

    def test_instantiate_share_driver(self):
        self._instantiate_share_driver(None)

    def test_instantiate_share_driver_another_config_group(self):
        self._instantiate_share_driver("fake_network_config_group")

    def test_instantiate_share_driver_no_configuration(self):
        self.stubs.Set(network, 'API', mock.Mock())

        share_driver = driver.ShareDriver(configuration=None)

        self.assertEqual(None, share_driver.configuration)
        network.API.assert_called_once_with(config_group_name=None)
