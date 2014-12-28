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

import os
import time

import ddt
import mock

from manila.common import constants
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


class ShareDriverWithExecuteMixin(driver.ShareDriver, driver.ExecuteMixin):
    pass


@ddt.ddt
class ShareDriverTestCase(test.TestCase):

    def setUp(self):
        super(ShareDriverTestCase, self).setUp()
        self.utils = utils
        self.stubs.Set(self.utils, 'execute', fake_execute_with_raise)
        self.time = time
        self.stubs.Set(self.time, 'sleep', fake_sleep)

        self.fake_valid_modes = ('v1', 'v2', )
        self.stubs.Set(
            constants, 'VALID_SHARE_DRIVER_MODES', self.fake_valid_modes)

    def test__try_execute(self):
        execute_mixin = ShareDriverWithExecuteMixin(
            configuration=configuration.Configuration(None))
        self.assertRaises(exception.ProcessExecutionError,
                          execute_mixin._try_execute)

    def test_verify_share_driver_mode_option_type(self):
        with utils.tempdir() as tmpdir:
            tmpfilename = os.path.join(tmpdir, 'share_driver_mode.conf')
            with open(tmpfilename, "w") as configfile:
                configfile.write("""[DEFAULT]\nshare_driver_mode = fake""")

            # Add config file with updated opt
            driver.CONF.default_config_files = [configfile.name]

            # Reload config instance to use redefined opt
            driver.CONF.reload_config_files()

            share_driver = driver.ShareDriver()
            self.assertEqual('fake', share_driver.mode)

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
        self.assertTrue(hasattr(share_driver, 'mode'))
        return share_driver

    def test_instantiate_share_driver(self):
        self._instantiate_share_driver(None)

    def test_instantiate_share_driver_another_config_group(self):
        self._instantiate_share_driver("fake_network_config_group")

    def test_instantiate_share_driver_no_configuration(self):
        self.stubs.Set(network, 'API', mock.Mock())

        share_driver = driver.ShareDriver(configuration=None)

        self.assertEqual(None, share_driver.configuration)
        network.API.assert_called_once_with(config_group_name=None)

    def test_get_share_stats_refresh_false(self):
        share_driver = driver.ShareDriver(configuration=None)
        share_driver._stats = {'fake_key': 'fake_value'}

        result = share_driver.get_share_stats(False)

        self.assertEqual(share_driver._stats, result)

    def test_get_share_stats_refresh_true(self):
        conf = configuration.Configuration(None)
        expected_keys = [
            'QoS_support', 'driver_version', 'share_backend_name',
            'free_capacity_gb', 'share_driver_mode', 'total_capacity_gb',
            'reserved_percentage', 'vendor_name', 'storage_protocol',
        ]
        share_driver = driver.ShareDriver(configuration=conf)
        fake_stats = {'fake_key': 'fake_value'}
        share_driver._stats = fake_stats

        result = share_driver.get_share_stats(True)

        self.assertNotEqual(fake_stats, result)
        for key in expected_keys:
            self.assertIn(key, result)
        self.assertEqual('Open Source', result['vendor_name'])

    @ddt.data(
        '', 'v1', 'v2', 'fake1', None,
        [], ['v1'], ['v2'], ['v1', 'v2'], ['fake1'], ['fake1', 'fake2'],
        (), ('v1'), ('v2'), ('v1', 'v2'), ('fake1', ), ('fake1', 'fake2'))
    def test_get_driver_mode_invalid_opt(self, driver_modes):
        share_driver = self._instantiate_share_driver(None)
        share_driver.mode = 'fake'
        self.assertRaises(
            exception.InvalidParameterValue,
            share_driver.get_driver_mode, driver_modes)

    @ddt.data(
        (), [], ('v1', 'v2'), ['v1', 'v2'], ('v1', 'fake1'), ['v1', 'fake1'],
        ('fake1', 'fake2'), ['fake1', 'fake2'], ('fake1', ), ['fake1'], '',
        'fake1', {}, {'v1': 'v2'}, None)
    def test_get_driver_mode_none_opt_invalid_cases(self, driver_modes):
        share_driver = self._instantiate_share_driver(None)
        share_driver.mode = None
        self.assertRaises(
            exception.InvalidParameterValue,
            share_driver.get_driver_mode, driver_modes)

    @ddt.data('v2', ('v2', ), ['v2', ])
    def test_get_driver_mode_none_opt_valid_cases(self, driver_modes):
        share_driver = self._instantiate_share_driver(None)
        share_driver.mode = None

        mode = share_driver.get_driver_mode(driver_modes)

        self.assertEqual('v2', mode)

    @ddt.data(
        (), [], '', 'fake1', 'v1', ('v1', ), ['v1'], {}, {'v1': 'v2'}, None,
        ('fake1', ), ['fake2'], ['fake1', 'fake2'], ('fake2', 'fake1'))
    def test_get_driver_mode_valid_opt_invalid_cases(self, driver_modes):
        share_driver = self._instantiate_share_driver(None)
        share_driver.mode = 'v2'
        self.assertRaises(
            exception.InvalidParameterValue,
            share_driver.get_driver_mode, driver_modes)

    @ddt.data(
        'v2', ('v2', ), ['v2'], ('v2', 'v1'), ['v2', 'v1'],
        ('v2', 'fake2'), ['v2', 'fake1'])
    def test_get_driver_mode_valid_opt_valid_cases(self, driver_modes):
        share_driver = self._instantiate_share_driver(None)
        share_driver.mode = 'v2'

        mode = share_driver.get_driver_mode(driver_modes)

        self.assertEqual('v2', mode)
