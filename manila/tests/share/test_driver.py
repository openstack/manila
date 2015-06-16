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

import ddt
import mock

from manila import exception
from manila import network
from manila.share import configuration
from manila.share import driver
from manila import test
from manila.tests import utils as test_utils
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
        self.mock_object(self.utils, 'execute', fake_execute_with_raise)
        self.time = time
        self.mock_object(self.time, 'sleep', fake_sleep)
        driver.CONF.set_default('driver_handles_share_servers', True)

    def test__try_execute(self):
        execute_mixin = ShareDriverWithExecuteMixin(
            True, configuration=configuration.Configuration(None))
        self.assertRaises(exception.ProcessExecutionError,
                          execute_mixin._try_execute)

    def test_verify_share_driver_mode_option_type(self):
        data = {'DEFAULT': {'driver_handles_share_servers': 'True'}}
        with test_utils.create_temp_config_with_opts(data):
            share_driver = driver.ShareDriver([True, False])
            self.assertEqual(True, share_driver.driver_handles_share_servers)

    def _instantiate_share_driver(self, network_config_group,
                                  driver_handles_share_servers):
        self.mock_object(network, 'API')
        config = mock.Mock()
        config.append_config_values = mock.Mock()
        config.config_group = 'fake_config_group'
        config.network_config_group = network_config_group
        config.safe_get = mock.Mock(return_value=driver_handles_share_servers)

        share_driver = driver.ShareDriver([True, False], configuration=config)

        self.assertTrue(hasattr(share_driver, 'configuration'))
        config.append_config_values.assert_called_once_with(driver.share_opts)
        if driver_handles_share_servers:
            if network_config_group:
                network.API.assert_called_once_with(
                    config_group_name=config.network_config_group)
            else:
                network.API.assert_called_once_with(
                    config_group_name=config.config_group)
        else:
            self.assertFalse(hasattr(share_driver, 'network_api'))
            self.assertFalse(network.API.called)
        return share_driver

    def test_instantiate_share_driver(self):
        self._instantiate_share_driver(None, True)

    def test_instantiate_share_driver_another_config_group(self):
        self._instantiate_share_driver("fake_network_config_group", True)

    def test_instantiate_share_driver_no_configuration(self):
        self.mock_object(network, 'API')

        share_driver = driver.ShareDriver(True, configuration=None)

        self.assertEqual(None, share_driver.configuration)
        network.API.assert_called_once_with(config_group_name=None)

    def test_get_share_stats_refresh_false(self):
        share_driver = driver.ShareDriver(True, configuration=None)
        share_driver._stats = {'fake_key': 'fake_value'}

        result = share_driver.get_share_stats(False)

        self.assertEqual(share_driver._stats, result)

    def test_get_share_stats_refresh_true(self):
        conf = configuration.Configuration(None)
        expected_keys = [
            'QoS_support', 'driver_version', 'share_backend_name',
            'free_capacity_gb', 'total_capacity_gb',
            'driver_handles_share_servers',
            'reserved_percentage', 'vendor_name', 'storage_protocol',
        ]
        share_driver = driver.ShareDriver(True, configuration=conf)
        fake_stats = {'fake_key': 'fake_value'}
        share_driver._stats = fake_stats

        result = share_driver.get_share_stats(True)

        self.assertNotEqual(fake_stats, result)
        for key in expected_keys:
            self.assertIn(key, result)
        self.assertEqual('Open Source', result['vendor_name'])

    @ddt.data(
        {'opt': True, 'allowed': True},
        {'opt': True, 'allowed': (True, False)},
        {'opt': True, 'allowed': [True, False]},
        {'opt': True, 'allowed': set([True, False])},
        {'opt': False, 'allowed': False},
        {'opt': False, 'allowed': (True, False)},
        {'opt': False, 'allowed': [True, False]},
        {'opt': False, 'allowed': set([True, False])})
    @ddt.unpack
    def test__verify_share_server_handling_valid_cases(self, opt, allowed):
        conf = configuration.Configuration(None)
        self.mock_object(conf, 'safe_get', mock.Mock(return_value=opt))
        share_driver = driver.ShareDriver(allowed, configuration=conf)
        self.assertTrue(conf.safe_get.celled)
        self.assertEqual(opt, share_driver.driver_handles_share_servers)

    @ddt.data(
        {'opt': False, 'allowed': True},
        {'opt': True, 'allowed': False},
        {'opt': None, 'allowed': True},
        {'opt': 'True', 'allowed': True},
        {'opt': 'False', 'allowed': False},
        {'opt': [], 'allowed': True},
        {'opt': True, 'allowed': []},
        {'opt': True, 'allowed': ['True']},
        {'opt': False, 'allowed': ['False']})
    @ddt.unpack
    def test__verify_share_server_handling_invalid_cases(self, opt, allowed):
        conf = configuration.Configuration(None)
        self.mock_object(conf, 'safe_get', mock.Mock(return_value=opt))
        self.assertRaises(
            exception.ManilaException,
            driver.ShareDriver, allowed, configuration=conf)
        self.assertTrue(conf.safe_get.celled)

    def test_setup_server_handling_disabled(self):
        share_driver = self._instantiate_share_driver(None, False)
        # We expect successful execution, nothing to assert
        share_driver.setup_server('Nothing is expected to happen.')

    def test_setup_server_handling_enabled(self):
        share_driver = self._instantiate_share_driver(None, True)
        self.assertRaises(
            NotImplementedError,
            share_driver.setup_server,
            'fake_network_info')

    def test_teardown_server_handling_disabled(self):
        share_driver = self._instantiate_share_driver(None, False)
        # We expect successful execution, nothing to assert
        share_driver.teardown_server('Nothing is expected to happen.')

    def test_teardown_server_handling_enabled(self):
        share_driver = self._instantiate_share_driver(None, True)
        self.assertRaises(
            NotImplementedError,
            share_driver.teardown_server,
            'fake_share_server_details')

    @ddt.data('manage_existing',
              'unmanage')
    def test_drivers_methods_needed_by_manage_functionality(self, method):
        share_driver = self._instantiate_share_driver(None, False)

        def assert_is_callable(obj, attr):
            self.assertTrue(callable(getattr(obj, attr)))

        assert_is_callable(share_driver, method)

    @ddt.data(True, False)
    def test_get_share_server_pools(self, value):
        driver.CONF.set_default('driver_handles_share_servers', value)
        share_driver = driver.ShareDriver(value)
        self.assertEqual([],
                         share_driver.get_share_server_pools('fake_server'))

    @ddt.data(0.8, 1.0, 10.5, 20.0, None)
    def test_check_for_setup_error(self, value):
        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)
        share_driver.configuration = configuration.Configuration(None)
        self.mock_object(share_driver.configuration, 'safe_get',
                         mock.Mock(return_value=value))
        if value >= 1.0:
            share_driver.check_for_setup_error()
        else:
            self.assertRaises(exception.InvalidParameterValue,
                              share_driver.check_for_setup_error)
