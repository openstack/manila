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

from manila.common import constants
from manila import exception
from manila import network
from manila.share import configuration
from manila.share import driver
from manila.share import migration
from manila.share import rpcapi
from manila.share import utils as share_utils
from manila import test
from manila.tests import db_utils
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
    _SNAPSHOT_METHOD_NAMES = ["create_snapshot", "delete_snapshot",
                              "create_share_from_snapshot"]

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
            self.assertTrue(share_driver.driver_handles_share_servers)

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

        self.assertIsNone(share_driver.configuration)
        network.API.assert_called_once_with(config_group_name=None)

    def test_get_share_stats_refresh_false(self):
        share_driver = driver.ShareDriver(True, configuration=None)
        share_driver._stats = {'fake_key': 'fake_value'}

        result = share_driver.get_share_stats(False)

        self.assertEqual(share_driver._stats, result)

    def test_get_share_stats_refresh_true(self):
        conf = configuration.Configuration(None)
        expected_keys = [
            'qos', 'driver_version', 'share_backend_name',
            'free_capacity_gb', 'total_capacity_gb',
            'driver_handles_share_servers',
            'reserved_percentage', 'vendor_name', 'storage_protocol',
            'snapshot_support',
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

    @ddt.data(0.8, 1.0, 10.5, 20.0, None, '1', '1.1')
    def test_check_for_setup_error(self, value):
        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)
        share_driver.configuration = configuration.Configuration(None)
        self.mock_object(share_driver.configuration, 'safe_get',
                         mock.Mock(return_value=value))
        if value and float(value) >= 1.0:
            share_driver.check_for_setup_error()
        else:
            self.assertRaises(exception.InvalidParameterValue,
                              share_driver.check_for_setup_error)

    def test_snapshot_support_exists(self):
        driver.CONF.set_default('driver_handles_share_servers', True)
        fake_method = lambda *args, **kwargs: None
        child_methods = {
            "create_snapshot": fake_method,
            "delete_snapshot": fake_method,
            "create_share_from_snapshot": fake_method,
        }
        child_class_instance = type(
            "NotRedefined", (driver.ShareDriver, ), child_methods)(True)
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats()

        self.assertEqual(
            True, child_class_instance._stats["snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    @ddt.data(
        ([], [], False),
        (_SNAPSHOT_METHOD_NAMES, [], True),
        (_SNAPSHOT_METHOD_NAMES, _SNAPSHOT_METHOD_NAMES, True),
        (_SNAPSHOT_METHOD_NAMES[0:1], _SNAPSHOT_METHOD_NAMES[1:],
            True),
        ([], _SNAPSHOT_METHOD_NAMES, True),
        (_SNAPSHOT_METHOD_NAMES[0:1], _SNAPSHOT_METHOD_NAMES[1:2],
            False),
    )
    @ddt.unpack
    def test_check_redefined_driver_methods(self, common_drv_meth_names,
                                            child_drv_meth_names,
                                            expected_result):
        # This test covers the case of drivers inheriting other drivers or
        # common classes.

        driver.CONF.set_default('driver_handles_share_servers', True)

        common_drv_methods, child_drv_methods = [
            {method_name: lambda *args, **kwargs: None
             for method_name in method_names}
            for method_names in (common_drv_meth_names,
                                 child_drv_meth_names)]

        common_drv = type(
            "NotRedefinedCommon", (driver.ShareDriver, ), common_drv_methods)
        child_drv_instance = type("NotRedefined", (common_drv, ),
                                  child_drv_methods)(True)

        has_redefined_methods = (
            child_drv_instance._has_redefined_driver_methods(
                self._SNAPSHOT_METHOD_NAMES))

        self.assertEqual(expected_result, has_redefined_methods)

    @ddt.data(
        (),
        ("create_snapshot"),
        ("delete_snapshot"),
        ("create_share_from_snapshot"),
        ("create_snapshot", "delete_snapshot"),
        ("create_snapshot", "create_share_from_snapshot"),
        ("delete_snapshot", "create_share_from_snapshot"),
        ("create_snapshot", "delete_snapshot",
         "create_share_from_snapshotFOO"),
        ("create_snapshot", "delete_snapshot",
         "FOOcreate_share_from_snapshot"),
    )
    def test_snapshot_support_absent(self, methods):
        driver.CONF.set_default('driver_handles_share_servers', True)
        fake_method = lambda *args, **kwargs: None
        child_methods = {}
        for method in methods:
            child_methods[method] = fake_method
        child_class_instance = type(
            "NotRedefined", (driver.ShareDriver, ), child_methods)(True)
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats()

        self.assertEqual(
            False, child_class_instance._stats["snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    @ddt.data(True, False)
    def test_snapshot_support_not_exists_and_set_explicitly(
            self, snapshots_are_supported):
        driver.CONF.set_default('driver_handles_share_servers', True)
        child_class_instance = type(
            "NotRedefined", (driver.ShareDriver, ), {})(True)
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats(
            {"snapshot_support": snapshots_are_supported})

        self.assertEqual(
            snapshots_are_supported,
            child_class_instance._stats["snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    @ddt.data(True, False)
    def test_snapshot_support_exists_and_set_explicitly(
            self, snapshots_are_supported):
        driver.CONF.set_default('driver_handles_share_servers', True)
        fake_method = lambda *args, **kwargs: None
        child_methods = {
            "create_snapshot": fake_method,
            "delete_snapshot": fake_method,
            "create_share_from_snapshot": fake_method,
        }
        child_class_instance = type(
            "NotRedefined", (driver.ShareDriver, ), child_methods)(True)
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats(
            {"snapshot_support": snapshots_are_supported})

        self.assertEqual(
            snapshots_are_supported,
            child_class_instance._stats["snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    def test_get_periodic_hook_data(self):
        share_driver = self._instantiate_share_driver(None, False)
        share_instances = ["list", "of", "share", "instances"]

        result = share_driver.get_periodic_hook_data(
            "fake_context", share_instances)

        self.assertEqual(share_instances, result)

    def test_migrate_share(self):

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)

        self.assertEqual((None, None),
                         share_driver.migrate_share(None, None, None, None))

    def test_get_driver_migration_info_default(self):

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)

        self.assertIsNone(
            share_driver.get_driver_migration_info(None, None, None), None)

    def test_get_migration_info_default(self):
        expected = {'mount': ['mount', '-t', 'fake_proto', '/fake/fake_id',
                              '/tmp/fake_id'],
                    'umount': ['umount', '/tmp/fake_id'],
                    'access': {'access_type': 'ip',
                               'access_level': 'rw',
                               'access_to': None}}
        fake_share = {'id': 'fake_id',
                      'share_proto': 'fake_proto',
                      'export_locations': [{'path': '/fake/fake_id'}]}

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)
        share_driver.configuration = configuration.Configuration(None)

        migration_info = share_driver.get_migration_info(None,
                                                         fake_share,
                                                         "fake_server")

        self.assertEqual(expected, migration_info)

    def test_get_migration_info_parameters(self):

        expected = {'mount': ['fake_mount', '/200.200.200.200/fake_id',
                              '/tmp/fake_id'],
                    'umount': ['umount', '/tmp/fake_id'],
                    'access': {'access_type': 'ip',
                               'access_level': 'rw',
                               'access_to': '100.100.100.100'}}

        fake_share = {'id': 'fake_id',
                      'export_locations': [{'path': '/5.5.5.5/fake_id'}]}

        driver.CONF.set_default('driver_handles_share_servers', False)
        driver.CONF.set_default('migration_protocol_mount_command',
                                'fake_mount')
        driver.CONF.set_default('migration_mounting_backend_ip',
                                '200.200.200.200')
        driver.CONF.set_default('migration_data_copy_node_ip',
                                '100.100.100.100')

        share_driver = driver.ShareDriver(False)
        share_driver.configuration = configuration.Configuration(None)
        migration_info = share_driver.get_migration_info(None,
                                                         fake_share,
                                                         "fake_server")

        self.assertEqual(expected, migration_info)

    def _setup_mocks_copy_share_data(self):

        get_migration_info_value = {'mount': 'fake',
                                    'umount': 'fake',
                                    'access':
                                    {'access_type': 'fake',
                                     'access_to': 'fake'}}

        self.mock_object(rpcapi.ShareAPI, 'get_migration_info',
                         mock.Mock(return_value=get_migration_info_value))

        self.mock_object(driver.ShareDriver, 'get_migration_info',
                         mock.Mock(return_value=get_migration_info_value))

        self.mock_object(share_utils.Copy, 'run')
        self.mock_object(time, 'sleep')

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(
            False, configuration=configuration.Configuration(None))

        return share_driver

    def test_copy_share_data(self):
        fake_share = db_utils.create_share(
            id='fakeid', status=constants.STATUS_AVAILABLE, host='fake_host')
        fake_share_instance = {'id': 'fake_id', 'host': 'fake_host'}
        share_driver = self._setup_mocks_copy_share_data()
        remote = {'access': {'access_to': '192.168.0.1'},
                  'mount': 'fake_mount',
                  'umount': 'fake_umount'}
        local = {'access': {'access_to': '192.168.1.1'},
                 'mount': 'fake_mount',
                 'umount': 'fake_umount'}
        helper = migration.ShareMigrationHelper(None, None, None, None, None)

        driver.CONF.set_default('migration_tmp_location', '/fake/path')
        driver.CONF.set_default('migration_ignore_files', None)

        self.mock_object(migration.ShareMigrationHelper,
                         'deny_migration_access')
        self.mock_object(migration.ShareMigrationHelper,
                         'allow_migration_access',
                         mock.Mock(return_value='fake_access_ref'))
        self.mock_object(utils, 'execute')
        self.mock_object(share_utils.Copy, 'get_progress', mock.Mock(
            return_value={'total_progress': 100}))

        share_driver.copy_share_data('ctx', helper, fake_share,
                                     fake_share_instance, None,
                                     fake_share_instance, None,
                                     local, remote)

        args = ((None, local['access'], False),
                (None, remote['access'], False),
                ('fake_access_ref', local['access']),
                ('fake_access_ref', remote['access']))
        migration.ShareMigrationHelper.deny_migration_access.assert_has_calls(
            [mock.call(*a) for a in args])

    def test_copy_share_data_failed(self):
        fake_share = db_utils.create_share(
            id='fakeid', status=constants.STATUS_AVAILABLE, host='fake_host')
        fake_share_instance = {'id': 'fake_id', 'host': 'fake_host'}
        share_driver = self._setup_mocks_copy_share_data()
        remote = {'access': {'access_to': '192.168.0.1'},
                  'mount': 'fake_mount',
                  'umount': 'fake_umount'}
        local = {'access': {'access_to': '192.168.1.1'},
                 'mount': 'fake_mount',
                 'umount': 'fake_umount'}
        helper = migration.ShareMigrationHelper(None, None, None, None, None)

        driver.CONF.set_default('migration_tmp_location', '/fake/path')
        driver.CONF.set_default('migration_ignore_files', None)

        self.mock_object(migration.ShareMigrationHelper,
                         'deny_migration_access')
        self.mock_object(migration.ShareMigrationHelper,
                         'allow_migration_access',
                         mock.Mock(return_value='fake_access_ref'))
        self.mock_object(utils, 'execute')
        self.mock_object(share_utils.Copy, 'get_progress', mock.Mock(
            return_value=None))
        self.assertRaises(exception.ShareMigrationFailed,
                          share_driver.copy_share_data, 'ctx', helper,
                          fake_share, fake_share_instance, None,
                          fake_share_instance, None, local, remote)

        args = ((None, local['access'], False),
                (None, remote['access'], False))
        migration.ShareMigrationHelper.deny_migration_access.assert_has_calls(
            [mock.call(*a) for a in args])

    def test_copy_share_data_local_access_exception(self):
        fake_share = db_utils.create_share(
            id='fakeid', status=constants.STATUS_AVAILABLE, host='fake_host')
        fake_share_instance = {'id': 'fake_id', 'host': 'fake_host'}
        share_driver = self._setup_mocks_copy_share_data()
        remote = {'access': {'access_to': '192.168.0.1'},
                  'mount': 'fake_mount',
                  'umount': 'fake_umount'}
        local = {'access': {'access_to': '192.168.1.1'},
                 'mount': 'fake_mount',
                 'umount': 'fake_umount'}
        helper = migration.ShareMigrationHelper(None, None, None, None, None)

        driver.CONF.set_default('migration_tmp_location', '/fake/path')
        driver.CONF.set_default('migration_ignore_files', None)

        self.mock_object(migration.ShareMigrationHelper,
                         'deny_migration_access')
        self.mock_object(
            migration.ShareMigrationHelper,
            'allow_migration_access',
            mock.Mock(side_effect=[
                exception.ShareMigrationFailed(reason='fake')]))
        self.assertRaises(exception.ShareMigrationFailed,
                          share_driver.copy_share_data, 'ctx', helper,
                          fake_share, fake_share_instance, None,
                          fake_share_instance, None, local, remote)

        args = ((None, local['access'], False),
                (None, remote['access'], False))
        migration.ShareMigrationHelper.deny_migration_access.assert_has_calls(
            [mock.call(*a) for a in args])

    def test_copy_share_data_remote_access_exception(self):
        fake_share = db_utils.create_share(
            id='fakeid', status=constants.STATUS_AVAILABLE, host='fake_host')
        fake_share_instance = {'id': 'fake_id', 'host': 'fake_host'}
        share_driver = self._setup_mocks_copy_share_data()
        remote = {'access': {'access_to': '192.168.0.1'},
                  'mount': 'fake_mount',
                  'umount': 'fake_umount'}
        local = {'access': {'access_to': '192.168.1.1'},
                 'mount': 'fake_mount',
                 'umount': 'fake_umount'}
        helper = migration.ShareMigrationHelper(None, None, None, None, None)

        driver.CONF.set_default('migration_tmp_location', '/fake/path')
        driver.CONF.set_default('migration_ignore_files', None)

        self.mock_object(migration.ShareMigrationHelper,
                         'deny_migration_access')
        self.mock_object(
            migration.ShareMigrationHelper,
            'allow_migration_access',
            mock.Mock(side_effect=[None,
                                   exception.ShareMigrationFailed(
                                       reason='fake')]))
        self.mock_object(migration.ShareMigrationHelper,
                         'cleanup_migration_access')
        self.assertRaises(exception.ShareMigrationFailed,
                          share_driver.copy_share_data, 'ctx', helper,
                          fake_share, fake_share_instance, None,
                          fake_share_instance, None, local, remote)

        args = ((None, local['access'], False),
                (None, remote['access'], False))
        migration.ShareMigrationHelper.deny_migration_access.assert_has_calls(
            [mock.call(*a) for a in args])

    def test_copy_share_data_mount_for_migration_exception(self):
        fake_share = db_utils.create_share(
            id='fakeid', status=constants.STATUS_AVAILABLE, host='fake_host')
        fake_share_instance = {'id': 'fake_id', 'host': 'fake_host'}
        share_driver = self._setup_mocks_copy_share_data()
        remote = {'access': {'access_to': '192.168.0.1'},
                  'mount': 'fake_mount',
                  'umount': 'fake_umount'}
        local = {'access': {'access_to': '192.168.1.1'},
                 'mount': 'fake_mount',
                 'umount': 'fake_umount'}
        helper = migration.ShareMigrationHelper(None, None, None, None, None)

        msg = ('Failed to mount temporary folder for migration of share '
               'instance fake_id to fake_id')

        driver.CONF.set_default('migration_tmp_location', '/fake/path')

        self.mock_object(migration.ShareMigrationHelper,
                         'deny_migration_access')
        self.mock_object(migration.ShareMigrationHelper,
                         'allow_migration_access',
                         mock.Mock(return_value='fake_access_ref'))
        self.mock_object(migration.ShareMigrationHelper,
                         'cleanup_migration_access')
        self.mock_object(migration.ShareMigrationHelper,
                         'cleanup_temp_folder')
        self.mock_object(utils, 'execute', mock.Mock(
            side_effect=[None, None, exception.ShareMigrationFailed(msg)]))

        self.assertRaises(exception.ShareMigrationFailed,
                          share_driver.copy_share_data,
                          'ctx', helper, fake_share,
                          fake_share_instance, None,
                          fake_share_instance, None,
                          local, remote)
        args = ((None, local['access'], False),
                (None, remote['access'], False))
        migration.ShareMigrationHelper.deny_migration_access.assert_has_calls(
            [mock.call(*a) for a in args])

    def test_copy_share_data_mount_for_migration_exception2(self):
        fake_share = db_utils.create_share(
            id='fakeid', status=constants.STATUS_AVAILABLE, host='fake_host')
        fake_share_instance = {'id': 'fake_id', 'host': 'fake_host'}
        share_driver = self._setup_mocks_copy_share_data()
        remote = {'access': {'access_to': '192.168.0.1'},
                  'mount': 'fake_mount',
                  'umount': 'fake_umount'}
        local = {'access': {'access_to': '192.168.1.1'},
                 'mount': 'fake_mount',
                 'umount': 'fake_umount'}
        helper = migration.ShareMigrationHelper(None, None, None, None, None)

        msg = ('Failed to mount temporary folder for migration of share '
               'instance fake_id to fake_id')

        driver.CONF.set_default('migration_tmp_location', '/fake/path')

        self.mock_object(migration.ShareMigrationHelper,
                         'deny_migration_access')
        self.mock_object(migration.ShareMigrationHelper,
                         'allow_migration_access',
                         mock.Mock(return_value='fake_access_ref'))
        self.mock_object(migration.ShareMigrationHelper,
                         'cleanup_migration_access')
        self.mock_object(migration.ShareMigrationHelper,
                         'cleanup_temp_folder')
        self.mock_object(migration.ShareMigrationHelper,
                         'cleanup_unmount_temp_folder')
        self.mock_object(utils, 'execute', mock.Mock(
            side_effect=[None, None, None,
                         exception.ShareMigrationFailed(msg)]))

        self.assertRaises(exception.ShareMigrationFailed,
                          share_driver.copy_share_data,
                          'ctx', helper, fake_share,
                          fake_share_instance, None,
                          fake_share_instance, None,
                          local, remote)
        args = ((None, local['access'], False),
                (None, remote['access'], False))
        migration.ShareMigrationHelper.deny_migration_access.assert_has_calls(
            [mock.call(*a) for a in args])

    def test_copy_share_data_access_rule_invalid(self):

        fake_share = db_utils.create_share(
            id='fakeid', status=constants.STATUS_AVAILABLE, host='fake_host')

        share_driver = self._setup_mocks_copy_share_data()
        remote = {'access': {'access_to': None},
                  'mount': 'fake_mount',
                  'umount': 'fake_umount'}
        local = {'access': {'access_to': '192.168.1.1'},
                 'mount': 'fake_mount',
                 'umount': 'fake_umount'}

        driver.CONF.set_default('migration_tmp_location', '/fake/path')

        self.assertRaises(exception.ShareMigrationFailed,
                          share_driver.copy_share_data, 'ctx', None,
                          fake_share, None, None, None, None, local, remote)
