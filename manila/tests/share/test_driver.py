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
from mock import PropertyMock

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
    _SNAPSHOT_METHOD_NAMES = ["create_snapshot", "delete_snapshot"]

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
                                  driver_handles_share_servers,
                                  admin_network_config_group=None):
        self.mock_object(network, 'API')
        config = mock.Mock()
        config.append_config_values = mock.Mock()
        config.config_group = 'fake_config_group'
        config.network_config_group = network_config_group
        if admin_network_config_group:
            config.admin_network_config_group = admin_network_config_group
        config.safe_get = mock.Mock(return_value=driver_handles_share_servers)

        share_driver = driver.ShareDriver([True, False], configuration=config)

        self.assertTrue(hasattr(share_driver, 'configuration'))
        config.append_config_values.assert_called_once_with(driver.share_opts)
        if driver_handles_share_servers:
            calls = []
            if network_config_group:
                calls.append(mock.call(
                    config_group_name=config.network_config_group))
            else:
                calls.append(mock.call(
                    config_group_name=config.config_group))
            if admin_network_config_group:
                calls.append(mock.call(
                    config_group_name=config.admin_network_config_group,
                    label='admin'))
            network.API.assert_has_calls(calls)
            self.assertTrue(hasattr(share_driver, 'network_api'))
            self.assertTrue(hasattr(share_driver, 'admin_network_api'))
            self.assertIsNotNone(share_driver.network_api)
            self.assertIsNotNone(share_driver.admin_network_api)
        else:
            self.assertFalse(hasattr(share_driver, 'network_api'))
            self.assertTrue(hasattr(share_driver, 'admin_network_api'))
            self.assertIsNone(share_driver.admin_network_api)
            self.assertFalse(network.API.called)
        return share_driver

    def test_instantiate_share_driver(self):
        self._instantiate_share_driver(None, True)

    def test_instantiate_share_driver_another_config_group(self):
        self._instantiate_share_driver("fake_network_config_group", True)

    def test_instantiate_share_driver_with_admin_network(self):
        self._instantiate_share_driver(
            "fake_network_config_group", True,
            "fake_admin_network_config_group")

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
            'snapshot_support', 'mount_snapshot_support',
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

    def _assert_is_callable(self, obj, attr):
        self.assertTrue(callable(getattr(obj, attr)))

    @ddt.data('manage_existing',
              'unmanage')
    def test_drivers_methods_needed_by_manage_functionality(self, method):
        share_driver = self._instantiate_share_driver(None, False)

        self._assert_is_callable(share_driver, method)

    @ddt.data('manage_existing_snapshot',
              'unmanage_snapshot')
    def test_drivers_methods_needed_by_manage_snapshot_functionality(
            self, method):
        share_driver = self._instantiate_share_driver(None, False)

        self._assert_is_callable(share_driver, method)

    @ddt.data('revert_to_snapshot',
              'revert_to_replicated_snapshot')
    def test_drivers_methods_needed_by_share_revert_to_snapshot_functionality(
            self, method):
        share_driver = self._instantiate_share_driver(None, False)

        self._assert_is_callable(share_driver, method)

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
        }
        child_class_instance = type(
            "NotRedefined", (driver.ShareDriver, ), child_methods)(True)
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats()

        self.assertTrue(child_class_instance._stats["snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    @ddt.data(
        ([], [], False),
        (_SNAPSHOT_METHOD_NAMES, [], True),
        (_SNAPSHOT_METHOD_NAMES, _SNAPSHOT_METHOD_NAMES, True),
        (_SNAPSHOT_METHOD_NAMES[0:1], _SNAPSHOT_METHOD_NAMES[1:], True),
        ([], _SNAPSHOT_METHOD_NAMES, True),
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
        ("create_snapshot", "delete_snapshotFOO"),
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

        self.assertFalse(child_class_instance._stats["snapshot_support"])
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

    def test_create_share_from_snapshot_support_exists(self):
        driver.CONF.set_default('driver_handles_share_servers', True)
        fake_method = lambda *args, **kwargs: None
        child_methods = {
            "create_share_from_snapshot": fake_method,
            "create_snapshot": fake_method,
            "delete_snapshot": fake_method,
        }
        child_class_instance = type(
            "NotRedefined", (driver.ShareDriver, ), child_methods)(True)
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats()

        self.assertTrue(
            child_class_instance._stats["create_share_from_snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    @ddt.data(
        (),
        ("create_snapshot"),
        ("create_share_from_snapshotFOO"),
    )
    def test_create_share_from_snapshot_support_absent(self, methods):
        driver.CONF.set_default('driver_handles_share_servers', True)
        fake_method = lambda *args, **kwargs: None
        child_methods = {}
        for method in methods:
            child_methods[method] = fake_method
        child_class_instance = type(
            "NotRedefined", (driver.ShareDriver, ), child_methods)(True)
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats()

        self.assertFalse(
            child_class_instance._stats["create_share_from_snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    @ddt.data(True, False)
    def test_create_share_from_snapshot_not_exists_and_set_explicitly(
            self, creating_shares_from_snapshot_is_supported):
        driver.CONF.set_default('driver_handles_share_servers', True)
        child_class_instance = type(
            "NotRedefined", (driver.ShareDriver, ), {})(True)
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats({
            "create_share_from_snapshot_support":
                creating_shares_from_snapshot_is_supported,
        })

        self.assertEqual(
            creating_shares_from_snapshot_is_supported,
            child_class_instance._stats["create_share_from_snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    @ddt.data(True, False)
    def test_create_share_from_snapshot_exists_and_set_explicitly(
            self, create_share_from_snapshot_supported):
        driver.CONF.set_default('driver_handles_share_servers', True)
        fake_method = lambda *args, **kwargs: None
        child_methods = {"create_share_from_snapshot": fake_method}
        child_class_instance = type(
            "NotRedefined", (driver.ShareDriver, ), child_methods)(True)
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats({
            "create_share_from_snapshot_support":
                create_share_from_snapshot_supported,
        })

        self.assertEqual(
            create_share_from_snapshot_supported,
            child_class_instance._stats["create_share_from_snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    def test_get_periodic_hook_data(self):
        share_driver = self._instantiate_share_driver(None, False)
        share_instances = ["list", "of", "share", "instances"]

        result = share_driver.get_periodic_hook_data(
            "fake_context", share_instances)

        self.assertEqual(share_instances, result)

    def test_get_admin_network_allocations_number(self):
        share_driver = self._instantiate_share_driver(None, True)

        self.assertEqual(
            0, share_driver.get_admin_network_allocations_number())

    def test_allocate_admin_network_count_None(self):
        share_driver = self._instantiate_share_driver(None, True)
        ctxt = 'fake_context'
        share_server = 'fake_share_server'
        mock_get_admin_network_allocations_number = self.mock_object(
            share_driver,
            'get_admin_network_allocations_number',
            mock.Mock(return_value=0))
        self.mock_object(
            share_driver.admin_network_api,
            'allocate_network',
            mock.Mock(side_effect=Exception('ShouldNotBeRaised')))

        share_driver.allocate_admin_network(ctxt, share_server)

        mock_get_admin_network_allocations_number.assert_called_once_with()
        self.assertFalse(
            share_driver.admin_network_api.allocate_network.called)

    def test_allocate_admin_network_count_0(self):
        share_driver = self._instantiate_share_driver(None, True)
        ctxt = 'fake_context'
        share_server = 'fake_share_server'
        self.mock_object(
            share_driver,
            'get_admin_network_allocations_number',
            mock.Mock(return_value=0))
        self.mock_object(
            share_driver.admin_network_api,
            'allocate_network',
            mock.Mock(side_effect=Exception('ShouldNotBeRaised')))

        share_driver.allocate_admin_network(ctxt, share_server, count=0)

        self.assertFalse(
            share_driver.get_admin_network_allocations_number.called)
        self.assertFalse(
            share_driver.admin_network_api.allocate_network.called)

    def test_allocate_admin_network_count_1_api_initialized(self):
        share_driver = self._instantiate_share_driver(None, True)
        ctxt = 'fake_context'
        share_server = 'fake_share_server'
        mock_get_admin_network_allocations_number = self.mock_object(
            share_driver,
            'get_admin_network_allocations_number',
            mock.Mock(return_value=1))
        self.mock_object(
            share_driver.admin_network_api,
            'allocate_network',
            mock.Mock())

        share_driver.allocate_admin_network(ctxt, share_server)

        mock_get_admin_network_allocations_number.assert_called_once_with()
        (share_driver.admin_network_api.allocate_network.
            assert_called_once_with(ctxt, share_server, count=1))

    def test_allocate_admin_network_count_1_api_not_initialized(self):
        share_driver = self._instantiate_share_driver(None, True, None)
        ctxt = 'fake_context'
        share_server = 'fake_share_server'
        share_driver._admin_network_api = None
        mock_get_admin_network_allocations_number = self.mock_object(
            share_driver,
            'get_admin_network_allocations_number',
            mock.Mock(return_value=1))

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            share_driver.allocate_admin_network,
            ctxt, share_server,
        )
        mock_get_admin_network_allocations_number.assert_called_once_with()

    def test_migration_start(self):

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)

        self.assertRaises(NotImplementedError, share_driver.migration_start,
                          None, None, None, None, None, None, None)

    def test_migration_continue(self):

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)

        self.assertRaises(NotImplementedError, share_driver.migration_continue,
                          None, None, None, None, None, None, None)

    def test_migration_complete(self):

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)

        self.assertRaises(NotImplementedError, share_driver.migration_complete,
                          None, None, None, None, None, None, None)

    def test_migration_cancel(self):

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)

        self.assertRaises(NotImplementedError, share_driver.migration_cancel,
                          None, None, None, None, None, None, None)

    def test_migration_get_progress(self):

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)

        self.assertRaises(NotImplementedError,
                          share_driver.migration_get_progress,
                          None, None, None, None, None, None, None)

    @ddt.data(True, False)
    def test_connection_get_info(self, admin):

        expected = {
            'mount': 'mount -vt nfs %(options)s /fake/fake_id %(path)s',
            'unmount': 'umount -v %(path)s',
            'access_mapping': {
                'ip': ['nfs']
            }
        }

        fake_share = {
            'id': 'fake_id',
            'share_proto': 'nfs',
            'export_locations': [{
                'path': '/fake/fake_id',
                'is_admin_only': admin
            }]
        }

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)
        share_driver.configuration = configuration.Configuration(None)

        connection_info = share_driver.connection_get_info(
            None, fake_share, "fake_server")

        self.assertEqual(expected, connection_info)

    def test_migration_check_compatibility(self):

        driver.CONF.set_default('driver_handles_share_servers', False)
        share_driver = driver.ShareDriver(False)
        share_driver.configuration = configuration.Configuration(None)
        expected = {
            'compatible': False,
            'writable': False,
            'preserve_metadata': False,
            'nondisruptive': False,
            'preserve_snapshots': False,
        }

        result = share_driver.migration_check_compatibility(
            None, None, None, None, None)

        self.assertEqual(expected, result)

    def test_update_access(self):
        share_driver = driver.ShareDriver(True, configuration=None)
        self.assertRaises(
            NotImplementedError,
            share_driver.update_access,
            'ctx',
            'fake_share',
            'fake_access_rules',
            'fake_add_rules',
            'fake_delete_rules'
        )

    def test_create_replica(self):
        share_driver = self._instantiate_share_driver(None, True)
        self.assertRaises(NotImplementedError,
                          share_driver.create_replica,
                          'fake_context', ['r1', 'r2'],
                          'fake_new_replica', [], [])

    def test_delete_replica(self):
        share_driver = self._instantiate_share_driver(None, True)
        self.assertRaises(NotImplementedError,
                          share_driver.delete_replica,
                          'fake_context', ['r1', 'r2'],
                          'fake_replica', [])

    def test_promote_replica(self):
        share_driver = self._instantiate_share_driver(None, True)
        self.assertRaises(NotImplementedError,
                          share_driver.promote_replica,
                          'fake_context', [], 'fake_replica', [])

    def test_update_replica_state(self):
        share_driver = self._instantiate_share_driver(None, True)
        self.assertRaises(NotImplementedError,
                          share_driver.update_replica_state,
                          'fake_context', ['r1', 'r2'], 'fake_replica', [], [])

    def test_create_replicated_snapshot(self):
        share_driver = self._instantiate_share_driver(None, False)
        self.assertRaises(NotImplementedError,
                          share_driver.create_replicated_snapshot,
                          'fake_context', ['r1', 'r2'], ['s1', 's2'])

    def test_delete_replicated_snapshot(self):
        share_driver = self._instantiate_share_driver(None, False)
        self.assertRaises(NotImplementedError,
                          share_driver.delete_replicated_snapshot,
                          'fake_context', ['r1', 'r2'], ['s1', 's2'])

    def test_update_replicated_snapshot(self):
        share_driver = self._instantiate_share_driver(None, False)
        self.assertRaises(NotImplementedError,
                          share_driver.update_replicated_snapshot,
                          'fake_context', ['r1', 'r2'], 'r1',
                          ['s1', 's2'], 's1')

    @ddt.data(True, False)
    def test_share_group_snapshot_support_exists_and_equals_snapshot_support(
            self, snapshots_are_supported):
        driver.CONF.set_default('driver_handles_share_servers', True)
        child_class_instance = driver.ShareDriver(True)
        child_class_instance._snapshots_are_supported = snapshots_are_supported
        self.mock_object(child_class_instance, "configuration")

        child_class_instance._update_share_stats()

        self.assertEqual(
            snapshots_are_supported,
            child_class_instance._stats["snapshot_support"])
        self.assertTrue(child_class_instance.configuration.safe_get.called)

    def test_create_share_group_from_share_group_snapshot(self):
        share_driver = self._instantiate_share_driver(None, False)
        fake_shares = [
            {'id': 'fake_share_%d' % i,
             'source_share_group_snapshot_member_id': 'fake_member_%d' % i}
            for i in (1, 2)]
        fake_share_group_dict = {
            'source_share_group_snapshot_id': 'some_fake_uuid_abc',
            'shares': fake_shares,
            'id': 'some_fake_uuid_def',
        }
        fake_share_group_snapshot_dict = {
            'share_group_snapshot_members': [
                {'id': 'fake_member_1'}, {'id': 'fake_member_2'}],
            'id': 'fake_share_group_snapshot_id',
        }
        mock_create = self.mock_object(
            share_driver, 'create_share_from_snapshot',
            mock.Mock(side_effect=['fake_export1', 'fake_export2']))
        expected_share_updates = [
            {
                'id': 'fake_share_1',
                'export_locations': 'fake_export1',
            },
            {
                'id': 'fake_share_2',
                'export_locations': 'fake_export2',
            },
        ]

        share_group_update, share_update = (
            share_driver.create_share_group_from_share_group_snapshot(
                'fake_context', fake_share_group_dict,
                fake_share_group_snapshot_dict))

        mock_create.assert_has_calls([
            mock.call(
                'fake_context',
                {'id': 'fake_share_1',
                 'source_share_group_snapshot_member_id': 'fake_member_1'},
                {'id': 'fake_member_1'}),
            mock.call(
                'fake_context',
                {'id': 'fake_share_2',
                 'source_share_group_snapshot_member_id': 'fake_member_2'},
                {'id': 'fake_member_2'})
        ])
        self.assertIsNone(share_group_update)
        self.assertEqual(expected_share_updates, share_update)

    def test_create_share_group_from_share_group_snapshot_dhss(self):
        share_driver = self._instantiate_share_driver(None, True)
        mock_share_server = mock.Mock()
        fake_shares = [
            {'id': 'fake_share_1',
             'source_share_group_snapshot_member_id': 'foo_member_1'},
            {'id': 'fake_share_2',
             'source_share_group_snapshot_member_id': 'foo_member_2'}]
        fake_share_group_dict = {
            'source_share_group_snapshot_id': 'some_fake_uuid',
            'shares': fake_shares,
            'id': 'eda52174-0442-476d-9694-a58327466c14',
        }
        fake_share_group_snapshot_dict = {
            'share_group_snapshot_members': [
                {'id': 'foo_member_1'}, {'id': 'foo_member_2'}],
            'id': 'fake_share_group_snapshot_id'
        }
        mock_create = self.mock_object(
            share_driver, 'create_share_from_snapshot',
            mock.Mock(side_effect=['fake_export1', 'fake_export2']))
        expected_share_updates = [
            {'id': 'fake_share_1', 'export_locations': 'fake_export1'},
            {'id': 'fake_share_2', 'export_locations': 'fake_export2'},
        ]

        share_group_update, share_update = (
            share_driver.create_share_group_from_share_group_snapshot(
                'fake_context',
                fake_share_group_dict,
                fake_share_group_snapshot_dict, share_server=mock_share_server,
            )
        )

        mock_create.assert_has_calls([
            mock.call(
                'fake_context',
                {'id': 'fake_share_%d' % i,
                 'source_share_group_snapshot_member_id': 'foo_member_%d' % i},
                {'id': 'foo_member_%d' % i},
                share_server=mock_share_server)
            for i in (1, 2)
        ])
        self.assertIsNone(share_group_update)
        self.assertEqual(expected_share_updates, share_update)

    def test_create_share_group_from_sg_snapshot_with_no_members(self):
        share_driver = self._instantiate_share_driver(None, False)
        fake_share_group_dict = {}
        fake_share_group_snapshot_dict = {'share_group_snapshot_members': []}

        share_group_update, share_update = (
            share_driver.create_share_group_from_share_group_snapshot(
                'fake_context', fake_share_group_dict,
                fake_share_group_snapshot_dict))

        self.assertIsNone(share_group_update)
        self.assertIsNone(share_update)

    def test_create_share_group_snapshot(self):
        fake_snap_member_1 = {
            'id': '6813e06b-a8f5-4784-b17d-f3e91afa370e',
            'share_id': 'a3ebdba5-b4e1-46c8-a0ea-a9ac8daf5296',
            'share_group_snapshot_id': 'fake_share_group_snapshot_id',
            'share_instance_id': 'fake_share_instance_id_1',
            'provider_location': 'should_not_be_used_1',
            'share': {
                'id': '420f978b-dbf6-4b3c-92fe-f5b17a0bb5e2',
                'size': 3,
                'share_proto': 'fake_share_proto',
            },
        }
        fake_snap_member_2 = {
            'id': '1e010dfe-545b-432d-ab95-4ef03cd82f89',
            'share_id': 'a3ebdba5-b4e1-46c8-a0ea-a9ac8daf5296',
            'share_group_snapshot_id': 'fake_share_group_snapshot_id',
            'share_instance_id': 'fake_share_instance_id_2',
            'provider_location': 'should_not_be_used_2',
            'share': {
                'id': '420f978b-dbf6-4b3c-92fe-f5b17a0bb5e2',
                'size': '2',
                'share_proto': 'fake_share_proto',
            },
        }
        fake_snap_dict = {
            'status': 'available',
            'project_id': '13c0be6290934bd98596cfa004650049',
            'user_id': 'a0314a441ca842019b0952224aa39192',
            'description': None,
            'deleted': '0',
            'share_group_id': '4b04fdc3-00b9-4909-ba1a-06e9b3f88b67',
            'share_group_snapshot_members': [
                fake_snap_member_1, fake_snap_member_2],
            'deleted_at': None,
            'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
            'name': None
        }
        share_driver = self._instantiate_share_driver(None, False)
        share_driver._stats['snapshot_support'] = True
        mock_create_snap = self.mock_object(
            share_driver, 'create_snapshot',
            mock.Mock(side_effect=lambda *args, **kwargs: {
                'foo_k': 'foo_v', 'bar_k': 'bar_v_%s' % args[1]['id']}))

        share_group_snapshot_update, member_update_list = (
            share_driver.create_share_group_snapshot(
                'fake_context', fake_snap_dict))

        mock_create_snap.assert_has_calls([
            mock.call(
                'fake_context',
                {'snapshot_id': member['share_group_snapshot_id'],
                 'share_id': member['share_id'],
                 'share_instance_id': member['share']['id'],
                 'id': member['id'],
                 'share': member['share'],
                 'size': member['share']['size'],
                 'share_size': member['share']['size'],
                 'share_proto': member['share']['share_proto'],
                 'provider_location': None},
                share_server=None)
            for member in (fake_snap_member_1, fake_snap_member_2)
        ])
        self.assertIsNone(share_group_snapshot_update)
        self.assertEqual(
            [{'id': member['id'], 'foo_k': 'foo_v',
              'bar_k': 'bar_v_%s' % member['id']}
             for member in (fake_snap_member_1, fake_snap_member_2)],
            member_update_list,
        )

    def test_create_share_group_snapshot_failed_snapshot(self):
        fake_snap_member_1 = {
            'id': '6813e06b-a8f5-4784-b17d-f3e91afa370e',
            'share_id': 'a3ebdba5-b4e1-46c8-a0ea-a9ac8daf5296',
            'share_group_snapshot_id': 'fake_share_group_snapshot_id',
            'share_instance_id': 'fake_share_instance_id_1',
            'provider_location': 'should_not_be_used_1',
            'share': {
                'id': '420f978b-dbf6-4b3c-92fe-f5b17a0bb5e2',
                'size': 3,
                'share_proto': 'fake_share_proto',
            },
        }
        fake_snap_member_2 = {
            'id': '1e010dfe-545b-432d-ab95-4ef03cd82f89',
            'share_id': 'a3ebdba5-b4e1-46c8-a0ea-a9ac8daf5296',
            'share_group_snapshot_id': 'fake_share_group_snapshot_id',
            'share_instance_id': 'fake_share_instance_id_2',
            'provider_location': 'should_not_be_used_2',
            'share': {
                'id': '420f978b-dbf6-4b3c-92fe-f5b17a0bb5e2',
                'size': '2',
                'share_proto': 'fake_share_proto',
            },
        }
        fake_snap_dict = {
            'status': 'available',
            'project_id': '13c0be6290934bd98596cfa004650049',
            'user_id': 'a0314a441ca842019b0952224aa39192',
            'description': None,
            'deleted': '0',
            'share_group_id': '4b04fdc3-00b9-4909-ba1a-06e9b3f88b67',
            'share_group_snapshot_members': [
                fake_snap_member_1, fake_snap_member_2],
            'deleted_at': None,
            'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
            'name': None
        }
        expected_exception = exception.ManilaException

        share_driver = self._instantiate_share_driver(None, False)
        share_driver._stats['snapshot_support'] = True
        mock_create_snap = self.mock_object(
            share_driver, 'create_snapshot',
            mock.Mock(side_effect=[None, expected_exception]))
        mock_delete_snap = self.mock_object(share_driver, 'delete_snapshot')

        self.assertRaises(
            expected_exception,
            share_driver.create_share_group_snapshot,
            'fake_context', fake_snap_dict)

        fake_snap_member_1_expected = {
            'snapshot_id': fake_snap_member_1['share_group_snapshot_id'],
            'share_id': fake_snap_member_1['share_id'],
            'share_instance_id': fake_snap_member_1['share']['id'],
            'id': fake_snap_member_1['id'],
            'share': fake_snap_member_1['share'],
            'size': fake_snap_member_1['share']['size'],
            'share_size': fake_snap_member_1['share']['size'],
            'share_proto': fake_snap_member_1['share']['share_proto'],
            'provider_location': None,
        }
        mock_create_snap.assert_has_calls([
            mock.call(
                'fake_context',
                {'snapshot_id': member['share_group_snapshot_id'],
                 'share_id': member['share_id'],
                 'share_instance_id': member['share']['id'],
                 'id': member['id'],
                 'share': member['share'],
                 'size': member['share']['size'],
                 'share_size': member['share']['size'],
                 'share_proto': member['share']['share_proto'],
                 'provider_location': None},
                share_server=None)
            for member in (fake_snap_member_1, fake_snap_member_2)
        ])
        mock_delete_snap.assert_called_with(
            'fake_context', fake_snap_member_1_expected, share_server=None)

    def test_create_share_group_snapshot_no_support(self):
        fake_snap_dict = {
            'status': 'available',
            'project_id': '13c0be6290934bd98596cfa004650049',
            'user_id': 'a0314a441ca842019b0952224aa39192',
            'description': None,
            'deleted': '0',
            'share_group_id': '4b04fdc3-00b9-4909-ba1a-06e9b3f88b67',
            'share_group_snapshot_members': [
                {
                    'status': 'available',
                    'share_type_id': '1a9ed31e-ee70-483d-93ba-89690e028d7f',
                    'user_id': 'a0314a441ca842019b0952224aa39192',
                    'deleted': 'False',
                    'share_proto': 'NFS',
                    'project_id': '13c0be6290934bd98596cfa004650049',
                    'share_group_snapshot_id':
                        'f6aa3b59-57eb-421e-965c-4e182538e36a',
                    'deleted_at': None,
                    'id': '6813e06b-a8f5-4784-b17d-f3e91afa370e',
                    'size': 1
                },
            ],
            'deleted_at': None,
            'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
            'name': None
        }
        share_driver = self._instantiate_share_driver(None, False)
        share_driver._stats['snapshot_support'] = False

        self.assertRaises(
            exception.ShareGroupSnapshotNotSupported,
            share_driver.create_share_group_snapshot,
            'fake_context', fake_snap_dict)

    def test_create_share_group_snapshot_no_members(self):
        fake_snap_dict = {
            'status': 'available',
            'project_id': '13c0be6290934bd98596cfa004650049',
            'user_id': 'a0314a441ca842019b0952224aa39192',
            'description': None,
            'deleted': '0',
            'share_group_id': '4b04fdc3-00b9-4909-ba1a-06e9b3f88b67',
            'share_group_snapshot_members': [],
            'deleted_at': None,
            'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
            'name': None
        }
        share_driver = self._instantiate_share_driver(None, False)
        share_driver._stats['snapshot_support'] = True

        share_group_snapshot_update, member_update_list = (
            share_driver.create_share_group_snapshot(
                'fake_context', fake_snap_dict))

        self.assertIsNone(share_group_snapshot_update)
        self.assertIsNone(member_update_list)

    def test_delete_share_group_snapshot(self):
        fake_snap_member_1 = {
            'id': '6813e06b-a8f5-4784-b17d-f3e91afa370e',
            'share_id': 'a3ebdba5-b4e1-46c8-a0ea-a9ac8daf5296',
            'share_group_snapshot_id': 'fake_share_group_snapshot_id',
            'share_instance_id': 'fake_share_instance_id_1',
            'provider_location': 'fake_provider_location_2',
            'share': {
                'id': '420f978b-dbf6-4b3c-92fe-f5b17a0bb5e2',
                'size': 3,
                'share_proto': 'fake_share_proto',
            },
        }
        fake_snap_member_2 = {
            'id': '1e010dfe-545b-432d-ab95-4ef03cd82f89',
            'share_id': 'a3ebdba5-b4e1-46c8-a0ea-a9ac8daf5296',
            'share_group_snapshot_id': 'fake_share_group_snapshot_id',
            'share_instance_id': 'fake_share_instance_id_2',
            'provider_location': 'fake_provider_location_2',
            'share': {
                'id': '420f978b-dbf6-4b3c-92fe-f5b17a0bb5e2',
                'size': '2',
                'share_proto': 'fake_share_proto',
            },
        }
        fake_snap_dict = {
            'status': 'available',
            'project_id': '13c0be6290934bd98596cfa004650049',
            'user_id': 'a0314a441ca842019b0952224aa39192',
            'description': None,
            'deleted': '0',
            'share_group_id': '4b04fdc3-00b9-4909-ba1a-06e9b3f88b67',
            'share_group_snapshot_members': [
                fake_snap_member_1, fake_snap_member_2],
            'deleted_at': None,
            'id': 'f6aa3b59-57eb-421e-965c-4e182538e36a',
            'name': None
        }

        share_driver = self._instantiate_share_driver(None, False)
        share_driver._stats['share_group_snapshot_support'] = True
        mock_delete_snap = self.mock_object(share_driver, 'delete_snapshot')

        share_group_snapshot_update, member_update_list = (
            share_driver.delete_share_group_snapshot(
                'fake_context', fake_snap_dict))

        mock_delete_snap.assert_has_calls([
            mock.call(
                'fake_context',
                {'snapshot_id': member['share_group_snapshot_id'],
                 'share_id': member['share_id'],
                 'share_instance_id': member['share']['id'],
                 'id': member['id'],
                 'share': member['share'],
                 'size': member['share']['size'],
                 'share_size': member['share']['size'],
                 'share_proto': member['share']['share_proto'],
                 'provider_location': member['provider_location']},
                share_server=None)
            for member in (fake_snap_member_1, fake_snap_member_2)
        ])
        self.assertIsNone(share_group_snapshot_update)
        self.assertIsNone(member_update_list)

    def test_snapshot_update_access(self):
        share_driver = self._instantiate_share_driver(None, False)
        self.assertRaises(NotImplementedError,
                          share_driver.snapshot_update_access,
                          'fake_context', 'fake_snapshot', ['r1', 'r2'],
                          [], [])

    @ddt.data({'user_networks': set([4]), 'conf': [4],
               'expected': {'ipv4': True, 'ipv6': False}},
              {'user_networks': set([6]), 'conf': [4],
               'expected': {'ipv4': False, 'ipv6': False}},
              {'user_networks': set([4, 6]), 'conf': [4],
               'expected': {'ipv4': True, 'ipv6': False}},
              {'user_networks': set([4]), 'conf': [6],
               'expected': {'ipv4': False, 'ipv6': False}},
              {'user_networks': set([6]), 'conf': [6],
               'expected': {'ipv4': False, 'ipv6': True}},
              {'user_networks': set([4, 6]), 'conf': [6],
               'expected': {'ipv4': False, 'ipv6': True}},
              {'user_networks': set([4]), 'conf': [4, 6],
               'expected': {'ipv4': True, 'ipv6': False}},
              {'user_networks': set([6]), 'conf': [4, 6],
               'expected': {'ipv4': False, 'ipv6': True}},
              {'user_networks': set([4, 6]), 'conf': [4, 6],
               'expected': {'ipv4': True, 'ipv6': True}},
              )
    @ddt.unpack
    def test_add_ip_version_capability_if_dhss_true(self,
                                                    user_networks,
                                                    conf,
                                                    expected):
        share_driver = self._instantiate_share_driver(None, True)
        self.mock_object(share_driver, 'get_configured_ip_versions',
                         mock.Mock(return_value=conf))
        versions = PropertyMock(return_value=user_networks)
        type(share_driver.network_api).enabled_ip_versions = versions
        data = {'share_backend_name': 'fake_backend'}

        result = share_driver.add_ip_version_capability(data)

        self.assertIsNotNone(result['ipv4_support'])
        self.assertEqual(expected['ipv4'], result['ipv4_support'])
        self.assertIsNotNone(result['ipv6_support'])
        self.assertEqual(expected['ipv6'], result['ipv6_support'])

    @ddt.data({'conf': [4],
               'expected': {'ipv4': True, 'ipv6': False}},
              {'conf': [6],
               'expected': {'ipv4': False, 'ipv6': True}},
              {'conf': [4, 6],
               'expected': {'ipv4': True, 'ipv6': True}},
              )
    @ddt.unpack
    def test_add_ip_version_capability_if_dhss_false(self, conf, expected):
        share_driver = self._instantiate_share_driver(None, False)
        self.mock_object(share_driver, 'get_configured_ip_versions',
                         mock.Mock(return_value=conf))
        data = {'share_backend_name': 'fake_backend'}
        result = share_driver.add_ip_version_capability(data)

        self.assertIsNotNone(result['ipv4_support'])
        self.assertEqual(expected['ipv4'], result['ipv4_support'])
        self.assertIsNotNone(result['ipv6_support'])
        self.assertEqual(expected['ipv6'], result['ipv6_support'])
