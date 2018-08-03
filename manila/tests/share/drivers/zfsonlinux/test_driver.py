# Copyright (c) 2016 Mirantis, Inc.
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
import mock

from oslo_config import cfg

from manila import context
from manila import exception
from manila.share.drivers.ganesha import utils as ganesha_utils
from manila.share.drivers.zfsonlinux import driver as zfs_driver
from manila import test

CONF = cfg.CONF


class FakeConfig(object):
    def __init__(self, *args, **kwargs):
        self.driver_handles_share_servers = False
        self.share_driver = 'fake_share_driver_name'
        self.share_backend_name = 'FAKE_BACKEND_NAME'
        self.zfs_share_export_ip = kwargs.get(
            "zfs_share_export_ip", "1.1.1.1")
        self.zfs_service_ip = kwargs.get("zfs_service_ip", "2.2.2.2")
        self.zfs_zpool_list = kwargs.get(
            "zfs_zpool_list", ["foo", "bar/subbar", "quuz"])
        self.zfs_use_ssh = kwargs.get("zfs_use_ssh", False)
        self.zfs_share_export_ip = kwargs.get(
            "zfs_share_export_ip", "240.241.242.243")
        self.zfs_service_ip = kwargs.get("zfs_service_ip", "240.241.242.244")
        self.ssh_conn_timeout = kwargs.get("ssh_conn_timeout", 123)
        self.zfs_ssh_username = kwargs.get(
            "zfs_ssh_username", 'fake_username')
        self.zfs_ssh_user_password = kwargs.get(
            "zfs_ssh_user_password", 'fake_pass')
        self.zfs_ssh_private_key_path = kwargs.get(
            "zfs_ssh_private_key_path", '/fake/path')
        self.zfs_replica_snapshot_prefix = kwargs.get(
            "zfs_replica_snapshot_prefix", "tmp_snapshot_for_replication_")
        self.zfs_migration_snapshot_prefix = kwargs.get(
            "zfs_migration_snapshot_prefix", "tmp_snapshot_for_migration_")
        self.zfs_dataset_creation_options = kwargs.get(
            "zfs_dataset_creation_options", ["fook=foov", "bark=barv"])
        self.network_config_group = kwargs.get(
            "network_config_group", "fake_network_config_group")
        self.admin_network_config_group = kwargs.get(
            "admin_network_config_group", "fake_admin_network_config_group")
        self.config_group = kwargs.get("config_group", "fake_config_group")
        self.reserved_share_percentage = kwargs.get(
            "reserved_share_percentage", 0)
        self.max_over_subscription_ratio = kwargs.get(
            "max_over_subscription_ratio", 15.0)
        self.filter_function = kwargs.get("filter_function", None)
        self.goodness_function = kwargs.get("goodness_function", None)

    def safe_get(self, key):
        return getattr(self, key)

    def append_config_values(self, *args, **kwargs):
        pass


class FakeDriverPrivateStorage(object):

    def __init__(self):
        self.storage = {}

    def update(self, entity_id, data):
        if entity_id not in self.storage:
            self.storage[entity_id] = {}
        self.storage[entity_id].update(data)

    def get(self, entity_id, key):
        return self.storage.get(entity_id, {}).get(key)

    def delete(self, entity_id):
        self.storage.pop(entity_id, None)


class FakeTempDir(object):

    def __enter__(self, *args, **kwargs):
        return '/foo/path'

    def __exit__(*args, **kwargs):
        pass


class GetBackendConfigurationTestCase(test.TestCase):

    def test_get_backend_configuration_success(self):
        backend_name = 'fake_backend_name'
        self.mock_object(
            zfs_driver.CONF, 'list_all_sections',
            mock.Mock(return_value=['fake1', backend_name, 'fake2']))
        mock_config = self.mock_object(
            zfs_driver.configuration, 'Configuration')

        result = zfs_driver.get_backend_configuration(backend_name)

        self.assertEqual(mock_config.return_value, result)
        mock_config.assert_called_once_with(
            zfs_driver.driver.share_opts, config_group=backend_name)
        mock_config.return_value.append_config_values.assert_has_calls([
            mock.call(zfs_driver.zfsonlinux_opts),
            mock.call(zfs_driver.share_manager_opts),
            mock.call(zfs_driver.driver.ssh_opts),
        ])

    def test_get_backend_configuration_error(self):
        backend_name = 'fake_backend_name'
        self.mock_object(
            zfs_driver.CONF, 'list_all_sections',
            mock.Mock(return_value=['fake1', 'fake2']))
        mock_config = self.mock_object(
            zfs_driver.configuration, 'Configuration')

        self.assertRaises(
            exception.BadConfigurationException,
            zfs_driver.get_backend_configuration,
            backend_name,
        )

        self.assertFalse(mock_config.called)
        self.assertFalse(mock_config.return_value.append_config_values.called)


@ddt.ddt
class ZFSonLinuxShareDriverTestCase(test.TestCase):

    def setUp(self):
        self.mock_object(zfs_driver.CONF, '_check_required_opts')
        super(self.__class__, self).setUp()
        self._context = context.get_admin_context()
        self.ssh_executor = self.mock_object(ganesha_utils, 'SSHExecutor')
        self.configuration = FakeConfig()
        self.private_storage = FakeDriverPrivateStorage()
        self.driver = zfs_driver.ZFSonLinuxShareDriver(
            configuration=self.configuration,
            private_storage=self.private_storage)

    def test_init(self):
        self.assertTrue(hasattr(self.driver, 'replica_snapshot_prefix'))
        self.assertEqual(
            self.driver.replica_snapshot_prefix,
            self.configuration.zfs_replica_snapshot_prefix)
        self.assertEqual(
            self.driver.backend_name,
            self.configuration.share_backend_name)
        self.assertEqual(
            self.driver.zpool_list, ['foo', 'bar', 'quuz'])
        self.assertEqual(
            self.driver.dataset_creation_options,
            self.configuration.zfs_dataset_creation_options)
        self.assertEqual(
            self.driver.share_export_ip,
            self.configuration.zfs_share_export_ip)
        self.assertEqual(
            self.driver.service_ip,
            self.configuration.zfs_service_ip)
        self.assertEqual(
            self.driver.private_storage,
            self.private_storage)
        self.assertTrue(hasattr(self.driver, '_helpers'))
        self.assertEqual(self.driver._helpers, {})
        for attr_name in ('execute', 'execute_with_retry', 'parse_zfs_answer',
                          'get_zpool_option', 'get_zfs_option', 'zfs'):
            self.assertTrue(hasattr(self.driver, attr_name))

    def test_init_error_with_duplicated_zpools(self):
        configuration = FakeConfig(
            zfs_zpool_list=['foo', 'bar', 'foo/quuz'])
        self.assertRaises(
            exception.BadConfigurationException,
            zfs_driver.ZFSonLinuxShareDriver,
            configuration=configuration,
            private_storage=self.private_storage
        )

    def test__setup_helpers(self):
        mock_import_class = self.mock_object(
            zfs_driver.importutils, 'import_class')
        self.configuration.zfs_share_helpers = ['FOO=foo.module.WithHelper']

        result = self.driver._setup_helpers()

        self.assertIsNone(result)
        mock_import_class.assert_called_once_with('foo.module.WithHelper')
        mock_import_class.return_value.assert_called_once_with(
            self.configuration)
        self.assertEqual(
            self.driver._helpers,
            {'FOO': mock_import_class.return_value.return_value})

    def test__setup_helpers_error(self):
        self.configuration.zfs_share_helpers = []
        self.assertRaises(
            exception.BadConfigurationException, self.driver._setup_helpers)

    def test__get_share_helper(self):
        self.driver._helpers = {'FOO': 'BAR'}

        result = self.driver._get_share_helper('FOO')

        self.assertEqual('BAR', result)

    @ddt.data({}, {'foo': 'bar'})
    def test__get_share_helper_error(self, share_proto):
        self.assertRaises(
            exception.InvalidShare, self.driver._get_share_helper, 'NFS')

    @ddt.data(True, False)
    def test_do_setup(self, use_ssh):
        self.mock_object(self.driver, '_setup_helpers')
        self.mock_object(self.driver, 'ssh_executor')
        self.configuration.zfs_use_ssh = use_ssh

        self.driver.do_setup('fake_context')

        self.driver._setup_helpers.assert_called_once_with()
        if use_ssh:
            self.assertEqual(4, self.driver.ssh_executor.call_count)
        else:
            self.assertEqual(3, self.driver.ssh_executor.call_count)

    @ddt.data(
        ('foo', '127.0.0.1'),
        ('127.0.0.1', 'foo'),
        ('256.0.0.1', '127.0.0.1'),
        ('::1/128', '127.0.0.1'),
        ('127.0.0.1', '::1/128'),
    )
    @ddt.unpack
    def test_do_setup_error_on_ip_addresses_configuration(
            self, share_export_ip, service_ip):
        self.mock_object(self.driver, '_setup_helpers')
        self.driver.share_export_ip = share_export_ip
        self.driver.service_ip = service_ip

        self.assertRaises(
            exception.BadConfigurationException,
            self.driver.do_setup, 'fake_context')

        self.driver._setup_helpers.assert_called_once_with()

    @ddt.data([], '', None)
    def test_do_setup_no_zpools_configured(self, zpool_list):
        self.mock_object(self.driver, '_setup_helpers')
        self.driver.zpool_list = zpool_list

        self.assertRaises(
            exception.BadConfigurationException,
            self.driver.do_setup, 'fake_context')

        self.driver._setup_helpers.assert_called_once_with()

    @ddt.data(None, '', 'foo_replication_domain')
    def test__get_pools_info(self, replication_domain):
        self.mock_object(
            self.driver, 'get_zpool_option',
            mock.Mock(side_effect=['2G', '3G', '5G', '4G']))
        self.configuration.replication_domain = replication_domain
        self.driver.zpool_list = ['foo', 'bar']
        expected = [
            {'pool_name': 'foo', 'total_capacity_gb': 3.0,
             'free_capacity_gb': 2.0, 'reserved_percentage': 0,
             'compression': [True, False],
             'dedupe': [True, False],
             'thin_provisioning': [True],
             'max_over_subscription_ratio': (
                 self.driver.configuration.max_over_subscription_ratio),
             'qos': [False]},
            {'pool_name': 'bar', 'total_capacity_gb': 4.0,
             'free_capacity_gb': 5.0, 'reserved_percentage': 0,
             'compression': [True, False],
             'dedupe': [True, False],
             'thin_provisioning': [True],
             'max_over_subscription_ratio': (
                 self.driver.configuration.max_over_subscription_ratio),
             'qos': [False]},
        ]
        if replication_domain:
            for pool in expected:
                pool['replication_type'] = 'readable'

        result = self.driver._get_pools_info()

        self.assertEqual(expected, result)
        self.driver.get_zpool_option.assert_has_calls([
            mock.call('foo', 'free'),
            mock.call('foo', 'size'),
            mock.call('bar', 'free'),
            mock.call('bar', 'size'),
        ])

    @ddt.data(
        ([], {'compression': [True, False], 'dedupe': [True, False]}),
        (['dedup=off'], {'compression': [True, False], 'dedupe': [False]}),
        (['dedup=on'], {'compression': [True, False], 'dedupe': [True]}),
        (['compression=on'], {'compression': [True], 'dedupe': [True, False]}),
        (['compression=off'],
         {'compression': [False], 'dedupe': [True, False]}),
        (['compression=fake'],
         {'compression': [True], 'dedupe': [True, False]}),
        (['compression=fake', 'dedup=off'],
         {'compression': [True], 'dedupe': [False]}),
        (['compression=off', 'dedup=on'],
         {'compression': [False], 'dedupe': [True]}),
    )
    @ddt.unpack
    def test__init_common_capabilities(
            self, dataset_creation_options, expected_part):
        self.driver.dataset_creation_options = (
            dataset_creation_options)
        expected = {
            'thin_provisioning': [True],
            'qos': [False],
            'max_over_subscription_ratio': (
                self.driver.configuration.max_over_subscription_ratio),
        }
        expected.update(expected_part)

        self.driver._init_common_capabilities()

        self.assertEqual(expected, self.driver.common_capabilities)

    @ddt.data(None, '', 'foo_replication_domain')
    def test__update_share_stats(self, replication_domain):
        self.configuration.replication_domain = replication_domain
        self.mock_object(self.driver, '_get_pools_info')
        self.assertEqual({}, self.driver._stats)
        expected = {
            'driver_handles_share_servers': False,
            'driver_name': 'ZFS',
            'driver_version': '1.0',
            'free_capacity_gb': 'unknown',
            'pools': self.driver._get_pools_info.return_value,
            'qos': False,
            'replication_domain': replication_domain,
            'reserved_percentage': 0,
            'share_backend_name': self.driver.backend_name,
            'share_group_stats': {'consistent_snapshot_support': None},
            'snapshot_support': True,
            'create_share_from_snapshot_support': True,
            'revert_to_snapshot_support': False,
            'mount_snapshot_support': False,
            'storage_protocol': 'NFS',
            'total_capacity_gb': 'unknown',
            'vendor_name': 'Open Source',
            'filter_function': None,
            'goodness_function': None,
            'ipv4_support': True,
            'ipv6_support': False,
        }
        if replication_domain:
            expected['replication_type'] = 'readable'

        self.driver._update_share_stats()

        self.assertEqual(expected, self.driver._stats)
        self.driver._get_pools_info.assert_called_once_with()

    @ddt.data('', 'foo', 'foo-bar', 'foo_bar', 'foo-bar_quuz')
    def test__get_share_name(self, share_id):
        prefix = 'fake_prefix_'
        self.configuration.zfs_dataset_name_prefix = prefix
        self.configuration.zfs_dataset_snapshot_name_prefix = 'quuz'
        expected = prefix + share_id.replace('-', '_')

        result = self.driver._get_share_name(share_id)

        self.assertEqual(expected, result)

    @ddt.data('', 'foo', 'foo-bar', 'foo_bar', 'foo-bar_quuz')
    def test__get_snapshot_name(self, snapshot_id):
        prefix = 'fake_prefix_'
        self.configuration.zfs_dataset_name_prefix = 'quuz'
        self.configuration.zfs_dataset_snapshot_name_prefix = prefix
        expected = prefix + snapshot_id.replace('-', '_')

        result = self.driver._get_snapshot_name(snapshot_id)

        self.assertEqual(expected, result)

    def test__get_dataset_creation_options_not_set(self):
        self.driver.dataset_creation_options = []
        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={}))
        share = {'size': '5'}

        result = self.driver._get_dataset_creation_options(share=share)

        self.assertIsInstance(result, list)
        self.assertEqual(2, len(result))
        for v in ('quota=5G', 'readonly=off'):
            self.assertIn(v, result)
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    @ddt.data(True, False)
    def test__get_dataset_creation_options(self, is_readonly):
        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={}))
        self.driver.dataset_creation_options = [
            'readonly=quuz', 'sharenfs=foo', 'sharesmb=bar', 'k=v', 'q=w',
        ]
        share = {'size': 5}
        readonly = 'readonly=%s' % ('on' if is_readonly else 'off')
        expected = [readonly, 'k=v', 'q=w', 'quota=5G']

        result = self.driver._get_dataset_creation_options(
            share=share, is_readonly=is_readonly)

        self.assertEqual(sorted(expected), sorted(result))
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    @ddt.data(
        ('<is> True', [True, False], ['dedup=off'], 'dedup=on'),
        ('True', [True, False], ['dedup=off'], 'dedup=on'),
        ('on', [True, False], ['dedup=off'], 'dedup=on'),
        ('yes', [True, False], ['dedup=off'], 'dedup=on'),
        ('1', [True, False], ['dedup=off'], 'dedup=on'),
        ('True', [True], [], 'dedup=on'),
        ('<is> False', [True, False], [], 'dedup=off'),
        ('False', [True, False], [], 'dedup=off'),
        ('False', [False], ['dedup=on'], 'dedup=off'),
        ('off', [False], ['dedup=on'], 'dedup=off'),
        ('no', [False], ['dedup=on'], 'dedup=off'),
        ('0', [False], ['dedup=on'], 'dedup=off'),
    )
    @ddt.unpack
    def test__get_dataset_creation_options_with_updated_dedupe(
            self, dedupe_extra_spec, dedupe_capability, driver_options,
            expected):
        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={'dedupe': dedupe_extra_spec}))
        self.driver.dataset_creation_options = driver_options
        self.driver.common_capabilities['dedupe'] = dedupe_capability
        share = {'size': 5}
        expected_options = ['quota=5G', 'readonly=off']
        expected_options.append(expected)

        result = self.driver._get_dataset_creation_options(share=share)

        self.assertEqual(sorted(expected_options), sorted(result))
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    @ddt.data(
        ('on', [True, False], ['compression=off'], 'compression=on'),
        ('on', [True], [], 'compression=on'),
        ('off', [False], ['compression=on'], 'compression=off'),
        ('off', [True, False], [], 'compression=off'),
        ('foo', [True, False], [], 'compression=foo'),
        ('bar', [True], [], 'compression=bar'),
    )
    @ddt.unpack
    def test__get_dataset_creation_options_with_updated_compression(
            self, extra_spec, capability, driver_options, expected_option):
        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={'zfsonlinux:compression': extra_spec}))
        self.driver.dataset_creation_options = driver_options
        self.driver.common_capabilities['compression'] = capability
        share = {'size': 5}
        expected_options = ['quota=5G', 'readonly=off']
        expected_options.append(expected_option)

        result = self.driver._get_dataset_creation_options(share=share)

        self.assertEqual(sorted(expected_options), sorted(result))
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    @ddt.data(
        ({'dedupe': 'fake'}, {'dedupe': [True, False]}),
        ({'dedupe': 'on'}, {'dedupe': [False]}),
        ({'dedupe': 'off'}, {'dedupe': [True]}),
        ({'zfsonlinux:compression': 'fake'}, {'compression': [False]}),
        ({'zfsonlinux:compression': 'on'}, {'compression': [False]}),
        ({'zfsonlinux:compression': 'off'}, {'compression': [True]}),
    )
    @ddt.unpack
    def test__get_dataset_creation_options_error(
            self, extra_specs, common_capabilities):
        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value=extra_specs))
        share = {'size': 5}
        self.driver.common_capabilities.update(common_capabilities)

        self.assertRaises(
            exception.ZFSonLinuxException,
            self.driver._get_dataset_creation_options,
            share=share
        )

        mock_get_extra_specs_from_share.assert_called_once_with(share)

    @ddt.data('bar/quuz', 'bar/quuz/', 'bar')
    def test__get_dataset_name(self, second_zpool):
        self.configuration.zfs_zpool_list = ['foo', second_zpool]
        prefix = 'fake_prefix_'
        self.configuration.zfs_dataset_name_prefix = prefix
        share = {'id': 'abc-def_ghi', 'host': 'hostname@backend_name#bar'}

        result = self.driver._get_dataset_name(share)

        if second_zpool[-1] == '/':
            second_zpool = second_zpool[0:-1]
        expected = '%s/%sabc_def_ghi' % (second_zpool, prefix)
        self.assertEqual(expected, result)

    def test_create_share(self):
        mock_get_helper = self.mock_object(self.driver, '_get_share_helper')
        self.mock_object(self.driver, 'zfs')
        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={}))
        context = 'fake_context'
        share = {
            'id': 'fake_share_id',
            'host': 'hostname@backend_name#bar',
            'share_proto': 'NFS',
            'size': 4,
        }
        self.configuration.zfs_dataset_name_prefix = 'some_prefix_'
        self.configuration.zfs_ssh_username = 'someuser'
        self.driver.share_export_ip = '1.1.1.1'
        self.driver.service_ip = '2.2.2.2'
        dataset_name = 'bar/subbar/some_prefix_fake_share_id'

        result = self.driver.create_share(context, share, share_server=None)

        self.assertEqual(
            mock_get_helper.return_value.create_exports.return_value,
            result,
        )
        self.assertEqual(
            'share',
            self.driver.private_storage.get(share['id'], 'entity_type'))
        self.assertEqual(
            dataset_name,
            self.driver.private_storage.get(share['id'], 'dataset_name'))
        self.assertEqual(
            'someuser@2.2.2.2',
            self.driver.private_storage.get(share['id'], 'ssh_cmd'))
        self.assertEqual(
            'bar',
            self.driver.private_storage.get(share['id'], 'pool_name'))
        self.driver.zfs.assert_called_once_with(
            'create', '-o', 'quota=4G', '-o', 'fook=foov', '-o', 'bark=barv',
            '-o', 'readonly=off', 'bar/subbar/some_prefix_fake_share_id')
        mock_get_helper.assert_has_calls([
            mock.call('NFS'), mock.call().create_exports(dataset_name)
        ])
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    def test_create_share_with_share_server(self):
        self.assertRaises(
            exception.InvalidInput,
            self.driver.create_share,
            'fake_context', 'fake_share', share_server={'id': 'fake_server'},
        )

    def test_delete_share(self):
        dataset_name = 'bar/subbar/some_prefix_fake_share_id'
        mock_delete = self.mock_object(
            self.driver, '_delete_dataset_or_snapshot_with_retry')
        self.mock_object(self.driver, '_get_share_helper')
        self.mock_object(zfs_driver.LOG, 'warning')
        self.mock_object(
            self.driver, 'zfs', mock.Mock(return_value=('a', 'b')))
        snap_name = '%s@%s' % (
            dataset_name, self.driver.replica_snapshot_prefix)
        self.mock_object(
            self.driver, 'parse_zfs_answer',
            mock.Mock(
                side_effect=[
                    [{'NAME': 'fake_dataset_name'}, {'NAME': dataset_name}],
                    [{'NAME': 'snap_name'},
                     {'NAME': '%s@foo' % dataset_name},
                     {'NAME': snap_name}],
                ]))
        context = 'fake_context'
        share = {
            'id': 'fake_share_id',
            'host': 'hostname@backend_name#bar',
            'share_proto': 'NFS',
            'size': 4,
        }
        self.configuration.zfs_dataset_name_prefix = 'some_prefix_'
        self.configuration.zfs_ssh_username = 'someuser'
        self.driver.share_export_ip = '1.1.1.1'
        self.driver.service_ip = '2.2.2.2'
        self.driver.private_storage.update(
            share['id'],
            {'pool_name': 'bar', 'dataset_name': dataset_name}
        )

        self.driver.delete_share(context, share, share_server=None)

        self.driver.zfs.assert_has_calls([
            mock.call('list', '-r', 'bar'),
            mock.call('list', '-r', '-t', 'snapshot', 'bar'),
        ])
        self.driver._get_share_helper.assert_has_calls([
            mock.call('NFS'), mock.call().remove_exports(dataset_name)])
        self.driver.parse_zfs_answer.assert_has_calls([
            mock.call('a'), mock.call('a')])
        mock_delete.assert_has_calls([
            mock.call(snap_name),
            mock.call(dataset_name),
        ])
        self.assertEqual(0, zfs_driver.LOG.warning.call_count)

    def test_delete_share_absent(self):
        dataset_name = 'bar/subbar/some_prefix_fake_share_id'
        mock_delete = self.mock_object(
            self.driver, '_delete_dataset_or_snapshot_with_retry')
        self.mock_object(self.driver, '_get_share_helper')
        self.mock_object(zfs_driver.LOG, 'warning')
        self.mock_object(
            self.driver, 'zfs', mock.Mock(return_value=('a', 'b')))
        snap_name = '%s@%s' % (
            dataset_name, self.driver.replica_snapshot_prefix)
        self.mock_object(
            self.driver, 'parse_zfs_answer',
            mock.Mock(side_effect=[[], [{'NAME': snap_name}]]))
        context = 'fake_context'
        share = {
            'id': 'fake_share_id',
            'host': 'hostname@backend_name#bar',
            'size': 4,
        }
        self.configuration.zfs_dataset_name_prefix = 'some_prefix_'
        self.configuration.zfs_ssh_username = 'someuser'
        self.driver.share_export_ip = '1.1.1.1'
        self.driver.service_ip = '2.2.2.2'
        self.driver.private_storage.update(share['id'], {'pool_name': 'bar'})

        self.driver.delete_share(context, share, share_server=None)

        self.assertEqual(0, self.driver._get_share_helper.call_count)
        self.assertEqual(0, mock_delete.call_count)
        self.driver.zfs.assert_called_once_with('list', '-r', 'bar')
        self.driver.parse_zfs_answer.assert_called_once_with('a')
        zfs_driver.LOG.warning.assert_called_once_with(
            mock.ANY, {'id': share['id'], 'name': dataset_name})

    def test_delete_share_with_share_server(self):
        self.assertRaises(
            exception.InvalidInput,
            self.driver.delete_share,
            'fake_context', 'fake_share', share_server={'id': 'fake_server'},
        )

    def test_create_snapshot(self):
        self.configuration.zfs_dataset_snapshot_name_prefix = 'prefx_'
        self.mock_object(self.driver, 'zfs')
        snapshot = {
            'id': 'fake_snapshot_instance_id',
            'snapshot_id': 'fake_snapshot_id',
            'host': 'hostname@backend_name#bar',
            'size': 4,
            'share_instance_id': 'fake_share_id'
        }
        snapshot_name = 'foo_data_set_name@prefx_%s' % snapshot['id']
        self.driver.private_storage.update(
            snapshot['share_instance_id'],
            {'dataset_name': 'foo_data_set_name'})

        result = self.driver.create_snapshot('fake_context', snapshot)

        self.driver.zfs.assert_called_once_with(
            'snapshot', snapshot_name)
        self.assertEqual(
            snapshot_name.split('@')[-1],
            self.driver.private_storage.get(
                snapshot['snapshot_id'], 'snapshot_tag'))
        self.assertEqual({"provider_location": snapshot_name}, result)

    def test_delete_snapshot(self):
        snapshot = {
            'id': 'fake_snapshot_instance_id',
            'snapshot_id': 'fake_snapshot_id',
            'host': 'hostname@backend_name#bar',
            'size': 4,
            'share_instance_id': 'fake_share_id',
        }
        dataset_name = 'foo_zpool/bar_dataset_name'
        snap_tag = 'prefix_%s' % snapshot['id']
        snap_name = '%(dataset)s@%(tag)s' % {
            'dataset': dataset_name, 'tag': snap_tag}
        mock_delete = self.mock_object(
            self.driver, '_delete_dataset_or_snapshot_with_retry')
        self.mock_object(zfs_driver.LOG, 'warning')
        self.mock_object(
            self.driver, 'zfs', mock.Mock(return_value=('a', 'b')))
        self.mock_object(
            self.driver, 'parse_zfs_answer',
            mock.Mock(side_effect=[
                [{'NAME': 'some_other_dataset@snapshot_name'},
                 {'NAME': snap_name}],
                []]))
        context = 'fake_context'
        self.driver.private_storage.update(
            snapshot['id'], {'snapshot_name': snap_name})
        self.driver.private_storage.update(
            snapshot['snapshot_id'], {'snapshot_tag': snap_tag})
        self.driver.private_storage.update(
            snapshot['share_instance_id'], {'dataset_name': dataset_name})

        self.assertEqual(
            snap_tag,
            self.driver.private_storage.get(
                snapshot['snapshot_id'], 'snapshot_tag'))

        self.driver.delete_snapshot(context, snapshot, share_server=None)

        self.assertIsNone(
            self.driver.private_storage.get(
                snapshot['snapshot_id'], 'snapshot_tag'))

        self.assertEqual(0, zfs_driver.LOG.warning.call_count)
        self.driver.zfs.assert_called_once_with(
            'list', '-r', '-t', 'snapshot', snap_name)
        self.driver.parse_zfs_answer.assert_called_once_with('a')
        mock_delete.assert_called_once_with(snap_name)

    def test_delete_snapshot_absent(self):
        snapshot = {
            'id': 'fake_snapshot_instance_id',
            'snapshot_id': 'fake_snapshot_id',
            'host': 'hostname@backend_name#bar',
            'size': 4,
            'share_instance_id': 'fake_share_id',
        }
        dataset_name = 'foo_zpool/bar_dataset_name'
        snap_tag = 'prefix_%s' % snapshot['id']
        snap_name = '%(dataset)s@%(tag)s' % {
            'dataset': dataset_name, 'tag': snap_tag}
        mock_delete = self.mock_object(
            self.driver, '_delete_dataset_or_snapshot_with_retry')
        self.mock_object(zfs_driver.LOG, 'warning')
        self.mock_object(
            self.driver, 'zfs', mock.Mock(return_value=('a', 'b')))
        self.mock_object(
            self.driver, 'parse_zfs_answer',
            mock.Mock(side_effect=[[], [{'NAME': snap_name}]]))
        context = 'fake_context'
        self.driver.private_storage.update(
            snapshot['id'], {'snapshot_name': snap_name})
        self.driver.private_storage.update(
            snapshot['snapshot_id'], {'snapshot_tag': snap_tag})
        self.driver.private_storage.update(
            snapshot['share_instance_id'], {'dataset_name': dataset_name})

        self.driver.delete_snapshot(context, snapshot, share_server=None)

        self.assertEqual(0, mock_delete.call_count)
        self.driver.zfs.assert_called_once_with(
            'list', '-r', '-t', 'snapshot', snap_name)
        self.driver.parse_zfs_answer.assert_called_once_with('a')
        zfs_driver.LOG.warning.assert_called_once_with(
            mock.ANY, {'id': snapshot['id'], 'name': snap_name})

    def test_delete_snapshot_with_share_server(self):
        self.assertRaises(
            exception.InvalidInput,
            self.driver.delete_snapshot,
            'fake_context', 'fake_snapshot',
            share_server={'id': 'fake_server'},
        )

    def test_create_share_from_snapshot(self):
        mock_get_helper = self.mock_object(self.driver, '_get_share_helper')
        self.mock_object(self.driver, 'zfs')
        self.mock_object(self.driver, 'execute')
        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={}))
        context = 'fake_context'
        share = {
            'id': 'fake_share_id',
            'host': 'hostname@backend_name#bar',
            'share_proto': 'NFS',
            'size': 4,
        }
        snapshot = {
            'id': 'fake_snapshot_instance_id',
            'snapshot_id': 'fake_snapshot_id',
            'host': 'hostname@backend_name#bar',
            'size': 4,
            'share_instance_id': share['id'],
        }
        dataset_name = 'bar/subbar/some_prefix_%s' % share['id']
        snap_tag = 'prefix_%s' % snapshot['id']
        snap_name = '%(dataset)s@%(tag)s' % {
            'dataset': dataset_name, 'tag': snap_tag}
        self.configuration.zfs_dataset_name_prefix = 'some_prefix_'
        self.configuration.zfs_ssh_username = 'someuser'
        self.driver.share_export_ip = '1.1.1.1'
        self.driver.service_ip = '2.2.2.2'
        self.driver.private_storage.update(
            snapshot['id'], {'snapshot_name': snap_name})
        self.driver.private_storage.update(
            snapshot['snapshot_id'], {'snapshot_tag': snap_tag})
        self.driver.private_storage.update(
            snapshot['share_instance_id'], {'dataset_name': dataset_name})

        result = self.driver.create_share_from_snapshot(
            context, share, snapshot, share_server=None)

        self.assertEqual(
            mock_get_helper.return_value.create_exports.return_value,
            result,
        )
        self.assertEqual(
            'share',
            self.driver.private_storage.get(share['id'], 'entity_type'))
        self.assertEqual(
            dataset_name,
            self.driver.private_storage.get(share['id'], 'dataset_name'))
        self.assertEqual(
            'someuser@2.2.2.2',
            self.driver.private_storage.get(share['id'], 'ssh_cmd'))
        self.assertEqual(
            'bar',
            self.driver.private_storage.get(share['id'], 'pool_name'))
        self.driver.execute.assert_has_calls([
            mock.call(
                'ssh', 'someuser@2.2.2.2',
                'sudo', 'zfs', 'send', '-vD', snap_name, '|',
                'sudo', 'zfs', 'receive', '-v',
                'bar/subbar/some_prefix_fake_share_id'),
            mock.call(
                'sudo', 'zfs', 'destroy',
                'bar/subbar/some_prefix_fake_share_id@%s' % snap_tag),
        ])
        self.driver.zfs.assert_has_calls([
            mock.call('set', opt, 'bar/subbar/some_prefix_fake_share_id')
            for opt in ('quota=4G', 'bark=barv', 'readonly=off', 'fook=foov')
        ], any_order=True)
        mock_get_helper.assert_has_calls([
            mock.call('NFS'), mock.call().create_exports(dataset_name)
        ])
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    def test_create_share_from_snapshot_with_share_server(self):
        self.assertRaises(
            exception.InvalidInput,
            self.driver.create_share_from_snapshot,
            'fake_context', 'fake_share', 'fake_snapshot',
            share_server={'id': 'fake_server'},
        )

    def test_get_pool(self):
        share = {'host': 'hostname@backend_name#bar'}

        result = self.driver.get_pool(share)

        self.assertEqual('bar', result)

    @ddt.data('on', 'off', 'rw=1.1.1.1')
    def test_ensure_share(self, get_zfs_option_answer):
        share = {
            'id': 'fake_share_id',
            'host': 'hostname@backend_name#bar',
            'share_proto': 'NFS',
        }
        dataset_name = 'foo_zpool/foo_fs'
        self.mock_object(
            self.driver, '_get_dataset_name',
            mock.Mock(return_value=dataset_name))
        self.mock_object(
            self.driver, 'get_zfs_option',
            mock.Mock(return_value=get_zfs_option_answer))
        mock_helper = self.mock_object(self.driver, '_get_share_helper')
        self.mock_object(
            self.driver, 'zfs', mock.Mock(return_value=('a', 'b')))
        self.mock_object(
            self.driver, 'parse_zfs_answer',
            mock.Mock(side_effect=[[{'NAME': 'fake1'},
                                    {'NAME': dataset_name},
                                    {'NAME': 'fake2'}]] * 2))

        for s in ('1', '2'):
            self.driver.zfs.reset_mock()
            self.driver.get_zfs_option.reset_mock()
            mock_helper.reset_mock()
            self.driver.parse_zfs_answer.reset_mock()
            self.driver._get_dataset_name.reset_mock()

            self.driver.share_export_ip = '1.1.1.%s' % s
            self.driver.service_ip = '2.2.2.%s' % s
            self.configuration.zfs_ssh_username = 'user%s' % s

            result = self.driver.ensure_share('fake_context', share)

            self.assertEqual(
                'user%(s)s@2.2.2.%(s)s' % {'s': s},
                self.driver.private_storage.get(share['id'], 'ssh_cmd'))
            self.driver.get_zfs_option.assert_called_once_with(
                dataset_name, 'sharenfs')
            mock_helper.assert_called_once_with(
                share['share_proto'])
            mock_helper.return_value.get_exports.assert_called_once_with(
                dataset_name)
            expected_calls = [mock.call('list', '-r', 'bar')]
            if get_zfs_option_answer != 'off':
                expected_calls.append(mock.call('share', dataset_name))
            self.driver.zfs.assert_has_calls(expected_calls)
            self.driver.parse_zfs_answer.assert_called_once_with('a')
            self.driver._get_dataset_name.assert_called_once_with(share)
            self.assertEqual(
                mock_helper.return_value.get_exports.return_value,
                result,
            )

    def test_ensure_share_absent(self):
        share = {'id': 'fake_share_id', 'host': 'hostname@backend_name#bar'}
        dataset_name = 'foo_zpool/foo_fs'
        self.driver.private_storage.update(
            share['id'], {'dataset_name': dataset_name})
        self.mock_object(self.driver, 'get_zfs_option')
        self.mock_object(self.driver, '_get_share_helper')
        self.mock_object(
            self.driver, 'zfs', mock.Mock(return_value=('a', 'b')))
        self.mock_object(
            self.driver, 'parse_zfs_answer',
            mock.Mock(side_effect=[[], [{'NAME': dataset_name}]]))

        self.assertRaises(
            exception.ShareResourceNotFound,
            self.driver.ensure_share,
            'fake_context', share,
        )

        self.assertEqual(0, self.driver.get_zfs_option.call_count)
        self.assertEqual(0, self.driver._get_share_helper.call_count)
        self.driver.zfs.assert_called_once_with('list', '-r', 'bar')
        self.driver.parse_zfs_answer.assert_called_once_with('a')

    def test_ensure_share_with_share_server(self):
        self.assertRaises(
            exception.InvalidInput,
            self.driver.ensure_share,
            'fake_context', 'fake_share', share_server={'id': 'fake_server'},
        )

    def test_get_network_allocations_number(self):
        self.assertEqual(0, self.driver.get_network_allocations_number())

    def test_extend_share(self):
        dataset_name = 'foo_zpool/foo_fs'
        self.mock_object(
            self.driver, '_get_dataset_name',
            mock.Mock(return_value=dataset_name))
        self.mock_object(self.driver, 'zfs')

        self.driver.extend_share('fake_share', 5)

        self.driver._get_dataset_name.assert_called_once_with('fake_share')
        self.driver.zfs.assert_called_once_with(
            'set', 'quota=5G', dataset_name)

    def test_extend_share_with_share_server(self):
        self.assertRaises(
            exception.InvalidInput,
            self.driver.extend_share,
            'fake_context', 'fake_share', 5,
            share_server={'id': 'fake_server'},
        )

    def test_shrink_share(self):
        dataset_name = 'foo_zpool/foo_fs'
        self.mock_object(
            self.driver, '_get_dataset_name',
            mock.Mock(return_value=dataset_name))
        self.mock_object(self.driver, 'zfs')
        self.mock_object(
            self.driver, 'get_zfs_option', mock.Mock(return_value='4G'))
        share = {'id': 'fake_share_id'}

        self.driver.shrink_share(share, 5)

        self.driver._get_dataset_name.assert_called_once_with(share)
        self.driver.get_zfs_option.assert_called_once_with(
            dataset_name, 'used')
        self.driver.zfs.assert_called_once_with(
            'set', 'quota=5G', dataset_name)

    def test_shrink_share_data_loss(self):
        dataset_name = 'foo_zpool/foo_fs'
        self.mock_object(
            self.driver, '_get_dataset_name',
            mock.Mock(return_value=dataset_name))
        self.mock_object(self.driver, 'zfs')
        self.mock_object(
            self.driver, 'get_zfs_option', mock.Mock(return_value='6G'))
        share = {'id': 'fake_share_id'}

        self.assertRaises(
            exception.ShareShrinkingPossibleDataLoss,
            self.driver.shrink_share, share, 5)

        self.driver._get_dataset_name.assert_called_once_with(share)
        self.driver.get_zfs_option.assert_called_once_with(
            dataset_name, 'used')
        self.assertEqual(0, self.driver.zfs.call_count)

    def test_shrink_share_with_share_server(self):
        self.assertRaises(
            exception.InvalidInput,
            self.driver.shrink_share,
            'fake_context', 'fake_share', 5,
            share_server={'id': 'fake_server'},
        )

    def test__get_replication_snapshot_prefix(self):
        replica = {'id': 'foo-_bar-_id'}
        self.driver.replica_snapshot_prefix = 'PrEfIx'

        result = self.driver._get_replication_snapshot_prefix(replica)

        self.assertEqual('PrEfIx_foo__bar__id', result)

    def test__get_replication_snapshot_tag(self):
        replica = {'id': 'foo-_bar-_id'}
        self.driver.replica_snapshot_prefix = 'PrEfIx'
        mock_utcnow = self.mock_object(zfs_driver.timeutils, 'utcnow')

        result = self.driver._get_replication_snapshot_tag(replica)

        self.assertEqual(
            ('PrEfIx_foo__bar__id_time_'
             '%s' % mock_utcnow.return_value.isoformat.return_value),
            result)
        mock_utcnow.assert_called_once_with()
        mock_utcnow.return_value.isoformat.assert_called_once_with()

    def test__get_active_replica(self):
        replica_list = [
            {'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
             'id': '1'},
            {'replica_state': zfs_driver.constants.REPLICA_STATE_ACTIVE,
             'id': '2'},
            {'replica_state': zfs_driver.constants.REPLICA_STATE_OUT_OF_SYNC,
             'id': '3'},
        ]

        result = self.driver._get_active_replica(replica_list)

        self.assertEqual(replica_list[1], result)

    def test__get_active_replica_not_found(self):
        replica_list = [
            {'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
             'id': '1'},
            {'replica_state': zfs_driver.constants.REPLICA_STATE_OUT_OF_SYNC,
             'id': '3'},
        ]

        self.assertRaises(
            exception.ReplicationException,
            self.driver._get_active_replica,
            replica_list,
        )

    def test_update_access(self):
        self.mock_object(self.driver, '_get_dataset_name')
        mock_helper = self.mock_object(self.driver, '_get_share_helper')
        mock_shell_executor = self.mock_object(
            self.driver, '_get_shell_executor_by_host')
        share = {
            'share_proto': 'NFS',
            'host': 'foo_host@bar_backend@quuz_pool',
        }

        result = self.driver.update_access(
            'fake_context', share, [1], [2], [3])

        self.driver._get_dataset_name.assert_called_once_with(share)
        mock_shell_executor.assert_called_once_with(share['host'])
        self.assertEqual(
            mock_helper.return_value.update_access.return_value,
            result,
        )

    def test_update_access_with_share_server(self):
        self.assertRaises(
            exception.InvalidInput,
            self.driver.update_access,
            'fake_context', 'fake_share', [], [], [],
            share_server={'id': 'fake_server'},
        )

    @ddt.data(
        ({}, True),
        ({"size": 5}, True),
        ({"size": 5, "foo": "bar"}, False),
        ({"size": "5", "foo": "bar"}, True),
    )
    @ddt.unpack
    def test_manage_share_success_expected(self, driver_options, mount_exists):
        old_dataset_name = "foopool/path/to/old/dataset/name"
        new_dataset_name = "foopool/path/to/new/dataset/name"
        share = {
            "id": "fake_share_instance_id",
            "share_id": "fake_share_id",
            "export_locations": [{"path": "1.1.1.1:/%s" % old_dataset_name}],
            "host": "foobackend@foohost#foopool",
            "share_proto": "NFS",
        }

        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={}))
        self.mock_object(zfs_driver.time, "sleep")
        mock__get_dataset_name = self.mock_object(
            self.driver, "_get_dataset_name",
            mock.Mock(return_value=new_dataset_name))
        mock_helper = self.mock_object(self.driver, "_get_share_helper")
        mock_zfs = self.mock_object(
            self.driver, "zfs",
            mock.Mock(return_value=("fake_out", "fake_error")))
        mock_zfs_with_retry = self.mock_object(self.driver, "zfs_with_retry")

        mock_execute_side_effects = [
            ("%s " % old_dataset_name, "fake_err")
            if mount_exists else ("foo", "bar")
        ] * 3
        if mount_exists:
            # After three retries, assume the mount goes away
            mock_execute_side_effects.append((("foo", "bar")))
        mock_execute = self.mock_object(
            self.driver, "execute",
            mock.Mock(side_effect=iter(mock_execute_side_effects)))

        mock_parse_zfs_answer = self.mock_object(
            self.driver,
            "parse_zfs_answer",
            mock.Mock(return_value=[
                {"NAME": "some_other_dataset_1"},
                {"NAME": old_dataset_name},
                {"NAME": "some_other_dataset_2"},
            ]))
        mock_get_zfs_option = self.mock_object(
            self.driver, 'get_zfs_option', mock.Mock(return_value="4G"))

        result = self.driver.manage_existing(share, driver_options)

        self.assertTrue(mock_helper.return_value.get_exports.called)
        self.assertTrue(mock_zfs_with_retry.called)
        self.assertEqual(2, len(result))
        self.assertIn("size", result)
        self.assertIn("export_locations", result)
        self.assertEqual(5, result["size"])
        self.assertEqual(
            mock_helper.return_value.get_exports.return_value,
            result["export_locations"])
        mock_execute.assert_called_with("sudo", "mount")
        if mount_exists:
            self.assertEqual(4, mock_execute.call_count)
        else:
            self.assertEqual(1, mock_execute.call_count)
        mock_parse_zfs_answer.assert_called_once_with(mock_zfs.return_value[0])
        if driver_options.get("size"):
            self.assertFalse(mock_get_zfs_option.called)
        else:
            mock_get_zfs_option.assert_called_once_with(
                old_dataset_name, "used")
        mock__get_dataset_name.assert_called_once_with(share)
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    def test_manage_share_wrong_pool(self):
        old_dataset_name = "foopool/path/to/old/dataset/name"
        new_dataset_name = "foopool/path/to/new/dataset/name"
        share = {
            "id": "fake_share_instance_id",
            "share_id": "fake_share_id",
            "export_locations": [{"path": "1.1.1.1:/%s" % old_dataset_name}],
            "host": "foobackend@foohost#barpool",
            "share_proto": "NFS",
        }

        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={}))
        mock__get_dataset_name = self.mock_object(
            self.driver, "_get_dataset_name",
            mock.Mock(return_value=new_dataset_name))
        mock_get_zfs_option = self.mock_object(
            self.driver, 'get_zfs_option', mock.Mock(return_value="4G"))

        self.assertRaises(
            exception.ZFSonLinuxException,
            self.driver.manage_existing,
            share, {}
        )

        mock__get_dataset_name.assert_called_once_with(share)
        mock_get_zfs_option.assert_called_once_with(old_dataset_name, "used")
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    def test_manage_share_dataset_not_found(self):
        old_dataset_name = "foopool/path/to/old/dataset/name"
        new_dataset_name = "foopool/path/to/new/dataset/name"
        share = {
            "id": "fake_share_instance_id",
            "share_id": "fake_share_id",
            "export_locations": [{"path": "1.1.1.1:/%s" % old_dataset_name}],
            "host": "foobackend@foohost#foopool",
            "share_proto": "NFS",
        }

        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={}))
        mock__get_dataset_name = self.mock_object(
            self.driver, "_get_dataset_name",
            mock.Mock(return_value=new_dataset_name))
        mock_get_zfs_option = self.mock_object(
            self.driver, 'get_zfs_option', mock.Mock(return_value="4G"))
        mock_zfs = self.mock_object(
            self.driver, "zfs",
            mock.Mock(return_value=("fake_out", "fake_error")))
        mock_parse_zfs_answer = self.mock_object(
            self.driver,
            "parse_zfs_answer",
            mock.Mock(return_value=[{"NAME": "some_other_dataset_1"}]))

        self.assertRaises(
            exception.ZFSonLinuxException,
            self.driver.manage_existing,
            share, {}
        )

        mock__get_dataset_name.assert_called_once_with(share)
        mock_get_zfs_option.assert_called_once_with(old_dataset_name, "used")
        mock_zfs.assert_called_once_with(
            "list", "-r", old_dataset_name.split("/")[0])
        mock_parse_zfs_answer.assert_called_once_with(mock_zfs.return_value[0])
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    def test_manage_unmount_exception(self):
        old_ds_name = "foopool/path/to/old/dataset/name"
        new_ds_name = "foopool/path/to/new/dataset/name"
        share = {
            "id": "fake_share_instance_id",
            "share_id": "fake_share_id",
            "export_locations": [{"path": "1.1.1.1:/%s" % old_ds_name}],
            "host": "foobackend@foohost#foopool",
            "share_proto": "NFS",
        }

        mock_get_extra_specs_from_share = self.mock_object(
            zfs_driver.share_types,
            'get_extra_specs_from_share',
            mock.Mock(return_value={}))
        self.mock_object(zfs_driver.time, "sleep")
        mock__get_dataset_name = self.mock_object(
            self.driver, "_get_dataset_name",
            mock.Mock(return_value=new_ds_name))
        mock_helper = self.mock_object(self.driver, "_get_share_helper")
        mock_zfs = self.mock_object(
            self.driver, "zfs",
            mock.Mock(return_value=("fake_out", "fake_error")))
        mock_zfs_with_retry = self.mock_object(self.driver, "zfs_with_retry")

        # 10 Retries, would mean 20 calls to check the mount still exists
        mock_execute_side_effects = [("%s " % old_ds_name, "fake_err")] * 21
        mock_execute = self.mock_object(
            self.driver, "execute",
            mock.Mock(side_effect=mock_execute_side_effects))

        mock_parse_zfs_answer = self.mock_object(
            self.driver,
            "parse_zfs_answer",
            mock.Mock(return_value=[
                {"NAME": "some_other_dataset_1"},
                {"NAME": old_ds_name},
                {"NAME": "some_other_dataset_2"},
            ]))
        mock_get_zfs_option = self.mock_object(
            self.driver, 'get_zfs_option', mock.Mock(return_value="4G"))

        self.assertRaises(exception.ZFSonLinuxException,
                          self.driver.manage_existing,
                          share, {'size': 10})

        self.assertFalse(mock_helper.return_value.get_exports.called)
        mock_zfs_with_retry.assert_called_with("umount", "-f", old_ds_name)
        mock_execute.assert_called_with("sudo", "mount")
        self.assertEqual(10, mock_zfs_with_retry.call_count)
        self.assertEqual(20, mock_execute.call_count)
        mock_parse_zfs_answer.assert_called_once_with(mock_zfs.return_value[0])
        self.assertFalse(mock_get_zfs_option.called)
        mock__get_dataset_name.assert_called_once_with(share)
        mock_get_extra_specs_from_share.assert_called_once_with(share)

    def test_unmanage(self):
        share = {'id': 'fake_share_id'}
        self.mock_object(self.driver.private_storage, 'delete')

        self.driver.unmanage(share)

        self.driver.private_storage.delete.assert_called_once_with(share['id'])

    @ddt.data(
        {},
        {"size": 5},
        {"size": "5"},
    )
    def test_manage_existing_snapshot(self, driver_options):
        dataset_name = "path/to/dataset"
        old_provider_location = dataset_name + "@original_snapshot_tag"
        snapshot_instance = {
            "id": "fake_snapshot_instance_id",
            "share_instance_id": "fake_share_instance_id",
            "snapshot_id": "fake_snapshot_id",
            "provider_location": old_provider_location,
        }
        new_snapshot_tag = "fake_new_snapshot_tag"
        new_provider_location = (
            old_provider_location.split("@")[0] + "@" + new_snapshot_tag)

        self.mock_object(self.driver, "zfs")
        self.mock_object(
            self.driver, "get_zfs_option", mock.Mock(return_value="5G"))
        self.mock_object(
            self.driver,
            '_get_snapshot_name',
            mock.Mock(return_value=new_snapshot_tag))
        self.driver.private_storage.update(
            snapshot_instance["share_instance_id"],
            {"dataset_name": dataset_name})

        result = self.driver.manage_existing_snapshot(
            snapshot_instance, driver_options)

        expected_result = {
            "size": 5,
            "provider_location": new_provider_location,
        }
        self.assertEqual(expected_result, result)
        self.driver._get_snapshot_name.assert_called_once_with(
            snapshot_instance["id"])
        self.driver.zfs.assert_has_calls([
            mock.call("list", "-r", "-t", "snapshot", old_provider_location),
            mock.call("rename", old_provider_location, new_provider_location),
        ])

    def test_manage_existing_snapshot_not_found(self):
        dataset_name = "path/to/dataset"
        old_provider_location = dataset_name + "@original_snapshot_tag"
        new_snapshot_tag = "fake_new_snapshot_tag"
        snapshot_instance = {
            "id": "fake_snapshot_instance_id",
            "snapshot_id": "fake_snapshot_id",
            "provider_location": old_provider_location,
        }
        self.mock_object(
            self.driver, "_get_snapshot_name",
            mock.Mock(return_value=new_snapshot_tag))
        self.mock_object(
            self.driver, "zfs",
            mock.Mock(side_effect=exception.ProcessExecutionError("FAKE")))

        self.assertRaises(
            exception.ManageInvalidShareSnapshot,
            self.driver.manage_existing_snapshot,
            snapshot_instance, {},
        )

        self.driver.zfs.assert_called_once_with(
            "list", "-r", "-t", "snapshot", old_provider_location)
        self.driver._get_snapshot_name.assert_called_once_with(
            snapshot_instance["id"])

    def test_unmanage_snapshot(self):
        snapshot_instance = {
            "id": "fake_snapshot_instance_id",
            "snapshot_id": "fake_snapshot_id",
        }
        self.mock_object(self.driver.private_storage, "delete")

        self.driver.unmanage_snapshot(snapshot_instance)

        self.driver.private_storage.delete.assert_called_once_with(
            snapshot_instance["snapshot_id"])

    def test__delete_dataset_or_snapshot_with_retry_snapshot(self):
        self.mock_object(self.driver, 'get_zfs_option')
        self.mock_object(self.driver, 'zfs')

        self.driver._delete_dataset_or_snapshot_with_retry('foo@bar')

        self.driver.get_zfs_option.assert_called_once_with(
            'foo@bar', 'mountpoint')
        self.driver.zfs.assert_called_once_with(
            'destroy', '-f', 'foo@bar')

    def test__delete_dataset_or_snapshot_with_retry_of(self):
        self.mock_object(self.driver, 'get_zfs_option')
        self.mock_object(
            self.driver, 'execute', mock.Mock(return_value=('a', 'b')))
        self.mock_object(zfs_driver.time, 'sleep')
        self.mock_object(zfs_driver.LOG, 'debug')
        self.mock_object(
            zfs_driver.time, 'time', mock.Mock(side_effect=range(1, 70, 2)))
        dataset_name = 'fake/dataset/name'

        self.assertRaises(
            exception.ZFSonLinuxException,
            self.driver._delete_dataset_or_snapshot_with_retry,
            dataset_name,
        )

        self.driver.get_zfs_option.assert_called_once_with(
            dataset_name, 'mountpoint')
        self.assertEqual(29, zfs_driver.LOG.debug.call_count)

    def test__delete_dataset_or_snapshot_with_retry_temp_of(self):
        self.mock_object(self.driver, 'get_zfs_option')
        self.mock_object(self.driver, 'zfs')
        self.mock_object(
            self.driver, 'execute', mock.Mock(side_effect=[
                ('a', 'b'),
                exception.ProcessExecutionError(
                    'FAKE lsof returns not found')]))
        self.mock_object(zfs_driver.time, 'sleep')
        self.mock_object(zfs_driver.LOG, 'debug')
        self.mock_object(
            zfs_driver.time, 'time', mock.Mock(side_effect=range(1, 70, 2)))
        dataset_name = 'fake/dataset/name'

        self.driver._delete_dataset_or_snapshot_with_retry(dataset_name)

        self.driver.get_zfs_option.assert_called_once_with(
            dataset_name, 'mountpoint')
        self.assertEqual(2, self.driver.execute.call_count)
        self.assertEqual(1, zfs_driver.LOG.debug.call_count)
        zfs_driver.LOG.debug.assert_called_once_with(
            mock.ANY, {'name': dataset_name, 'out': 'a'})
        zfs_driver.time.sleep.assert_called_once_with(2)
        self.driver.zfs.assert_called_once_with('destroy', '-f', dataset_name)

    def test__delete_dataset_or_snapshot_with_retry_busy(self):
        self.mock_object(self.driver, 'get_zfs_option')
        self.mock_object(
            self.driver, 'execute', mock.Mock(
                side_effect=exception.ProcessExecutionError(
                    'FAKE lsof returns not found')))
        self.mock_object(
            self.driver, 'zfs', mock.Mock(side_effect=[
                exception.ProcessExecutionError(
                    'cannot destroy FAKE: dataset is busy\n'),
                None, None]))
        self.mock_object(zfs_driver.time, 'sleep')
        self.mock_object(zfs_driver.LOG, 'info')
        dataset_name = 'fake/dataset/name'

        self.driver._delete_dataset_or_snapshot_with_retry(dataset_name)

        self.driver.get_zfs_option.assert_called_once_with(
            dataset_name, 'mountpoint')
        self.assertEqual(2, zfs_driver.time.sleep.call_count)
        self.assertEqual(2, self.driver.execute.call_count)
        self.assertEqual(1, zfs_driver.LOG.info.call_count)
        self.assertEqual(2, self.driver.zfs.call_count)

    def test_create_replica(self):
        active_replica = {
            'id': 'fake_active_replica_id',
            'host': 'hostname1@backend_name1#foo',
            'size': 5,
            'replica_state': zfs_driver.constants.REPLICA_STATE_ACTIVE,
        }
        replica_list = [active_replica]
        new_replica = {
            'id': 'fake_new_replica_id',
            'host': 'hostname2@backend_name2#bar',
            'share_proto': 'NFS',
            'replica_state': None,
        }
        dst_dataset_name = (
            'bar/subbar/fake_dataset_name_prefix%s' % new_replica['id'])
        access_rules = ['foo_rule', 'bar_rule']
        self.driver.private_storage.update(
            active_replica['id'],
            {'dataset_name': 'fake/active/dataset/name',
             'ssh_cmd': 'fake_ssh_cmd'}
        )
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(side_effect=[('a', 'b'), ('c', 'd')]))
        self.mock_object(self.driver, 'zfs')
        mock_helper = self.mock_object(self.driver, '_get_share_helper')
        self.configuration.zfs_dataset_name_prefix = 'fake_dataset_name_prefix'
        mock_utcnow = self.mock_object(zfs_driver.timeutils, 'utcnow')
        mock_utcnow.return_value.isoformat.return_value = 'some_time'

        result = self.driver.create_replica(
            'fake_context', replica_list, new_replica, access_rules, [])

        expected = {
            'export_locations': (
                mock_helper.return_value.create_exports.return_value),
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
            'access_rules_status': zfs_driver.constants.STATUS_ACTIVE,
        }
        self.assertEqual(expected, result)
        mock_helper.assert_has_calls([
            mock.call('NFS'),
            mock.call().update_access(
                dst_dataset_name, access_rules, add_rules=[],
                delete_rules=[], make_all_ro=True),
            mock.call('NFS'),
            mock.call().create_exports(dst_dataset_name),
        ])
        self.driver.zfs.assert_has_calls([
            mock.call('set', 'readonly=on', dst_dataset_name),
            mock.call('set', 'quota=%sG' % active_replica['size'],
                      dst_dataset_name),
        ])
        src_snapshot_name = (
            'fake/active/dataset/name@'
            'tmp_snapshot_for_replication__fake_new_replica_id_time_some_time')
        self.driver.execute.assert_has_calls([
            mock.call('ssh', 'fake_ssh_cmd', 'sudo', 'zfs', 'snapshot',
                      src_snapshot_name),
            mock.call(
                'ssh', 'fake_ssh_cmd',
                'sudo', 'zfs', 'send', '-vDR', src_snapshot_name, '|',
                'ssh', 'fake_username@240.241.242.244',
                'sudo', 'zfs', 'receive', '-v', dst_dataset_name
            ),
        ])
        mock_utcnow.assert_called_once_with()
        mock_utcnow.return_value.isoformat.assert_called_once_with()

    def test_delete_replica_not_found(self):
        dataset_name = 'foo/dataset/name'
        pool_name = 'foo_pool'
        replica = {'id': 'fake_replica_id'}
        replica_list = [replica]
        replica_snapshots = []
        self.mock_object(
            self.driver, '_get_dataset_name',
            mock.Mock(return_value=dataset_name))
        self.mock_object(
            self.driver, 'zfs',
            mock.Mock(side_effect=[('a', 'b'), ('c', 'd')]))
        self.mock_object(
            self.driver, 'parse_zfs_answer', mock.Mock(side_effect=[[], []]))
        self.mock_object(self.driver, '_delete_dataset_or_snapshot_with_retry')
        self.mock_object(zfs_driver.LOG, 'warning')
        self.mock_object(self.driver, '_get_share_helper')
        self.driver.private_storage.update(
            replica['id'], {'pool_name': pool_name})

        self.driver.delete_replica('fake_context', replica_list,
                                   replica_snapshots, replica)

        zfs_driver.LOG.warning.assert_called_once_with(
            mock.ANY, {'id': replica['id'], 'name': dataset_name})
        self.assertEqual(0, self.driver._get_share_helper.call_count)
        self.assertEqual(
            0, self.driver._delete_dataset_or_snapshot_with_retry.call_count)
        self.driver._get_dataset_name.assert_called_once_with(replica)
        self.driver.zfs.assert_has_calls([
            mock.call('list', '-r', '-t', 'snapshot', pool_name),
            mock.call('list', '-r', pool_name),
        ])
        self.driver.parse_zfs_answer.assert_has_calls([
            mock.call('a'), mock.call('c'),
        ])

    def test_delete_replica(self):
        dataset_name = 'foo/dataset/name'
        pool_name = 'foo_pool'
        replica = {'id': 'fake_replica_id', 'share_proto': 'NFS'}
        replica_list = [replica]
        self.mock_object(
            self.driver, '_get_dataset_name',
            mock.Mock(return_value=dataset_name))
        self.mock_object(
            self.driver, 'zfs',
            mock.Mock(side_effect=[('a', 'b'), ('c', 'd')]))
        self.mock_object(
            self.driver, 'parse_zfs_answer', mock.Mock(side_effect=[
                [{'NAME': 'some_other_dataset@snapshot'},
                 {'NAME': dataset_name + '@foo_snap'}],
                [{'NAME': 'some_other_dataset'},
                 {'NAME': dataset_name}],
            ]))
        mock_helper = self.mock_object(self.driver, '_get_share_helper')
        self.mock_object(self.driver, '_delete_dataset_or_snapshot_with_retry')
        self.mock_object(zfs_driver.LOG, 'warning')
        self.driver.private_storage.update(
            replica['id'],
            {'pool_name': pool_name, 'dataset_name': dataset_name})

        self.driver.delete_replica('fake_context', replica_list, [], replica)

        self.assertEqual(0, zfs_driver.LOG.warning.call_count)
        self.assertEqual(0, self.driver._get_dataset_name.call_count)
        self.driver._delete_dataset_or_snapshot_with_retry.assert_has_calls([
            mock.call(dataset_name + '@foo_snap'),
            mock.call(dataset_name),
        ])
        self.driver.zfs.assert_has_calls([
            mock.call('list', '-r', '-t', 'snapshot', pool_name),
            mock.call('list', '-r', pool_name),
        ])
        self.driver.parse_zfs_answer.assert_has_calls([
            mock.call('a'), mock.call('c'),
        ])
        mock_helper.assert_called_once_with(replica['share_proto'])
        mock_helper.return_value.remove_exports.assert_called_once_with(
            dataset_name)

    def test_update_replica(self):
        active_replica = {
            'id': 'fake_active_replica_id',
            'host': 'hostname1@backend_name1#foo',
            'size': 5,
            'replica_state': zfs_driver.constants.REPLICA_STATE_ACTIVE,
        }
        replica = {
            'id': 'fake_new_replica_id',
            'host': 'hostname2@backend_name2#bar',
            'share_proto': 'NFS',
            'replica_state': None,
        }
        replica_list = [replica, active_replica]
        replica_snapshots = []
        dst_dataset_name = (
            'bar/subbar/fake_dataset_name_prefix%s' % replica['id'])
        src_dataset_name = (
            'bar/subbar/fake_dataset_name_prefix%s' % active_replica['id'])
        access_rules = ['foo_rule', 'bar_rule']
        old_repl_snapshot_tag = (
            self.driver._get_replication_snapshot_prefix(
                active_replica) + 'foo')
        snap_tag_prefix = self.driver._get_replication_snapshot_prefix(
            replica)
        self.driver.private_storage.update(
            active_replica['id'],
            {'dataset_name': src_dataset_name,
             'ssh_cmd': 'fake_src_ssh_cmd',
             'repl_snapshot_tag': old_repl_snapshot_tag}
        )
        self.driver.private_storage.update(
            replica['id'],
            {'dataset_name': dst_dataset_name,
             'ssh_cmd': 'fake_dst_ssh_cmd',
             'repl_snapshot_tag': old_repl_snapshot_tag}
        )
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(side_effect=[('a', 'b'), ('c', 'd'), ('e', 'f')]))
        self.mock_object(self.driver, 'execute_with_retry',
                         mock.Mock(side_effect=[('g', 'h')]))
        self.mock_object(self.driver, 'zfs',
                         mock.Mock(side_effect=[('j', 'k'), ('l', 'm')]))
        self.mock_object(
            self.driver, 'parse_zfs_answer',
            mock.Mock(side_effect=[
                ({'NAME': dst_dataset_name + '@' + old_repl_snapshot_tag},
                 {'NAME': dst_dataset_name + '@%s_time_some_time' %
                  snap_tag_prefix},
                 {'NAME': 'other/dataset/name1@' + old_repl_snapshot_tag}),
                ({'NAME': src_dataset_name + '@' + old_repl_snapshot_tag},
                 {'NAME': src_dataset_name + '@' + snap_tag_prefix + 'quuz'},
                 {'NAME': 'other/dataset/name2@' + old_repl_snapshot_tag}),
            ])
        )
        mock_helper = self.mock_object(self.driver, '_get_share_helper')
        self.configuration.zfs_dataset_name_prefix = 'fake_dataset_name_prefix'
        mock_utcnow = self.mock_object(zfs_driver.timeutils, 'utcnow')
        mock_utcnow.return_value.isoformat.return_value = 'some_time'
        mock_delete_snapshot = self.mock_object(
            self.driver, '_delete_dataset_or_snapshot_with_retry')

        result = self.driver.update_replica_state(
            'fake_context', replica_list, replica, access_rules,
            replica_snapshots)

        self.assertEqual(zfs_driver.constants.REPLICA_STATE_IN_SYNC, result)
        mock_helper.assert_called_once_with('NFS')
        mock_helper.return_value.update_access.assert_called_once_with(
            dst_dataset_name, access_rules, add_rules=[], delete_rules=[],
            make_all_ro=True)
        self.driver.execute_with_retry.assert_called_once_with(
            'ssh', 'fake_src_ssh_cmd', 'sudo', 'zfs', 'destroy', '-f',
            src_dataset_name + '@' + snap_tag_prefix + 'quuz')
        self.driver.execute.assert_has_calls([
            mock.call(
                'ssh', 'fake_src_ssh_cmd', 'sudo', 'zfs', 'snapshot',
                src_dataset_name + '@' +
                self.driver._get_replication_snapshot_tag(replica)),
            mock.call(
                'ssh', 'fake_src_ssh_cmd', 'sudo', 'zfs', 'send',
                '-vDRI', old_repl_snapshot_tag,
                src_dataset_name + '@%s' % snap_tag_prefix + '_time_some_time',
                '|', 'ssh', 'fake_dst_ssh_cmd',
                'sudo', 'zfs', 'receive', '-vF', dst_dataset_name),
            mock.call(
                'ssh', 'fake_src_ssh_cmd',
                'sudo', 'zfs', 'list', '-r', '-t', 'snapshot', 'bar'),
        ])
        mock_delete_snapshot.assert_called_once_with(
            dst_dataset_name + '@' + old_repl_snapshot_tag)
        self.driver.parse_zfs_answer.assert_has_calls(
            [mock.call('l'), mock.call('e')])

    def test_promote_replica_active_available(self):
        active_replica = {
            'id': 'fake_active_replica_id',
            'host': 'hostname1@backend_name1#foo',
            'size': 5,
            'replica_state': zfs_driver.constants.REPLICA_STATE_ACTIVE,
        }
        replica = {
            'id': 'fake_first_replica_id',
            'host': 'hostname2@backend_name2#bar',
            'share_proto': 'NFS',
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
        }
        second_replica = {
            'id': 'fake_second_replica_id',
            'host': 'hostname3@backend_name3#quuz',
            'share_proto': 'NFS',
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
        }
        replica_list = [replica, active_replica, second_replica]
        dst_dataset_name = (
            'bar/subbar/fake_dataset_name_prefix%s' % replica['id'])
        src_dataset_name = (
            'bar/subbar/fake_dataset_name_prefix%s' % active_replica['id'])
        access_rules = ['foo_rule', 'bar_rule']
        old_repl_snapshot_tag = (
            self.driver._get_replication_snapshot_prefix(
                active_replica) + 'foo')
        snap_tag_prefix = self.driver._get_replication_snapshot_prefix(
            active_replica) + '_time_some_time'
        self.driver.private_storage.update(
            active_replica['id'],
            {'dataset_name': src_dataset_name,
             'ssh_cmd': 'fake_src_ssh_cmd',
             'repl_snapshot_tag': old_repl_snapshot_tag}
        )
        for repl in (replica, second_replica):
            self.driver.private_storage.update(
                repl['id'],
                {'dataset_name': (
                    'bar/subbar/fake_dataset_name_prefix%s' % repl['id']),
                 'ssh_cmd': 'fake_dst_ssh_cmd',
                 'repl_snapshot_tag': old_repl_snapshot_tag}
            )
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(side_effect=[
                ('a', 'b'),
                ('c', 'd'),
                ('e', 'f'),
                exception.ProcessExecutionError('Second replica sync failure'),
            ]))
        self.mock_object(self.driver, 'zfs',
                         mock.Mock(side_effect=[('g', 'h')]))
        mock_helper = self.mock_object(self.driver, '_get_share_helper')
        self.configuration.zfs_dataset_name_prefix = 'fake_dataset_name_prefix'
        mock_utcnow = self.mock_object(zfs_driver.timeutils, 'utcnow')
        mock_utcnow.return_value.isoformat.return_value = 'some_time'
        mock_delete_snapshot = self.mock_object(
            self.driver, '_delete_dataset_or_snapshot_with_retry')

        result = self.driver.promote_replica(
            'fake_context', replica_list, replica, access_rules)

        expected = [
            {'access_rules_status':
                zfs_driver.constants.SHARE_INSTANCE_RULES_SYNCING,
             'id': 'fake_active_replica_id',
             'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC},
            {'access_rules_status': zfs_driver.constants.STATUS_ACTIVE,
             'id': 'fake_first_replica_id',
             'replica_state': zfs_driver.constants.REPLICA_STATE_ACTIVE},
            {'access_rules_status':
                zfs_driver.constants.SHARE_INSTANCE_RULES_SYNCING,
             'id': 'fake_second_replica_id',
             'replica_state': zfs_driver.constants.REPLICA_STATE_OUT_OF_SYNC},
        ]
        for repl in expected:
            self.assertIn(repl, result)
        self.assertEqual(3, len(result))
        mock_helper.assert_called_once_with('NFS')
        mock_helper.return_value.update_access.assert_called_once_with(
            dst_dataset_name, access_rules, add_rules=[], delete_rules=[])
        self.driver.zfs.assert_called_once_with(
            'set', 'readonly=off', dst_dataset_name)
        self.assertEqual(0, mock_delete_snapshot.call_count)
        for repl in (active_replica, replica):
            self.assertEqual(
                snap_tag_prefix,
                self.driver.private_storage.get(
                    repl['id'], 'repl_snapshot_tag'))
        self.assertEqual(
            old_repl_snapshot_tag,
            self.driver.private_storage.get(
                second_replica['id'], 'repl_snapshot_tag'))

    def test_promote_replica_active_not_available(self):
        active_replica = {
            'id': 'fake_active_replica_id',
            'host': 'hostname1@backend_name1#foo',
            'size': 5,
            'replica_state': zfs_driver.constants.REPLICA_STATE_ACTIVE,
        }
        replica = {
            'id': 'fake_first_replica_id',
            'host': 'hostname2@backend_name2#bar',
            'share_proto': 'NFS',
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
        }
        second_replica = {
            'id': 'fake_second_replica_id',
            'host': 'hostname3@backend_name3#quuz',
            'share_proto': 'NFS',
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
        }
        third_replica = {
            'id': 'fake_third_replica_id',
            'host': 'hostname4@backend_name4#fff',
            'share_proto': 'NFS',
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
        }
        replica_list = [replica, active_replica, second_replica, third_replica]
        dst_dataset_name = (
            'bar/subbar/fake_dataset_name_prefix%s' % replica['id'])
        src_dataset_name = (
            'bar/subbar/fake_dataset_name_prefix%s' % active_replica['id'])
        access_rules = ['foo_rule', 'bar_rule']
        old_repl_snapshot_tag = (
            self.driver._get_replication_snapshot_prefix(
                active_replica) + 'foo')
        snap_tag_prefix = self.driver._get_replication_snapshot_prefix(
            replica) + '_time_some_time'
        self.driver.private_storage.update(
            active_replica['id'],
            {'dataset_name': src_dataset_name,
             'ssh_cmd': 'fake_src_ssh_cmd',
             'repl_snapshot_tag': old_repl_snapshot_tag}
        )
        for repl in (replica, second_replica, third_replica):
            self.driver.private_storage.update(
                repl['id'],
                {'dataset_name': (
                    'bar/subbar/fake_dataset_name_prefix%s' % repl['id']),
                 'ssh_cmd': 'fake_dst_ssh_cmd',
                 'repl_snapshot_tag': old_repl_snapshot_tag}
            )
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(side_effect=[
                exception.ProcessExecutionError('Active replica failure'),
                ('a', 'b'),
                exception.ProcessExecutionError('Second replica sync failure'),
                ('c', 'd'),
            ]))
        self.mock_object(self.driver, 'zfs',
                         mock.Mock(side_effect=[('g', 'h'), ('i', 'j')]))
        mock_helper = self.mock_object(self.driver, '_get_share_helper')
        self.configuration.zfs_dataset_name_prefix = 'fake_dataset_name_prefix'
        mock_utcnow = self.mock_object(zfs_driver.timeutils, 'utcnow')
        mock_utcnow.return_value.isoformat.return_value = 'some_time'
        mock_delete_snapshot = self.mock_object(
            self.driver, '_delete_dataset_or_snapshot_with_retry')

        result = self.driver.promote_replica(
            'fake_context', replica_list, replica, access_rules)

        expected = [
            {'access_rules_status':
                zfs_driver.constants.SHARE_INSTANCE_RULES_SYNCING,
             'id': 'fake_active_replica_id',
             'replica_state': zfs_driver.constants.REPLICA_STATE_OUT_OF_SYNC},
            {'access_rules_status': zfs_driver.constants.STATUS_ACTIVE,
             'id': 'fake_first_replica_id',
             'replica_state': zfs_driver.constants.REPLICA_STATE_ACTIVE},
            {'access_rules_status':
                zfs_driver.constants.SHARE_INSTANCE_RULES_SYNCING,
             'id': 'fake_second_replica_id'},
            {'access_rules_status':
                zfs_driver.constants.SHARE_INSTANCE_RULES_SYNCING,
             'id': 'fake_third_replica_id',
             'replica_state': zfs_driver.constants.REPLICA_STATE_OUT_OF_SYNC},
        ]
        for repl in expected:
            self.assertIn(repl, result)
        self.assertEqual(4, len(result))
        mock_helper.assert_called_once_with('NFS')
        mock_helper.return_value.update_access.assert_called_once_with(
            dst_dataset_name, access_rules, add_rules=[], delete_rules=[])
        self.driver.zfs.assert_has_calls([
            mock.call('snapshot', dst_dataset_name + '@' + snap_tag_prefix),
            mock.call('set', 'readonly=off', dst_dataset_name),
        ])
        self.assertEqual(0, mock_delete_snapshot.call_count)
        for repl in (second_replica, replica):
            self.assertEqual(
                snap_tag_prefix,
                self.driver.private_storage.get(
                    repl['id'], 'repl_snapshot_tag'))
        for repl in (active_replica, third_replica):
            self.assertEqual(
                old_repl_snapshot_tag,
                self.driver.private_storage.get(
                    repl['id'], 'repl_snapshot_tag'))

    def test_create_replicated_snapshot(self):
        active_replica = {
            'id': 'fake_active_replica_id',
            'replica_state': zfs_driver.constants.REPLICA_STATE_ACTIVE,
        }
        replica = {
            'id': 'fake_first_replica_id',
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
        }
        second_replica = {
            'id': 'fake_second_replica_id',
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
        }
        replica_list = [replica, active_replica, second_replica]
        snapshot_instances = [
            {'id': 'si_%s' % r['id'], 'share_instance_id': r['id'],
             'snapshot_id': 'some_snapshot_id'}
            for r in replica_list
        ]
        src_dataset_name = (
            'bar/subbar/fake_dataset_name_prefix%s' % active_replica['id'])
        old_repl_snapshot_tag = (
            self.driver._get_replication_snapshot_prefix(
                active_replica) + 'foo')
        self.driver.private_storage.update(
            active_replica['id'],
            {'dataset_name': src_dataset_name,
             'ssh_cmd': 'fake_src_ssh_cmd',
             'repl_snapshot_tag': old_repl_snapshot_tag}
        )
        for repl in (replica, second_replica):
            self.driver.private_storage.update(
                repl['id'],
                {'dataset_name': (
                    'bar/subbar/fake_dataset_name_prefix%s' % repl['id']),
                 'ssh_cmd': 'fake_dst_ssh_cmd',
                 'repl_snapshot_tag': old_repl_snapshot_tag}
            )
        self.mock_object(
            self.driver, 'execute', mock.Mock(side_effect=[
                ('a', 'b'),
                ('c', 'd'),
                ('e', 'f'),
                exception.ProcessExecutionError('Second replica sync failure'),
            ]))
        self.configuration.zfs_dataset_name_prefix = 'fake_dataset_name_prefix'
        self.configuration.zfs_dataset_snapshot_name_prefix = (
            'fake_dataset_snapshot_name_prefix')
        snap_tag_prefix = (
            self.configuration.zfs_dataset_snapshot_name_prefix +
            'si_%s' % active_replica['id'])
        repl_snap_tag = 'fake_repl_tag'
        self.mock_object(
            self.driver, '_get_replication_snapshot_tag',
            mock.Mock(return_value=repl_snap_tag))

        result = self.driver.create_replicated_snapshot(
            'fake_context', replica_list, snapshot_instances)

        expected = [
            {'id': 'si_fake_active_replica_id',
             'status': zfs_driver.constants.STATUS_AVAILABLE},
            {'id': 'si_fake_first_replica_id',
             'status': zfs_driver.constants.STATUS_AVAILABLE},
            {'id': 'si_fake_second_replica_id',
             'status': zfs_driver.constants.STATUS_ERROR},
        ]
        for repl in expected:
            self.assertIn(repl, result)
        self.assertEqual(3, len(result))
        for repl in (active_replica, replica):
            self.assertEqual(
                repl_snap_tag,
                self.driver.private_storage.get(
                    repl['id'], 'repl_snapshot_tag'))
        self.assertEqual(
            old_repl_snapshot_tag,
            self.driver.private_storage.get(
                second_replica['id'], 'repl_snapshot_tag'))
        self.assertEqual(
            snap_tag_prefix,
            self.driver.private_storage.get(
                snapshot_instances[0]['snapshot_id'], 'snapshot_tag'))
        self.driver._get_replication_snapshot_tag.assert_called_once_with(
            active_replica)

    def test_delete_replicated_snapshot(self):
        active_replica = {
            'id': 'fake_active_replica_id',
            'replica_state': zfs_driver.constants.REPLICA_STATE_ACTIVE,
        }
        replica = {
            'id': 'fake_first_replica_id',
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
        }
        second_replica = {
            'id': 'fake_second_replica_id',
            'replica_state': zfs_driver.constants.REPLICA_STATE_IN_SYNC,
        }
        replica_list = [replica, active_replica, second_replica]
        active_snapshot_instance = {
            'id': 'si_%s' % active_replica['id'],
            'share_instance_id': active_replica['id'],
            'snapshot_id': 'some_snapshot_id',
            'share_id': 'some_share_id',
        }
        snapshot_instances = [
            {'id': 'si_%s' % r['id'], 'share_instance_id': r['id'],
             'snapshot_id': active_snapshot_instance['snapshot_id'],
             'share_id': active_snapshot_instance['share_id']}
            for r in (replica, second_replica)
        ]
        snapshot_instances.append(active_snapshot_instance)
        for si in snapshot_instances:
            self.driver.private_storage.update(
                si['id'], {'snapshot_name': 'fake_snap_name_%s' % si['id']})
        src_dataset_name = (
            'bar/subbar/fake_dataset_name_prefix%s' % active_replica['id'])
        old_repl_snapshot_tag = (
            self.driver._get_replication_snapshot_prefix(
                active_replica) + 'foo')
        new_repl_snapshot_tag = 'foo_snapshot_tag'
        dataset_name = 'some_dataset_name'
        self.driver.private_storage.update(
            active_replica['id'],
            {'dataset_name': src_dataset_name,
             'ssh_cmd': 'fake_src_ssh_cmd',
             'repl_snapshot_tag': old_repl_snapshot_tag}
        )
        for replica in (replica, second_replica):
            self.driver.private_storage.update(
                replica['id'],
                {'dataset_name': dataset_name,
                 'ssh_cmd': 'fake_ssh_cmd'}
            )
        self.driver.private_storage.update(
            snapshot_instances[0]['snapshot_id'],
            {'snapshot_tag': new_repl_snapshot_tag}
        )

        snap_name = 'fake_snap_name'
        self.mock_object(
            self.driver, 'zfs', mock.Mock(return_value=['out', 'err']))
        self.mock_object(
            self.driver, 'execute', mock.Mock(side_effect=[
                ('a', 'b'),
                ('c', 'd'),
                exception.ProcessExecutionError('Second replica sync failure'),
            ]))
        self.mock_object(
            self.driver, 'parse_zfs_answer', mock.Mock(side_effect=[
                ({'NAME': 'foo'}, {'NAME': snap_name}),
                ({'NAME': 'bar'}, {'NAME': snap_name}),
                [],
            ]))
        expected = sorted([
            {'id': si['id'], 'status': 'deleted'} for si in snapshot_instances
        ], key=lambda item: item['id'])

        self.assertEqual(
            new_repl_snapshot_tag,
            self.driver.private_storage.get(
                snapshot_instances[0]['snapshot_id'], 'snapshot_tag'))

        result = self.driver.delete_replicated_snapshot(
            'fake_context', replica_list, snapshot_instances)

        self.assertIsNone(
            self.driver.private_storage.get(
                snapshot_instances[0]['snapshot_id'], 'snapshot_tag'))

        self.driver.execute.assert_has_calls([
            mock.call('ssh', 'fake_ssh_cmd', 'sudo', 'zfs', 'list', '-r', '-t',
                      'snapshot', dataset_name + '@' + new_repl_snapshot_tag)
            for i in (0, 1)
        ])

        self.assertIsInstance(result, list)
        self.assertEqual(3, len(result))
        self.assertEqual(expected, sorted(result, key=lambda item: item['id']))
        self.driver.parse_zfs_answer.assert_has_calls([
            mock.call('out'),
        ])

    @ddt.data(
        ({'NAME': 'fake'}, zfs_driver.constants.STATUS_ERROR),
        ({'NAME': 'fake_snap_name'}, zfs_driver.constants.STATUS_AVAILABLE),
    )
    @ddt.unpack
    def test_update_replicated_snapshot(self, parse_answer, expected_status):
        snap_name = 'fake_snap_name'
        self.mock_object(self.driver, '_update_replica_state')
        self.mock_object(
            self.driver, '_get_saved_snapshot_name',
            mock.Mock(return_value=snap_name))
        self.mock_object(
            self.driver, 'zfs', mock.Mock(side_effect=[('a', 'b')]))
        self.mock_object(
            self.driver, 'parse_zfs_answer', mock.Mock(side_effect=[
                [parse_answer]
            ]))
        fake_context = 'fake_context'
        replica_list = ['foo', 'bar']
        share_replica = 'quuz'
        snapshot_instance = {'id': 'fake_snapshot_instance_id'}
        snapshot_instances = ['q', 'w', 'e', 'r', 't', 'y']

        result = self.driver.update_replicated_snapshot(
            fake_context, replica_list, share_replica, snapshot_instances,
            snapshot_instance)

        self.driver._update_replica_state.assert_called_once_with(
            fake_context, replica_list, share_replica)
        self.driver._get_saved_snapshot_name.assert_called_once_with(
            snapshot_instance)
        self.driver.zfs.assert_called_once_with(
            'list', '-r', '-t', 'snapshot', snap_name)
        self.driver.parse_zfs_answer.assert_called_once_with('a')
        self.assertIsInstance(result, dict)
        self.assertEqual(2, len(result))
        self.assertIn('status', result)
        self.assertIn('id', result)
        self.assertEqual(expected_status, result['status'])
        self.assertEqual(snapshot_instance['id'], result['id'])

    def test__get_shell_executor_by_host_local(self):
        backend_name = 'foobackend'
        host = 'foohost@%s#foopool' % backend_name
        CONF.set_default(
            'enabled_share_backends', 'fake1,%s,fake2,fake3' % backend_name)

        self.assertIsNone(self.driver._shell_executors.get(backend_name))

        result = self.driver._get_shell_executor_by_host(host)

        self.assertEqual(self.driver.execute, result)

    def test__get_shell_executor_by_host_remote(self):
        backend_name = 'foobackend'
        host = 'foohost@%s#foopool' % backend_name
        CONF.set_default('enabled_share_backends', 'fake1,fake2,fake3')
        mock_get_remote_shell_executor = self.mock_object(
            zfs_driver.zfs_utils, 'get_remote_shell_executor')
        mock_config = self.mock_object(zfs_driver, 'get_backend_configuration')
        self.assertIsNone(self.driver._shell_executors.get(backend_name))

        for i in (1, 2):
            result = self.driver._get_shell_executor_by_host(host)

            self.assertEqual(
                mock_get_remote_shell_executor.return_value, result)
            mock_get_remote_shell_executor.assert_called_once_with(
                ip=mock_config.return_value.zfs_service_ip,
                port=22,
                conn_timeout=mock_config.return_value.ssh_conn_timeout,
                login=mock_config.return_value.zfs_ssh_username,
                password=mock_config.return_value.zfs_ssh_user_password,
                privatekey=mock_config.return_value.zfs_ssh_private_key_path,
                max_size=10,
            )
            zfs_driver.get_backend_configuration.assert_called_once_with(
                backend_name)

    def test__get_migration_snapshot_tag(self):
        share_instance = {'id': 'fake-share_instance_id'}
        current_time = 'fake_current_time'
        mock_utcnow = self.mock_object(zfs_driver.timeutils, 'utcnow')
        mock_utcnow.return_value.isoformat.return_value = current_time
        expected_value = (
            self.driver.migration_snapshot_prefix +
            '_fake_share_instance_id_time_' + current_time)

        result = self.driver._get_migration_snapshot_tag(share_instance)

        self.assertEqual(expected_value, result)

    def test_migration_check_compatibility(self):
        src_share = {'host': 'foohost@foobackend#foopool'}
        dst_backend_name = 'barbackend'
        dst_share = {'host': 'barhost@%s#barpool' % dst_backend_name}
        expected = {
            'compatible': True,
            'writable': False,
            'preserve_metadata': True,
            'nondisruptive': True,
        }
        self.mock_object(
            zfs_driver,
            'get_backend_configuration',
            mock.Mock(return_value=type(
                'FakeConfig', (object,), {
                    'share_driver': self.driver.configuration.share_driver})))

        actual = self.driver.migration_check_compatibility(
            'fake_context', src_share, dst_share)

        self.assertEqual(expected, actual)
        zfs_driver.get_backend_configuration.assert_called_once_with(
            dst_backend_name)

    def test_migration_start(self):
        username = self.driver.configuration.zfs_ssh_username
        hostname = self.driver.configuration.zfs_service_ip
        dst_username = username + '_dst'
        dst_hostname = hostname + '_dst'
        src_share = {
            'id': 'fake_src_share_id',
            'host': 'foohost@foobackend#foopool',
        }
        src_dataset_name = 'foo_dataset_name'
        dst_share = {
            'id': 'fake_dst_share_id',
            'host': 'barhost@barbackend#barpool',
        }
        dst_dataset_name = 'bar_dataset_name'
        snapshot_tag = 'fake_migration_snapshot_tag'
        self.mock_object(
            self.driver,
            '_get_dataset_name',
            mock.Mock(return_value=dst_dataset_name))
        self.mock_object(
            self.driver,
            '_get_migration_snapshot_tag',
            mock.Mock(return_value=snapshot_tag))
        self.mock_object(
            zfs_driver,
            'get_backend_configuration',
            mock.Mock(return_value=type(
                'FakeConfig', (object,), {
                    'zfs_ssh_username': dst_username,
                    'zfs_service_ip': dst_hostname,
                })))
        self.mock_object(self.driver, 'execute')

        self.mock_object(
            zfs_driver.utils, 'tempdir',
            mock.MagicMock(side_effect=FakeTempDir))

        self.driver.private_storage.update(
            src_share['id'],
            {'dataset_name': src_dataset_name,
             'ssh_cmd': username + '@' + hostname})

        src_snapshot_name = (
            '%(dataset_name)s@%(snapshot_tag)s' % {
                'snapshot_tag': snapshot_tag,
                'dataset_name': src_dataset_name,
            }
        )
        with mock.patch("six.moves.builtins.open",
                        mock.mock_open(read_data="data")) as mock_file:
            self.driver.migration_start(
                self._context, src_share, dst_share, None, None)

            expected_file_content = (
                'ssh %(ssh_cmd)s sudo zfs send -vDR %(snap)s | '
                'ssh %(dst_ssh_cmd)s sudo zfs receive -v %(dst_dataset)s'
            ) % {
                'ssh_cmd': self.driver.private_storage.get(
                    src_share['id'], 'ssh_cmd'),
                'dst_ssh_cmd': self.driver.private_storage.get(
                    dst_share['id'], 'ssh_cmd'),
                'snap': src_snapshot_name,
                'dst_dataset': dst_dataset_name,
            }
            mock_file.assert_called_with("/foo/path/bar_dataset_name.sh", "w")
            mock_file.return_value.write.assert_called_once_with(
                expected_file_content)

        self.driver.execute.assert_has_calls([
            mock.call('sudo', 'zfs', 'snapshot', src_snapshot_name),
            mock.call('sudo', 'chmod', '755', mock.ANY),
            mock.call('nohup', mock.ANY, '&'),
        ])
        self.driver._get_migration_snapshot_tag.assert_called_once_with(
            dst_share)
        self.driver._get_dataset_name.assert_called_once_with(
            dst_share)
        for k, v in (('dataset_name', dst_dataset_name),
                     ('migr_snapshot_tag', snapshot_tag),
                     ('pool_name', 'barpool'),
                     ('ssh_cmd', dst_username + '@' + dst_hostname)):
            self.assertEqual(
                v, self.driver.private_storage.get(dst_share['id'], k))

    def test_migration_continue_success(self):
        dst_share = {
            'id': 'fake_dst_share_id',
            'host': 'barhost@barbackend#barpool',
        }
        dst_dataset_name = 'bar_dataset_name'
        snapshot_tag = 'fake_migration_snapshot_tag'
        self.driver.private_storage.update(
            dst_share['id'], {
                'migr_snapshot_tag': snapshot_tag,
                'dataset_name': dst_dataset_name,
            })
        mock_executor = self.mock_object(
            self.driver, '_get_shell_executor_by_host')
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(return_value=('fake_out', 'fake_err')))

        result = self.driver.migration_continue(
            self._context, 'fake_src_share', dst_share, None, None)

        self.assertTrue(result)
        mock_executor.assert_called_once_with(dst_share['host'])
        self.driver.execute.assert_has_calls([
            mock.call('ps', 'aux'),
            mock.call('sudo', 'zfs', 'get', 'quota', dst_dataset_name,
                      executor=mock_executor.return_value),
        ])

    def test_migration_continue_pending(self):
        dst_share = {
            'id': 'fake_dst_share_id',
            'host': 'barhost@barbackend#barpool',
        }
        dst_dataset_name = 'bar_dataset_name'
        snapshot_tag = 'fake_migration_snapshot_tag'
        self.driver.private_storage.update(
            dst_share['id'], {
                'migr_snapshot_tag': snapshot_tag,
                'dataset_name': dst_dataset_name,
            })
        mock_executor = self.mock_object(
            self.driver, '_get_shell_executor_by_host')
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(return_value=('foo@%s' % snapshot_tag, 'fake_err')))

        result = self.driver.migration_continue(
            self._context, 'fake_src_share', dst_share, None, None)

        self.assertIsNone(result)
        self.assertFalse(mock_executor.called)
        self.driver.execute.assert_called_once_with('ps', 'aux')

    def test_migration_continue_exception(self):
        dst_share = {
            'id': 'fake_dst_share_id',
            'host': 'barhost@barbackend#barpool',
        }
        dst_dataset_name = 'bar_dataset_name'
        snapshot_tag = 'fake_migration_snapshot_tag'
        self.driver.private_storage.update(
            dst_share['id'], {
                'migr_snapshot_tag': snapshot_tag,
                'dataset_name': dst_dataset_name,
            })
        mock_executor = self.mock_object(
            self.driver, '_get_shell_executor_by_host')
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(side_effect=[
                ('fake_out', 'fake_err'),
                exception.ProcessExecutionError('fake'),
            ]))

        self.assertRaises(
            exception.ZFSonLinuxException,
            self.driver.migration_continue,
            self._context, 'fake_src_share', dst_share, None, None
        )

        mock_executor.assert_called_once_with(dst_share['host'])
        self.driver.execute.assert_has_calls([
            mock.call('ps', 'aux'),
            mock.call('sudo', 'zfs', 'get', 'quota', dst_dataset_name,
                      executor=mock_executor.return_value),
        ])

    def test_migration_complete(self):
        src_share = {'id': 'fake_src_share_id'}
        dst_share = {
            'id': 'fake_dst_share_id',
            'host': 'barhost@barbackend#barpool',
            'share_proto': 'fake_share_proto',
        }
        dst_dataset_name = 'bar_dataset_name'
        snapshot_tag = 'fake_migration_snapshot_tag'
        self.driver.private_storage.update(
            dst_share['id'], {
                'migr_snapshot_tag': snapshot_tag,
                'dataset_name': dst_dataset_name,
            })
        dst_snapshot_name = (
            '%(dataset_name)s@%(snapshot_tag)s' % {
                'snapshot_tag': snapshot_tag,
                'dataset_name': dst_dataset_name,
            }
        )
        mock_helper = self.mock_object(self.driver, '_get_share_helper')
        mock_executor = self.mock_object(
            self.driver, '_get_shell_executor_by_host')
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(return_value=('fake_out', 'fake_err')))
        self.mock_object(self.driver, 'delete_share')

        result = self.driver.migration_complete(
            self._context, src_share, dst_share, None, None)

        expected_result = {
            'export_locations': (mock_helper.return_value.
                                 create_exports.return_value)
        }

        self.assertEqual(expected_result, result)
        mock_executor.assert_called_once_with(dst_share['host'])
        self.driver.execute.assert_called_once_with(
            'sudo', 'zfs', 'destroy', dst_snapshot_name,
            executor=mock_executor.return_value,
        )
        self.driver.delete_share.assert_called_once_with(
            self._context, src_share)
        mock_helper.assert_called_once_with(dst_share['share_proto'])
        mock_helper.return_value.create_exports.assert_called_once_with(
            dst_dataset_name,
            executor=self.driver._get_shell_executor_by_host.return_value)

    def test_migration_cancel_success(self):
        src_dataset_name = 'fake_src_dataset_name'
        src_share = {
            'id': 'fake_src_share_id',
            'dataset_name': src_dataset_name,
        }
        dst_share = {
            'id': 'fake_dst_share_id',
            'host': 'barhost@barbackend#barpool',
            'share_proto': 'fake_share_proto',
        }
        dst_dataset_name = 'fake_dst_dataset_name'
        snapshot_tag = 'fake_migration_snapshot_tag'
        dst_ssh_cmd = 'fake_dst_ssh_cmd'
        self.driver.private_storage.update(
            src_share['id'], {'dataset_name': src_dataset_name})
        self.driver.private_storage.update(
            dst_share['id'], {
                'migr_snapshot_tag': snapshot_tag,
                'dataset_name': dst_dataset_name,
                'ssh_cmd': dst_ssh_cmd,
            })
        self.mock_object(zfs_driver.time, 'sleep')
        mock_delete_dataset = self.mock_object(
            self.driver, '_delete_dataset_or_snapshot_with_retry')
        ps_output = (
            "fake_line1\nfoo_user   12345   foo_dataset_name@%s\n"
            "fake_line2") % snapshot_tag
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(return_value=(ps_output, 'fake_err'))
        )

        self.driver.migration_cancel(
            self._context, src_share, dst_share, [], {})

        self.driver.execute.assert_has_calls([
            mock.call('ps', 'aux'),
            mock.call('sudo', 'kill', '-9', '12345'),
            mock.call('ssh', dst_ssh_cmd, 'sudo', 'zfs', 'destroy', '-r',
                      dst_dataset_name),
        ])
        zfs_driver.time.sleep.assert_called_once_with(2)
        mock_delete_dataset.assert_called_once_with(
            src_dataset_name + '@' + snapshot_tag)

    def test_migration_cancel_error(self):
        src_dataset_name = 'fake_src_dataset_name'
        src_share = {
            'id': 'fake_src_share_id',
            'dataset_name': src_dataset_name,
        }
        dst_share = {
            'id': 'fake_dst_share_id',
            'host': 'barhost@barbackend#barpool',
            'share_proto': 'fake_share_proto',
        }
        dst_dataset_name = 'fake_dst_dataset_name'
        snapshot_tag = 'fake_migration_snapshot_tag'
        dst_ssh_cmd = 'fake_dst_ssh_cmd'
        self.driver.private_storage.update(
            src_share['id'], {'dataset_name': src_dataset_name})
        self.driver.private_storage.update(
            dst_share['id'], {
                'migr_snapshot_tag': snapshot_tag,
                'dataset_name': dst_dataset_name,
                'ssh_cmd': dst_ssh_cmd,
            })
        self.mock_object(zfs_driver.time, 'sleep')
        mock_delete_dataset = self.mock_object(
            self.driver, '_delete_dataset_or_snapshot_with_retry')
        self.mock_object(
            self.driver, 'execute',
            mock.Mock(side_effect=exception.ProcessExecutionError),
        )

        self.driver.migration_cancel(
            self._context, src_share, dst_share, [], {})

        self.driver.execute.assert_has_calls([
            mock.call('ps', 'aux'),
            mock.call('ssh', dst_ssh_cmd, 'sudo', 'zfs', 'destroy', '-r',
                      dst_dataset_name),
        ])
        zfs_driver.time.sleep.assert_called_once_with(2)
        mock_delete_dataset.assert_called_once_with(
            src_dataset_name + '@' + snapshot_tag)
