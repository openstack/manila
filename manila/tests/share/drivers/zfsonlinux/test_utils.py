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

import time

import ddt
import mock
from oslo_config import cfg

from manila import exception
from manila.share.drivers.ganesha import utils as ganesha_utils
from manila.share.drivers.zfsonlinux import utils as zfs_utils
from manila import test

CONF = cfg.CONF


def get_fake_configuration(*args, **kwargs):
    fake_config_options = {
        "zfs_use_ssh": kwargs.get("zfs_use_ssh", False),
        "zfs_share_export_ip": kwargs.get(
            "zfs_share_export_ip", "240.241.242.243"),
        "zfs_service_ip": kwargs.get("zfs_service_ip", "240.241.242.244"),
        "ssh_conn_timeout": kwargs.get("ssh_conn_timeout", 123),
        "zfs_ssh_username": kwargs.get(
            "zfs_ssh_username", 'fake_username'),
        "zfs_ssh_user_password": kwargs.get(
            "zfs_ssh_user_password", 'fake_pass'),
        "zfs_ssh_private_key_path": kwargs.get(
            "zfs_ssh_private_key_path", '/fake/path'),
        "append_config_values": mock.Mock(),
    }
    return type("FakeConfig", (object, ), fake_config_options)


class FakeShareDriver(zfs_utils.ExecuteMixin):
    def __init__(self, *args, **kwargs):
        self.configuration = get_fake_configuration(*args, **kwargs)
        self.init_execute_mixin(*args, **kwargs)


@ddt.ddt
class ExecuteMixinTestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.ssh_executor = self.mock_object(ganesha_utils, 'SSHExecutor')
        self.driver = FakeShareDriver()

    def test_init(self):
        self.assertIsNone(self.driver.ssh_executor)
        self.assertEqual(0, self.ssh_executor.call_count)

    def test_init_ssh(self):
        driver = FakeShareDriver(zfs_use_ssh=True)

        self.assertIsNotNone(driver.ssh_executor)
        self.ssh_executor.assert_called_once_with(
            ip=driver.configuration.zfs_service_ip,
            port=22,
            conn_timeout=driver.configuration.ssh_conn_timeout,
            login=driver.configuration.zfs_ssh_username,
            password=driver.configuration.zfs_ssh_user_password,
            privatekey=driver.configuration.zfs_ssh_private_key_path,
            max_size=10,
        )

    def test_execute_with_provided_executor(self):
        self.mock_object(self.driver, '_execute')
        fake_executor = mock.Mock()

        self.driver.execute('fake', '--foo', '--bar', executor=fake_executor)

        self.assertFalse(self.driver._execute.called)
        self.assertFalse(self.ssh_executor.called)
        fake_executor.assert_called_once_with('fake', '--foo', '--bar')

    def test_local_shell_execute(self):
        self.mock_object(self.driver, '_execute')

        self.driver.execute('fake', '--foo', '--bar')

        self.assertEqual(0, self.ssh_executor.call_count)
        self.driver._execute.assert_called_once_with(
            'fake', '--foo', '--bar')

    def test_local_shell_execute_with_sudo(self):
        self.mock_object(self.driver, '_execute')

        self.driver.execute('sudo', 'fake', '--foo', '--bar')

        self.assertEqual(0, self.ssh_executor.call_count)
        self.driver._execute.assert_called_once_with(
            'fake', '--foo', '--bar', run_as_root=True)

    def test_ssh_execute(self):
        driver = FakeShareDriver(zfs_use_ssh=True)

        self.mock_object(driver, '_execute')

        driver.execute('fake', '--foo', '--bar')

        self.assertEqual(0, driver._execute.call_count)
        self.ssh_executor.return_value.assert_called_once_with(
            'fake', '--foo', '--bar')

    def test_ssh_execute_with_sudo(self):
        driver = FakeShareDriver(zfs_use_ssh=True)

        self.mock_object(driver, '_execute')

        driver.execute('sudo', 'fake', '--foo', '--bar')

        self.assertEqual(0, driver._execute.call_count)
        self.ssh_executor.return_value.assert_called_once_with(
            'fake', '--foo', '--bar', run_as_root=True)

    def test_execute_with_retry(self):
        self.mock_object(time, 'sleep')
        self.mock_object(self.driver, 'execute', mock.Mock(
            side_effect=[exception.ProcessExecutionError('FAKE'), None]))
        self.driver.execute_with_retry('foo', 'bar')

        self.assertEqual(2, self.driver.execute.call_count)
        self.driver.execute.assert_has_calls(
            [mock.call('foo', 'bar'), mock.call('foo', 'bar')])

    def test_execute_with_retry_exceeded(self):
        self.mock_object(time, 'sleep')
        self.mock_object(self.driver, 'execute', mock.Mock(
            side_effect=exception.ProcessExecutionError('FAKE')))

        self.assertRaises(
            exception.ProcessExecutionError,
            self.driver.execute_with_retry,
            'foo', 'bar',
        )

        self.assertEqual(36, self.driver.execute.call_count)

    @ddt.data(True, False)
    def test__get_option(self, pool_level):
        out = """NAME   PROPERTY              VALUE                  SOURCE\n
foo_resource_name  bar_option_name           some_value              local"""
        self.mock_object(
            self.driver, '_execute', mock.Mock(return_value=(out, '')))
        res_name = 'foo_resource_name'
        opt_name = 'bar_option_name'

        result = self.driver._get_option(
            res_name, opt_name, pool_level=pool_level)

        self.assertEqual('some_value', result)
        self.driver._execute.assert_called_once_with(
            'zpool' if pool_level else 'zfs', 'get', opt_name, res_name,
            run_as_root=True)

    def test_parse_zfs_answer(self):
        not_parsed_str = ''
        not_parsed_str = """NAME   PROPERTY       VALUE              SOURCE\n
foo_res  opt_1           bar              local
foo_res  opt_2           foo              default
foo_res  opt_3           some_value       local"""
        expected = [
            {'NAME': 'foo_res', 'PROPERTY': 'opt_1', 'VALUE': 'bar',
             'SOURCE': 'local'},
            {'NAME': 'foo_res', 'PROPERTY': 'opt_2', 'VALUE': 'foo',
             'SOURCE': 'default'},
            {'NAME': 'foo_res', 'PROPERTY': 'opt_3', 'VALUE': 'some_value',
             'SOURCE': 'local'},
        ]

        result = self.driver.parse_zfs_answer(not_parsed_str)

        self.assertEqual(expected, result)

    def test_parse_zfs_answer_empty(self):
        result = self.driver.parse_zfs_answer('')

        self.assertEqual([], result)

    def test_get_zpool_option(self):
        self.mock_object(self.driver, '_get_option')
        zpool_name = 'foo_resource_name'
        opt_name = 'bar_option_name'

        result = self.driver.get_zpool_option(zpool_name, opt_name)

        self.assertEqual(self.driver._get_option.return_value, result)
        self.driver._get_option.assert_called_once_with(
            zpool_name, opt_name, True)

    def test_get_zfs_option(self):
        self.mock_object(self.driver, '_get_option')
        dataset_name = 'foo_resource_name'
        opt_name = 'bar_option_name'

        result = self.driver.get_zfs_option(dataset_name, opt_name)

        self.assertEqual(self.driver._get_option.return_value, result)
        self.driver._get_option.assert_called_once_with(
            dataset_name, opt_name, False)

    def test_zfs(self):
        self.mock_object(self.driver, 'execute')
        self.mock_object(self.driver, 'execute_with_retry')

        self.driver.zfs('foo', 'bar')

        self.assertEqual(0, self.driver.execute_with_retry.call_count)
        self.driver.execute.asssert_called_once_with(
            'sudo', 'zfs', 'foo', 'bar')

    def test_zfs_with_retry(self):
        self.mock_object(self.driver, 'execute')
        self.mock_object(self.driver, 'execute_with_retry')

        self.driver.zfs_with_retry('foo', 'bar')

        self.assertEqual(0, self.driver.execute.call_count)
        self.driver.execute_with_retry.asssert_called_once_with(
            'sudo', 'zfs', 'foo', 'bar')


@ddt.ddt
class NFSviaZFSHelperTestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        configuration = get_fake_configuration()
        self.out = "fake_out"
        self.mock_object(
            zfs_utils.utils, "execute", mock.Mock(return_value=(self.out, "")))
        self.helper = zfs_utils.NFSviaZFSHelper(configuration)

    def test_init(self):
        zfs_utils.utils.execute.assert_has_calls([
            mock.call("which", "exportfs"),
            mock.call("exportfs", run_as_root=True),
        ])

    def test_verify_setup_exportfs_not_installed(self):
        zfs_utils.utils.execute.reset_mock()
        zfs_utils.utils.execute.side_effect = [('', '')]

        self.assertRaises(
            exception.ZFSonLinuxException, self.helper.verify_setup)

        zfs_utils.utils.execute.assert_called_once_with("which", "exportfs")

    def test_verify_setup_error_calling_exportfs(self):
        zfs_utils.utils.execute.reset_mock()
        zfs_utils.utils.execute.side_effect = [
            ('fake_out', ''), exception.ProcessExecutionError('Fake')]

        self.assertRaises(
            exception.ProcessExecutionError, self.helper.verify_setup)

        zfs_utils.utils.execute.assert_has_calls([
            mock.call("which", "exportfs"),
            mock.call("exportfs", run_as_root=True),
        ])

    def test_is_kernel_version_true(self):
        delattr(self.helper, '_is_kernel_version')
        zfs_utils.utils.execute.reset_mock()

        self.assertTrue(self.helper.is_kernel_version)

        zfs_utils.utils.execute.assert_has_calls([
            mock.call("modinfo", "zfs"),
        ])

    def test_is_kernel_version_false(self):
        delattr(self.helper, '_is_kernel_version')
        zfs_utils.utils.execute.reset_mock()
        zfs_utils.utils.execute.side_effect = (
            exception.ProcessExecutionError('Fake'))

        self.assertFalse(self.helper.is_kernel_version)

        zfs_utils.utils.execute.assert_has_calls([
            mock.call("modinfo", "zfs"),
        ])

    def test_is_kernel_version_second_call(self):
        delattr(self.helper, '_is_kernel_version')
        zfs_utils.utils.execute.reset_mock()

        self.assertTrue(self.helper.is_kernel_version)
        self.assertTrue(self.helper.is_kernel_version)

        zfs_utils.utils.execute.assert_has_calls([
            mock.call("modinfo", "zfs"),
        ])

    def test_create_exports(self):
        self.mock_object(self.helper, 'get_exports')

        result = self.helper.create_exports('foo')

        self.assertEqual(
            self.helper.get_exports.return_value, result)

    def test_get_exports(self):
        self.mock_object(
            self.helper, 'get_zfs_option', mock.Mock(return_value='fake_mp'))
        expected = [
            {
                "path": "%s:fake_mp" % ip,
                "metadata": {},
                "is_admin_only": is_admin_only,
            } for ip, is_admin_only in (
                (self.helper.configuration.zfs_share_export_ip, False),
                (self.helper.configuration.zfs_service_ip, True))
        ]

        result = self.helper.get_exports('foo')

        self.assertEqual(expected, result)
        self.helper.get_zfs_option.assert_called_once_with(
            'foo', 'mountpoint', executor=None)

    def test_remove_exports(self):
        zfs_utils.utils.execute.reset_mock()
        self.mock_object(
            self.helper, 'get_zfs_option', mock.Mock(return_value='bar'))

        self.helper.remove_exports('foo')

        self.helper.get_zfs_option.assert_called_once_with(
            'foo', 'sharenfs', executor=None)
        zfs_utils.utils.execute.assert_called_once_with(
            'zfs', 'set', 'sharenfs=off', 'foo', run_as_root=True)

    def test_remove_exports_that_absent(self):
        zfs_utils.utils.execute.reset_mock()
        self.mock_object(
            self.helper, 'get_zfs_option', mock.Mock(return_value='off'))

        self.helper.remove_exports('foo')

        self.helper.get_zfs_option.assert_called_once_with(
            'foo', 'sharenfs', executor=None)
        self.assertEqual(0, zfs_utils.utils.execute.call_count)

    @ddt.data(
        (('fake_modinfo_result', ''),
         ('sharenfs=rw=1.1.1.1:3.3.3.0/255.255.255.0,no_root_squash,'
          'ro=2.2.2.2,no_root_squash'), False),
        (('fake_modinfo_result', ''),
         ('sharenfs=ro=1.1.1.1:2.2.2.2:3.3.3.0/255.255.255.0,no_root_squash'),
         True),
        (exception.ProcessExecutionError('Fake'),
         ('sharenfs=1.1.1.1:rw,no_root_squash 3.3.3.0/255.255.255.0:rw,'
          'no_root_squash 2.2.2.2:ro,no_root_squash'), False),
        (exception.ProcessExecutionError('Fake'),
         ('sharenfs=1.1.1.1:ro,no_root_squash 2.2.2.2:ro,'
          'no_root_squash 3.3.3.0/255.255.255.0:ro,no_root_squash'), True),
    )
    @ddt.unpack
    def test_update_access_rw_and_ro(self, modinfo_response, access_str,
                                     make_all_ro):
        delattr(self.helper, '_is_kernel_version')
        zfs_utils.utils.execute.reset_mock()
        dataset_name = 'zpoolz/foo_dataset_name/fake'
        zfs_utils.utils.execute.side_effect = [
            modinfo_response,
            ("""NAME            USED  AVAIL  REFER  MOUNTPOINT\n
%(dn)s                2.58M  14.8G  27.5K  /%(dn)s\n
%(dn)s_some_other     3.58M  15.8G  28.5K  /%(dn)s\n
             """ % {'dn': dataset_name}, ''),
            ('fake_set_opt_result', ''),
            ("""NAME                     PROPERTY    VALUE            SOURCE\n
%s          mountpoint  /%s  default\n
             """ % (dataset_name, dataset_name), ''),
            ('fake_1_result', ''),
            ('fake_2_result', ''),
            ('fake_3_result', ''),
            ('fake_4_result', ''),
            ('fake_5_result', ''),
        ]
        access_rules = [
            {'access_type': 'ip', 'access_level': 'rw',
             'access_to': '1.1.1.1'},
            {'access_type': 'ip', 'access_level': 'ro',
             'access_to': '2.2.2.2'},
            {'access_type': 'ip', 'access_level': 'rw',
             'access_to': '3.3.3.0/24'},
        ]
        delete_rules = [
            {'access_type': 'ip', 'access_level': 'rw',
             'access_to': '4.4.4.4'},
            {'access_type': 'ip', 'access_level': 'ro',
             'access_to': '5.5.5.5/32'},
            {'access_type': 'ip', 'access_level': 'ro',
             'access_to': '5.5.5.6/16'},
            {'access_type': 'ip', 'access_level': 'ro',
             'access_to': '5.5.5.7/0'},
            {'access_type': 'user', 'access_level': 'rw',
             'access_to': '6.6.6.6'},
            {'access_type': 'user', 'access_level': 'ro',
             'access_to': '7.7.7.7'},
        ]

        self.helper.update_access(
            dataset_name, access_rules, [], delete_rules,
            make_all_ro=make_all_ro)

        zfs_utils.utils.execute.assert_has_calls([
            mock.call('modinfo', 'zfs'),
            mock.call('zfs', 'list', '-r', 'zpoolz', run_as_root=True),
            mock.call(
                'zfs', 'set',
                access_str,
                dataset_name, run_as_root=True),
            mock.call(
                'zfs', 'get', 'mountpoint', dataset_name, run_as_root=True),
            mock.call(
                'exportfs', '-u', '4.4.4.4:/%s' % dataset_name,
                run_as_root=True),
            mock.call(
                'exportfs', '-u', '5.5.5.5:/%s' % dataset_name,
                run_as_root=True),
            mock.call(
                'exportfs', '-u', '5.5.5.6/255.255.0.0:/%s' % dataset_name,
                run_as_root=True),
            mock.call(
                'exportfs', '-u', '5.5.5.7/0.0.0.0:/%s' % dataset_name,
                run_as_root=True),
        ])

    def test_update_access_dataset_not_found(self):
        self.mock_object(zfs_utils.LOG, 'warning')
        zfs_utils.utils.execute.reset_mock()
        dataset_name = 'zpoolz/foo_dataset_name/fake'
        zfs_utils.utils.execute.side_effect = [
            ('fake_modinfo_result', ''),
            ('fake_dataset_not_found_result', ''),
            ('fake_set_opt_result', ''),
        ]
        access_rules = [
            {'access_type': 'ip', 'access_level': 'rw',
             'access_to': '1.1.1.1'},
            {'access_type': 'ip', 'access_level': 'ro',
             'access_to': '1.1.1.2'},
        ]

        self.helper.update_access(dataset_name, access_rules, [], [])

        zfs_utils.utils.execute.assert_has_calls([
            mock.call('zfs', 'list', '-r', 'zpoolz', run_as_root=True),
        ])
        zfs_utils.LOG.warning.assert_called_once_with(
            mock.ANY, {'name': dataset_name})

    @ddt.data(exception.ProcessExecutionError('Fake'), ('Ok', ''))
    def test_update_access_no_rules(self, first_execute_result):
        zfs_utils.utils.execute.reset_mock()
        dataset_name = 'zpoolz/foo_dataset_name/fake'
        zfs_utils.utils.execute.side_effect = [
            ("""NAME            USED  AVAIL  REFER  MOUNTPOINT\n
%s          2.58M  14.8G  27.5K  /%s\n
             """ % (dataset_name, dataset_name), ''),
            ('fake_set_opt_result', ''),
        ]

        self.helper.update_access(dataset_name, [], [], [])

        zfs_utils.utils.execute.assert_has_calls([
            mock.call('zfs', 'list', '-r', 'zpoolz', run_as_root=True),
            mock.call('zfs', 'set', 'sharenfs=off', dataset_name,
                      run_as_root=True),
        ])

    @ddt.data('user', 'cert', 'cephx', '', 'fake', 'i', 'p')
    def test_update_access_not_ip_access_type(self, access_type):
        zfs_utils.utils.execute.reset_mock()
        dataset_name = 'zpoolz/foo_dataset_name/fake'
        access_rules = [
            {'access_type': access_type, 'access_level': 'rw',
             'access_to': '1.1.1.1'},
            {'access_type': 'ip', 'access_level': 'ro',
             'access_to': '1.1.1.2'},
        ]

        self.assertRaises(
            exception.InvalidShareAccess,
            self.helper.update_access,
            dataset_name, access_rules, access_rules, [],
        )

        self.assertEqual(0, zfs_utils.utils.execute.call_count)

    @ddt.data('', 'r', 'o', 'w', 'fake', 'su')
    def test_update_access_neither_rw_nor_ro_access_level(self, access_level):
        zfs_utils.utils.execute.reset_mock()
        dataset_name = 'zpoolz/foo_dataset_name/fake'
        access_rules = [
            {'access_type': 'ip', 'access_level': access_level,
             'access_to': '1.1.1.1'},
            {'access_type': 'ip', 'access_level': 'ro',
             'access_to': '1.1.1.2'},
        ]

        self.assertRaises(
            exception.InvalidShareAccess,
            self.helper.update_access,
            dataset_name, access_rules, access_rules, [],
        )

        self.assertEqual(0, zfs_utils.utils.execute.call_count)
