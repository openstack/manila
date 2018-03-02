# Copyright 2015 Mirantis Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os

import ddt
import mock
from oslo_config import cfg

from manila.common import constants as const
from manila import exception
import manila.share.configuration
from manila.share.drivers import helpers
from manila import test
from manila.tests import fake_compute
from manila.tests import fake_utils
from manila.tests.share.drivers import test_generic


CONF = cfg.CONF


@ddt.ddt
class NFSHelperTestCase(test.TestCase):
    """Test case for NFS helper."""

    def setUp(self):
        super(NFSHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self)
        self.fake_conf = manila.share.configuration.Configuration(None)
        self._ssh_exec = mock.Mock(return_value=('', ''))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = helpers.NFSHelper(self._execute, self._ssh_exec,
                                         self.fake_conf)
        ip = '10.254.0.3'
        self.server = fake_compute.FakeServer(
            ip=ip, public_address=ip, instance_id='fake_instance_id')
        self.share_name = 'fake_share_name'

    def test_init_helper(self):

        # mocks
        self.mock_object(
            self._helper, '_ssh_exec',
            mock.Mock(side_effect=exception.ProcessExecutionError(
                stderr='command not found')))

        # run
        self.assertRaises(exception.ManilaException,
                          self._helper.init_helper, self.server)

        # asserts
        self._helper._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'exportfs'])

    def test_init_helper_log(self):

        # mocks
        self.mock_object(
            self._helper, '_ssh_exec',
            mock.Mock(side_effect=exception.ProcessExecutionError(
                stderr='fake')))

        # run
        self._helper.init_helper(self.server)

        # asserts
        self._helper._ssh_exec.assert_called_once_with(
            self.server, ['sudo', 'exportfs'])

    @ddt.data(
        {"server": {"public_address": "1.2.3.4"}, "version": 4},
        {"server": {"public_address": "1001::1002"}, "version": 6},
        {"server": {"public_address": "1.2.3.4", "admin_ip": "5.6.7.8"},
         "version": 4},
        {"server": {"public_address": "1.2.3.4", "ip": "9.10.11.12"},
         "version": 4},
        {"server": {"public_address": "1001::1001", "ip": "1001::1002"},
         "version": 6},
        {"server": {"public_address": "1001::1002", "admin_ip": "1001::1002"},
         "version": 6},
        {"server": {"public_addresses": ["1001::1002"]}, "version": 6},
        {"server": {"public_addresses": ["1.2.3.4", "1001::1002"]},
         "version": {"1.2.3.4": 4, "1001::1002": 6}},
    )
    @ddt.unpack
    def test_create_exports(self, server, version):
        result = self._helper.create_exports(server, self.share_name)

        expected_export_locations = []
        path = os.path.join(CONF.share_mount_path, self.share_name)
        service_address = server.get("admin_ip", server.get("ip"))
        version_copy = version

        def convert_address(address, version):
            if version == 4:
                return address
            return "[%s]" % address

        if 'public_addresses' in server:
            pairs = list(map(lambda addr: (addr, False),
                             server['public_addresses']))
        else:
            pairs = [(server['public_address'], False)]

        service_address = server.get("admin_ip", server.get("ip"))
        if service_address:
            pairs.append((service_address, True))

        for ip, is_admin in pairs:
            if isinstance(version_copy, dict):
                version = version_copy.get(ip)

            expected_export_locations.append({
                "path": "%s:%s" % (convert_address(ip, version), path),
                "is_admin_only": is_admin,
                "metadata": {
                    "export_location_metadata_example": "example",
                },
            })
        self.assertEqual(expected_export_locations, result)

    @ddt.data(const.ACCESS_LEVEL_RW, const.ACCESS_LEVEL_RO)
    def test_update_access(self, access_level):
        expected_mount_options = '%s,no_subtree_check,no_root_squash'
        self.mock_object(self._helper, '_sync_nfs_temp_and_perm_files')
        local_path = os.path.join(CONF.share_mount_path, self.share_name)
        exec_result = ' '.join([local_path, '2.2.2.3'])
        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(return_value=(exec_result, '')))
        access_rules = [
            test_generic.get_fake_access_rule('1.1.1.1', access_level),
            test_generic.get_fake_access_rule('2.2.2.2', access_level),
            test_generic.get_fake_access_rule('2.2.2.3', access_level)]
        add_rules = [
            test_generic.get_fake_access_rule('2.2.2.2', access_level),
            test_generic.get_fake_access_rule('2.2.2.3', access_level),
            test_generic.get_fake_access_rule('5.5.5.0/24', access_level)]
        delete_rules = [
            test_generic.get_fake_access_rule('3.3.3.3', access_level),
            test_generic.get_fake_access_rule('4.4.4.4', access_level, 'user'),
            test_generic.get_fake_access_rule('0.0.0.0/0', access_level)]
        self._helper.update_access(self.server, self.share_name, access_rules,
                                   add_rules=add_rules,
                                   delete_rules=delete_rules)
        local_path = os.path.join(CONF.share_mount_path, self.share_name)
        self._helper._ssh_exec.assert_has_calls([
            mock.call(self.server, ['sudo', 'exportfs']),
            mock.call(self.server, ['sudo', 'exportfs', '-u',
                                    ':'.join(['3.3.3.3', local_path])]),
            mock.call(self.server, ['sudo', 'exportfs', '-u',
                                    ':'.join(['*',
                                              local_path])]),
            mock.call(self.server, ['sudo', 'exportfs', '-o',
                                    expected_mount_options % access_level,
                                    ':'.join(['2.2.2.2', local_path])]),
            mock.call(self.server, ['sudo', 'exportfs', '-o',
                                    expected_mount_options % access_level,
                                    ':'.join(['5.5.5.0/24',
                                              local_path])]),
        ])
        self._helper._sync_nfs_temp_and_perm_files.assert_has_calls([
            mock.call(self.server), mock.call(self.server)])

    @ddt.data({'access': '10.0.0.1', 'result': '10.0.0.1'},
              {'access': '10.0.0.1/32', 'result': '10.0.0.1'},
              {'access': '10.0.0.0/24', 'result': '10.0.0.0/24'},
              {'access': '1001::1001', 'result': '[1001::1001]'},
              {'access': '1001::1000/128', 'result': '[1001::1000]'},
              {'access': '1001::1000/124', 'result': '[1001::1000]/124'})
    @ddt.unpack
    def test__get_parsed_address_or_cidr(self, access, result):
        self.assertEqual(result,
                         self._helper._get_parsed_address_or_cidr(access))

    @ddt.data('10.0.0.265', '10.0.0.1/33', '1001::10069', '1001::1000/129')
    def test__get_parsed_address_or_cidr_with_invalid_access(self, access):
        self.assertRaises(ValueError,
                          self._helper._get_parsed_address_or_cidr,
                          access)

    def test_update_access_invalid_type(self):
        access_rules = [test_generic.get_fake_access_rule(
            '2.2.2.2', const.ACCESS_LEVEL_RW, access_type='fake'), ]
        self.assertRaises(
            exception.InvalidShareAccess,
            self._helper.update_access,
            self.server,
            self.share_name,
            access_rules,
            [],
            [])

    def test_update_access_invalid_level(self):
        access_rules = [test_generic.get_fake_access_rule(
            '2.2.2.2', 'fake_level', access_type='ip'), ]
        self.assertRaises(
            exception.InvalidShareAccessLevel,
            self._helper.update_access,
            self.server,
            self.share_name,
            access_rules,
            [],
            [])

    def test_update_access_delete_invalid_rule(self):
        delete_rules = [test_generic.get_fake_access_rule(
            'lala', 'fake_level', access_type='user'), ]
        self.mock_object(self._helper, '_sync_nfs_temp_and_perm_files')
        self._helper.update_access(self.server, self.share_name, [],
                                   [], delete_rules)
        self._helper._sync_nfs_temp_and_perm_files.assert_called_with(
            self.server)

    def test_get_host_list(self):
        fake_exportfs = ('/shares/share-1\n\t\t20.0.0.3\n'
                         '/shares/share-1\n\t\t20.0.0.6\n'
                         '/shares/share-2\n\t\t10.0.0.2\n'
                         '/shares/share-2\n\t\t10.0.0.5\n'
                         '/shares/share-3\n\t\t30.0.0.4\n'
                         '/shares/share-3\n\t\t30.0.0.7\n')
        expected = ['20.0.0.3', '20.0.0.6']
        result = self._helper.get_host_list(fake_exportfs, '/shares/share-1')
        self.assertEqual(expected, result)

    @ddt.data({"level": const.ACCESS_LEVEL_RW, "ip": "1.1.1.1",
               "expected": "1.1.1.1"},
              {"level": const.ACCESS_LEVEL_RO, "ip": "1.1.1.1",
               "expected": "1.1.1.1"},
              {"level": const.ACCESS_LEVEL_RW, "ip": "fd12:abcd::10",
               "expected": "[fd12:abcd::10]"},
              {"level": const.ACCESS_LEVEL_RO, "ip": "fd12:abcd::10",
               "expected": "[fd12:abcd::10]"})
    @ddt.unpack
    def test_update_access_recovery_mode(self, level, ip, expected):
        expected_mount_options = '%s,no_subtree_check,no_root_squash'
        access_rules = [test_generic.get_fake_access_rule(
            ip, level), ]
        self.mock_object(self._helper, '_sync_nfs_temp_and_perm_files')
        self.mock_object(self._helper, 'get_host_list',
                         mock.Mock(return_value=[ip]))
        self._helper.update_access(self.server, self.share_name, access_rules,
                                   [], [])
        local_path = os.path.join(CONF.share_mount_path, self.share_name)
        self._ssh_exec.assert_has_calls([
            mock.call(self.server, ['sudo', 'exportfs']),
            mock.call(
                self.server, ['sudo', 'exportfs', '-u',
                              ':'.join([expected,
                                        local_path])]),
            mock.call(self.server, ['sudo', 'exportfs', '-o',
                                    expected_mount_options % level,
                                    ':'.join([expected, local_path])]),
        ])
        self._helper._sync_nfs_temp_and_perm_files.assert_called_with(
            self.server)

    def test_sync_nfs_temp_and_perm_files(self):
        self._helper._sync_nfs_temp_and_perm_files(self.server)
        self._helper._ssh_exec.assert_has_calls(
            [mock.call(self.server, mock.ANY) for i in range(1)])

    @ddt.data('/foo/bar', '5.6.7.8:/bar/quuz', '5.6.7.9:/foo/quuz',
              '[1001::1001]:/foo/bar', '[1001::1000]/:124:/foo/bar')
    def test_get_exports_for_share_single_ip(self, export_location):
        server = dict(public_address='1.2.3.4')

        result = self._helper.get_exports_for_share(server, export_location)

        path = export_location.split(':')[-1]
        expected_export_locations = [
            {"is_admin_only": False,
             "path": "%s:%s" % (server["public_address"], path),
             "metadata": {"export_location_metadata_example": "example"}}
        ]
        self.assertEqual(expected_export_locations, result)

    @ddt.data('/foo/bar', '5.6.7.8:/bar/quuz', '5.6.7.9:/foo/quuz')
    def test_get_exports_for_share_multi_ip(self, export_location):
        server = dict(public_addresses=['1.2.3.4', '1.2.3.5'])

        result = self._helper.get_exports_for_share(server, export_location)

        path = export_location.split(':')[-1]
        expected_export_locations = list(map(
            lambda addr: {
                "is_admin_only": False,
                "path": "%s:%s" % (addr, path),
                "metadata": {"export_location_metadata_example": "example"}
            },
            server['public_addresses'])
        )
        self.assertEqual(expected_export_locations, result)

    @ddt.data(
        {'public_address_with_suffix': 'foo'},
        {'with_prefix_public_address': 'bar'},
        {'with_prefix_public_address_and_with_suffix': 'quuz'}, {})
    def test_get_exports_for_share_with_error(self, server):
        export_location = '1.2.3.4:/foo/bar'

        self.assertRaises(
            exception.ManilaException,
            self._helper.get_exports_for_share, server, export_location)

    @ddt.data('/foo/bar', '5.6.7.8:/foo/bar', '5.6.7.88:fake:/foo/bar',
              '[1001::1002]:/foo/bar', '[1001::1000]/124:/foo/bar')
    def test_get_share_path_by_export_location(self, export_location):
        result = self._helper.get_share_path_by_export_location(
            dict(), export_location)

        self.assertEqual('/foo/bar', result)

    @ddt.data(
        ('/shares/fake_share1\n\t\t1.1.1.10\n'
         '/shares/fake_share2\n\t\t1.1.1.16\n'
         '/mnt/fake_share1 1.1.1.11', False),
        ('/shares/fake_share_name\n\t\t1.1.1.10\n'
         '/shares/fake_share_name\n\t\t1.1.1.16\n'
         '/mnt/fake_share1\n\t\t1.1.1.11', True),
        ('/mnt/fake_share_name\n\t\t1.1.1.11\n'
         '/shares/fake_share_name\n\t\t1.1.1.10\n'
         '/shares/fake_share_name\n\t\t1.1.1.16\n', True))
    @ddt.unpack
    def test_disable_access_for_maintenance(self, output, hosts_match):
        fake_maintenance_path = "fake.path"
        self._helper.configuration.share_mount_path = '/shares'
        local_path = os.path.join(self._helper.configuration.share_mount_path,
                                  self.share_name)

        def fake_ssh_exec(*args, **kwargs):
            if 'exportfs' in args[1] and '-u' not in args[1]:
                return output, ''
            else:
                return '', ''

        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(side_effect=fake_ssh_exec))

        self.mock_object(self._helper, '_sync_nfs_temp_and_perm_files')
        self.mock_object(self._helper, '_get_maintenance_file_path',
                         mock.Mock(return_value=fake_maintenance_path))

        self._helper.disable_access_for_maintenance(
            self.server, self.share_name)

        self._helper._ssh_exec.assert_any_call(
            self.server,
            ['cat', const.NFS_EXPORTS_FILE,
             '|', 'grep', self.share_name,
             '|', 'sudo', 'tee', fake_maintenance_path]
        )
        self._helper._ssh_exec.assert_has_calls([
            mock.call(self.server, ['sudo', 'exportfs']),
        ])

        if hosts_match:
            self._helper._ssh_exec.assert_has_calls([
                mock.call(self.server, ['sudo', 'exportfs', '-u',
                                        ':'.join(['1.1.1.10', local_path])]),
                mock.call(self.server, ['sudo', 'exportfs', '-u',
                                        ':'.join(['1.1.1.16', local_path])]),
            ])

        self._helper._sync_nfs_temp_and_perm_files.assert_called_once_with(
            self.server
        )

    def test_restore_access_after_maintenance(self):
        fake_maintenance_path = "fake.path"
        self.mock_object(self._helper, '_get_maintenance_file_path',
                         mock.Mock(return_value=fake_maintenance_path))
        self.mock_object(self._helper, '_ssh_exec')

        self._helper.restore_access_after_maintenance(
            self.server, self.share_name)

        self._helper._ssh_exec.assert_called_once_with(
            self.server,
            ['cat', fake_maintenance_path,
             '|', 'sudo', 'tee', '-a', const.NFS_EXPORTS_FILE,
             '&&', 'sudo', 'exportfs', '-r', '&&', 'sudo', 'rm', '-f',
             fake_maintenance_path]
        )


@ddt.ddt
class CIFSHelperIPAccessTestCase(test.TestCase):
    """Test case for CIFS helper with IP access."""

    def setUp(self):
        super(CIFSHelperIPAccessTestCase, self).setUp()
        self.server_details = {'instance_id': 'fake',
                               'public_address': '1.2.3.4', }
        self.share_name = 'fake_share_name'
        self.fake_conf = manila.share.configuration.Configuration(None)
        self._ssh_exec = mock.Mock(return_value=('', ''))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = helpers.CIFSHelperIPAccess(self._execute,
                                                  self._ssh_exec,
                                                  self.fake_conf)
        self.access = dict(
            access_level=const.ACCESS_LEVEL_RW,
            access_type='ip',
            access_to='1.1.1.1')

    def test_init_helper(self):
        self._helper.init_helper(self.server_details)
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details,
            ['sudo', 'net', 'conf', 'list'],
        )

    def test_create_export_share_does_not_exist(self):
        def fake_ssh_exec(*args, **kwargs):
            if 'showshare' in args[1]:
                raise exception.ProcessExecutionError()
            else:
                return '', ''

        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(side_effect=fake_ssh_exec))

        ret = self._helper.create_exports(self.server_details, self.share_name)

        expected_location = [{
            "is_admin_only": False,
            "path": "\\\\%s\\%s" % (
                self.server_details['public_address'], self.share_name),
            "metadata": {"export_location_metadata_example": "example"}
        }]
        self.assertEqual(expected_location, ret)
        share_path = os.path.join(
            self._helper.configuration.share_mount_path,
            self.share_name)
        self._helper._ssh_exec.assert_has_calls([
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'showshare', self.share_name, ]
            ),
            mock.call(
                self.server_details,
                [
                    'sudo', 'net', 'conf', 'addshare', self.share_name,
                    share_path, 'writeable=y', 'guest_ok=y',
                ]
            ),
            mock.call(self.server_details, mock.ANY),
        ])

    def test_create_export_share_does_not_exist_exception(self):

        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(
                             side_effect=[exception.ProcessExecutionError(),
                                          Exception('')]
                         ))

        self.assertRaises(
            exception.ManilaException, self._helper.create_exports,
            self.server_details, self.share_name)

    def test_create_exports_share_exist_recreate_true(self):
        ret = self._helper.create_exports(
            self.server_details, self.share_name, recreate=True)

        expected_location = [{
            "is_admin_only": False,
            "path": "\\\\%s\\%s" % (
                self.server_details['public_address'], self.share_name),
            "metadata": {"export_location_metadata_example": "example"}
        }]
        self.assertEqual(expected_location, ret)
        share_path = os.path.join(
            self._helper.configuration.share_mount_path,
            self.share_name)
        self._helper._ssh_exec.assert_has_calls([
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'showshare', self.share_name, ]
            ),
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'delshare', self.share_name, ]
            ),
            mock.call(
                self.server_details,
                [
                    'sudo', 'net', 'conf', 'addshare', self.share_name,
                    share_path, 'writeable=y', 'guest_ok=y',
                ]
            ),
            mock.call(self.server_details, mock.ANY),
        ])

    def test_create_export_share_exist_recreate_false(self):
        self.assertRaises(
            exception.ShareBackendException,
            self._helper.create_exports,
            self.server_details,
            self.share_name,
            recreate=False,
        )
        self._helper._ssh_exec.assert_has_calls([
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'showshare', self.share_name, ]
            ),
        ])

    def test_remove_exports(self):
        self._helper.remove_exports(self.server_details, self.share_name)

        self._helper._ssh_exec.assert_called_once_with(
            self.server_details,
            ['sudo', 'net', 'conf', 'delshare', self.share_name],
        )

    def test_remove_export_forcibly(self):
        delshare_command = ['sudo', 'net', 'conf', 'delshare', self.share_name]

        def fake_ssh_exec(*args, **kwargs):
            if delshare_command == args[1]:
                raise exception.ProcessExecutionError()
            else:
                return ('', '')

        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(side_effect=fake_ssh_exec))

        self._helper.remove_exports(self.server_details, self.share_name)

        self._helper._ssh_exec.assert_has_calls([
            mock.call(
                self.server_details,
                ['sudo', 'net', 'conf', 'delshare', self.share_name],
            ),
            mock.call(
                self.server_details,
                ['sudo', 'smbcontrol', 'all', 'close-share', self.share_name],
            ),
        ])

    def test_update_access_wrong_access_level(self):
        access_rules = [test_generic.get_fake_access_rule(
            '2.2.2.2', const.ACCESS_LEVEL_RO), ]
        self.assertRaises(
            exception.InvalidShareAccessLevel,
            self._helper.update_access,
            self.server_details,
            self.share_name,
            access_rules,
            [],
            [])

    def test_update_access_wrong_access_type(self):
        access_rules = [test_generic.get_fake_access_rule(
            '2.2.2.2', const.ACCESS_LEVEL_RW, access_type='fake'), ]
        self.assertRaises(
            exception.InvalidShareAccess,
            self._helper.update_access,
            self.server_details,
            self.share_name,
            access_rules,
            [],
            [])

    def test_update_access(self):
        access_rules = [test_generic.get_fake_access_rule(
            '1.1.1.1', const.ACCESS_LEVEL_RW), ]

        self._helper.update_access(self.server_details, self.share_name,
                                   access_rules, [], [])
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details, ['sudo', 'net', 'conf', 'setparm',
                                  self.share_name, 'hosts allow',
                                  '1.1.1.1'])

    def test_get_allow_hosts(self):
        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(
                             return_value=('1.1.1.1 2.2.2.2 3.3.3.3', '')))
        expected = ['1.1.1.1', '2.2.2.2', '3.3.3.3']
        result = self._helper._get_allow_hosts(
            self.server_details, self.share_name)
        self.assertEqual(expected, result)
        cmd = ['sudo', 'net', 'conf', 'getparm', self.share_name,
               'hosts allow']
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details, cmd)

    @ddt.data(
        '', '1.2.3.4:/nfs/like/export', '/1.2.3.4/foo', '\\1.2.3.4\\foo',
        '//1.2.3.4\\mixed_slashes_and_backslashes_one',
        '\\\\1.2.3.4/mixed_slashes_and_backslashes_two')
    def test__get_share_group_name_from_export_location(self, export_location):
        self.assertRaises(
            exception.InvalidShare,
            self._helper._get_share_group_name_from_export_location,
            export_location)

    @ddt.data('//5.6.7.8/foo', '\\\\5.6.7.8\\foo')
    def test_get_exports_for_share(self, export_location):
        server = dict(public_address='1.2.3.4')
        self.mock_object(
            self._helper, '_get_share_group_name_from_export_location',
            mock.Mock(side_effect=(
                self._helper._get_share_group_name_from_export_location)))

        result = self._helper.get_exports_for_share(server, export_location)

        expected_export_location = [{
            "is_admin_only": False,
            "path": "\\\\%s\\foo" % server['public_address'],
            "metadata": {"export_location_metadata_example": "example"}
        }]
        self.assertEqual(expected_export_location, result)
        (self._helper._get_share_group_name_from_export_location.
            assert_called_once_with(export_location))

    @ddt.data(
        {'public_address_with_suffix': 'foo'},
        {'with_prefix_public_address': 'bar'},
        {'with_prefix_public_address_and_with_suffix': 'quuz'}, {})
    def test_get_exports_for_share_with_exception(self, server):
        export_location = '1.2.3.4:/foo/bar'

        self.assertRaises(
            exception.ManilaException,
            self._helper.get_exports_for_share, server, export_location)

    @ddt.data('//5.6.7.8/foo', '\\\\5.6.7.8\\foo')
    def test_get_share_path_by_export_location(self, export_location):
        fake_path = ' /bar/quuz\n '
        fake_server = dict()
        self.mock_object(
            self._helper, '_ssh_exec',
            mock.Mock(return_value=(fake_path, 'fake')))
        self.mock_object(
            self._helper, '_get_share_group_name_from_export_location',
            mock.Mock(side_effect=(
                self._helper._get_share_group_name_from_export_location)))

        result = self._helper.get_share_path_by_export_location(
            fake_server, export_location)

        self.assertEqual('/bar/quuz', result)
        self._helper._ssh_exec.assert_called_once_with(
            fake_server, ['sudo', 'net', 'conf', 'getparm', 'foo', 'path'])
        (self._helper._get_share_group_name_from_export_location.
            assert_called_once_with(export_location))

    def test_disable_access_for_maintenance(self):
        allowed_hosts = ['test', 'test2']
        maintenance_path = os.path.join(
            self._helper.configuration.share_mount_path,
            "%s.maintenance" % self.share_name)
        self.mock_object(self._helper, '_set_allow_hosts')
        self.mock_object(self._helper, '_get_allow_hosts',
                         mock.Mock(return_value=allowed_hosts))

        self._helper.disable_access_for_maintenance(
            self.server_details, self.share_name)

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_called_once_with(
            self.server_details, [], self.share_name)
        valid_cmd = ['echo', "'test test2'", '|', 'sudo', 'tee',
                     maintenance_path]
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details, valid_cmd)

    def test_restore_access_after_maintenance(self):
        fake_maintenance_path = "test.path"
        self.mock_object(self._helper, '_set_allow_hosts')
        self.mock_object(self._helper, '_get_maintenance_file_path',
                         mock.Mock(return_value=fake_maintenance_path))
        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(side_effect=[("fake fake2", 0), "fake"]))

        self._helper.restore_access_after_maintenance(
            self.server_details, self.share_name)

        self._helper._set_allow_hosts.assert_called_once_with(
            self.server_details, ['fake', 'fake2'], self.share_name)
        self._helper._ssh_exec.assert_any_call(
            self.server_details, ['cat', fake_maintenance_path])
        self._helper._ssh_exec.assert_any_call(
            self.server_details, ['sudo', 'rm', '-f', fake_maintenance_path])


@ddt.ddt
class CIFSHelperUserAccessTestCase(test.TestCase):
    """Test case for CIFS helper with user access."""
    access_rw = dict(
        access_level=const.ACCESS_LEVEL_RW,
        access_type='user',
        access_to='manila-user')
    access_ro = dict(
        access_level=const.ACCESS_LEVEL_RO,
        access_type='user',
        access_to='manila-user')

    def setUp(self):
        super(CIFSHelperUserAccessTestCase, self).setUp()
        self.server_details = {'instance_id': 'fake',
                               'public_address': '1.2.3.4', }
        self.share_name = 'fake_share_name'
        self.fake_conf = manila.share.configuration.Configuration(None)
        self._ssh_exec = mock.Mock(return_value=('', ''))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = helpers.CIFSHelperUserAccess(
            self._execute, self._ssh_exec, self.fake_conf)

    def test_update_access_exception_type(self):
        access_rules = [test_generic.get_fake_access_rule(
            'user1', const.ACCESS_LEVEL_RW, access_type='ip')]
        self.assertRaises(exception.InvalidShareAccess,
                          self._helper.update_access, self.server_details,
                          self.share_name, access_rules, [], [])

    def test_update_access(self):
        access_list = [test_generic.get_fake_access_rule(
            'user1', const.ACCESS_LEVEL_RW, access_type='user'),
            test_generic.get_fake_access_rule(
                'user2', const.ACCESS_LEVEL_RO, access_type='user')]
        self._helper.update_access(self.server_details, self.share_name,
                                   access_list, [], [])

        self._helper._ssh_exec.assert_has_calls([
            mock.call(self.server_details,
                      ['sudo', 'net', 'conf', 'setparm', self.share_name,
                       'valid users', 'user1']),
            mock.call(self.server_details,
                      ['sudo', 'net', 'conf', 'setparm', self.share_name,
                       'read list', 'user2'])
        ])

    def test_update_access_exception_level(self):
        access_rules = [test_generic.get_fake_access_rule(
            'user1', 'fake_level', access_type='user'), ]
        self.assertRaises(
            exception.InvalidShareAccessLevel,
            self._helper.update_access,
            self.server_details,
            self.share_name,
            access_rules,
            [],
            [])


@ddt.ddt
class NFSSynchronizedTestCase(test.TestCase):

    @helpers.nfs_synchronized
    def wrapped_method(self, server, share_name):
        return server['instance_id'] + share_name

    @ddt.data(
        ({'lock_name': 'FOO', 'instance_id': 'QUUZ'}, 'nfs-FOO'),
        ({'instance_id': 'QUUZ'}, 'nfs-QUUZ'),
    )
    @ddt.unpack
    def test_with_lock_name(self, server, expected_lock_name):
        share_name = 'fake_share_name'
        self.mock_object(
            helpers.utils, 'synchronized',
            mock.Mock(side_effect=helpers.utils.synchronized))

        result = self.wrapped_method(server, share_name)

        self.assertEqual(server['instance_id'] + share_name, result)
        helpers.utils.synchronized.assert_called_once_with(
            expected_lock_name, external=True)
