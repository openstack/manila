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

    def test_create_export(self):
        ret = self._helper.create_export(self.server, self.share_name)
        expected_location = ':'.join([self.server['public_address'],
                                      os.path.join(CONF.share_mount_path,
                                                   self.share_name)])
        self.assertEqual(expected_location, ret)

    @ddt.data(const.ACCESS_LEVEL_RW, const.ACCESS_LEVEL_RO)
    def test_allow_access(self, data):
        self.mock_object(self._helper, '_sync_nfs_temp_and_perm_files')
        self._helper.allow_access(
            self.server, self.share_name, 'ip', data, '10.0.0.2')
        local_path = os.path.join(CONF.share_mount_path, self.share_name)
        self._ssh_exec.assert_has_calls([
            mock.call(self.server, ['sudo', 'exportfs']),
            mock.call(self.server, ['sudo', 'exportfs', '-o',
                                    '%s,no_subtree_check' % data,
                                    ':'.join(['10.0.0.2', local_path])])
        ])
        self._helper._sync_nfs_temp_and_perm_files.assert_called_once_with(
            self.server)

    def test_allow_access_no_ip(self):
        self.assertRaises(
            exception.InvalidShareAccess,
            self._helper.allow_access,
            self.server, self.share_name,
            'fake_type', 'fake_level', 'fake_rule')

    @ddt.data(const.ACCESS_LEVEL_RW, const.ACCESS_LEVEL_RO)
    def test_deny_access(self, data):
        self.mock_object(self._helper, '_sync_nfs_temp_and_perm_files')
        local_path = os.path.join(CONF.share_mount_path, self.share_name)
        access = dict(
            access_to='10.0.0.2', access_type='ip', access_level=data)
        self._helper.deny_access(self.server, self.share_name, access)
        export_string = ':'.join(['10.0.0.2', local_path])
        expected_exec = ['sudo', 'exportfs', '-u', export_string]
        self._ssh_exec.assert_called_once_with(self.server, expected_exec)
        self._helper._sync_nfs_temp_and_perm_files.assert_called_once_with(
            self.server)

    def test_sync_nfs_temp_and_perm_files(self):
        self._helper._sync_nfs_temp_and_perm_files(self.server)
        self._helper._ssh_exec.assert_has_calls(
            [mock.call(self.server, mock.ANY) for i in range(1)])

    @ddt.data('/foo/bar', '5.6.7.8:/bar/quuz', '5.6.7.88:/foo/quuz')
    def test_get_exports_for_share(self, export_location):
        server = dict(public_address='1.2.3.4')

        result = self._helper.get_exports_for_share(server, export_location)

        path = export_location.split(':')[-1]
        self.assertEqual([':'.join([server['public_address'], path])], result)

    @ddt.data(
        {'public_address_with_suffix': 'foo'},
        {'with_prefix_public_address': 'bar'},
        {'with_prefix_public_address_and_with_suffix': 'quuz'}, {})
    def test_get_exports_for_share_with_error(self, server):
        export_location = '1.2.3.4:/foo/bar'

        self.assertRaises(
            exception.ManilaException,
            self._helper.get_exports_for_share, server, export_location)

    @ddt.data('/foo/bar', '5.6.7.8:/foo/bar', '5.6.7.88:fake:/foo/bar')
    def test_get_share_path_by_export_location(self, export_location):
        result = self._helper.get_share_path_by_export_location(
            dict(), export_location)

        self.assertEqual('/foo/bar', result)

    def test_disable_access_for_maintenance(self):
        fake_maintenance_path = "fake.path"
        share_mount_path = os.path.join(
            self._helper.configuration.share_mount_path, self.share_name)
        self.mock_object(self._helper, '_ssh_exec')
        self.mock_object(self._helper, '_sync_nfs_temp_and_perm_files')
        self.mock_object(self._helper, '_get_maintenance_file_path',
                         mock.Mock(return_value=fake_maintenance_path))

        self._helper.disable_access_for_maintenance(
            self.server, self.share_name)

        self._helper._ssh_exec.assert_any_call(
            self.server,
            ['cat', const.NFS_EXPORTS_FILE,
             '| grep', self.share_name,
             '| sudo tee', fake_maintenance_path]
        )
        self._helper._ssh_exec.assert_any_call(
            self.server,
            ['sudo', 'exportfs', '-u', share_mount_path]
        )
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
             '| sudo tee -a', const.NFS_EXPORTS_FILE,
             '&& sudo exportfs -r', '&& sudo rm -f',
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
                return ('', '')

        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(side_effect=fake_ssh_exec))

        ret = self._helper.create_export(self.server_details, self.share_name)
        expected_location = '\\\\%s\\%s' % (
            self.server_details['public_address'], self.share_name)
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
        ])

    def test_create_export_share_exist_recreate_true(self):
        ret = self._helper.create_export(self.server_details, self.share_name,
                                         recreate=True)
        expected_location = '\\\\%s\\%s' % (
            self.server_details['public_address'], self.share_name)
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
        ])

    def test_create_export_share_exist_recreate_false(self):
        self.assertRaises(
            exception.ShareBackendException,
            self._helper.create_export,
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

    def test_remove_export(self):
        self._helper.remove_export(self.server_details, self.share_name)
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

        self._helper.remove_export(self.server_details, self.share_name)

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

    def test_allow_access_ip_exist(self):
        hosts = [self.access['access_to'], ]
        self.mock_object(self._helper, '_get_allow_hosts',
                         mock.Mock(return_value=hosts))
        self.mock_object(self._helper, '_set_allow_hosts')

        self.assertRaises(
            exception.ShareAccessExists,
            self._helper.allow_access,
            self.server_details,
            self.share_name,
            self.access['access_type'],
            self.access['access_level'],
            self.access['access_to'])

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_has_calls([])

    def test_allow_access_ip_does_not_exist(self):
        hosts = []
        self.mock_object(self._helper, '_get_allow_hosts',
                         mock.Mock(return_value=hosts))
        self.mock_object(self._helper, '_set_allow_hosts')

        self._helper.allow_access(
            self.server_details, self.share_name,
            self.access['access_type'], self.access['access_level'],
            self.access['access_to'])

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_called_once_with(
            self.server_details, hosts, self.share_name)

    def test_allow_access_wrong_type(self):
        self.assertRaises(
            exception.InvalidShareAccess,
            self._helper.allow_access,
            self.server_details,
            self.share_name, 'fake', const.ACCESS_LEVEL_RW, '1.1.1.1')

    @ddt.data(const.ACCESS_LEVEL_RO, 'fake')
    def test_allow_access_wrong_access_level(self, data):
        self.assertRaises(
            exception.InvalidShareAccessLevel,
            self._helper.allow_access,
            self.server_details,
            self.share_name, 'ip', data, '1.1.1.1')

    @ddt.data(const.ACCESS_LEVEL_RO, 'fake')
    def test_deny_access_unsupported_access_level(self, data):
        access = dict(access_to='1.1.1.1', access_level=data)
        self.mock_object(self._helper, '_get_allow_hosts')
        self.mock_object(self._helper, '_set_allow_hosts')

        self._helper.deny_access(self.server_details, self.share_name, access)

        self.assertFalse(self._helper._get_allow_hosts.called)
        self.assertFalse(self._helper._set_allow_hosts.called)

    def test_deny_access_list_has_value(self):
        hosts = [self.access['access_to'], ]
        self.mock_object(self._helper, '_get_allow_hosts',
                         mock.Mock(return_value=hosts))
        self.mock_object(self._helper, '_set_allow_hosts')

        self._helper.deny_access(
            self.server_details, self.share_name, self.access)
        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_called_once_with(
            self.server_details, [], self.share_name)

    def test_deny_access_list_does_not_have_value(self):
        hosts = []
        self.mock_object(self._helper, '_get_allow_hosts',
                         mock.Mock(return_value=hosts))
        self.mock_object(self._helper, '_set_allow_hosts')

        self._helper.deny_access(
            self.server_details, self.share_name, self.access)

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_has_calls([])

    def test_deny_access_force(self):
        self.mock_object(
            self._helper,
            '_get_allow_hosts',
            mock.Mock(side_effect=exception.ProcessExecutionError()),
        )
        self.mock_object(self._helper, '_set_allow_hosts')

        self._helper.deny_access(
            self.server_details, self.share_name, self.access, force=True)

        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_has_calls([])

    def test_deny_access_not_force(self):
        def raise_process_execution_error(*args, **kwargs):
            raise exception.ProcessExecutionError()

        self.mock_object(self._helper, '_get_allow_hosts',
                         mock.Mock(side_effect=raise_process_execution_error))
        self.mock_object(self._helper, '_set_allow_hosts')
        self.assertRaises(
            exception.ProcessExecutionError,
            self._helper.deny_access,
            self.server_details, self.share_name, self.access)
        self._helper._get_allow_hosts.assert_called_once_with(
            self.server_details, self.share_name)
        self._helper._set_allow_hosts.assert_has_calls([])

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

        expected_export_location = ['\\\\%s\\foo' % server['public_address']]
        self.assertEqual(expected_export_location, result)
        self._helper._get_share_group_name_from_export_location.\
            assert_called_once_with(export_location)

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
        self._helper._get_share_group_name_from_export_location.\
            assert_called_once_with(export_location)

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
        valid_cmd = ['echo', "'test test2'", '| sudo tee', maintenance_path]
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
            self.server_details, ['sudo rm -f', fake_maintenance_path])


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

    @ddt.data('ip', 'cert', 'fake')
    def test_allow_access_wrong_type(self, wrong_access_type):
        self.assertRaises(
            exception.InvalidShareAccess,
            self._helper.allow_access,
            self.server_details,
            self.share_name,
            wrong_access_type,
            const.ACCESS_LEVEL_RW,
            '1.1.1.1')

    @ddt.data(access_rw, access_ro)
    def test_allow_access_ro_rule_does_not_exist(self, access):
        users = ['user1', 'user2']
        self.mock_object(self._helper, '_get_valid_users',
                         mock.Mock(return_value=users))
        self.mock_object(self._helper, '_set_valid_users')

        self._helper.allow_access(
            self.server_details, self.share_name,
            access['access_type'], access['access_level'],
            access['access_to'])
        self.assertEqual(
            [mock.call(self.server_details, self.share_name),
             mock.call(self.server_details, self.share_name,
                       access['access_level'])],
            self._helper._get_valid_users.call_args_list)
        self._helper._set_valid_users.assert_called_once_with(
            self.server_details,
            users,
            self.share_name,
            access['access_level'])

    @ddt.data(access_rw, access_ro)
    def test_allow_access_ro_rule_exists(self, access):
        users = ['user1', 'user2', 'manila-user']
        self.mock_object(self._helper, '_get_valid_users',
                         mock.Mock(return_value=users))

        self.assertRaises(
            exception.ShareAccessExists,
            self._helper.allow_access,
            self.server_details,
            self.share_name,
            access['access_type'],
            access['access_level'],
            access['access_to'])

    @ddt.data(access_rw, access_ro)
    def test_deny_access_list_has_value(self, access):
        users = ['user1', 'user2', 'manila-user']
        self.mock_object(self._helper, '_get_valid_users',
                         mock.Mock(return_value=users))
        self.mock_object(self._helper, '_set_valid_users')

        self._helper.deny_access(
            self.server_details, self.share_name, access)
        self._helper._get_valid_users.assert_called_once_with(
            self.server_details,
            self.share_name,
            access['access_level'],
            force=False)
        self._helper._set_valid_users.assert_called_once_with(
            self.server_details, ['user1', 'user2'], self.share_name,
            access['access_level'])

    @ddt.data(access_rw, access_ro)
    def test_deny_access_list_does_not_have_value(self, access):
        users = []
        self.mock_object(self._helper, '_get_valid_users',
                         mock.Mock(return_value=users))
        self.mock_object(self._helper, '_set_valid_users')

        self._helper.deny_access(
            self.server_details, self.share_name, access)
        self._helper._get_valid_users.assert_called_once_with(
            self.server_details,
            self.share_name,
            access['access_level'],
            force=False)
        self._helper._set_valid_users.assert_has_calls([])

    @ddt.data(access_rw, access_ro)
    def test_deny_access_force_access_exists(self, access):
        users = ['user1', 'user2', 'manila-user']
        self.mock_object(self._helper, '_get_valid_users',
                         mock.Mock(return_value=users))
        self.mock_object(self._helper, '_set_valid_users')

        self._helper.deny_access(
            self.server_details, self.share_name, access, force=True)
        self._helper._get_valid_users.assert_called_once_with(
            self.server_details,
            self.share_name,
            access['access_level'],
            force=True)
        self._helper._set_valid_users.assert_called_once_with(
            self.server_details, ['user1', 'user2'], self.share_name,
            access['access_level'])

    @ddt.data(access_rw, access_ro)
    def test_deny_access_force_access_does_not_exist(self, access):
        self.mock_object(
            self._helper,
            '_get_valid_users',
            mock.Mock(return_value=[]),
        )
        self.mock_object(self._helper, '_set_valid_users')

        self._helper.deny_access(
            self.server_details, self.share_name, access, force=True)

        self._helper._get_valid_users.assert_called_once_with(
            self.server_details,
            self.share_name,
            access['access_level'],
            force=True)
        self._helper._set_valid_users.assert_has_calls([])

    @ddt.data(access_rw, access_ro)
    def test_deny_access_force_exc(self, access):
        self.mock_object(
            self._helper,
            '_get_valid_users',
            mock.Mock(side_effect=exception.ProcessExecutionError()),
        )
        self.mock_object(self._helper, '_set_valid_users')

        self.assertRaises(exception.ProcessExecutionError,
                          self._helper.deny_access,
                          self.server_details,
                          self.share_name,
                          access,
                          force=True)
        self._helper._get_valid_users.assert_called_once_with(
            self.server_details,
            self.share_name,
            access['access_level'],
            force=True)

    def test_get_conf_param_rw(self):
        result = self._helper._get_conf_param(const.ACCESS_LEVEL_RW)
        self.assertEqual('valid users', result)

    def test_get_conf_param_ro(self):
        result = self._helper._get_conf_param(const.ACCESS_LEVEL_RO)
        self.assertEqual('read list', result)

    @ddt.data(False, True)
    def test_get_valid_users(self, force):
        users = ("\"manila-user\" \"user1\" \"user2\"", None)
        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(return_value=users))
        result = self._helper._get_valid_users(self.server_details,
                                               self.share_name,
                                               const.ACCESS_LEVEL_RW,
                                               force=force)
        self.assertEqual(['manila-user', 'user1', 'user2'], result)
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details,
            ['sudo', 'net', 'conf', 'getparm', self.share_name, 'valid users'])

    @ddt.data(False, True)
    def test_get_valid_users_access_level_none(self, force):
        def fake_ssh_exec(*args, **kwargs):
            if 'valid users' in args[1]:
                return ("\"user1\"", '')
            else:
                return ("\"user2\"", '')

        self.mock_object(self._helper, '_ssh_exec',
                         mock.Mock(side_effect=fake_ssh_exec))

        result = self._helper._get_valid_users(self.server_details,
                                               self.share_name,
                                               force=force)
        self.assertEqual(['user1', 'user2'], result)
        for param in ['read list', 'valid users']:
            self._helper._ssh_exec.assert_any_call(
                self.server_details,
                ['sudo', 'net', 'conf', 'getparm', self.share_name, param])

    def test_get_valid_users_access_level_none_with_exc(self):
        self.mock_object(
            self._helper,
            '_ssh_exec',
            mock.Mock(side_effect=exception.ProcessExecutionError()))
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper._get_valid_users,
                          self.server_details,
                          self.share_name,
                          force=False)
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details,
            ['sudo', 'net', 'conf', 'getparm', self.share_name, 'valid users'])

    def test_get_valid_users_force_with_exc(self):
        self.mock_object(
            self._helper,
            '_ssh_exec',
            mock.Mock(side_effect=exception.ProcessExecutionError()))
        result = self._helper._get_valid_users(self.server_details,
                                               self.share_name,
                                               const.ACCESS_LEVEL_RW)
        self.assertEqual([], result)
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details,
            ['sudo', 'net', 'conf', 'getparm', self.share_name, 'valid users'])

    def test_get_valid_users_not_force_with_exc(self):
        self.mock_object(
            self._helper,
            '_ssh_exec',
            mock.Mock(side_effect=exception.ProcessExecutionError()))
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper._get_valid_users, self.server_details,
                          self.share_name, const.ACCESS_LEVEL_RW, force=False)
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details,
            ['sudo', 'net', 'conf', 'getparm', self.share_name, 'valid users'])

    def test_set_valid_users(self):
        self.mock_object(self._helper, '_ssh_exec', mock.Mock())
        self._helper._set_valid_users(self.server_details, ['user1', 'user2'],
                                      self.share_name, const.ACCESS_LEVEL_RW)
        self._helper._ssh_exec.assert_called_once_with(
            self.server_details,
            ['sudo', 'net', 'conf', 'setparm', self.share_name,
             'valid users', '"user1 user2"'])
