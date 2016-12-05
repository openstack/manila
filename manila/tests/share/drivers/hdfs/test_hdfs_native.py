# Copyright 2015 Intel, Corp.
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

"""Unit tests for HDFS native protocol driver module."""

import socket

import mock
from oslo_concurrency import processutils
from oslo_config import cfg
import six

from manila import context
from manila import exception
import manila.share.configuration as config
import manila.share.drivers.hdfs.hdfs_native as hdfs_native
from manila import test
from manila.tests import fake_share
from manila import utils


CONF = cfg.CONF


class HDFSNativeShareDriverTestCase(test.TestCase):
    """Tests HDFSNativeShareDriver."""

    def setUp(self):
        super(HDFSNativeShareDriverTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._hdfs_execute = mock.Mock(return_value=('', ''))
        self.local_ip = '192.168.1.1'

        CONF.set_default('driver_handles_share_servers', False)
        CONF.set_default('hdfs_namenode_ip', self.local_ip)
        CONF.set_default('hdfs_ssh_name', 'fake_sshname')
        CONF.set_default('hdfs_ssh_pw', 'fake_sshpw')
        CONF.set_default('hdfs_ssh_private_key', 'fake_sshkey')

        self.fake_conf = config.Configuration(None)
        self._driver = hdfs_native.HDFSNativeShareDriver(
            execute=self._hdfs_execute,
            configuration=self.fake_conf)
        self.hdfs_bin = 'hdfs'
        self._driver._hdfs_bin = 'fake_hdfs_bin'
        self.share = fake_share.fake_share(share_proto='HDFS')
        self.snapshot = fake_share.fake_snapshot(share_proto='HDFS')
        self.access = fake_share.fake_access(access_type='user')
        self.fakesharepath = 'hdfs://1.2.3.4:5/share-0'
        self.fakesnapshotpath = '/share-0/.snapshot/snapshot-0'

        socket.gethostname = mock.Mock(return_value='testserver')
        socket.gethostbyname_ex = mock.Mock(return_value=(
            'localhost',
            ['localhost.localdomain', 'testserver'],
            ['127.0.0.1', self.local_ip]))

    def test_do_setup(self):
        self._driver.do_setup(self._context)
        self.assertEqual(self._driver._hdfs_bin, self.hdfs_bin)

    def test_create_share(self):
        self._driver._create_share = mock.Mock()
        self._driver._get_share_path = mock.Mock(
            return_value=self.fakesharepath)
        result = self._driver.create_share(self._context, self.share,
                                           share_server=None)
        self._driver._create_share.assert_called_once_with(self.share)
        self._driver._get_share_path.assert_called_once_with(self.share)

        self.assertEqual(self.fakesharepath, result)

    def test_create_share_unsupported_proto(self):
        self._driver._get_share_path = mock.Mock()
        self.assertRaises(exception.HDFSException,
                          self._driver.create_share,
                          self._context,
                          fake_share.fake_share(),
                          share_server=None)
        self.assertFalse(self._driver._get_share_path.called)

    def test__set_share_size(self):
        share_dir = '/' + self.share['name']
        sizestr = six.text_type(self.share['size']) + 'g'
        self._driver._hdfs_execute = mock.Mock(return_value=True)
        self._driver._set_share_size(self.share)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfsadmin', '-setSpaceQuota', sizestr, share_dir)

    def test__set_share_size_exception(self):
        share_dir = '/' + self.share['name']
        sizestr = six.text_type(self.share['size']) + 'g'
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.HDFSException,
                          self._driver._set_share_size, self.share)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfsadmin', '-setSpaceQuota', sizestr, share_dir)

    def test__set_share_size_with_new_size(self):
        share_dir = '/' + self.share['name']
        new_size = 'fake_size'
        sizestr = new_size + 'g'
        self._driver._hdfs_execute = mock.Mock(return_value=True)
        self._driver._set_share_size(self.share, new_size)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfsadmin', '-setSpaceQuota', sizestr, share_dir)

    def test__create_share(self):
        share_dir = '/' + self.share['name']
        self._driver._hdfs_execute = mock.Mock(return_value=True)
        self._driver._set_share_size = mock.Mock()
        self._driver._create_share(self.share)
        self._driver._hdfs_execute.assert_any_call(
            'fake_hdfs_bin', 'dfs', '-mkdir', share_dir)
        self._driver._set_share_size.assert_called_once_with(self.share)
        self._driver._hdfs_execute.assert_any_call(
            'fake_hdfs_bin', 'dfsadmin', '-allowSnapshot', share_dir)

    def test__create_share_exception(self):
        share_dir = '/' + self.share['name']
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.HDFSException,
                          self._driver._create_share, self.share)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfs', '-mkdir', share_dir)

    def test_create_share_from_empty_snapshot(self):
        return_hdfs_execute = (None, None)
        self._driver._hdfs_execute = mock.Mock(
            return_value=return_hdfs_execute)
        self._driver._create_share = mock.Mock(return_value=True)
        self._driver._get_share_path = mock.Mock(return_value=self.
                                                 fakesharepath)
        self._driver._get_snapshot_path = mock.Mock(return_value=self.
                                                    fakesnapshotpath)
        result = self._driver.create_share_from_snapshot(self._context,
                                                         self.share,
                                                         self.snapshot,
                                                         share_server=None)
        self._driver._create_share.assert_called_once_with(self.share)
        self._driver._get_snapshot_path.assert_called_once_with(
            self.snapshot)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfs', '-ls', self.fakesnapshotpath)
        self._driver._get_share_path.assert_called_once_with(self.share)
        self.assertEqual(self.fakesharepath, result)

    def test_create_share_from_snapshot(self):
        return_hdfs_execute = ("fake_content", None)
        self._driver._hdfs_execute = mock.Mock(
            return_value=return_hdfs_execute)
        self._driver._create_share = mock.Mock(return_value=True)
        self._driver._get_share_path = mock.Mock(return_value=self.
                                                 fakesharepath)
        self._driver._get_snapshot_path = mock.Mock(return_value=self.
                                                    fakesnapshotpath)
        result = self._driver.create_share_from_snapshot(self._context,
                                                         self.share,
                                                         self.snapshot,
                                                         share_server=None)
        self._driver._create_share.assert_called_once_with(self.share)
        self._driver._get_snapshot_path.assert_called_once_with(
            self.snapshot)

        calls = [mock.call('fake_hdfs_bin', 'dfs',
                           '-ls', self.fakesnapshotpath),
                 mock.call('fake_hdfs_bin', 'dfs', '-cp',
                           self.fakesnapshotpath + '/*',
                           '/' + self.share['name'])]

        self._driver._hdfs_execute.assert_has_calls(calls)
        self._driver._get_share_path.assert_called_once_with(self.share)
        self.assertEqual(self.fakesharepath, result)

    def test_create_share_from_snapshot_exception(self):
        self._driver._create_share = mock.Mock(return_value=True)
        self._driver._get_snapshot_path = mock.Mock(return_value=self.
                                                    fakesnapshotpath)
        self._driver._get_share_path = mock.Mock(return_value=self.
                                                 fakesharepath)
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.HDFSException,
                          self._driver.create_share_from_snapshot,
                          self._context, self.share,
                          self.snapshot, share_server=None)
        self._driver._create_share.assert_called_once_with(self.share)
        self._driver._get_snapshot_path.assert_called_once_with(self.snapshot)

        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfs', '-ls', self.fakesnapshotpath)
        self.assertFalse(self._driver._get_share_path.called)

    def test_create_snapshot(self):
        self._driver._hdfs_execute = mock.Mock(return_value=True)
        self._driver.create_snapshot(self._context, self.snapshot,
                                     share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfs', '-createSnapshot',
            '/' + self.snapshot['share_name'], self.snapshot['name'])

    def test_create_snapshot_exception(self):
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.HDFSException,
                          self._driver.create_snapshot, self._context,
                          self.snapshot, share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfs', '-createSnapshot',
            '/' + self.snapshot['share_name'], self.snapshot['name'])

    def test_delete_share(self):
        self._driver._hdfs_execute = mock.Mock(return_value=True)
        self._driver.delete_share(self._context,
                                  self.share,
                                  share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfs', '-rm', '-r',
            '/' + self.share['name'])

    def test_delete_share_exception(self):
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.HDFSException,
                          self._driver.delete_share,
                          self._context,
                          self.share,
                          share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfs', '-rm', '-r',
            '/' + self.share['name'])

    def test_delete_snapshot(self):
        self._driver._hdfs_execute = mock.Mock(return_value=True)
        self._driver.delete_snapshot(self._context,
                                     self.snapshot,
                                     share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfs', '-deleteSnapshot',
            '/' + self.snapshot['share_name'], self.snapshot['name'])

    def test_delete_snapshot_exception(self):
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.HDFSException,
                          self._driver.delete_snapshot,
                          self._context,
                          self.snapshot,
                          share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfs', '-deleteSnapshot',
            '/' + self.snapshot['share_name'], self.snapshot['name'])

    def test_allow_access(self):
        self._driver._hdfs_execute = mock.Mock(
            return_value=['', ''])
        share_dir = '/' + self.share['name']
        user_access = ':'.join([self.access['access_type'],
                                self.access['access_to'],
                                'rwx'])
        cmd = ['fake_hdfs_bin', 'dfs', '-setfacl', '-m', '-R',
               user_access, share_dir]
        self._driver.allow_access(self._context, self.share, self.access,
                                  share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            *cmd, check_exit_code=True)

    def test_allow_access_invalid_access_type(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.allow_access,
                          self._context,
                          self.share,
                          fake_share.fake_access(
                              access_type='invalid_access_type'),
                          share_server=None)

    def test_allow_access_invalid_access_level(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.allow_access,
                          self._context,
                          self.share,
                          fake_share.fake_access(
                              access_level='invalid_access_level'),
                          share_server=None)

    def test_allow_access_exception(self):
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        share_dir = '/' + self.share['name']
        user_access = ':'.join([self.access['access_type'],
                                self.access['access_to'],
                                'rwx'])
        cmd = ['fake_hdfs_bin', 'dfs', '-setfacl', '-m', '-R',
               user_access, share_dir]
        self.assertRaises(exception.HDFSException,
                          self._driver.allow_access,
                          self._context,
                          self.share,
                          self.access,
                          share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            *cmd, check_exit_code=True)

    def test_deny_access(self):
        self._driver._hdfs_execute = mock.Mock(return_value=['', ''])
        share_dir = '/' + self.share['name']
        access_name = ':'.join([self.access['access_type'],
                                self.access['access_to']])
        cmd = ['fake_hdfs_bin', 'dfs', '-setfacl', '-x', '-R',
               access_name, share_dir]
        self._driver.deny_access(self._context,
                                 self.share,
                                 self.access,
                                 share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            *cmd, check_exit_code=True)

    def test_deny_access_exception(self):
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        share_dir = '/' + self.share['name']
        access_name = ':'.join([self.access['access_type'],
                                self.access['access_to']])
        cmd = ['fake_hdfs_bin', 'dfs', '-setfacl', '-x', '-R',
               access_name, share_dir]
        self.assertRaises(exception.HDFSException,
                          self._driver.deny_access,
                          self._context,
                          self.share,
                          self.access,
                          share_server=None)
        self._driver._hdfs_execute.assert_called_once_with(
            *cmd, check_exit_code=True)

    def test_extend_share(self):
        new_size = "fake_size"
        self._driver._set_share_size = mock.Mock()
        self._driver.extend_share(self.share, new_size)
        self._driver._set_share_size.assert_called_once_with(
            self.share, new_size)

    def test__check_hdfs_state_healthy(self):
        fake_out = "fakeinfo\n...Status: HEALTHY"
        self._driver._hdfs_execute = mock.Mock(return_value=(fake_out, ''))
        result = self._driver._check_hdfs_state()
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'fsck', '/')
        self.assertTrue(result)

    def test__check_hdfs_state_down(self):
        fake_out = "fakeinfo\n...Status: DOWN"
        self._driver._hdfs_execute = mock.Mock(return_value=(fake_out, ''))
        result = self._driver._check_hdfs_state()
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'fsck', '/')
        self.assertFalse(result)

    def test__check_hdfs_state_exception(self):
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.HDFSException,
                          self._driver._check_hdfs_state)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'fsck', '/')

    def test__get_available_capacity(self):
        fake_out = ('Configured Capacity: 2.4\n' +
                    'Total Capacity: 2\n' +
                    'DFS free: 1')
        self._driver._hdfs_execute = mock.Mock(return_value=(fake_out, ''))
        total, free = self._driver._get_available_capacity()
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfsadmin', '-report')
        self.assertEqual(2, total)
        self.assertEqual(1, free)

    def test__get_available_capacity_exception(self):
        self._driver._hdfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.HDFSException,
                          self._driver._get_available_capacity)
        self._driver._hdfs_execute.assert_called_once_with(
            'fake_hdfs_bin', 'dfsadmin', '-report')

    def test_get_share_stats_refresh_false(self):
        self._driver._stats = {'fake_key': 'fake_value'}
        result = self._driver.get_share_stats(False)
        self.assertEqual(self._driver._stats, result)

    def test_get_share_stats_refresh_true(self):
        self._driver._get_available_capacity = mock.Mock(
            return_value=(11111.0, 12345.0))
        result = self._driver.get_share_stats(True)
        expected_keys = [
            'qos', 'driver_version', 'share_backend_name',
            'free_capacity_gb', 'total_capacity_gb',
            'driver_handles_share_servers',
            'reserved_percentage', 'vendor_name', 'storage_protocol',
            'ipv4_support', 'ipv6_support'
        ]
        for key in expected_keys:
            self.assertIn(key, result)
        self.assertTrue(result['ipv4_support'])
        self.assertFalse(False, result['ipv6_support'])
        self.assertEqual('HDFS', result['storage_protocol'])
        self._driver._get_available_capacity.assert_called_once_with()

    def test__hdfs_local_execute(self):
        cmd = 'testcmd'
        self.mock_object(utils, 'execute', mock.Mock(return_value=True))
        self._driver._hdfs_local_execute(cmd)
        utils.execute.assert_called_once_with(cmd, run_as_root=False)

    def test__hdfs_remote_execute(self):
        self._driver._run_ssh = mock.Mock(return_value=True)
        cmd = 'testcmd'
        self._driver._hdfs_remote_execute(cmd, check_exit_code=True)
        self._driver._run_ssh.assert_called_once_with(
            self.local_ip, tuple([cmd]), True)

    def test__run_ssh(self):
        ssh_output = 'fake_ssh_output'
        cmd_list = ['fake', 'cmd']
        ssh = mock.Mock()
        ssh.get_transport = mock.Mock()
        ssh.get_transport().is_active = mock.Mock(return_value=True)
        ssh_pool = mock.Mock()
        ssh_pool.create = mock.Mock(return_value=ssh)
        self.mock_object(utils, 'SSHPool', mock.Mock(return_value=ssh_pool))
        self.mock_object(processutils, 'ssh_execute',
                         mock.Mock(return_value=ssh_output))
        result = self._driver._run_ssh(self.local_ip, cmd_list)
        utils.SSHPool.assert_called_once_with(
            self._driver.configuration.hdfs_namenode_ip,
            self._driver.configuration.hdfs_ssh_port,
            self._driver.configuration.ssh_conn_timeout,
            self._driver.configuration.hdfs_ssh_name,
            password=self._driver.configuration.hdfs_ssh_pw,
            privatekey=self._driver.configuration.hdfs_ssh_private_key,
            min_size=self._driver.configuration.ssh_min_pool_conn,
            max_size=self._driver.configuration.ssh_max_pool_conn)
        ssh_pool.create.assert_called_once_with()
        ssh.get_transport().is_active.assert_called_once_with()
        processutils.ssh_execute.assert_called_once_with(
            ssh, 'fake cmd', check_exit_code=False)
        self.assertEqual(ssh_output, result)

    def test__run_ssh_exception(self):
        cmd_list = ['fake', 'cmd']
        ssh = mock.Mock()
        ssh.get_transport = mock.Mock()
        ssh.get_transport().is_active = mock.Mock(return_value=True)
        ssh_pool = mock.Mock()
        ssh_pool.create = mock.Mock(return_value=ssh)
        self.mock_object(utils, 'SSHPool', mock.Mock(return_value=ssh_pool))
        self.mock_object(processutils, 'ssh_execute',
                         mock.Mock(side_effect=Exception))
        self.assertRaises(exception.HDFSException,
                          self._driver._run_ssh,
                          self.local_ip,
                          cmd_list)
        utils.SSHPool.assert_called_once_with(
            self._driver.configuration.hdfs_namenode_ip,
            self._driver.configuration.hdfs_ssh_port,
            self._driver.configuration.ssh_conn_timeout,
            self._driver.configuration.hdfs_ssh_name,
            password=self._driver.configuration.hdfs_ssh_pw,
            privatekey=self._driver.configuration.hdfs_ssh_private_key,
            min_size=self._driver.configuration.ssh_min_pool_conn,
            max_size=self._driver.configuration.ssh_max_pool_conn)
        ssh_pool.create.assert_called_once_with()
        ssh.get_transport().is_active.assert_called_once_with()
        processutils.ssh_execute.assert_called_once_with(
            ssh, 'fake cmd', check_exit_code=False)
