# Copyright (c) 2014 IBM Corp.
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

"""Unit tests for the IBM GPFS driver module."""

import re
import socket

import ddt
import mock
from oslo_config import cfg

from manila import context
from manila import exception
import manila.share.configuration as config
import manila.share.drivers.ibm.ganesha_utils as ganesha_utils
import manila.share.drivers.ibm.gpfs as gpfs
from manila import test
from manila.tests import fake_share
from manila import utils


CONF = cfg.CONF


@ddt.ddt
class GPFSShareDriverTestCase(test.TestCase):
    """Tests GPFSShareDriver."""

    def setUp(self):
        super(GPFSShareDriverTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._gpfs_execute = mock.Mock(return_value=('', ''))

        self._helper_fake = mock.Mock()
        CONF.set_default('driver_handles_share_servers', False)
        self.fake_conf = config.Configuration(None)
        self._driver = gpfs.GPFSShareDriver(execute=self._gpfs_execute,
                                            configuration=self.fake_conf)
        self._knfs_helper = gpfs.KNFSHelper(self._gpfs_execute,
                                            self.fake_conf)
        self._gnfs_helper = gpfs.GNFSHelper(self._gpfs_execute,
                                            self.fake_conf)
        self.fakedev = "/dev/gpfs0"
        self.fakefspath = "/gpfs0"
        self.fakesharepath = "/gpfs0/share-fakeid"
        self.fakesnapshotpath = "/gpfs0/.snapshots/snapshot-fakesnapshotid"
        self.mock_object(gpfs.os.path, 'exists', mock.Mock(return_value=True))
        self._driver._helpers = {
            'KNFS': self._helper_fake
        }
        self.share = fake_share.fake_share(share_proto='NFS')
        self.server = {
            'backend_details': {
                'ip': '1.2.3.4',
                'instance_id': 'fake'
            }
        }
        self.access = fake_share.fake_access()
        self.snapshot = fake_share.fake_snapshot()
        self.local_ip = "192.11.22.1"
        self.remote_ip = "192.11.22.2"
        gpfs_nfs_server_list = [self.local_ip, self.remote_ip]
        self._knfs_helper.configuration.gpfs_nfs_server_list = \
            gpfs_nfs_server_list
        self._gnfs_helper.configuration.gpfs_nfs_server_list = \
            gpfs_nfs_server_list
        self._gnfs_helper.configuration.ganesha_config_path = \
            "fake_ganesha_config_path"
        self.sshlogin = "fake_login"
        self.sshkey = "fake_sshkey"
        self.gservice = "fake_ganesha_service"
        self._gnfs_helper.configuration.gpfs_ssh_login = self.sshlogin
        self._gnfs_helper.configuration.gpfs_ssh_private_key = self.sshkey
        self._gnfs_helper.configuration.ganesha_service_name = self.gservice
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value="testserver"))
        self.mock_object(socket, 'gethostbyname_ex', mock.Mock(
            return_value=('localhost',
                          ['localhost.localdomain', 'testserver'],
                          ['127.0.0.1', self.local_ip])
        ))

    def test__run_ssh(self):
        cmd_list = ['fake', 'cmd']
        expected_cmd = 'fake cmd'
        ssh_pool = mock.Mock()
        ssh = mock.Mock()
        self.mock_object(utils, 'SSHPool', mock.Mock(return_value=ssh_pool))
        ssh_pool.item = mock.Mock(return_value=ssh)
        setattr(ssh, '__enter__', mock.Mock())
        setattr(ssh, '__exit__', mock.Mock())
        self.mock_object(self._driver, '_gpfs_ssh_execute')
        self._driver._run_ssh(self.local_ip, cmd_list)

        self._driver._gpfs_ssh_execute.assert_called_once_with(
            mock.ANY, expected_cmd, check_exit_code=True)

    def test__run_ssh_exception(self):
        cmd_list = ['fake', 'cmd']
        ssh_pool = mock.Mock()
        ssh = mock.Mock()
        self.mock_object(utils, 'SSHPool', mock.Mock(return_value=ssh_pool))
        ssh_pool.item = mock.Mock(return_value=ssh)
        self.mock_object(self._driver, '_gpfs_ssh_execute')
        self.assertRaises(exception.GPFSException,
                          self._driver._run_ssh,
                          self.local_ip, cmd_list)

    def test__gpfs_ssh_execute(self):
        cmd = 'fake cmd'
        expected_out = 'cmd successful'
        expected_err = 'cmd error'
        ssh = mock.Mock()
        stdin_stream = mock.Mock()
        stdout_stream = mock.Mock()
        stderr_stream = mock.Mock()
        ssh.exec_command = mock.Mock(return_value=(stdin_stream,
                                                   stdout_stream,
                                                   stderr_stream))
        stdout_stream.channel.recv_exit_status = mock.Mock(return_value=-1)
        stdout_stream.read = mock.Mock(return_value=expected_out)
        stderr_stream.read = mock.Mock(return_value=expected_err)
        stdin_stream.close = mock.Mock()
        actual_out, actual_err = self._driver._gpfs_ssh_execute(ssh, cmd)

        self.assertEqual(actual_out, expected_out)
        self.assertEqual(actual_err, expected_err)

    def test__gpfs_ssh_execute_exception(self):
        cmd = 'fake cmd'
        ssh = mock.Mock()
        stdin_stream = mock.Mock()
        stdout_stream = mock.Mock()
        stderr_stream = mock.Mock()
        ssh.exec_command = mock.Mock(return_value=(stdin_stream,
                                                   stdout_stream,
                                                   stderr_stream))
        stdout_stream.channel.recv_exit_status = mock.Mock(return_value=1)
        stdout_stream.read = mock.Mock()
        stderr_stream.read = mock.Mock()
        stdin_stream.close = mock.Mock()
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._gpfs_ssh_execute,
                          ssh, cmd)

    def test_get_share_stats_refresh_false(self):
        self._driver._stats = {'fake_key': 'fake_value'}
        result = self._driver.get_share_stats(False)
        self.assertEqual(self._driver._stats, result)

    def test_get_share_stats_refresh_true(self):
        self.mock_object(
            self._driver, '_get_available_capacity',
            mock.Mock(return_value=(11111.0, 12345.0)))
        result = self._driver.get_share_stats(True)
        expected_keys = [
            'qos', 'driver_version', 'share_backend_name',
            'free_capacity_gb', 'total_capacity_gb',
            'driver_handles_share_servers',
            'reserved_percentage', 'vendor_name', 'storage_protocol',
        ]
        for key in expected_keys:
            self.assertIn(key, result)
        self.assertFalse(result['driver_handles_share_servers'])
        self.assertEqual('IBM', result['vendor_name'])
        self._driver._get_available_capacity.assert_called_once_with(
            self._driver.configuration.gpfs_mount_point_base)

    def test_do_setup(self):
        self.mock_object(self._driver, '_setup_helpers')
        self._driver.do_setup(self._context)
        self._driver._setup_helpers.assert_called_once_with()

    def test_setup_helpers(self):
        self._driver._helpers = {}
        CONF.set_default('gpfs_share_helpers', ['KNFS=fakenfs'])
        self.mock_object(gpfs.importutils, 'import_class',
                         mock.Mock(return_value=self._helper_fake))
        self._driver._setup_helpers()
        gpfs.importutils.import_class.assert_has_calls(
            [mock.call('fakenfs')]
        )
        self.assertEqual(len(self._driver._helpers), 1)

    @ddt.data(fake_share.fake_share(),
              fake_share.fake_share(share_proto='NFSBOGUS'))
    def test__get_helper_with_wrong_proto(self, share):
        self.assertRaises(exception.InvalidShare,
                          self._driver._get_helper, share)

    def test__local_path(self):
        sharename = 'fakesharename'
        self._driver.configuration.gpfs_mount_point_base =\
            self.fakefspath
        local_path = self._driver._local_path(sharename)
        self.assertEqual(self.fakefspath + '/' + sharename,
                         local_path)

    def test__get_share_path(self):
        self._driver.configuration.gpfs_mount_point_base =\
            self.fakefspath
        share_path = self._driver._get_share_path(self.share)
        self.assertEqual(self.fakefspath + '/' + self.share['name'],
                         share_path)

    def test__get_snapshot_path(self):
        self._driver.configuration.gpfs_mount_point_base =\
            self.fakefspath
        snapshot_path = self._driver._get_snapshot_path(self.snapshot)
        self.assertEqual(self.fakefspath + '/' + self.snapshot['share_name'] +
                         '/.snapshots/' + self.snapshot['name'],
                         snapshot_path)

    def test_check_for_setup_error_for_gpfs_state(self):
        self.mock_object(self._driver, '_check_gpfs_state',
                         mock.Mock(return_value=False))
        self.assertRaises(exception.GPFSException,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_for_export_ip(self):
        self.mock_object(self._driver, '_check_gpfs_state',
                         mock.Mock(return_value=True))

        self._driver.configuration.gpfs_share_export_ip = None
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_for_gpfs_mount_point_base(self):
        self.mock_object(self._driver, '_check_gpfs_state',
                         mock.Mock(return_value=True))
        self._driver.configuration.gpfs_share_export_ip = self.local_ip
        self._driver.configuration.gpfs_mount_point_base = 'test'
        self.assertRaises(exception.GPFSException,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_for_directory_check(self):
        self.mock_object(self._driver, '_check_gpfs_state',
                         mock.Mock(return_value=True))
        self._driver.configuration.gpfs_share_export_ip = self.local_ip
        self._driver.configuration.gpfs_mount_point_base = self.fakefspath
        self.mock_object(self._driver, '_is_dir',
                         mock.Mock(return_value=False))
        self.assertRaises(exception.GPFSException,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_for_gpfs_path_check(self):
        self.mock_object(self._driver, '_check_gpfs_state',
                         mock.Mock(return_value=True))
        self._driver.configuration.gpfs_share_export_ip = self.local_ip
        self._driver.configuration.gpfs_mount_point_base = self.fakefspath
        self.mock_object(self._driver, '_is_dir',
                         mock.Mock(return_value=True))
        self.mock_object(self._driver, '_is_gpfs_path',
                         mock.Mock(return_value=False))
        self.assertRaises(exception.GPFSException,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_for_nfs_server_type(self):
        self.mock_object(self._driver, '_check_gpfs_state',
                         mock.Mock(return_value=True))
        self._driver.configuration.gpfs_share_export_ip = self.local_ip
        self._driver.configuration.gpfs_mount_point_base = self.fakefspath
        self.mock_object(self._driver, '_is_dir',
                         mock.Mock(return_value=True))
        self.mock_object(self._driver, '_is_gpfs_path',
                         mock.Mock(return_value=True))
        self._driver.configuration.gpfs_nfs_server_type = 'test'
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_for_nfs_server_list(self):
        self.mock_object(self._driver, '_check_gpfs_state',
                         mock.Mock(return_value=True))
        self._driver.configuration.gpfs_share_export_ip = self.local_ip
        self._driver.configuration.gpfs_mount_point_base = self.fakefspath
        self.mock_object(self._driver, '_is_dir',
                         mock.Mock(return_value=True))
        self.mock_object(self._driver, '_is_gpfs_path',
                         mock.Mock(return_value=True))
        self._driver.configuration.gpfs_nfs_server_type = 'KNFS'
        self._driver.configuration.gpfs_nfs_server_list = None
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test__get_available_capacity(self):
        path = self.fakefspath
        mock_out = "Filesystem 1-blocks Used Available Capacity Mounted on\n\
                    /dev/gpfs0 100 30 70 30% /gpfs0"
        self.mock_object(self._driver, '_gpfs_execute',
                         mock.Mock(return_value=(mock_out, '')))
        available, size = self._driver._get_available_capacity(path)
        self.assertEqual(70, available)
        self.assertEqual(100, size)

    def test_create_share(self):
        self._helper_fake.create_export.return_value = 'fakelocation'
        methods = ('_create_share', '_get_share_path')
        for method in methods:
            self.mock_object(self._driver, method)
        result = self._driver.create_share(self._context, self.share,
                                           share_server=self.server)
        self._driver._create_share.assert_called_once_with(self.share)
        self._driver._get_share_path.assert_called_once_with(self.share)

        self.assertEqual(result, 'fakelocation')

    def test_create_share_from_snapshot(self):
        self._helper_fake.create_export.return_value = 'fakelocation'
        self._driver._get_share_path = mock.Mock(return_value=self.
                                                 fakesharepath)
        self._driver._create_share_from_snapshot = mock.Mock()
        result = self._driver.create_share_from_snapshot(self._context,
                                                         self.share,
                                                         self.snapshot,
                                                         share_server=None)
        self._driver._get_share_path.assert_called_once_with(self.share)
        self._driver._create_share_from_snapshot.assert_called_once_with(
            self.share, self.snapshot,
            self.fakesharepath
        )
        self.assertEqual(result, 'fakelocation')

    def test_create_snapshot(self):
        self._driver._create_share_snapshot = mock.Mock()
        self._driver.create_snapshot(self._context, self.snapshot,
                                     share_server=None)
        self._driver._create_share_snapshot.assert_called_once_with(
            self.snapshot
        )

    def test_delete_share(self):
        self._driver._get_share_path = mock.Mock(
            return_value=self.fakesharepath
        )
        self._driver._delete_share = mock.Mock()

        self._driver.delete_share(self._context, self.share,
                                  share_server=None)

        self._driver._get_share_path.assert_called_once_with(self.share)
        self._driver._delete_share.assert_called_once_with(self.share)
        self._helper_fake.remove_export.assert_called_once_with(
            self.fakesharepath, self.share
        )

    def test_delete_snapshot(self):
        self._driver._delete_share_snapshot = mock.Mock()
        self._driver.delete_snapshot(self._context, self.snapshot,
                                     share_server=None)
        self._driver._delete_share_snapshot.assert_called_once_with(
            self.snapshot
        )

    def test__delete_share_snapshot(self):
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._gpfs_execute = mock.Mock(return_value=0)
        self._driver._delete_share_snapshot(self.snapshot)
        self._driver._gpfs_execute.assert_called_once_with(
            'mmdelsnapshot', self.fakedev, self.snapshot['name'],
            '-j', self.snapshot['share_name']
        )
        self._driver._get_gpfs_device.assert_called_once_with()

    def test__delete_share_snapshot_exception(self):
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._delete_share_snapshot, self.snapshot)
        self._driver._get_gpfs_device.assert_called_once_with()
        self._driver._gpfs_execute.assert_called_once_with(
            'mmdelsnapshot', self.fakedev, self.snapshot['name'],
            '-j', self.snapshot['share_name']
        )

    def test_extend_share(self):
        self._driver._extend_share = mock.Mock()
        self._driver.extend_share(self.share, 10)
        self._driver._extend_share.assert_called_once_with(self.share, 10)

    def test__extend_share(self):
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._gpfs_execute = mock.Mock(return_value=True)
        self._driver._extend_share(self.share, 10)
        self._driver._gpfs_execute.assert_called_once_with('mmsetquota', '-j',
                                                           self.share['name'],
                                                           '-h', '10G',
                                                           self.fakedev)
        self._driver._get_gpfs_device.assert_called_once_with()

    def test__extend_share_exception(self):
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._extend_share, self.share, 10)
        self._driver._gpfs_execute.assert_called_once_with('mmsetquota', '-j',
                                                           self.share['name'],
                                                           '-h', '10G',
                                                           self.fakedev)
        self._driver._get_gpfs_device.assert_called_once_with()

    def test_allow_access(self):
        self._driver._get_share_path = mock.Mock(
            return_value=self.fakesharepath
        )
        self._helper_fake.allow_access = mock.Mock()
        self._driver.allow_access(self._context, self.share,
                                  self.access, share_server=None)
        self._helper_fake.allow_access.assert_called_once_with(
            self.fakesharepath, self.share,
            self.access['access_type'],
            self.access['access_to']
        )
        self._driver._get_share_path.assert_called_once_with(self.share)

    def test_deny_access(self):
        self._driver._get_share_path = mock.Mock(return_value=self.
                                                 fakesharepath)
        self._helper_fake.deny_access = mock.Mock()
        self._driver.deny_access(self._context, self.share,
                                 self.access, share_server=None)
        self._helper_fake.deny_access.assert_called_once_with(
            self.fakesharepath, self.share,
            self.access['access_type'],
            self.access['access_to']
        )
        self._driver._get_share_path.assert_called_once_with(self.share)

    def test__check_gpfs_state_active(self):
        fakeout = "mmgetstate::state:\nmmgetstate::active:"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))
        result = self._driver._check_gpfs_state()
        self._driver._gpfs_execute.assert_called_once_with('mmgetstate', '-Y')
        self.assertEqual(result, True)

    def test__check_gpfs_state_down(self):
        fakeout = "mmgetstate::state:\nmmgetstate::down:"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))
        result = self._driver._check_gpfs_state()
        self._driver._gpfs_execute.assert_called_once_with('mmgetstate', '-Y')
        self.assertEqual(result, False)

    def test__check_gpfs_state_wrong_output_exception(self):
        fakeout = "mmgetstate fake out"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))
        self.assertRaises(exception.GPFSException,
                          self._driver._check_gpfs_state)
        self._driver._gpfs_execute.assert_called_once_with('mmgetstate', '-Y')

    def test__check_gpfs_state_exception(self):
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._check_gpfs_state)
        self._driver._gpfs_execute.assert_called_once_with('mmgetstate', '-Y')

    def test__is_dir_success(self):
        fakeoutput = "directory"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeoutput, ''))
        result = self._driver._is_dir(self.fakefspath)
        self._driver._gpfs_execute.assert_called_once_with(
            'stat', '--format=%F', self.fakefspath, run_as_root=False
        )
        self.assertEqual(result, True)

    def test__is_dir_failure(self):
        fakeoutput = "regulalr file"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeoutput, ''))
        result = self._driver._is_dir(self.fakefspath)
        self._driver._gpfs_execute.assert_called_once_with(
            'stat', '--format=%F', self.fakefspath, run_as_root=False
        )
        self.assertEqual(result, False)

    def test__is_dir_exception(self):
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._is_dir, self.fakefspath)
        self._driver._gpfs_execute.assert_called_once_with(
            'stat', '--format=%F', self.fakefspath, run_as_root=False
        )

    def test__is_gpfs_path_ok(self):
        self._driver._gpfs_execute = mock.Mock(return_value=0)
        result = self._driver._is_gpfs_path(self.fakefspath)
        self._driver._gpfs_execute.assert_called_once_with('mmlsattr',
                                                           self.fakefspath)
        self.assertEqual(result, True)

    def test__is_gpfs_path_exception(self):
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._is_gpfs_path,
                          self.fakefspath)
        self._driver._gpfs_execute.assert_called_once_with('mmlsattr',
                                                           self.fakefspath)

    def test__get_gpfs_device(self):
        fakeout = "Filesystem\n" + self.fakedev
        orig_val = self._driver.configuration.gpfs_mount_point_base
        self._driver.configuration.gpfs_mount_point_base = self.fakefspath
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))
        result = self._driver._get_gpfs_device()
        self._driver._gpfs_execute.assert_called_once_with('df',
                                                           self.fakefspath)
        self.assertEqual(result, self.fakedev)
        self._driver.configuration.gpfs_mount_point_base = orig_val

    def test__get_gpfs_device_exception(self):
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.GPFSException,
                          self._driver._get_gpfs_device)

    def test__create_share(self):
        sizestr = '%sG' % self.share['size']
        self._driver._gpfs_execute = mock.Mock(return_value=True)
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._create_share(self.share)
        self._driver._gpfs_execute.assert_any_call('mmcrfileset',
                                                   self.fakedev,
                                                   self.share['name'],
                                                   '--inode-space', 'new')
        self._driver._gpfs_execute.assert_any_call('mmlinkfileset',
                                                   self.fakedev,
                                                   self.share['name'],
                                                   '-J', self.fakesharepath)
        self._driver._gpfs_execute.assert_any_call('mmsetquota', '-j',
                                                   self.share['name'], '-h',
                                                   sizestr,
                                                   self.fakedev)
        self._driver._gpfs_execute.assert_any_call('chmod',
                                                   '777',
                                                   self.fakesharepath)

        self._driver._local_path.assert_called_once_with(self.share['name'])
        self._driver._get_gpfs_device.assert_called_once_with()

    def test__create_share_exception(self):
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._create_share, self.share)
        self._driver._get_gpfs_device.assert_called_once_with()
        self._driver._local_path.assert_called_once_with(self.share['name'])
        self._driver._gpfs_execute.assert_called_once_with('mmcrfileset',
                                                           self.fakedev,
                                                           self.share['name'],
                                                           '--inode-space',
                                                           'new')

    def test__delete_share(self):
        self._driver._gpfs_execute = mock.Mock(return_value=True)
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._delete_share(self.share)
        self._driver._gpfs_execute.assert_any_call(
            'mmunlinkfileset', self.fakedev, self.share['name'],
            '-f')
        self._driver._gpfs_execute.assert_any_call(
            'mmdelfileset', self.fakedev, self.share['name'],
            '-f')
        self._driver._get_gpfs_device.assert_called_once_with()

    def test__delete_share_exception(self):
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._delete_share, self.share)
        self._driver._get_gpfs_device.assert_called_once_with()
        self._driver._gpfs_execute.assert_called_once_with(
            'mmunlinkfileset', self.fakedev, self.share['name'],
            '-f')

    def test__create_share_snapshot(self):
        self._driver._gpfs_execute = mock.Mock(return_value=True)
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._create_share_snapshot(self.snapshot)
        self._driver._gpfs_execute.assert_called_once_with(
            'mmcrsnapshot', self.fakedev, self.snapshot['name'],
            '-j', self.snapshot['share_name']
        )
        self._driver._get_gpfs_device.assert_called_once_with()

    def test__create_share_snapshot_exception(self):
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._create_share_snapshot, self.snapshot)
        self._driver._get_gpfs_device.assert_called_once_with()
        self._driver._gpfs_execute.assert_called_once_with(
            'mmcrsnapshot', self.fakedev, self.snapshot['name'],
            '-j', self.snapshot['share_name']
        )

    def test__create_share_from_snapshot(self):
        self._driver._gpfs_execute = mock.Mock(return_value=True)
        self._driver._create_share = mock.Mock(return_value=True)
        self._driver._get_snapshot_path = mock.Mock(return_value=self.
                                                    fakesnapshotpath)
        self._driver._create_share_from_snapshot(self.share, self.snapshot,
                                                 self.fakesharepath)
        self._driver._gpfs_execute.assert_called_once_with(
            'rsync', '-rp', self.fakesnapshotpath + '/', self.fakesharepath
        )
        self._driver._create_share.assert_called_once_with(self.share)
        self._driver._get_snapshot_path.assert_called_once_with(self.snapshot)

    def test__create_share_from_snapshot_exception(self):
        self._driver._create_share = mock.Mock(return_value=True)
        self._driver._get_snapshot_path = mock.Mock(return_value=self.
                                                    fakesnapshotpath)
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._create_share_from_snapshot,
                          self.share, self.snapshot, self.fakesharepath)
        self._driver._create_share.assert_called_once_with(self.share)
        self._driver._get_snapshot_path.assert_called_once_with(self.snapshot)
        self._driver._gpfs_execute.assert_called_once_with(
            'rsync', '-rp', self.fakesnapshotpath + '/', self.fakesharepath
        )

    def test__gpfs_local_execute(self):
        self.mock_object(utils, 'execute', mock.Mock(return_value=True))
        cmd = "testcmd"
        self._driver._gpfs_local_execute(cmd)
        utils.execute.assert_called_once_with(cmd, run_as_root=True)

    def test__gpfs_remote_execute(self):
        self._driver._run_ssh = mock.Mock(return_value=True)
        cmd = "testcmd"
        orig_value = self._driver.configuration.gpfs_share_export_ip
        self._driver.configuration.gpfs_share_export_ip = self.local_ip
        self._driver._gpfs_remote_execute(cmd, check_exit_code=True)
        self._driver._run_ssh.assert_called_once_with(
            self.local_ip, tuple([cmd]), True
        )
        self._driver.configuration.gpfs_share_export_ip = orig_value

    def test_knfs_allow_access(self):
        self._knfs_helper._execute = mock.Mock(
            return_value=['/fs0 <world>', 0]
        )
        self.mock_object(re, 'search', mock.Mock(return_value=None))
        export_opts = None
        self._knfs_helper._get_export_options = mock.Mock(
            return_value=export_opts
        )
        self._knfs_helper._publish_access = mock.Mock()
        access_type = self.access['access_type']
        access = self.access['access_to']
        local_path = self.fakesharepath
        self._knfs_helper.allow_access(local_path, self.share,
                                       access_type, access)
        self._knfs_helper._execute.assert_called_once_with('exportfs',
                                                           run_as_root=True)
        self.assertTrue(re.search.called)
        self._knfs_helper._get_export_options.assert_any_call(self.share)
        cmd = ['exportfs', '-o', export_opts, ':'.join([access, local_path])]
        self._knfs_helper._publish_access.assert_called_once_with(*cmd)

    def test_knfs_allow_access_access_exists(self):
        out = ['/fs0 <world>', 0]
        self._knfs_helper._execute = mock.Mock(return_value=out)
        self.mock_object(re, 'search', mock.Mock(return_value="fake"))
        self._knfs_helper._get_export_options = mock.Mock()
        access_type = self.access['access_type']
        access = self.access['access_to']
        local_path = self.fakesharepath
        self.assertRaises(exception.ShareAccessExists,
                          self._knfs_helper.allow_access,
                          local_path, self.share,
                          access_type, access)
        self._knfs_helper._execute.assert_any_call('exportfs',
                                                   run_as_root=True)
        self.assertTrue(re.search.called)
        self.assertFalse(self._knfs_helper._get_export_options.called)

    def test_knfs_allow_access_invalid_access(self):
        access_type = 'invalid_access_type'
        self.assertRaises(exception.InvalidShareAccess,
                          self._knfs_helper.allow_access,
                          self.fakesharepath, self.share,
                          access_type,
                          self.access['access_to'])

    def test_knfs_allow_access_exception(self):
        self._knfs_helper._execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        access_type = self.access['access_type']
        access = self.access['access_to']
        local_path = self.fakesharepath
        self.assertRaises(exception.GPFSException,
                          self._knfs_helper.allow_access,
                          local_path, self.share,
                          access_type, access)
        self._knfs_helper._execute.assert_called_once_with('exportfs',
                                                           run_as_root=True)

    def test_knfs_deny_access(self):
        self._knfs_helper._publish_access = mock.Mock()
        access = self.access['access_to']
        access_type = self.access['access_type']
        local_path = self.fakesharepath
        self._knfs_helper.deny_access(local_path, self.share,
                                      access_type, access)
        cmd = ['exportfs', '-u', ':'.join([access, local_path])]
        self._knfs_helper._publish_access.assert_called_once_with(*cmd)

    def test_knfs_deny_access_exception(self):
        self._knfs_helper._publish_access = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        access = self.access['access_to']
        access_type = self.access['access_type']
        local_path = self.fakesharepath
        cmd = ['exportfs', '-u', ':'.join([access, local_path])]
        self.assertRaises(exception.GPFSException,
                          self._knfs_helper.deny_access, local_path,
                          self.share, access_type, access)
        self._knfs_helper._publish_access.assert_called_once_with(*cmd)

    def test_knfs__publish_access(self):
        self.mock_object(utils, 'execute')
        cmd = ['fakecmd']
        self._knfs_helper._publish_access(*cmd)
        utils.execute.assert_any_call(*cmd, run_as_root=True,
                                      check_exit_code=True)
        remote_login = self.sshlogin + '@' + self.remote_ip
        cmd = ['ssh', remote_login] + list(cmd)
        utils.execute.assert_any_call(*cmd, run_as_root=False,
                                      check_exit_code=True)
        self.assertTrue(socket.gethostbyname_ex.called)
        self.assertTrue(socket.gethostname.called)

    def test_knfs__publish_access_exception(self):
        self.mock_object(
            utils, 'execute',
            mock.Mock(side_effect=exception.ProcessExecutionError))
        cmd = ['fakecmd']
        self.assertRaises(exception.ProcessExecutionError,
                          self._knfs_helper._publish_access, *cmd)
        self.assertTrue(socket.gethostbyname_ex.called)
        self.assertTrue(socket.gethostname.called)
        utils.execute.assert_called_once_with(*cmd, run_as_root=True,
                                              check_exit_code=True)

    def test_gnfs_allow_access(self):
        self._gnfs_helper._ganesha_process_request = mock.Mock()
        access = self.access['access_to']
        access_type = self.access['access_type']
        local_path = self.fakesharepath
        self._gnfs_helper.allow_access(local_path, self.share,
                                       access_type, access)
        self._gnfs_helper._ganesha_process_request.assert_called_once_with(
            "allow_access", local_path, self.share, access_type, access
        )

    def test_gnfs_allow_access_invalid_access(self):
        access_type = 'invalid_access_type'
        self.assertRaises(exception.InvalidShareAccess,
                          self._gnfs_helper.allow_access,
                          self.fakesharepath, self.share,
                          access_type,
                          self.access['access_to'])

    def test_gnfs_deny_access(self):
        self._gnfs_helper._ganesha_process_request = mock.Mock()
        access = self.access['access_to']
        access_type = self.access['access_type']
        local_path = self.fakesharepath
        self._gnfs_helper.deny_access(local_path, self.share,
                                      access_type, access)
        self._gnfs_helper._ganesha_process_request.assert_called_once_with(
            "deny_access", local_path, self.share, access_type, access, False
        )

    def test_gnfs_remove_export(self):
        self._gnfs_helper._ganesha_process_request = mock.Mock()
        local_path = self.fakesharepath
        self._gnfs_helper.remove_export(local_path, self.share)
        self._gnfs_helper._ganesha_process_request.assert_called_once_with(
            "remove_export", local_path, self.share
        )

    def test_gnfs__ganesha_process_request_allow_access(self):
        access = self.access['access_to']
        access_type = self.access['access_type']
        local_path = self.fakesharepath
        cfgpath = self._gnfs_helper.configuration.ganesha_config_path
        gservers = self._gnfs_helper.configuration.gpfs_nfs_server_list
        export_opts = []
        pre_lines = []
        exports = {}
        self._gnfs_helper._get_export_options = mock.Mock(
            return_value=export_opts
        )
        self.mock_object(ganesha_utils, 'parse_ganesha_config', mock.Mock(
            return_value=(pre_lines, exports)
        ))
        self.mock_object(ganesha_utils, 'export_exists', mock.Mock(
            return_value=False
        ))
        self.mock_object(ganesha_utils, 'get_next_id', mock.Mock(
            return_value=101
        ))
        self.mock_object(ganesha_utils, 'get_export_template', mock.Mock(
            return_value={}
        ))
        self.mock_object(ganesha_utils, 'publish_ganesha_config')
        self.mock_object(ganesha_utils, 'reload_ganesha_config')
        self._gnfs_helper._ganesha_process_request(
            "allow_access", local_path, self.share, access_type, access
        )
        self._gnfs_helper._get_export_options.assert_called_once_with(
            self.share
        )
        ganesha_utils.export_exists.assert_called_once_with(exports,
                                                            local_path)
        ganesha_utils.parse_ganesha_config.assert_called_once_with(cfgpath)
        ganesha_utils.publish_ganesha_config.assert_called_once_with(
            gservers, self.sshlogin, self.sshkey, cfgpath, pre_lines, exports
        )
        ganesha_utils.reload_ganesha_config.assert_called_once_with(
            gservers, self.sshlogin, self.gservice
        )

    def test_gnfs__ganesha_process_request_deny_access(self):
        access = self.access['access_to']
        access_type = self.access['access_type']
        local_path = self.fakesharepath
        cfgpath = self._gnfs_helper.configuration.ganesha_config_path
        gservers = self._gnfs_helper.configuration.gpfs_nfs_server_list
        pre_lines = []
        initial_access = "10.0.0.1,10.0.0.2"
        export = {"rw_access": initial_access}
        exports = {}
        self.mock_object(ganesha_utils, 'parse_ganesha_config', mock.Mock(
            return_value=(pre_lines, exports)
        ))
        self.mock_object(ganesha_utils, 'get_export_by_path', mock.Mock(
            return_value=export
        ))
        self.mock_object(ganesha_utils, 'format_access_list', mock.Mock(
            return_value="10.0.0.1"
        ))
        self.mock_object(ganesha_utils, 'publish_ganesha_config')
        self.mock_object(ganesha_utils, 'reload_ganesha_config')
        self._gnfs_helper._ganesha_process_request(
            "deny_access", local_path, self.share, access_type, access
        )
        ganesha_utils.parse_ganesha_config.assert_called_once_with(cfgpath)
        ganesha_utils.get_export_by_path.assert_called_once_with(exports,
                                                                 local_path)
        ganesha_utils.format_access_list.assert_called_once_with(
            initial_access, deny_access=access
        )
        ganesha_utils.publish_ganesha_config.assert_called_once_with(
            gservers, self.sshlogin, self.sshkey, cfgpath, pre_lines, exports
        )
        ganesha_utils.reload_ganesha_config.assert_called_once_with(
            gservers, self.sshlogin, self.gservice
        )

    def test_gnfs__ganesha_process_request_remove_export(self):
        local_path = self.fakesharepath
        cfgpath = self._gnfs_helper.configuration.ganesha_config_path
        pre_lines = []
        exports = {}
        export = {}
        self.mock_object(ganesha_utils, 'parse_ganesha_config', mock.Mock(
            return_value=(pre_lines, exports)
        ))
        self.mock_object(ganesha_utils, 'get_export_by_path', mock.Mock(
            return_value=export
        ))
        self.mock_object(ganesha_utils, 'publish_ganesha_config')
        self.mock_object(ganesha_utils, 'reload_ganesha_config')
        self._gnfs_helper._ganesha_process_request(
            "remove_export", local_path, self.share
        )
        ganesha_utils.parse_ganesha_config.assert_called_once_with(cfgpath)
        ganesha_utils.get_export_by_path.assert_called_once_with(exports,
                                                                 local_path)
        self.assertFalse(ganesha_utils.publish_ganesha_config.called)
        self.assertFalse(ganesha_utils.reload_ganesha_config.called)
