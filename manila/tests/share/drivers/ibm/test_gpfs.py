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
import manila.share.drivers.ibm.gpfs as gpfs
from manila.share import share_types
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
        self.GPFS_PATH = '/usr/lpp/mmfs/bin/'

        self._helper_fake = mock.Mock()
        CONF.set_default('driver_handles_share_servers', False)
        CONF.set_default('share_backend_name', 'GPFS')
        self.fake_conf = config.Configuration(None)
        self._driver = gpfs.GPFSShareDriver(execute=self._gpfs_execute,
                                            configuration=self.fake_conf)
        self._knfs_helper = gpfs.KNFSHelper(self._gpfs_execute,
                                            self.fake_conf)
        self._ces_helper = gpfs.CESHelper(self._gpfs_execute,
                                          self.fake_conf)
        self.fakedev = "/dev/gpfs0"
        self.fakefspath = "/gpfs0"
        self.fakesharepath = "/gpfs0/share-fakeid"
        self.fakeexistingshare = "existingshare"
        self.fakesnapshotpath = "/gpfs0/.snapshots/snapshot-fakesnapshotid"

        self.fake_ces_exports = """
mmcesnfslsexport:nfsexports:HEADER:version:reserved:reserved:Path:Delegations:Clients:Access_Type:Protocols:Transports:Squash:Anonymous_uid:Anonymous_gid:SecType:PrivilegedPort:DefaultDelegations:Manage_Gids:NFS_Commit:
mmcesnfslsexport:nfsexports:0:1:::/gpfs0/share-fakeid:none:44.3.2.11:RW:3,4:TCP:ROOT_SQUASH:-2:-2:SYS:FALSE:none:FALSE:FALSE:
mmcesnfslsexport:nfsexports:0:1:::/gpfs0/share-fakeid:none:1:2:3:4:5:6:7:8:RW:3,4:TCP:ROOT_SQUASH:-2:-2:SYS:FALSE:none:FALSE:FALSE:
mmcesnfslsexport:nfsexports:0:1:::/gpfs0/share-fakeid:none:10.0.0.1:RW:3,4:TCP:ROOT_SQUASH:-2:-2:SYS:FALSE:none:FALSE:FALSE:

        """
        self.fake_ces_exports_not_found = """

mmcesnfslsexport:nfsexports:HEADER:version:reserved:reserved:Path:Delegations:Clients:Access_Type:Protocols:Transports:Squash:Anonymous_uid:Anonymous_gid:SecType:PrivilegedPort:DefaultDelegations:Manage_Gids:NFS_Commit:

        """

        self.mock_object(gpfs.os.path, 'exists', mock.Mock(return_value=True))
        self._driver._helpers = {
            'CES': self._helper_fake
        }
        self.share = fake_share.fake_share(share_proto='NFS',
                                           host='fakehost@fakehost#GPFS')
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
        self.remote_ip2 = "2.2.2.2"
        gpfs_nfs_server_list = [self.remote_ip, self.local_ip, self.remote_ip2,
                                "fake_location"]
        self._knfs_helper.configuration.gpfs_nfs_server_list = (
            gpfs_nfs_server_list)
        self._ces_helper.configuration.gpfs_nfs_server_list = (
            gpfs_nfs_server_list)
        self._ces_helper.configuration.ganesha_config_path = (
            "fake_ganesha_config_path")
        self.sshlogin = "fake_login"
        self.sshkey = "fake_sshkey"
        self.gservice = "fake_ganesha_service"
        self._ces_helper.configuration.gpfs_ssh_login = self.sshlogin
        self._ces_helper.configuration.gpfs_ssh_private_key = self.sshkey
        self._ces_helper.configuration.ganesha_service_name = self.gservice
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
            mock.ANY, expected_cmd, check_exit_code=True,
            ignore_exit_code=None)

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
        self.assertEqual(self._driver._gpfs_execute,
                         self._driver._gpfs_remote_execute)
        self._driver._setup_helpers.assert_called_once_with()

    def test_do_setup_gpfs_local_execute(self):
        self.mock_object(self._driver, '_setup_helpers')
        self._driver.configuration.is_gpfs_node = True
        self._driver.do_setup(self._context)
        self.assertEqual(self._driver._gpfs_execute,
                         self._driver._gpfs_local_execute)
        self._driver._setup_helpers.assert_called_once_with()

    def test_setup_helpers(self):
        self._driver._helpers = {}
        CONF.set_default('gpfs_share_helpers', ['CES=fakenfs'])
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
        self._driver.configuration.gpfs_mount_point_base = (
            self.fakefspath)
        local_path = self._driver._local_path(sharename)
        self.assertEqual(self.fakefspath + '/' + sharename,
                         local_path)

    def test__get_share_path(self):
        self._driver.configuration.gpfs_mount_point_base = (
            self.fakefspath)
        share_path = self._driver._get_share_path(self.share)
        self.assertEqual(self.fakefspath + '/' + self.share['name'],
                         share_path)

    def test__get_snapshot_path(self):
        self._driver.configuration.gpfs_mount_point_base = (
            self.fakefspath)
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
            self.GPFS_PATH + 'mmdelsnapshot', self.fakedev,
            self.snapshot['name'], '-j', self.snapshot['share_name']
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
            self.GPFS_PATH + 'mmdelsnapshot', self.fakedev,
            self.snapshot['name'], '-j', self.snapshot['share_name']
        )

    def test_extend_share(self):
        self._driver._extend_share = mock.Mock()
        self._driver.extend_share(self.share, 10)
        self._driver._extend_share.assert_called_once_with(self.share, 10)

    def test__extend_share(self):
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._gpfs_execute = mock.Mock(return_value=True)
        self._driver._extend_share(self.share, 10)
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmsetquota', self.fakedev + ':' +
            self.share['name'], '--block', '0:10G')
        self._driver._get_gpfs_device.assert_called_once_with()

    def test__extend_share_exception(self):
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._extend_share, self.share, 10)
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmsetquota', self.fakedev + ':' +
            self.share['name'], '--block', '0:10G')
        self._driver._get_gpfs_device.assert_called_once_with()

    def test_update_access_allow(self):
        """Test allow_access functionality via update_access."""
        self._driver._get_share_path = mock.Mock(
            return_value=self.fakesharepath
        )
        self._helper_fake.allow_access = mock.Mock()

        self._driver.update_access(self._context,
                                   self.share,
                                   ["ignored"],
                                   [self.access],
                                   [],
                                   share_server=None)

        self._helper_fake.allow_access.assert_called_once_with(
            self.fakesharepath, self.share, self.access)
        self.assertFalse(self._helper_fake.resync_access.called)
        self._driver._get_share_path.assert_called_once_with(self.share)

    def test_update_access_deny(self):
        """Test deny_access functionality via update_access."""
        self._driver._get_share_path = mock.Mock(return_value=self.
                                                 fakesharepath)
        self._helper_fake.deny_access = mock.Mock()

        self._driver.update_access(self._context,
                                   self.share,
                                   ["ignored"],
                                   [],
                                   [self.access],
                                   share_server=None)

        self._helper_fake.deny_access.assert_called_once_with(
            self.fakesharepath, self.share, self.access)
        self.assertFalse(self._helper_fake.resync_access.called)
        self._driver._get_share_path.assert_called_once_with(self.share)

    def test_update_access_both(self):
        """Test update_access with allow and deny lists."""
        self._driver._get_share_path = mock.Mock(return_value=self.
                                                 fakesharepath)
        self._helper_fake.deny_access = mock.Mock()
        self._helper_fake.allow_access = mock.Mock()
        self._helper_fake.resync_access = mock.Mock()

        access_1 = fake_share.fake_access(access_to="1.1.1.1")
        access_2 = fake_share.fake_access(access_to="2.2.2.2")
        self._driver.update_access(self._context,
                                   self.share,
                                   ["ignore"],
                                   [access_1],
                                   [access_2],
                                   share_server=None)

        self.assertFalse(self._helper_fake.resync_access.called)
        self._helper_fake.allow_access.assert_called_once_with(
            self.fakesharepath, self.share, access_1)
        self._helper_fake.deny_access.assert_called_once_with(
            self.fakesharepath, self.share, access_2)
        self._driver._get_share_path.assert_called_once_with(self.share)

    def test_update_access_resync(self):
        """Test recovery mode update_access."""
        self._driver._get_share_path = mock.Mock(return_value=self.
                                                 fakesharepath)
        self._helper_fake.deny_access = mock.Mock()
        self._helper_fake.allow_access = mock.Mock()
        self._helper_fake.resync_access = mock.Mock()

        access_1 = fake_share.fake_access(access_to="1.1.1.1")
        access_2 = fake_share.fake_access(access_to="2.2.2.2")
        self._driver.update_access(self._context,
                                   self.share,
                                   [access_1, access_2],
                                   [],
                                   [],
                                   share_server=None)

        self._helper_fake.resync_access.assert_called_once_with(
            self.fakesharepath, self.share, [access_1, access_2])
        self.assertFalse(self._helper_fake.allow_access.called)
        self.assertFalse(self._helper_fake.allow_access.called)
        self._driver._get_share_path.assert_called_once_with(self.share)

    def test__check_gpfs_state_active(self):
        fakeout = "mmgetstate::state:\nmmgetstate::active:"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))
        result = self._driver._check_gpfs_state()
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmgetstate', '-Y')
        self.assertEqual(result, True)

    def test__check_gpfs_state_down(self):
        fakeout = "mmgetstate::state:\nmmgetstate::down:"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))
        result = self._driver._check_gpfs_state()
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmgetstate', '-Y')
        self.assertEqual(result, False)

    def test__check_gpfs_state_wrong_output_exception(self):
        fakeout = "mmgetstate fake out"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))
        self.assertRaises(exception.GPFSException,
                          self._driver._check_gpfs_state)
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmgetstate', '-Y')

    def test__check_gpfs_state_exception(self):
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._check_gpfs_state)
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmgetstate', '-Y')

    def test__is_dir_success(self):
        fakeoutput = "directory"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeoutput, ''))
        result = self._driver._is_dir(self.fakefspath)
        self._driver._gpfs_execute.assert_called_once_with(
            'stat', '--format=%F', self.fakefspath, run_as_root=False
        )
        self.assertEqual(result, True)

    def test__is_dir_failure(self):
        fakeoutput = "regular file"
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
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmlsattr', self.fakefspath)
        self.assertEqual(result, True)

    def test__is_gpfs_path_exception(self):
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        self.assertRaises(exception.GPFSException,
                          self._driver._is_gpfs_path,
                          self.fakefspath)
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmlsattr', self.fakefspath)

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
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmcrfileset', self.fakedev, self.share['name'],
            '--inode-space', 'new')
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmlinkfileset', self.fakedev, self.share['name'],
            '-J', self.fakesharepath)
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmsetquota', self.fakedev + ':' +
            self.share['name'], '--block', '0:' + sizestr)
        self._driver._gpfs_execute.assert_any_call(
            'chmod', '777', self.fakesharepath)

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
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmcrfileset', self.fakedev, self.share['name'],
            '--inode-space', 'new')

    def test__delete_share(self):
        self._driver._gpfs_execute = mock.Mock(return_value=True)
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._delete_share(self.share)
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
            self.share['name'], '-f', ignore_exit_code=[2])
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmdelfileset', self.fakedev, self.share['name'],
            '-f', ignore_exit_code=[2])
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
            self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
            self.share['name'], '-f', ignore_exit_code=[2])

    def test__create_share_snapshot(self):
        self._driver._gpfs_execute = mock.Mock(return_value=True)
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._create_share_snapshot(self.snapshot)
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmcrsnapshot', self.fakedev,
            self.snapshot['name'], '-j', self.snapshot['share_name']
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
            self.GPFS_PATH + 'mmcrsnapshot', self.fakedev,
            self.snapshot['name'], '-j', self.snapshot['share_name']
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

    @ddt.data("mmlsfileset::allocInodes:\nmmlsfileset::100096:",
              "mmlsfileset::allocInodes:\nmmlsfileset::0:")
    def test__is_share_valid_with_quota(self, fakeout):
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))

        result = self._driver._is_share_valid(self.fakedev, self.fakesharepath)

        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmlsfileset', self.fakedev, '-J',
            self.fakesharepath, '-L', '-Y')
        if fakeout == "mmlsfileset::allocInodes:\nmmlsfileset::100096:":
            self.assertTrue(result)
        else:
            self.assertFalse(result)

    def test__is_share_valid_exception(self):
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver._is_share_valid, self.fakedev,
                          self.fakesharepath)

        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmlsfileset', self.fakedev, '-J',
            self.fakesharepath, '-L', '-Y')

    def test__is_share_valid_no_share_exist_exception(self):
        fakeout = "mmlsfileset::allocInodes:"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))

        self.assertRaises(exception.GPFSException,
                          self._driver._is_share_valid, self.fakedev,
                          self.fakesharepath)

        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmlsfileset', self.fakedev, '-J',
            self.fakesharepath, '-L', '-Y')

    def test__get_share_name(self):
        fakeout = "mmlsfileset::filesetName:\nmmlsfileset::existingshare:"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))

        result = self._driver._get_share_name(self.fakedev, self.fakesharepath)

        self.assertEqual('existingshare', result)

    def test__get_share_name_exception(self):
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver._get_share_name, self.fakedev,
                          self.fakesharepath)

        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmlsfileset', self.fakedev, '-J',
            self.fakesharepath, '-L', '-Y')

    def test__get_share_name_no_share_exist_exception(self):
        fakeout = "mmlsfileset::filesetName:"
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))

        self.assertRaises(exception.GPFSException,
                          self._driver._get_share_name, self.fakedev,
                          self.fakesharepath)

        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmlsfileset', self.fakedev, '-J',
            self.fakesharepath, '-L', '-Y')

    @ddt.data("mmlsquota::blockLimit:\nmmlsquota::1048577",
              "mmlsquota::blockLimit:\nmmlsquota::1048576",
              "mmlsquota::blockLimit:\nmmlsquota::0")
    def test__manage_existing(self, fakeout):
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))
        self._helper_fake.create_export.return_value = 'fakelocation'
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)

        actual_size, actual_path = self._driver._manage_existing(
            self.fakedev, self.share, self.fakeexistingshare)

        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
            self.fakeexistingshare, '-f')
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmchfileset', self.fakedev,
            self.fakeexistingshare, '-j', self.share['name'])
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmlinkfileset', self.fakedev, self.share['name'],
            '-J', self.fakesharepath)
        self._driver._gpfs_execute.assert_any_call(
            'chmod', '777', self.fakesharepath)
        if fakeout == "mmlsquota::blockLimit:\nmmlsquota::1048577":
            self._driver._gpfs_execute.assert_called_with(
                self.GPFS_PATH + 'mmsetquota', self.fakedev + ':' +
                self.share['name'], '--block', '0:2G')
            self.assertEqual(2, actual_size)
            self.assertEqual('fakelocation', actual_path)
        elif fakeout == "mmlsquota::blockLimit:\nmmlsquota::0":
            self._driver._gpfs_execute.assert_called_with(
                self.GPFS_PATH + 'mmsetquota', self.fakedev + ':' +
                self.share['name'], '--block', '0:1G')
            self.assertEqual(1, actual_size)
            self.assertEqual('fakelocation', actual_path)
        else:
            self.assertEqual(1, actual_size)
            self.assertEqual('fakelocation', actual_path)

    def test__manage_existing_fileset_unlink_exception(self):
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self._driver._gpfs_execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)

        self.assertRaises(exception.GPFSException,
                          self._driver._manage_existing, self.fakedev,
                          self.share, self.fakeexistingshare)

        self._driver._local_path.assert_called_once_with(self.share['name'])
        self._driver._gpfs_execute.assert_called_once_with(
            self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
            self.fakeexistingshare, '-f')

    def test__manage_existing_fileset_creation_exception(self):
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self.mock_object(self._driver, '_gpfs_execute', mock.Mock(
            side_effect=['', exception.ProcessExecutionError]))

        self.assertRaises(exception.GPFSException,
                          self._driver._manage_existing, self.fakedev,
                          self.share, self.fakeexistingshare)

        self._driver._local_path.assert_any_call(self.share['name'])
        self._driver._gpfs_execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
                      self.fakeexistingshare, '-f'),
            mock.call(self.GPFS_PATH + 'mmchfileset', self.fakedev,
                      self.fakeexistingshare, '-j', self.share['name'])])

    def test__manage_existing_fileset_relink_exception(self):
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self.mock_object(self._driver, '_gpfs_execute', mock.Mock(
            side_effect=['', '', exception.ProcessExecutionError]))

        self.assertRaises(exception.GPFSException,
                          self._driver._manage_existing, self.fakedev,
                          self.share, self.fakeexistingshare)

        self._driver._local_path.assert_any_call(self.share['name'])
        self._driver._gpfs_execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
                      self.fakeexistingshare, '-f'),
            mock.call(self.GPFS_PATH + 'mmchfileset', self.fakedev,
                      self.fakeexistingshare, '-j', self.share['name']),
            mock.call(self.GPFS_PATH + 'mmlinkfileset', self.fakedev,
                      self.share['name'], '-J', self.fakesharepath)])

    def test__manage_existing_permission_change_exception(self):
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self.mock_object(self._driver, '_gpfs_execute', mock.Mock(
            side_effect=['', '', '', exception.ProcessExecutionError]))

        self.assertRaises(exception.GPFSException,
                          self._driver._manage_existing, self.fakedev,
                          self.share, self.fakeexistingshare)

        self._driver._local_path.assert_any_call(self.share['name'])
        self._driver._gpfs_execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
                      self.fakeexistingshare, '-f'),
            mock.call(self.GPFS_PATH + 'mmchfileset', self.fakedev,
                      self.fakeexistingshare, '-j', self.share['name']),
            mock.call(self.GPFS_PATH + 'mmlinkfileset', self.fakedev,
                      self.share['name'], '-J', self.fakesharepath),
            mock.call('chmod', '777', self.fakesharepath)])

    def test__manage_existing_checking_quota_of_fileset_exception(self):
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self.mock_object(self._driver, '_gpfs_execute', mock.Mock(
            side_effect=['', '', '', '', exception.ProcessExecutionError]))

        self.assertRaises(exception.GPFSException,
                          self._driver._manage_existing, self.fakedev,
                          self.share, self.fakeexistingshare)

        self._driver._local_path.assert_any_call(self.share['name'])
        self._driver._gpfs_execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
                      self.fakeexistingshare, '-f'),
            mock.call(self.GPFS_PATH + 'mmchfileset', self.fakedev,
                      self.fakeexistingshare, '-j', self.share['name']),
            mock.call(self.GPFS_PATH + 'mmlinkfileset', self.fakedev,
                      self.share['name'], '-J', self.fakesharepath),
            mock.call('chmod', '777', self.fakesharepath),
            mock.call(self.GPFS_PATH + 'mmlsquota', '-j', self.share['name'],
                      '-Y', self.fakedev)])

    def test__manage_existing_unable_to_get_quota_of_fileset_exception(self):
        fakeout = "mmlsquota::blockLimit:"
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self._driver._gpfs_execute = mock.Mock(return_value=(fakeout, ''))

        self.assertRaises(exception.GPFSException,
                          self._driver._manage_existing, self.fakedev,
                          self.share, self.fakeexistingshare)

        self._driver._local_path.assert_any_call(self.share['name'])
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
            self.fakeexistingshare, '-f')
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmchfileset', self.fakedev,
            self.fakeexistingshare, '-j', self.share['name'])
        self._driver._gpfs_execute.assert_any_call(
            self.GPFS_PATH + 'mmlinkfileset', self.fakedev,
            self.share['name'], '-J', self.fakesharepath)
        self._driver._gpfs_execute.assert_any_call(
            'chmod', '777', self.fakesharepath)
        self._driver._gpfs_execute.assert_called_with(
            self.GPFS_PATH + 'mmlsquota', '-j', self.share['name'],
            '-Y', self.fakedev)

    def test__manage_existing_set_quota_of_fileset_less_than_1G_exception(
            self):
        sizestr = '1G'
        mock_out = "mmlsquota::blockLimit:\nmmlsquota::0:", None
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self.mock_object(self._driver, '_gpfs_execute', mock.Mock(
            side_effect=['', '', '', '', mock_out,
                         exception.ProcessExecutionError]))

        self.assertRaises(exception.GPFSException,
                          self._driver._manage_existing, self.fakedev,
                          self.share, self.fakeexistingshare)

        self._driver._local_path.assert_any_call(self.share['name'])
        self._driver._gpfs_execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
                      self.fakeexistingshare, '-f'),
            mock.call(self.GPFS_PATH + 'mmchfileset', self.fakedev,
                      self.fakeexistingshare, '-j', self.share['name']),
            mock.call(self.GPFS_PATH + 'mmlinkfileset', self.fakedev,
                      self.share['name'], '-J', self.fakesharepath),
            mock.call('chmod', '777', self.fakesharepath),
            mock.call(self.GPFS_PATH + 'mmlsquota', '-j', self.share['name'],
                      '-Y', self.fakedev),
            mock.call(self.GPFS_PATH + 'mmsetquota', self.fakedev + ':' +
                      self.share['name'], '--block', '0:' + sizestr)])

    def test__manage_existing_set_quota_of_fileset_grater_than_1G_exception(
            self):
        sizestr = '2G'
        mock_out = "mmlsquota::blockLimit:\nmmlsquota::1048577:", None
        self._driver._local_path = mock.Mock(return_value=self.fakesharepath)
        self.mock_object(self._driver, '_gpfs_execute', mock.Mock(
            side_effect=['', '', '', '', mock_out,
                         exception.ProcessExecutionError]))

        self.assertRaises(exception.GPFSException,
                          self._driver._manage_existing, self.fakedev,
                          self.share, self.fakeexistingshare)

        self._driver._local_path.assert_any_call(self.share['name'])
        self._driver._gpfs_execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmunlinkfileset', self.fakedev,
                      self.fakeexistingshare, '-f'),
            mock.call(self.GPFS_PATH + 'mmchfileset', self.fakedev,
                      self.fakeexistingshare, '-j', self.share['name']),
            mock.call(self.GPFS_PATH + 'mmlinkfileset', self.fakedev,
                      self.share['name'], '-J', self.fakesharepath),
            mock.call('chmod', '777', self.fakesharepath),
            mock.call(self.GPFS_PATH + 'mmlsquota', '-j', self.share['name'],
                      '-Y', self.fakedev),
            mock.call(self.GPFS_PATH + 'mmsetquota', self.fakedev + ':' +
                      self.share['name'], '--block', '0:' + sizestr)])

    def test_manage_existing(self):
        self._driver._manage_existing = mock.Mock(return_value=('1',
                                                  'fakelocation'))
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._is_share_valid = mock.Mock(return_value=True)
        self._driver._get_share_name = mock.Mock(return_value=self.
                                                 fakeexistingshare)
        self._helper_fake._has_client_access = mock.Mock(return_value=[])

        result = self._driver.manage_existing(self.share, {})

        self.assertEqual('1', result['size'])
        self.assertEqual('fakelocation', result['export_locations'])

    def test_manage_existing_incorrect_path_exception(self):
        share = fake_share.fake_share(export_location="wrong_ip::wrong_path")

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing, share, {})

    def test_manage_existing_incorrect_ip_exception(self):
        share = fake_share.fake_share(export_location="wrong_ip:wrong_path")

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing, share, {})

    def test__manage_existing_invalid_export_exception(self):
        share = fake_share.fake_share(export_location="wrong_ip/wrong_path")

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing, share, {})

    @ddt.data(True, False)
    def test_manage_existing_invalid_share_exception(self, valid_share):
        self._driver._get_gpfs_device = mock.Mock(return_value=self.fakedev)
        self._driver._is_share_valid = mock.Mock(return_value=valid_share)
        if valid_share:
            self._driver._get_share_name = mock.Mock(return_value=self.
                                                     fakeexistingshare)
            self._helper_fake._has_client_access = mock.Mock()
        else:
            self.assertFalse(self._helper_fake._has_client_access.called)

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing, self.share, {})

    def test__gpfs_local_execute(self):
        self.mock_object(utils, 'execute', mock.Mock(return_value=True))
        cmd = "testcmd"
        self._driver._gpfs_local_execute(cmd, ignore_exit_code=[2])
        utils.execute.assert_called_once_with(cmd, run_as_root=True,
                                              check_exit_code=[2, 0])

    def test__gpfs_remote_execute(self):
        self._driver._run_ssh = mock.Mock(return_value=True)
        cmd = "testcmd"
        orig_value = self._driver.configuration.gpfs_share_export_ip
        self._driver.configuration.gpfs_share_export_ip = self.local_ip
        self._driver._gpfs_remote_execute(cmd, check_exit_code=True)
        self._driver._run_ssh.assert_called_once_with(
            self.local_ip, tuple([cmd]), None, True
        )
        self._driver.configuration.gpfs_share_export_ip = orig_value

    def test_knfs_resync_access(self):
        self._knfs_helper.allow_access = mock.Mock()
        path = self.fakesharepath
        to_remove = '3.3.3.3'
        fake_exportfs_before = ('%(path)s\n\t\t%(ip)s\n'
                                '/other/path\n\t\t4.4.4.4\n' %
                                {'path': path, 'ip': to_remove})
        fake_exportfs_after = '/other/path\n\t\t4.4.4.4\n'
        self._knfs_helper._execute = mock.Mock(
            return_value=(fake_exportfs_before, ''))
        self._knfs_helper._publish_access = mock.Mock(
            side_effect=[[(fake_exportfs_before, '')],
                         [(fake_exportfs_after, '')]])

        access_1 = fake_share.fake_access(access_to="1.1.1.1")
        access_2 = fake_share.fake_access(access_to="2.2.2.2")
        self._knfs_helper.resync_access(path, self.share, [access_1, access_2])

        self._knfs_helper.allow_access.assert_has_calls([
            mock.call(path, self.share, access_1, error_on_exists=False),
            mock.call(path, self.share, access_2, error_on_exists=False)])
        self._knfs_helper._execute.assert_called_once_with(
            'exportfs', run_as_root=True)
        self._knfs_helper._publish_access.assert_has_calls([
            mock.call('exportfs', '-u',
                      '%(ip)s:%(path)s' % {'ip': to_remove, 'path': path},
                      check_exit_code=[0, 1]),
            mock.call('exportfs')])

    @ddt.data('rw', 'ro')
    def test_knfs_get_export_options(self, access_level):
        mock_out = {"knfs:export_options": "no_root_squash"}
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=mock_out))
        access = fake_share.fake_access(access_level=access_level)
        out = self._knfs_helper.get_export_options(self.share, access, 'KNFS')
        self.assertEqual("no_root_squash,%s" % access_level, out)

    def test_knfs_get_export_options_default(self):
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={}))
        access = self.access
        out = self._knfs_helper.get_export_options(self.share, access, 'KNFS')
        self.assertEqual("rw", out)

    def test_knfs_get_export_options_invalid_option_ro(self):
        mock_out = {"knfs:export_options": "ro"}
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=mock_out))
        access = self.access
        share = fake_share.fake_share(share_type="fake_share_type")
        self.assertRaises(exception.InvalidInput,
                          self._knfs_helper.get_export_options,
                          share, access, 'KNFS')

    def test_knfs_get_export_options_invalid_option_rw(self):
        mock_out = {"knfs:export_options": "rw"}
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=mock_out))
        access = self.access
        share = fake_share.fake_share(share_type="fake_share_type")
        self.assertRaises(exception.InvalidInput,
                          self._knfs_helper.get_export_options,
                          share, access, 'KNFS')

    @ddt.data(("/gpfs0/share-fakeid\t10.0.0.1", None),
              ("", None),
              ("/gpfs0/share-fakeid\t10.0.0.1", "10.0.0.1"),
              ("/gpfs0/share-fakeid\t10.0.0.1", "10.0.0.2"))
    @ddt.unpack
    def test_knfs__has_client_access(self, mock_out, access_to):
        self._knfs_helper._execute = mock.Mock(return_value=[mock_out, 0])

        result = self._knfs_helper._has_client_access(self.fakesharepath,
                                                      access_to)

        self._ces_helper._execute.assert_called_once_with('exportfs',
                                                          check_exit_code=True,
                                                          run_as_root=True)
        if mock_out == "/gpfs0/share-fakeid\t10.0.0.1":
            if access_to in (None, "10.0.0.1"):
                self.assertTrue(result)
            else:
                self.assertFalse(result)
        else:
            self.assertFalse(result)

    def test_knfs_allow_access(self):
        self._knfs_helper._execute = mock.Mock(
            return_value=['/fs0 <world>', 0]
        )
        self.mock_object(re, 'search', mock.Mock(return_value=None))
        export_opts = None
        self._knfs_helper.get_export_options = mock.Mock(
            return_value=export_opts
        )
        self._knfs_helper._publish_access = mock.Mock()
        access = self.access
        local_path = self.fakesharepath
        self._knfs_helper.allow_access(local_path, self.share, access)
        self._knfs_helper._execute.assert_called_once_with('exportfs',
                                                           run_as_root=True)
        self.assertTrue(re.search.called)
        self._knfs_helper.get_export_options.assert_any_call(
            self.share, access, 'KNFS')
        cmd = ['exportfs', '-o', export_opts, ':'.join([access['access_to'],
                                                       local_path])]
        self._knfs_helper._publish_access.assert_called_once_with(*cmd)

    def test_knfs_allow_access_access_exists(self):
        out = ['/fs0 <world>', 0]
        self._knfs_helper._execute = mock.Mock(return_value=out)
        self.mock_object(re, 'search', mock.Mock(return_value="fake"))
        self._knfs_helper.get_export_options = mock.Mock()
        access = self.access
        local_path = self.fakesharepath
        self.assertRaises(exception.ShareAccessExists,
                          self._knfs_helper.allow_access,
                          local_path, self.share, access)
        self._knfs_helper._execute.assert_any_call('exportfs',
                                                   run_as_root=True)
        self.assertTrue(re.search.called)
        self.assertFalse(self._knfs_helper.get_export_options.called)

    def test_knfs_allow_access_publish_exception(self):
        self._knfs_helper.get_export_options = mock.Mock()
        self._knfs_helper._publish_access = mock.Mock(
            side_effect=exception.ProcessExecutionError('boom'))

        self.assertRaises(exception.GPFSException,
                          self._knfs_helper.allow_access,
                          self.fakesharepath,
                          self.share,
                          self.access,
                          error_on_exists=False)

        self.assertTrue(self._knfs_helper.get_export_options.called)
        self.assertTrue(self._knfs_helper._publish_access.called)

    def test_knfs_allow_access_invalid_access(self):
        access = fake_share.fake_access(access_type='test')
        self.assertRaises(exception.InvalidShareAccess,
                          self._knfs_helper.allow_access,
                          self.fakesharepath, self.share,
                          access)

    def test_knfs_allow_access_exception(self):
        self._knfs_helper._execute = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )
        access = self.access
        local_path = self.fakesharepath
        self.assertRaises(exception.GPFSException,
                          self._knfs_helper.allow_access,
                          local_path, self.share,
                          access)
        self._knfs_helper._execute.assert_called_once_with('exportfs',
                                                           run_as_root=True)

    def test_knfs__verify_denied_access_pass(self):
        local_path = self.fakesharepath
        ip = self.access['access_to']
        fake_exportfs = ('/shares/share-1\n\t\t1.1.1.1\n'
                         '/shares/share-2\n\t\t2.2.2.2\n')
        self._knfs_helper._publish_access = mock.Mock(
            return_value=[(fake_exportfs, '')])

        self._knfs_helper._verify_denied_access(local_path, self.share, ip)

        self._knfs_helper._publish_access.assert_called_once_with('exportfs')

    def test_knfs__verify_denied_access_fail(self):
        local_path = self.fakesharepath
        ip = self.access['access_to']
        data = {'path': local_path, 'ip': ip}
        fake_exportfs = ('/shares/share-1\n\t\t1.1.1.1\n'
                         '%(path)s\n\t\t%(ip)s\n'
                         '/shares/share-2\n\t\t2.2.2.2\n') % data
        self._knfs_helper._publish_access = mock.Mock(
            return_value=[(fake_exportfs, '')])

        self.assertRaises(exception.GPFSException,
                          self._knfs_helper._verify_denied_access,
                          local_path,
                          self.share,
                          ip)

        self._knfs_helper._publish_access.assert_called_once_with('exportfs')

    def test_knfs__verify_denied_access_exception(self):
        self._knfs_helper._publish_access = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )

        ip = self.access['access_to']
        local_path = self.fakesharepath

        self.assertRaises(exception.GPFSException,
                          self._knfs_helper._verify_denied_access,
                          local_path,
                          self.share,
                          ip)

        self._knfs_helper._publish_access.assert_called_once_with('exportfs')

    @ddt.data((None, False),
              ('', False),
              (' ', False),
              ('Some error to log', True))
    @ddt.unpack
    def test_knfs__verify_denied_access_stderr(self, stderr, is_logged):
        """Stderr debug logging should only happen when not empty."""
        outputs = [('', stderr)]
        self._knfs_helper._publish_access = mock.Mock(return_value=outputs)
        gpfs.LOG.debug = mock.Mock()

        self._knfs_helper._verify_denied_access(
            self.fakesharepath, self.share, self.remote_ip)

        self._knfs_helper._publish_access.assert_called_once_with('exportfs')
        self.assertEqual(is_logged, gpfs.LOG.debug.called)

    def test_knfs_deny_access(self):
        self._knfs_helper._publish_access = mock.Mock(return_value=[('', '')])

        access = self.access
        local_path = self.fakesharepath
        self._knfs_helper.deny_access(local_path, self.share, access)

        deny = ['exportfs', '-u', ':'.join([access['access_to'], local_path])]
        self._knfs_helper._publish_access.assert_has_calls([
            mock.call(*deny, check_exit_code=[0, 1]),
            mock.call('exportfs')])

    def test_knfs_deny_access_exception(self):
        self._knfs_helper._publish_access = mock.Mock(
            side_effect=exception.ProcessExecutionError
        )

        access = self.access
        local_path = self.fakesharepath
        cmd = ['exportfs', '-u', ':'.join([access['access_to'], local_path])]
        self.assertRaises(exception.GPFSException,
                          self._knfs_helper.deny_access, local_path,
                          self.share, access)

        self._knfs_helper._publish_access.assert_called_once_with(
            *cmd, check_exit_code=[0, 1])

    def test_knfs__publish_access(self):
        self.mock_object(utils, 'execute')

        fake_command = 'fakecmd'
        cmd = [fake_command]
        self._knfs_helper._publish_access(*cmd)

        utils.execute.assert_any_call(*cmd, run_as_root=True,
                                      check_exit_code=True)
        remote_login = self.sshlogin + '@' + self.remote_ip
        remote_login2 = self.sshlogin + '@' + self.remote_ip2
        utils.execute.assert_has_calls([
            mock.call('ssh', remote_login, fake_command,
                      check_exit_code=True, run_as_root=False),
            mock.call(fake_command, check_exit_code=True, run_as_root=True),
            mock.call('ssh', remote_login2, fake_command,
                      check_exit_code=True, run_as_root=False)])
        self.assertTrue(socket.gethostbyname_ex.called)
        self.assertTrue(socket.gethostname.called)

    def test_knfs__publish_access_exception(self):
        self.mock_object(
            utils, 'execute',
            mock.Mock(side_effect=(0, exception.ProcessExecutionError)))

        fake_command = 'fakecmd'
        cmd = [fake_command]
        self.assertRaises(exception.ProcessExecutionError,
                          self._knfs_helper._publish_access, *cmd)

        self.assertTrue(socket.gethostbyname_ex.called)
        self.assertTrue(socket.gethostname.called)
        remote_login = self.sshlogin + '@' + self.remote_ip
        utils.execute.assert_has_calls([
            mock.call('ssh', remote_login, fake_command,
                      check_exit_code=True, run_as_root=False),
            mock.call(fake_command, check_exit_code=True, run_as_root=True)])

    @ddt.data('rw', 'ro')
    def test_ces_get_export_options(self, access_level):
        mock_out = {"ces:export_options": "squash=no_root_squash"}
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=mock_out))
        access = fake_share.fake_access(access_level=access_level)
        out = self._ces_helper.get_export_options(self.share, access, 'CES')
        self.assertEqual("squash=no_root_squash,access_type=%s" % access_level,
                         out)

    def test_ces_get_export_options_default(self):
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={}))
        access = self.access
        out = self._ces_helper.get_export_options(self.share, access,
                                                  'CES')
        self.assertEqual("access_type=rw", out)

    def test_ces_get_export_options_invalid_option_ro(self):
        mock_out = {"ces:export_options": "access_type=ro"}
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=mock_out))
        access = self.access
        share = fake_share.fake_share(share_type="fake_share_type")
        self.assertRaises(exception.InvalidInput,
                          self._ces_helper.get_export_options,
                          share, access, 'CES')

    def test_ces_get_export_options_invalid_option_rw(self):
        mock_out = {"ces:export_options": "access_type=rw"}
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=mock_out))
        access = self.access
        share = fake_share.fake_share(share_type="fake_share_type")
        self.assertRaises(exception.InvalidInput,
                          self._ces_helper.get_export_options,
                          share, access, 'CES')

    def test__get_nfs_client_exports_exception(self):
        self._ces_helper._execute = mock.Mock(return_value=('junk', ''))

        local_path = self.fakesharepath
        self.assertRaises(exception.GPFSException,
                          self._ces_helper._get_nfs_client_exports,
                          local_path)

        self._ces_helper._execute.assert_called_once_with(
            self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n', local_path, '-Y')

    @ddt.data('44.3.2.11', '1:2:3:4:5:6:7:8')
    def test__fix_export_data(self, ip):
        data = None
        for line in self.fake_ces_exports.splitlines():
            if "HEADER" in line:
                headers = line.split(':')
            if ip in line:
                data = line.split(':')
                break
        self.assertIsNotNone(
            data, "Test data did not contain a line with the test IP.")

        result_data = self._ces_helper._fix_export_data(data, headers)

        self.assertEqual(ip, result_data[headers.index('Clients')])

    @ddt.data((None, True),
              ('44.3.2.11', True),
              ('44.3.2.1', False),
              ('4.3.2.1', False),
              ('4.3.2.11', False),
              ('1.2.3.4', False),
              ('', False),
              ('*', False),
              ('.', False),
              ('1:2:3:4:5:6:7:8', True))
    @ddt.unpack
    def test_ces__has_client_access(self, ip, has_access):
        mock_out = self.fake_ces_exports
        self._ces_helper._execute = mock.Mock(
            return_value=(mock_out, ''))

        local_path = self.fakesharepath
        self.assertEqual(has_access,
                         self._ces_helper._has_client_access(local_path, ip))

        self._ces_helper._execute.assert_called_once_with(
            self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n', local_path, '-Y')

    def test_ces_remove_export_no_exports(self):
        mock_out = self.fake_ces_exports_not_found
        self._ces_helper._execute = mock.Mock(
            return_value=(mock_out, ''))

        local_path = self.fakesharepath
        self._ces_helper.remove_export(local_path, self.share)

        self._ces_helper._execute.assert_called_once_with(
            self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n', local_path, '-Y')

    def test_ces_remove_export_existing_exports(self):
        mock_out = self.fake_ces_exports
        self._ces_helper._execute = mock.Mock(
            return_value=(mock_out, ''))

        local_path = self.fakesharepath
        self._ces_helper.remove_export(local_path, self.share)

        self._ces_helper._execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n',
                      local_path, '-Y'),
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'remove',
                      local_path),
        ])

    def test_ces_remove_export_exception(self):
        local_path = self.fakesharepath
        self._ces_helper._execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.GPFSException,
                          self._ces_helper.remove_export,
                          local_path, self.share)

    def test_ces_allow_access(self):
        mock_out = self.fake_ces_exports_not_found
        self._ces_helper._execute = mock.Mock(
            return_value=(mock_out, ''))

        export_opts = "access_type=rw"
        self._ces_helper.get_export_options = mock.Mock(
            return_value=export_opts)

        access = self.access
        local_path = self.fakesharepath

        self._ces_helper.allow_access(local_path, self.share, access)

        self._ces_helper._execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n',
                      local_path, '-Y'),
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'add', local_path,
                      '-c', access['access_to'] + '(' + export_opts + ')')])

    def test_ces_allow_access_existing_exports(self):
        mock_out = self.fake_ces_exports
        self._ces_helper._execute = mock.Mock(
            return_value=(mock_out, ''))

        export_opts = "access_type=rw"
        self._ces_helper.get_export_options = mock.Mock(
            return_value=export_opts)

        access = self.access
        local_path = self.fakesharepath

        self._ces_helper.allow_access(self.fakesharepath, self.share,
                                      self.access)

        self._ces_helper._execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n',
                      local_path, '-Y'),
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'change', local_path,
                      '--nfsadd', access['access_to'] + '(' +
                      export_opts + ')')])

    def test_ces_allow_access_invalid_access_type(self):
        access = fake_share.fake_access(access_type='test')
        self.assertRaises(exception.InvalidShareAccess,
                          self._ces_helper.allow_access,
                          self.fakesharepath, self.share,
                          access)

    def test_ces_allow_access_exception(self):
        access = self.access
        local_path = self.fakesharepath
        self._ces_helper._execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.GPFSException,
                          self._ces_helper.allow_access, local_path,
                          self.share, access)

    def test_ces_deny_access(self):
        mock_out = self.fake_ces_exports
        self._ces_helper._execute = mock.Mock(
            return_value=(mock_out, ''))

        access = self.access
        local_path = self.fakesharepath

        self._ces_helper.deny_access(local_path, self.share, access)

        self._ces_helper._execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n',
                      local_path, '-Y'),
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'change', local_path,
                      '--nfsremove', access['access_to'])])

    def test_ces_deny_access_exception(self):
        access = self.access
        local_path = self.fakesharepath
        self._ces_helper._execute = mock.Mock(
            side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.GPFSException,
                          self._ces_helper.deny_access, local_path,
                          self.share, access)

    def test_ces_resync_access_add(self):
        mock_out = self.fake_ces_exports_not_found
        self._ces_helper._execute = mock.Mock(return_value=(mock_out, ''))
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={}))

        access_rules = [self.access]
        local_path = self.fakesharepath
        self._ces_helper.resync_access(local_path, self.share, access_rules)

        self._ces_helper._execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n',
                      local_path, '-Y'),
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'add', local_path,
                      '-c', self.access['access_to'] + '(' + "access_type=rw" +
                      ')')
        ])
        share_types.get_extra_specs_from_share.assert_called_once_with(
            self.share)

    def test_ces_resync_access_change(self):

        class SortedMatch(object):
            def __init__(self, f, expected):
                self.assertEqual = f
                self.expected = expected

            def __eq__(self, actual):
                expected_list = self.expected.split(',')
                actual_list = actual.split(',')
                self.assertEqual(sorted(expected_list), sorted(actual_list))
                return True

        mock_out = self.fake_ces_exports
        self._ces_helper._execute = mock.Mock(
            return_value=(mock_out, ''))
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={}))

        access_rules = [fake_share.fake_access(access_to='1.1.1.1'),
                        fake_share.fake_access(
                            access_to='10.0.0.1', access_level='ro')]
        local_path = self.fakesharepath
        self._ces_helper.resync_access(local_path, self.share, access_rules)

        share_types.get_extra_specs_from_share.assert_called_once_with(
            self.share)
        to_remove = '1:2:3:4:5:6:7:8,44.3.2.11'
        to_add = access_rules[0]['access_to'] + '(' + "access_type=rw" + ')'
        to_change = access_rules[1]['access_to'] + '(' + "access_type=ro" + ')'
        self._ces_helper._execute.assert_has_calls([
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n',
                      local_path, '-Y'),
            mock.call(self.GPFS_PATH + 'mmnfs', 'export', 'change', local_path,
                      '--nfsremove', SortedMatch(self.assertEqual, to_remove),
                      '--nfsadd', to_add,
                      '--nfschange', to_change)
        ])

    def test_ces_resync_nothing(self):
        """Test that hits the add-no-rules case."""
        mock_out = self.fake_ces_exports_not_found
        self._ces_helper._execute = mock.Mock(return_value=(mock_out, ''))

        local_path = self.fakesharepath
        self._ces_helper.resync_access(local_path, None, [])

        self._ces_helper._execute.assert_called_once_with(
            self.GPFS_PATH + 'mmnfs', 'export', 'list', '-n', local_path, '-Y')
