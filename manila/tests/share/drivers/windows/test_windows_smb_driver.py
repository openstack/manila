# Copyright (c) 2015 Cloudbase Solutions SRL
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

import os

from manila.share import configuration
from manila.share.drivers import generic
from manila.share.drivers.windows import service_instance
from manila.share.drivers.windows import windows_smb_driver as windows_drv
from manila.share.drivers.windows import windows_smb_helper
from manila.share.drivers.windows import windows_utils
from manila.share.drivers.windows import winrm_helper
from manila import test


@ddt.ddt
class WindowsSMBDriverTestCase(test.TestCase):
    @mock.patch.object(winrm_helper, 'WinRMHelper')
    @mock.patch.object(windows_utils, 'WindowsUtils')
    @mock.patch.object(windows_smb_helper, 'WindowsSMBHelper')
    @mock.patch.object(service_instance,
                       'WindowsServiceInstanceManager')
    def setUp(self, mock_sv_instance_mgr, mock_smb_helper_cls,
              mock_utils_cls, mock_winrm_helper_cls):
        self.flags(driver_handles_share_servers=False)
        self._fake_conf = configuration.Configuration(None)

        self._drv = windows_drv.WindowsSMBDriver(
            configuration=self._fake_conf)

        self._remote_execute = mock_winrm_helper_cls.return_value
        self._windows_utils = mock_utils_cls.return_value
        self._smb_helper = mock_smb_helper_cls.return_value
        super(WindowsSMBDriverTestCase, self).setUp()

    @mock.patch('manila.share.driver.ShareDriver')
    def test_update_share_stats(self, mock_base_driver):
        self._drv._update_share_stats()
        mock_base_driver._update_share_stats.assert_called_once_with(
            self._drv,
            data=dict(storage_protocol="CIFS"))

    @mock.patch.object(service_instance, 'WindowsServiceInstanceManager')
    def test_setup_service_instance_manager(self, mock_sv_instance_mgr):
        self._drv._setup_service_instance_manager()
        mock_sv_instance_mgr.assert_called_once_with(
            driver_config=self._fake_conf)

    def test_setup_helpers(self):
        expected_helpers = {"SMB": self._smb_helper,
                            "CIFS": self._smb_helper}
        self._drv._setup_helpers()
        self.assertEqual(expected_helpers, self._drv._helpers)

    @mock.patch.object(generic.GenericShareDriver, '_teardown_server')
    def test_teardown_server(self, mock_super_teardown):
        mock_server = {'joined_domain': True,
                       'instance_id': mock.sentinel.instance_id}
        mock_sec_service = {'user': mock.sentinel.user,
                            'password': mock.sentinel.password,
                            'domain': mock.sentinel.domain}

        sv_mgr = self._drv.service_instance_manager
        sv_mgr.get_valid_security_service.return_value = mock_sec_service
        # We ensure that domain unjoin exceptions do not prevent the
        # service instance from being teared down.
        self._windows_utils.unjoin_domain.side_effect = Exception

        self._drv._teardown_server(mock_server,
                                   mock_sec_service)

        sv_mgr.get_valid_security_service.assert_called_once_with(
            mock_sec_service)
        self._windows_utils.unjoin_domain.assert_called_once_with(
            mock_server,
            mock_sec_service['user'],
            mock_sec_service['password'])
        mock_super_teardown.assert_called_once_with(mock_server,
                                                    mock_sec_service)

    @mock.patch.object(windows_drv.WindowsSMBDriver, '_get_disk_number')
    def test_format_device(self, mock_get_disk_number):
        mock_get_disk_number.return_value = mock.sentinel.disk_number

        self._drv._format_device(mock.sentinel.server, mock.sentinel.vol)

        self._drv._get_disk_number.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.vol)
        self._windows_utils.initialize_disk.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number)
        self._windows_utils.create_partition.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number)
        self._windows_utils.format_partition.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number,
            self._drv._DEFAULT_SHARE_PARTITION)

    @mock.patch.object(windows_drv.WindowsSMBDriver,
                       '_ensure_disk_online_and_writable')
    @mock.patch.object(windows_drv.WindowsSMBDriver, '_get_disk_number')
    @mock.patch.object(windows_drv.WindowsSMBDriver, '_get_mount_path')
    @mock.patch.object(windows_drv.WindowsSMBDriver, '_is_device_mounted')
    def test_mount_device(self, mock_device_mounted, mock_get_mount_path,
                          mock_get_disk_number, mock_ensure_disk):
        mock_get_mount_path.return_value = mock.sentinel.mount_path
        mock_get_disk_number.return_value = mock.sentinel.disk_number
        mock_device_mounted.return_value = False

        self._drv._mount_device(share=mock.sentinel.share,
                                server_details=mock.sentinel.server,
                                volume=mock.sentinel.vol)

        mock_device_mounted.assert_called_once_with(
            mock.sentinel.mount_path, mock.sentinel.server, mock.sentinel.vol)
        mock_get_disk_number.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.vol)
        self._windows_utils.ensure_directory_exists.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.mount_path)
        self._windows_utils.add_access_path(
            mock.sentinel.server,
            mock.sentinel.mount_path,
            mock.sentinel.disk_number,
            self._drv._DEFAULT_SHARE_PARTITION)
        mock_ensure_disk.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number)

    @mock.patch.object(windows_drv.WindowsSMBDriver, '_get_mount_path')
    def test_unmount_device(self, mock_get_mount_path):
        mock_get_mount_path.return_value = mock.sentinel.mount_path
        mock_get_disk_number_by_path = (
            self._windows_utils.get_disk_number_by_mount_path)

        self._drv._unmount_device(mock.sentinel.share,
                                  mock.sentinel.server)

        mock_get_mount_path.assert_called_once_with(mock.sentinel.share)

        mock_get_disk_number_by_path.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.mount_path)
        self._windows_utils.set_disk_online_status.assert_called_once_with(
            mock.sentinel.server,
            mock_get_disk_number_by_path.return_value,
            online=False)

    @ddt.data(None, 1)
    @mock.patch.object(windows_drv.WindowsSMBDriver, '_get_disk_number')
    @mock.patch.object(windows_drv.WindowsSMBDriver,
                       '_ensure_disk_online_and_writable')
    def test_resize_filesystem(self, new_size, mock_ensure_disk,
                               mock_get_disk_number):
        mock_get_disk_number.return_value = mock.sentinel.disk_number
        mock_get_max_size = self._windows_utils.get_partition_maximum_size
        mock_get_max_size.return_value = mock.sentinel.max_size

        self._drv._resize_filesystem(mock.sentinel.server,
                                     mock.sentinel.vol,
                                     new_size=new_size)

        mock_get_disk_number.assert_called_once_with(mock.sentinel.server,
                                                     mock.sentinel.vol)
        self._drv._ensure_disk_online_and_writable.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number)

        if not new_size:
            mock_get_max_size.assert_called_once_with(
                mock.sentinel.server,
                mock.sentinel.disk_number,
                self._drv._DEFAULT_SHARE_PARTITION)
            expected_new_size = mock.sentinel.max_size
        else:
            expected_new_size = new_size << 30

        self._windows_utils.resize_partition.assert_called_once_with(
            mock.sentinel.server,
            expected_new_size,
            mock.sentinel.disk_number,
            self._drv._DEFAULT_SHARE_PARTITION)

    def test_ensure_disk_online_and_writable(self):
        self._drv._ensure_disk_online_and_writable(
            mock.sentinel.server, mock.sentinel.disk_number)

        self._windows_utils.update_disk.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number)
        self._windows_utils.set_disk_online_status.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number, online=True)
        self._windows_utils.set_disk_readonly_status.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number, readonly=False)

    def test_get_mounted_share_size(self):
        fake_size_gb = 10
        self._windows_utils.get_disk_space_by_path.return_value = (
            fake_size_gb << 30, mock.sentinel.free_bytes)

        share_size = self._drv._get_mounted_share_size(
            mock.sentinel.mount_path,
            mock.sentinel.server)

        self.assertEqual(fake_size_gb, share_size)

    def test_get_consumed_space(self):
        fake_size_gb = 2
        fake_free_space_gb = 1
        self._windows_utils.get_disk_space_by_path.return_value = (
            fake_size_gb << 30, fake_free_space_gb << 30)

        consumed_space = self._drv._get_consumed_space(
            mock.sentinel.mount_path,
            mock.sentinel.server)

        self.assertEqual(fake_size_gb - fake_free_space_gb, consumed_space)

    def test_get_mount_path(self):
        fake_mount_path = 'fake_mount_path'
        fake_share_name = 'fake_share_name'
        mock_share = {'name': fake_share_name}
        self.flags(share_mount_path=fake_mount_path)

        mount_path = self._drv._get_mount_path(mock_share)

        self._windows_utils.normalize_path.assert_called_once_with(
            os.path.join(fake_mount_path, fake_share_name))
        self.assertEqual(self._windows_utils.normalize_path.return_value,
                         mount_path)

    @ddt.data(None, 2)
    def test_get_disk_number(self, disk_number_by_serial=None):
        mock_get_disk_number_by_serial = (
            self._windows_utils.get_disk_number_by_serial_number)

        mock_get_disk_number_by_serial.return_value = disk_number_by_serial
        mock_volume = {'id': mock.sentinel.vol_id,
                       'mountpoint': "/dev/sdb"}
        # If the disk number cannot be identified using the disk serial
        # number, we expect it to be retrieved based on the volume mountpoint,
        # having disk number 1 in this case.
        expected_disk_number = (disk_number_by_serial
                                if disk_number_by_serial else 1)

        disk_number = self._drv._get_disk_number(mock.sentinel.server,
                                                 mock_volume)

        mock_get_disk_number_by_serial.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.vol_id)
        self.assertEqual(expected_disk_number, disk_number)

    @ddt.data(None, 2)
    def test_is_device_mounted(self, disk_number_by_path):
        mock_get_disk_number_by_path = (
            self._windows_utils.get_disk_number_by_mount_path)
        mock_get_disk_number_by_path.return_value = disk_number_by_path

        expected_result = disk_number_by_path is not None
        is_mounted = self._drv._is_device_mounted(
            mount_path=mock.sentinel.mount_path,
            server_details=mock.sentinel.server)

        mock_get_disk_number_by_path.assert_called_once_with(
            mock.sentinel.server,
            mock.sentinel.mount_path)
        self.assertEqual(expected_result, is_mounted)
