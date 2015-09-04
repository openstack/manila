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

from manila.share.drivers.windows import windows_utils
from manila import test


@ddt.ddt
class WindowsUtilsTestCase(test.TestCase):
    def setUp(self):
        self._remote_exec = mock.Mock()
        self._windows_utils = windows_utils.WindowsUtils(self._remote_exec)
        super(WindowsUtilsTestCase, self).setUp()

    def test_initialize_disk(self):
        self._windows_utils.initialize_disk(mock.sentinel.server,
                                            mock.sentinel.disk_number)

        cmd = ["Initialize-Disk", "-Number", mock.sentinel.disk_number]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_create_partition(self):
        self._windows_utils.create_partition(mock.sentinel.server,
                                             mock.sentinel.disk_number)

        cmd = ["New-Partition", "-DiskNumber",
               mock.sentinel.disk_number, "-UseMaximumSize"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_format_partition(self):
        self._windows_utils.format_partition(mock.sentinel.server,
                                             mock.sentinel.disk_number,
                                             mock.sentinel.partition_number)
        cmd = ("Get-Partition -DiskNumber %(disk_number)s "
               "-PartitionNumber %(partition_number)s | "
               "Format-Volume -FileSystem NTFS -Force -Confirm:$false" % {
                   'disk_number': mock.sentinel.disk_number,
                   'partition_number': mock.sentinel.partition_number,
               })
        self._remote_exec.assert_called_once_with(mock.sentinel.server,
                                                  cmd)

    def test_add_access_path(self):
        self._windows_utils.add_access_path(mock.sentinel.server,
                                            mock.sentinel.mount_path,
                                            mock.sentinel.disk_number,
                                            mock.sentinel.partition_number)

        cmd = ["Add-PartitionAccessPath", "-DiskNumber",
               mock.sentinel.disk_number,
               "-PartitionNumber", mock.sentinel.partition_number,
               "-AccessPath", self._windows_utils.quote_string(
                   mock.sentinel.mount_path)
               ]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_resize_partition(self):
        self._windows_utils.resize_partition(mock.sentinel.server,
                                             mock.sentinel.size_bytes,
                                             mock.sentinel.disk_number,
                                             mock.sentinel.partition_number)

        cmd = ['Resize-Partition', '-DiskNumber', mock.sentinel.disk_number,
               '-PartitionNumber', mock.sentinel.partition_number,
               '-Size', mock.sentinel.size_bytes]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @ddt.data("1", "")
    def test_get_disk_number_by_serial_number(self, disk_number):
        mock_serial_number = "serial_number"
        self._remote_exec.return_value = (disk_number, mock.sentinel.std_err)
        expected_disk_number = int(disk_number) if disk_number else None

        result = self._windows_utils.get_disk_number_by_serial_number(
            mock.sentinel.server,
            mock_serial_number)

        pattern = "%s*" % mock_serial_number
        cmd = ("Get-Disk | "
               "Where-Object {$_.SerialNumber -like '%s'} | "
               "Select-Object -ExpandProperty Number" % pattern)

        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(expected_disk_number, result)

    @ddt.data("1", "")
    def test_get_disk_number_by_mount_path(self, disk_number):
        fake_mount_path = "fake_mount_path"
        self._remote_exec.return_value = (disk_number, mock.sentinel.std_err)
        expected_disk_number = int(disk_number) if disk_number else None

        result = self._windows_utils.get_disk_number_by_mount_path(
            mock.sentinel.server,
            fake_mount_path)

        cmd = ('Get-Partition | '
               'Where-Object {$_.AccessPaths -contains "%s"} | '
               'Select-Object -ExpandProperty DiskNumber' %
               (fake_mount_path + "\\"))
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(expected_disk_number, result)

    def test_get_volume_path_by_mount_path(self):
        fake_mount_path = "fake_mount_path"
        fake_volume_path = "fake_volume_path"
        self._remote_exec.return_value = fake_volume_path + '\r\n', None

        result = self._windows_utils.get_volume_path_by_mount_path(
            mock.sentinel.server,
            fake_mount_path)

        cmd = ('Get-Partition | '
               'Where-Object {$_.AccessPaths -contains "%s"} | '
               'Get-Volume | '
               'Select-Object -ExpandProperty Path' %
               (fake_mount_path + "\\"))
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(fake_volume_path, result)

    def test_get_disk_space_by_path(self):
        fake_disk_size = 1024
        fake_free_bytes = 1000
        fake_fsutil_output = ("Total # of bytes  : %(total_bytes)s"
                              "Total # of avail free bytes  : %(free_bytes)s"
                              % dict(total_bytes=fake_disk_size,
                                     free_bytes=fake_free_bytes))
        self._remote_exec.return_value = fake_fsutil_output, None

        result = self._windows_utils.get_disk_space_by_path(
            mock.sentinel.server,
            mock.sentinel.mount_path)

        cmd = ["fsutil", "volume", "diskfree",
               self._windows_utils.quote_string(mock.sentinel.mount_path)]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual((fake_disk_size, fake_free_bytes), result)

    def test_get_partition_maximum_size(self):
        fake_max_size = 1024
        self._remote_exec.return_value = ("%s" % fake_max_size,
                                          mock.sentinel.std_err)

        result = self._windows_utils.get_partition_maximum_size(
            mock.sentinel.server,
            mock.sentinel.disk_number,
            mock.sentinel.partition_number)

        cmd = ('Get-PartitionSupportedSize -DiskNumber %(disk_number)s '
               '-PartitionNumber %(partition_number)s | '
               'Select-Object -ExpandProperty SizeMax' %
               dict(disk_number=mock.sentinel.disk_number,
                    partition_number=mock.sentinel.partition_number))
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(fake_max_size, result)

    def test_set_disk_online_status(self):
        self._windows_utils.set_disk_online_status(mock.sentinel.server,
                                                   mock.sentinel.disk_number,
                                                   online=True)

        cmd = ["Set-Disk", "-Number", mock.sentinel.disk_number,
               "-IsOffline", 0]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_set_disk_readonly_status(self):
        self._windows_utils.set_disk_readonly_status(mock.sentinel.server,
                                                     mock.sentinel.disk_number,
                                                     readonly=False)

        cmd = ["Set-Disk", "-Number", mock.sentinel.disk_number,
               "-IsReadOnly", 0]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_update_disk(self):
        self._windows_utils.update_disk(mock.sentinel.server,
                                        mock.sentinel.disk_number)

        cmd = ["Update-Disk", mock.sentinel.disk_number]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_join_domain(self):
        mock_server = {'ip': mock.sentinel.server_ip}

        self._windows_utils.join_domain(mock_server,
                                        mock.sentinel.domain,
                                        mock.sentinel.admin_username,
                                        mock.sentinel.admin_password)

        cmds = [
            ('$password = "%s" | '
             'ConvertTo-SecureString -asPlainText -Force' %
             mock.sentinel.admin_password),
            ('$credential = '
             'New-Object System.Management.Automation.PSCredential('
             '"%s", $password)' % mock.sentinel.admin_username),
            ('Add-Computer -DomainName "%s" -Credential $credential' %
             mock.sentinel.domain)]
        cmd = ";".join(cmds)
        self._remote_exec.assert_called_once_with(mock_server, cmd)

    def test_unjoin_domain(self):
        self._windows_utils.unjoin_domain(mock.sentinel.server,
                                          mock.sentinel.admin_username,
                                          mock.sentinel.admin_password)

        cmds = [
            ('$password = "%s" | '
             'ConvertTo-SecureString -asPlainText -Force' %
             mock.sentinel.admin_password),
            ('$credential = '
             'New-Object System.Management.Automation.PSCredential('
             '"%s", $password)' % mock.sentinel.admin_username),
            ('Remove-Computer -UnjoinDomaincredential $credential '
             '-Passthru -Verbose -Force')]
        cmd = ";".join(cmds)
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_get_current_domain(self):
        fake_domain = " domain"
        self._remote_exec.return_value = (fake_domain, mock.sentinel.std_err)

        result = self._windows_utils.get_current_domain(mock.sentinel.server)

        cmd = "(Get-WmiObject Win32_ComputerSystem).Domain"
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(fake_domain.strip(), result)

    def test_ensure_directory_exists(self):
        self._windows_utils.ensure_directory_exists(mock.sentinel.server,
                                                    mock.sentinel.path)

        cmd = ["New-Item", "-ItemType", "Directory", "-Force", "-Path",
               self._windows_utils.quote_string(mock.sentinel.path)]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @ddt.data(False, True)
    @mock.patch.object(windows_utils.WindowsUtils, 'path_exists')
    def test_remove(self, is_junction, mock_path_exists):
        recurse = True
        self._windows_utils.remove(mock.sentinel.server,
                                   mock.sentinel.path,
                                   is_junction=is_junction,
                                   recurse=recurse)

        if is_junction:
            cmd = ('[System.IO.Directory]::Delete('
                   '%(path)s, %(recurse)d)'
                   % dict(path=self._windows_utils.quote_string(
                          mock.sentinel.path),
                          recurse=recurse))
        else:
            cmd = ["Remove-Item", "-Confirm:$false", "-Path",
                   self._windows_utils.quote_string(mock.sentinel.path),
                   "-Force", '-Recurse']

        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @mock.patch.object(windows_utils.WindowsUtils, 'path_exists')
    def test_remove_unexisting_path(self, mock_path_exists):
        mock_path_exists.return_value = False
        self._windows_utils.remove(mock.sentinel.server,
                                   mock.sentinel.path)
        self.assertFalse(self._remote_exec.called)

    @ddt.data("True", "False")
    def test_path_exists(self, path_exists):
        self._remote_exec.return_value = (path_exists,
                                          mock.sentinel.std_err)

        result = self._windows_utils.path_exists(mock.sentinel.server,
                                                 mock.sentinel.path)

        cmd = ["Test-Path", mock.sentinel.path]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(path_exists == "True", result)

    def test_normalize_path(self):
        fake_path = "C:/"
        result = self._windows_utils.normalize_path(fake_path)

        self.assertEqual("C:\\", result)

    def test_get_interface_index_by_ip(self):
        _FAKE_INDEX = "2"
        self._remote_exec.return_value = (_FAKE_INDEX, mock.sentinel.std_err)

        result = self._windows_utils.get_interface_index_by_ip(
            mock.sentinel.server,
            mock.sentinel.ip)

        cmd = ('Get-NetIPAddress | '
               'Where-Object {$_.IPAddress -eq "%(ip)s"} | '
               'Select-Object -ExpandProperty InterfaceIndex' %
               dict(ip=mock.sentinel.ip))
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(int(_FAKE_INDEX), result)

    def test_set_dns_client_search_list(self):
        mock_search_list = ["A", "B", "C"]

        self._windows_utils.set_dns_client_search_list(mock.sentinel.server,
                                                       mock_search_list)

        cmd = ["Set-DnsClientGlobalSetting",
               "-SuffixSearchList", "@('A','B','C')"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_set_dns_client_server_addresses(self):
        mock_dns_servers = ["A", "B", "C"]

        self._windows_utils.set_dns_client_server_addresses(
            mock.sentinel.server,
            mock.sentinel.if_index,
            mock_dns_servers)

        cmd = ["Set-DnsClientServerAddress",
               "-InterfaceIndex", mock.sentinel.if_index,
               "-ServerAddresses", "('A','B','C')"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_set_win_reg_value(self):
        self._windows_utils.set_win_reg_value(mock.sentinel.server,
                                              mock.sentinel.path,
                                              mock.sentinel.key,
                                              mock.sentinel.value)

        cmd = ['Set-ItemProperty', '-Path',
               self._windows_utils.quote_string(mock.sentinel.path),
               '-Name', mock.sentinel.key, '-Value', mock.sentinel.value]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @ddt.data(None, mock.sentinel.key_name)
    def test_get_win_reg_value(self, key_name):
        self._remote_exec.return_value = (mock.sentinel.value,
                                          mock.sentinel.std_err)

        result = self._windows_utils.get_win_reg_value(mock.sentinel.server,
                                                       mock.sentinel.path,
                                                       name=key_name)

        cmd = "Get-ItemProperty -Path %s" % (
            self._windows_utils.quote_string(mock.sentinel.path))
        if key_name:
            cmd += " | Select-Object -ExpandProperty %s" % key_name
        self._remote_exec.assert_called_once_with(mock.sentinel.server,
                                                  cmd,
                                                  retry=False)
        self.assertEqual(mock.sentinel.value, result)

    def test_quote_string(self):
        result = self._windows_utils.quote_string(mock.sentinel.string)
        self.assertEqual('"%s"' % mock.sentinel.string, result)
