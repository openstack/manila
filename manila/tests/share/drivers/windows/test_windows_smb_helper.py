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

import os

import ddt
import mock

from manila.common import constants
from manila import exception
from manila.share import configuration
from manila.share.drivers.windows import windows_smb_helper
from manila.share.drivers.windows import windows_utils
from manila import test

from oslo_config import cfg

CONF = cfg.CONF
CONF.import_opt('share_mount_path',
                'manila.share.drivers.generic')


@ddt.ddt
class WindowsSMBHelperTestCase(test.TestCase):
    _FAKE_SERVER = {'public_address': mock.sentinel.public_address}
    _FAKE_SHARE_NAME = "fake_share_name"
    _FAKE_SHARE = "\\\\%s\\%s" % (_FAKE_SERVER['public_address'],
                                  _FAKE_SHARE_NAME)
    _FAKE_SHARE_LOCATION = os.path.join(
        configuration.Configuration(None).share_mount_path,
        _FAKE_SHARE_NAME)

    def setUp(self):
        self._remote_exec = mock.Mock()
        fake_conf = configuration.Configuration(None)

        self._win_smb_helper = windows_smb_helper.WindowsSMBHelper(
            self._remote_exec, fake_conf)

        super(WindowsSMBHelperTestCase, self).setUp()

    def test_init_helper(self):
        self._win_smb_helper.init_helper(mock.sentinel.server)
        self._remote_exec.assert_called_once_with(mock.sentinel.server,
                                                  "Get-SmbShare")

    @ddt.data(True, False)
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper, '_share_exists')
    def test_create_export(self, share_exists, mock_share_exists):
        mock_share_exists.return_value = share_exists

        result = self._win_smb_helper.create_export(self._FAKE_SERVER,
                                                    self._FAKE_SHARE_NAME)

        if not share_exists:
            cmd = ['New-SmbShare', '-Name', self._FAKE_SHARE_NAME, '-Path',
                   self._win_smb_helper._windows_utils.normalize_path(
                       self._FAKE_SHARE_LOCATION)]
            self._remote_exec.assert_called_once_with(self._FAKE_SERVER, cmd)
        else:
            self.assertFalse(self._remote_exec.called)

        self.assertEqual(self._FAKE_SHARE, result)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper, '_share_exists')
    def test_remove_export(self, mock_share_exists):
        mock_share_exists.return_value = True

        self._win_smb_helper.remove_export(mock.sentinel.server,
                                           mock.sentinel.share_name)

        cmd = ['Remove-SmbShare', '-Name', mock.sentinel.share_name, "-Force"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @mock.patch.object(windows_utils.WindowsUtils,
                       'get_volume_path_by_mount_path')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_get_share_path_by_name')
    def test_get_volume_path_by_share_name(self, mock_get_share_path,
                                           mock_get_vol_path):
        mock_get_share_path.return_value = self._FAKE_SHARE_LOCATION

        volume_path = self._win_smb_helper._get_volume_path_by_share_name(
            mock.sentinel.server, self._FAKE_SHARE_NAME)

        mock_get_share_path.assert_called_once_with(mock.sentinel.server,
                                                    self._FAKE_SHARE_NAME)
        mock_get_vol_path.assert_called_once_with(mock.sentinel.server,
                                                  self._FAKE_SHARE_LOCATION)

        self.assertEqual(mock_get_vol_path.return_value, volume_path)

    @ddt.data('ip', 'user')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_grant_share_access')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_grant_share_path_access')
    def test_allow_access(self, access_type, mock_grant_share_access,
                          mock_grant_share_path_access):
        mock_args = (mock.sentinel.server, mock.sentinel.share_name,
                     access_type, mock.sentinel.access_level,
                     mock.sentinel.username)

        if access_type != 'user':
            self.assertRaises(exception.InvalidShareAccess,
                              self._win_smb_helper.allow_access,
                              *mock_args)
        else:
            self._win_smb_helper.allow_access(*mock_args)

            mock_grant_share_access.assert_called_once_with(
                mock.sentinel.server,
                mock.sentinel.share_name,
                mock.sentinel.access_level,
                mock.sentinel.username)
            mock_grant_share_path_access.assert_called_once_with(
                mock.sentinel.server,
                mock.sentinel.share_name,
                mock.sentinel.access_level,
                mock.sentinel.username)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper, '_refresh_acl')
    def test_grant_share_access(self, mock_refresh_acl):
        self._win_smb_helper._grant_share_access(mock.sentinel.server,
                                                 mock.sentinel.share_name,
                                                 constants.ACCESS_LEVEL_RW,
                                                 mock.sentinel.username)

        cmd = ["Grant-SmbShareAccess", "-Name", mock.sentinel.share_name,
               "-AccessRight", "Change",
               "-AccountName", mock.sentinel.username, "-Force"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        mock_refresh_acl.assert_called_once_with(mock.sentinel.server,
                                                 mock.sentinel.share_name)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_get_volume_path_by_share_name')
    def test_grant_share_path_access(self, mock_get_vol_path):
        fake_vol_path = 'fake_vol_path'
        mock_get_vol_path.return_value = fake_vol_path

        self._win_smb_helper._grant_share_path_access(
            mock.sentinel.server,
            mock.sentinel.share_name,
            constants.ACCESS_LEVEL_RW,
            mock.sentinel.username)

        expected_ace = '"%s:(OI)(CI)M"' % mock.sentinel.username
        cmd = ["icacls", '"%s"' % fake_vol_path, "/grant",
               expected_ace, "/t", "/c"]

        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_refresh_acl(self):
        self._win_smb_helper._refresh_acl(mock.sentinel.server,
                                          mock.sentinel.share_name)

        cmd = ['Set-SmbPathAcl', '-ShareName', mock.sentinel.share_name]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_revoke_share_path_access')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_revoke_share_access')
    def test_deny_access(self, mock_revoke_share_path_access,
                         mock_revoke_share_access):
        mock_access = {'access_to': mock.sentinel.username}

        self._win_smb_helper.deny_access(mock.sentinel.server,
                                         mock.sentinel.share_name,
                                         mock_access)

        mock_revoke_share_access.assert_called_once_with(
            mock.sentinel.server,
            mock.sentinel.share_name,
            mock.sentinel.username)
        mock_revoke_share_path_access.assert_called_once_with(
            mock.sentinel.server,
            mock.sentinel.share_name,
            mock.sentinel.username)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper, '_refresh_acl')
    def test_revoke_share_access(self, mock_refresh_acl):
        self._win_smb_helper._revoke_share_access(mock.sentinel.server,
                                                  mock.sentinel.share_name,
                                                  mock.sentinel.username)

        cmd = ["Revoke-SmbShareAccess", "-Name", mock.sentinel.share_name,
               "-AccountName", mock.sentinel.username, "-Force"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        mock_refresh_acl.assert_called_once_with(mock.sentinel.server,
                                                 mock.sentinel.share_name)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_get_volume_path_by_share_name')
    def test_revoke_share_path_access(self, mock_get_vol_path):
        fake_vol_path = 'fake_vol_path'
        mock_get_vol_path.return_value = fake_vol_path

        self._win_smb_helper._revoke_share_path_access(
            mock.sentinel.server,
            mock.sentinel.share_name,
            mock.sentinel.username)

        cmd = ["icacls", '"%s"' % fake_vol_path,
               "/remove", mock.sentinel.username, "/t", "/c"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_get_share_name(self):
        result = self._win_smb_helper._get_share_name(self._FAKE_SHARE)
        self.assertEqual(self._FAKE_SHARE_NAME, result)

    def test_exports_for_share(self):
        result = self._win_smb_helper.get_exports_for_share(
            self._FAKE_SERVER, self._FAKE_SHARE_LOCATION)
        self.assertEqual([self._FAKE_SHARE], result)

    def test_get_share_path_by_name(self):
        self._remote_exec.return_value = (self._FAKE_SHARE_LOCATION,
                                          mock.sentinel.std_err)

        result = self._win_smb_helper._get_share_path_by_name(
            mock.sentinel.server,
            mock.sentinel.share_name)

        cmd = ('Get-SmbShare -Name %s | '
               'Select-Object -ExpandProperty Path' % mock.sentinel.share_name)
        self._remote_exec.assert_called_once_with(mock.sentinel.server,
                                                  cmd,
                                                  check_exit_code=True)
        self.assertEqual(self._FAKE_SHARE_LOCATION, result)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_get_share_path_by_name')
    def test_get_share_path_by_export_location(self,
                                               mock_get_share_path_by_name):
        mock_get_share_path_by_name.return_value = mock.sentinel.share_path

        result = self._win_smb_helper.get_share_path_by_export_location(
            mock.sentinel.server, self._FAKE_SHARE)

        mock_get_share_path_by_name.assert_called_once_with(
            mock.sentinel.server, self._FAKE_SHARE_NAME)
        self.assertEqual(mock.sentinel.share_path, result)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_get_share_path_by_name')
    def test_share_exists(self, mock_get_share_path_by_name):
        result = self._win_smb_helper._share_exists(mock.sentinel.server,
                                                    mock.sentinel.share_name)

        mock_get_share_path_by_name.assert_called_once_with(
            mock.sentinel.server,
            mock.sentinel.share_name,
            ignore_missing=True)
        self.assertTrue(result)
