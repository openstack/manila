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
    _FAKE_ACCOUNT_NAME = 'FakeDomain\\FakeUser'
    _FAKE_RW_ACC_RULE = {
        'access_to': _FAKE_ACCOUNT_NAME,
        'access_level': constants.ACCESS_LEVEL_RW,
        'access_type': 'user',
    }

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
    def test_create_exports(self, share_exists, mock_share_exists):
        mock_share_exists.return_value = share_exists

        result = self._win_smb_helper.create_exports(self._FAKE_SERVER,
                                                     self._FAKE_SHARE_NAME)

        if not share_exists:
            cmd = ['New-SmbShare', '-Name', self._FAKE_SHARE_NAME, '-Path',
                   self._win_smb_helper._windows_utils.normalize_path(
                       self._FAKE_SHARE_LOCATION),
                   '-ReadAccess', "*%s" % self._win_smb_helper._NULL_SID]
            self._remote_exec.assert_called_once_with(self._FAKE_SERVER, cmd)
        else:
            self.assertFalse(self._remote_exec.called)

        expected_exports = [
            {
                'is_admin_only': False,
                'metadata': {'export_location_metadata_example': 'example'},
                'path': self._FAKE_SHARE
            },
        ]

        self.assertEqual(expected_exports, result)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper, '_share_exists')
    def test_remove_exports(self, mock_share_exists):
        mock_share_exists.return_value = True

        self._win_smb_helper.remove_exports(mock.sentinel.server,
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

    @ddt.data({'raw_out': '', 'expected': []},
              {'raw_out': '{"key": "val"}',
               'expected': [{"key": "val"}]},
              {'raw_out': '[{"key": "val"}, {"key2": "val2"}]',
               'expected': [{"key": "val"}, {"key2": "val2"}]})
    @ddt.unpack
    def test_get_acls_helper(self, raw_out, expected):
        self._remote_exec.return_value = (raw_out, mock.sentinel.err)

        rules = self._win_smb_helper._get_acls(mock.sentinel.server,
                                               self._FAKE_SHARE_NAME)

        self.assertEqual(expected, rules)
        expected_cmd = (
            'Get-SmbShareAccess -Name %s | '
            'Select-Object @("Name", "AccountName", '
            '"AccessControlType", "AccessRight") | '
            'ConvertTo-JSON -Compress') % self._FAKE_SHARE_NAME
        self._remote_exec.assert_called_once_with(mock.sentinel.server,
                                                  expected_cmd)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_get_acls')
    def test_get_access_rules(self, mock_get_acls):
        helper = self._win_smb_helper
        valid_acl = {
            'AccountName': self._FAKE_ACCOUNT_NAME,
            'AccessRight': helper._WIN_ACCESS_RIGHT_FULL,
            'AccessControlType': helper._WIN_ACL_ALLOW,
        }

        valid_acls = [valid_acl,
                      dict(valid_acl,
                           AccessRight=helper._WIN_ACCESS_RIGHT_CHANGE),
                      dict(valid_acl,
                           AccessRight=helper._WIN_ACCESS_RIGHT_READ)]
        # Those are rules that were not added by us and are expected to
        # be ignored. When encountering such a rule, a warning message
        # will be logged.
        ignored_acls = [
            dict(valid_acl, AccessRight=helper._WIN_ACCESS_RIGHT_CUSTOM),
            dict(valid_acl, AccessControlType=helper._WIN_ACL_DENY)]

        mock_get_acls.return_value = valid_acls + ignored_acls
        # There won't be multiple access rules for the same account,
        # but we'll ignore this fact for the sake of this test.
        expected_rules = [self._FAKE_RW_ACC_RULE, self._FAKE_RW_ACC_RULE,
                          dict(self._FAKE_RW_ACC_RULE,
                               access_level=constants.ACCESS_LEVEL_RO)]

        rules = helper.get_access_rules(mock.sentinel.server,
                                        mock.sentinel.share_name)
        self.assertEqual(expected_rules, rules)

        mock_get_acls.assert_called_once_with(mock.sentinel.server,
                                              mock.sentinel.share_name)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper, '_refresh_acl')
    def test_grant_share_access(self, mock_refresh_acl):
        self._win_smb_helper._grant_share_access(mock.sentinel.server,
                                                 mock.sentinel.share_name,
                                                 constants.ACCESS_LEVEL_RW,
                                                 mock.sentinel.username)

        cmd = ["Grant-SmbShareAccess", "-Name", mock.sentinel.share_name,
               "-AccessRight", "Change",
               "-AccountName", "'%s'" % mock.sentinel.username, "-Force"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        mock_refresh_acl.assert_called_once_with(mock.sentinel.server,
                                                 mock.sentinel.share_name)

    def test_refresh_acl(self):
        self._win_smb_helper._refresh_acl(mock.sentinel.server,
                                          mock.sentinel.share_name)

        cmd = ['Set-SmbPathAcl', '-ShareName', mock.sentinel.share_name]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper, '_refresh_acl')
    def test_revoke_share_access(self, mock_refresh_acl):
        self._win_smb_helper._revoke_share_access(mock.sentinel.server,
                                                  mock.sentinel.share_name,
                                                  mock.sentinel.username)

        cmd = ["Revoke-SmbShareAccess", "-Name", mock.sentinel.share_name,
               "-AccountName", '"%s"' % mock.sentinel.username, "-Force"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        mock_refresh_acl.assert_called_once_with(mock.sentinel.server,
                                                 mock.sentinel.share_name)

    def test_update_access_invalid_type(self):
        invalid_access_rule = dict(self._FAKE_RW_ACC_RULE,
                                   access_type='ip')
        self.assertRaises(
            exception.InvalidShareAccess,
            self._win_smb_helper.update_access,
            mock.sentinel.server, mock.sentinel.share_name,
            [invalid_access_rule], [], [])

    def test_update_access_invalid_level(self):
        invalid_access_rule = dict(self._FAKE_RW_ACC_RULE,
                                   access_level='fake_level')
        self.assertRaises(
            exception.InvalidShareAccessLevel,
            self._win_smb_helper.update_access,
            mock.sentinel.server, mock.sentinel.share_name,
            [], [invalid_access_rule], [])

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_revoke_share_access')
    def test_update_access_deleting_invalid_rule(self, mock_revoke):
        # We want to make sure that we allow deleting invalid rules.
        invalid_access_rule = dict(self._FAKE_RW_ACC_RULE,
                                   access_level='fake_level')
        delete_rules = [invalid_access_rule, self._FAKE_RW_ACC_RULE]

        self._win_smb_helper.update_access(
            mock.sentinel.server, mock.sentinel.share_name,
            [], [], delete_rules)

        mock_revoke.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.share_name,
            self._FAKE_RW_ACC_RULE['access_to'])

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       'validate_access_rules')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       'get_access_rules')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_grant_share_access')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_revoke_share_access')
    def test_update_access(self, mock_revoke, mock_grant,
                           mock_get_access_rules, mock_validate):
        added_rules = [mock.MagicMock(), mock.MagicMock()]
        deleted_rules = [mock.MagicMock(), mock.MagicMock()]

        self._win_smb_helper.update_access(
            mock.sentinel.server, mock.sentinel.share_name,
            [], added_rules, deleted_rules)

        mock_revoke.assert_has_calls(
            [mock.call(mock.sentinel.server, mock.sentinel.share_name,
                       deleted_rule['access_to'])
             for deleted_rule in deleted_rules])

        mock_grant.assert_has_calls(
            [mock.call(mock.sentinel.server, mock.sentinel.share_name,
                       added_rule['access_level'], added_rule['access_to'])
             for added_rule in added_rules])

    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_get_rule_updates')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       'validate_access_rules')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       'get_access_rules')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_grant_share_access')
    @mock.patch.object(windows_smb_helper.WindowsSMBHelper,
                       '_revoke_share_access')
    def test_update_access_maintenance(
            self, mock_revoke, mock_grant,
            mock_get_access_rules, mock_validate,
            mock_get_rule_updates):
        all_rules = mock.MagicMock()
        added_rules = [mock.MagicMock(), mock.MagicMock()]
        deleted_rules = [mock.MagicMock(), mock.MagicMock()]

        mock_get_rule_updates.return_value = [
            added_rules, deleted_rules]

        self._win_smb_helper.update_access(
            mock.sentinel.server, mock.sentinel.share_name,
            all_rules, [], [])

        mock_get_access_rules.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.share_name)
        mock_get_rule_updates.assert_called_once_with(
            existing_rules=mock_get_access_rules.return_value,
            requested_rules=all_rules)
        mock_revoke.assert_has_calls(
            [mock.call(mock.sentinel.server, mock.sentinel.share_name,
                       deleted_rule['access_to'])
             for deleted_rule in deleted_rules])

        mock_grant.assert_has_calls(
            [mock.call(mock.sentinel.server, mock.sentinel.share_name,
                       added_rule['access_level'], added_rule['access_to'])
             for added_rule in added_rules])

    def test_get_rule_updates(self):
        req_rule_0 = self._FAKE_RW_ACC_RULE
        req_rule_1 = dict(self._FAKE_RW_ACC_RULE,
                          access_to='fake_acc')

        curr_rule_0 = dict(self._FAKE_RW_ACC_RULE,
                           access_to=self._FAKE_RW_ACC_RULE[
                               'access_to'].upper())
        curr_rule_1 = dict(self._FAKE_RW_ACC_RULE,
                           access_to='fake_acc2')
        curr_rule_2 = dict(req_rule_1,
                           access_level=constants.ACCESS_LEVEL_RO)

        expected_added_rules = [req_rule_1]
        expected_deleted_rules = [curr_rule_1, curr_rule_2]

        existing_rules = [curr_rule_0, curr_rule_1, curr_rule_2]
        requested_rules = [req_rule_0, req_rule_1]

        (added_rules,
         deleted_rules) = self._win_smb_helper._get_rule_updates(
            existing_rules, requested_rules)

        self.assertEqual(expected_added_rules, added_rules)
        self.assertEqual(expected_deleted_rules, deleted_rules)

    def test_get_share_name(self):
        result = self._win_smb_helper._get_share_name(self._FAKE_SHARE)
        self.assertEqual(self._FAKE_SHARE_NAME, result)

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
