# Copyright 2021 Pure Storage Inc.
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
"""Unit tests for Pure Storage FlashBlade driver."""

import sys
from unittest import mock

sys.modules["purity_fb"] = mock.Mock()

from manila.common import constants
from manila import exception
from manila.share.drivers.purestorage import flashblade
from manila import test


_MOCK_SHARE_ID = 1
_MOCK_SNAPSHOT_ID = "snap"
_MOCK_SHARE_SIZE = 4294967296


def _create_mock__getitem__(mock):
    def mock__getitem__(self, key, default=None):
        return getattr(mock, key, default)

    return mock__getitem__


test_nfs_share = mock.Mock(
    id=_MOCK_SHARE_ID, size=_MOCK_SHARE_SIZE, share_proto="NFS"
)
test_nfs_share.__getitem__ = _create_mock__getitem__(test_nfs_share)

test_snapshot = mock.Mock(id=_MOCK_SNAPSHOT_ID, share=test_nfs_share)
test_snapshot.__getitem__ = _create_mock__getitem__(test_snapshot)


class FakePurityFBException(Exception):
    def __init__(self, message=None, error_code=None, *args):
        self.message = message
        self.error_code = error_code
        super(FakePurityFBException, self).__init__(message, error_code, *args)


class FlashBladeDriverTestCaseBase(test.TestCase):
    def setUp(self):
        super(FlashBladeDriverTestCaseBase, self).setUp()
        self.configuration = mock.Mock()
        self.configuration.flashblade_mgmt_vip = "mockfb1"
        self.configuration.flashblade_data_vip = "mockfb2"
        self.configuration.flashblade_api = "api"
        self.configuration.flashblade_eradicate = True

        self.configuration.driver_handles_share_servers = False
        self._mock_filesystem = mock.Mock()
        self.mock_object(self.configuration, "safe_get", self._fake_safe_get)
        self.purity_fb = self._patch(
            "manila.share.drivers.purestorage.flashblade.purity_fb"
        )

        self.driver = flashblade.FlashBladeShareDriver(
            configuration=self.configuration
        )

        self._sys = self._flashblade_mock()

        self._sys.api_version = mock.Mock()

        self._sys.arrays.list_arrays_space = mock.Mock()
        self.purity_fb.rest.ApiException = FakePurityFBException
        self.purity_fb.PurityFb.return_value = self._sys

        self.driver.do_setup(None)
        self.mock_object(
            self.driver,
            "_resize_share",
            mock.Mock(return_value="fake_dataset"),
        )
        self.mock_object(
            self.driver,
            "_make_source_name",
            mock.Mock(return_value="fake_dataset"),
        )
        self.mock_object(
            self.driver,
            "_get_flashblade_filesystem_by_name",
            mock.Mock(return_value="fake_dataset"),
        )
        self.mock_object(
            self.driver,
            "_get_flashblade_snapshot_by_name",
            mock.Mock(return_value="fake_snapshot.snap"),
        )

    def _flashblade_mock(self):
        result = mock.Mock()
        self._mock_filesystem = mock.Mock()
        result.file_systems.create_file_systems.return_value = (
            self._mock_filesystem
        )
        result.file_systems.update_file_systems.return_value = (
            self._mock_filesystem
        )
        result.file_systems.delete_file_systems.return_value = (
            self._mock_filesystem
        )
        result.file_system_snapshots.create_file_system_snapshots\
            .return_value = (self._mock_filesystem)
        return result

    def _raise_purity_fb(self, *args, **kwargs):
        raise FakePurityFBException()

    def _fake_safe_get(self, value):
        return getattr(self.configuration, value, None)

    def _patch(self, path, *args, **kwargs):
        patcher = mock.patch(path, *args, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result


class FlashBladeDriverTestCase(FlashBladeDriverTestCaseBase):
    @mock.patch("manila.share.drivers.purestorage.flashblade.purity_fb", None)
    def test_no_purity_fb_module(self):
        self.assertRaises(exception.ManilaException,
                          self.driver.do_setup, None)

    def test_no_auth_parameters(self):
        self.configuration.flashblade_api = None
        self.assertRaises(
            exception.BadConfigurationException, self.driver.do_setup, None
        )

    def test_empty_auth_parameters(self):
        self.configuration.flashblade_api = ""
        self.assertRaises(
            exception.BadConfigurationException, self.driver.do_setup, None
        )

    def test_create_share_incorrect_protocol(self):
        test_nfs_share.share_proto = "CIFS"
        self.assertRaises(
            exception.InvalidShare,
            self.driver.create_share,
            None,
            test_nfs_share,
        )

    def test_create_nfs_share(self):
        location = self.driver.create_share(None, test_nfs_share)
        self._sys.file_systems.create_file_systems.assert_called_once_with(
            self.purity_fb.FileSystem(
                name="share-%s-manila" % test_nfs_share["id"],
                provisioned=test_nfs_share["size"],
                hard_limit_enabled=True,
                fast_remove_directory_enabled=True,
                snapshot_directory_enabled=True,
                nfs=self.purity_fb.NfsRule(
                    v3_enabled=True, rules="", v4_1_enabled=True
                ),
            )
        )
        self.assertEqual("mockfb2:/share-1-manila", location)

    def test_delete_share(self):
        self.mock_object(self.driver, "_get_flashblade_filesystem_by_name")

        self.driver.delete_share(None, test_nfs_share)

        share_name = "share-%s-manila" % test_nfs_share["id"]
        self.driver._get_flashblade_filesystem_by_name.assert_called_once_with(
            share_name
        )
        self._sys.file_systems.update_file_systems.assert_called_once_with(
            name=share_name,
            attributes=self.purity_fb.FileSystem(
                nfs=self.purity_fb.NfsRule(
                    v3_enabled=False, v4_1_enabled=False
                ),
                smb=self.purity_fb.ProtocolRule(enabled=False),
                destroyed=True,
            ),
        )
        self._sys.file_systems.delete_file_systems.assert_called_once_with(
            name=share_name
        )

    def test_delete_share_no_eradicate(self):
        self.configuration.flashblade_eradicate = False
        self.mock_object(self.driver, "_get_flashblade_filesystem_by_name")

        self.driver.delete_share(None, test_nfs_share)

        share_name = "share-%s-manila" % test_nfs_share["id"]
        self.driver._get_flashblade_filesystem_by_name.assert_called_once_with(
            share_name
        )
        self._sys.file_systems.update_file_systems.assert_called_once_with(
            name=share_name,
            attributes=self.purity_fb.FileSystem(
                nfs=self.purity_fb.NfsRule(
                    v3_enabled=False, v4_1_enabled=False
                ),
                smb=self.purity_fb.ProtocolRule(enabled=False),
                destroyed=True,
            ),
        )
        assert not self._sys.file_systems.delete_file_systems.called

    def test_delete_share_not_found(self):
        self.mock_object(
            self.driver,
            "_get_flashblade_filesystem_by_name",
            mock.Mock(side_effect=self.purity_fb.rest.ApiException),
        )
        mock_result = self.driver.delete_share(None, test_nfs_share)
        self.assertIsNone(mock_result)

    def test_extend_share(self):
        self.driver.extend_share(test_nfs_share, _MOCK_SHARE_SIZE * 2)
        self.driver._resize_share.assert_called_once_with(
            test_nfs_share,
            _MOCK_SHARE_SIZE * 2,
        )

    def test_shrink_share(self):
        self.driver.shrink_share(test_nfs_share, _MOCK_SHARE_SIZE / 2)
        self.driver._resize_share.assert_called_once_with(
            test_nfs_share,
            _MOCK_SHARE_SIZE / 2,
        )

    def test_shrink_share_over_consumed(self):
        self.mock_object(
            self.driver,
            "_resize_share",
            mock.Mock(
                side_effect=exception.ShareShrinkingPossibleDataLoss(
                    share_id=test_nfs_share["id"]
                )
            ),
        )
        self.assertRaises(
            exception.ShareShrinkingPossibleDataLoss,
            self.driver.shrink_share,
            test_nfs_share,
            _MOCK_SHARE_SIZE / 2,
        )

    def test_create_snapshot(self):
        self.mock_object(self.driver, "_get_flashblade_filesystem_by_name")
        self.mock_object(self.driver, "_get_flashblade_snapshot_by_name")
        self.mock_object(self.driver, "_make_source_name")
        self.driver.create_snapshot(None, test_snapshot)
        self._sys.file_system_snapshots.create_file_system_snapshots\
            .assert_called_once_with(
                suffix=self.purity_fb.SnapshotSuffix(test_snapshot["id"]),
                sources=[mock.ANY],
            )

    def test_delete_snapshot_no_eradicate(self):
        self.configuration.flashblade_eradicate = False
        self.mock_object(self.driver, "_get_flashblade_snapshot_by_name")
        self.driver.delete_snapshot(None, test_snapshot)
        self._sys.file_system_snapshots.update_file_system_snapshots\
            .assert_called_once_with(
                name=mock.ANY,
                attributes=self.purity_fb.FileSystemSnapshot(destroyed=True),
            )
        assert not self._sys.file_system_snapshots\
            .delete_file_system_snapshots.called

    def test_delete_snapshot(self):
        self.mock_object(self.driver, "_get_flashblade_snapshot_by_name")
        self.driver.delete_snapshot(None, test_snapshot)
        self._sys.file_system_snapshots.update_file_system_snapshots\
            .assert_called_once_with(
                name=mock.ANY,
                attributes=self.purity_fb.FileSystemSnapshot(destroyed=True),
            )
        self._sys.file_system_snapshots.delete_file_system_snapshots\
            .assert_called_once_with(
                name=mock.ANY
            )

    def test_delete_snapshot_not_found(self):
        self.mock_object(
            self.driver,
            "_get_flashblade_snapshot_by_name",
            mock.Mock(
                side_effect=exception.ShareResourceNotFound(
                    share_id=test_nfs_share["id"]
                )
            ),
        )
        mock_result = self.driver.delete_snapshot(None, test_snapshot)
        self.assertIsNone(mock_result)

    def test_update_access_share(self):
        access_rules = [
            {
                "access_level": constants.ACCESS_LEVEL_RO,
                "access_to": "1.2.3.4",
                "access_type": "ip",
                "access_id": "09960614-8574-4e03-89cf-7cf267b0bd09",
            },
            {
                "access_level": constants.ACCESS_LEVEL_RW,
                "access_to": "1.2.3.5",
                "access_type": "user",
                "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
            },
        ]

        expected_rule_map = {
            "09960614-8574-4e03-89cf-7cf267b0bd08": {"state": "error"},
            "09960614-8574-4e03-89cf-7cf267b0bd09": {"state": "active"},
        }

        rule_map = self.driver.update_access(
            None, test_nfs_share, access_rules, [], []
        )
        self.assertEqual(expected_rule_map, rule_map)

    def test_revert_to_snapshot_bad_snapshot(self):
        self.mock_object(
            self.driver,
            "_get_flashblade_filesystem_by_name",
            mock.Mock(side_effect=self.purity_fb.rest.ApiException),
        )
        mock_result = self.driver.revert_to_snapshot(
            None, test_snapshot, None, None
        )
        self.assertIsNone(mock_result)

    def test_revert_to_snapshot(self):
        self.mock_object(self.driver, "_get_flashblade_snapshot_by_name")
        self.driver.revert_to_snapshot(None, test_snapshot, [], [])
        self._sys.file_systems.create_file_systems.assert_called_once_with(
            overwrite=True,
            discard_non_snapshotted_data=True,
            file_system=self.purity_fb.FileSystem(
                name=test_nfs_share,
                source=self.purity_fb.Reference(name=mock.ANY),
            ),
        )
