# Copyright (c) 2026 Hewlett Packard Enterprise Development LP
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

from unittest import mock

import ddt

from manila import exception
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    helpers)
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    snapshot_handler as snapshot)
from manila import test


@ddt.ddt
class SnapshotHandlerTestCase(test.TestCase):
    """Test case for SnapshotHandler class."""

    def setUp(self):
        """Test Setup"""
        super(SnapshotHandlerTestCase, self).setUp()

        # Create mock rest client and feature support handler
        self.mock_rest_client = mock.Mock()
        self.mock_feature_support_handler = mock.Mock()

        # Initialize handler
        self.handler = snapshot.SnapshotHandler(
            self.mock_rest_client,
            self.mock_feature_support_handler
        )

    # create_snapshot()
    def test_create_snapshot_success_without_mount_support(self):
        """Test successful snapshot creation without mount_snapshot_support."""

        # Configure frontend snapshot request
        fe_create_snapshot = {
            'id': 'snap-id-1',
            'name': 'snap_name_1',
            'share': {'mount_snapshot_support': False}
        }
        be_share_name = 'be_share_1'
        be_filesystem_name = 'be_fs_1'
        be_sharesetting_name = 'be_sharesetting_1'

        # Configure mock responses
        fe_filesystem = {'be_uid': 'fs-uid-1', 'be_filesystem_name': 'be_fs_1'}
        fe_snap_filesystem = {
            'be_uid': 'snap-fs-uid-1',
            'be_filesystem_name': 'snap_name_1'
        }
        fe_snap_fileshare = {
            'be_uid': 'snap-share-uid-1',
            'host_ip': '10.0.0.1',
            'mount_path': '/mnt/snap'
        }

        self.handler.validator.validate_create_snapshot_fe_req = mock.Mock()
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=[fe_filesystem, fe_snap_filesystem])
        self.handler.filesystem_handler.snapshot_create = mock.Mock()
        self.handler.filesystem_handler.snapshot_online = mock.Mock()
        self.handler.fileshare_handler._get_fileshare_by_name = mock.Mock(
            return_value=fe_snap_fileshare)

        # Execute create_snapshot
        result_fileshare, result_filesystem = self.handler.create_snapshot(
            fe_create_snapshot, be_share_name,
            be_filesystem_name, be_sharesetting_name)

        # Verify validator was called
        self.handler.validator.validate_create_snapshot_fe_req.\
            assert_called_once_with(fe_create_snapshot)

        # Verify filesystem lookup for base filesystem
        self.handler.filesystem_handler._get_filesystem_by_name.\
            assert_any_call(be_filesystem_name)

        # Verify snapshot_create called with correct params
        self.handler.filesystem_handler.snapshot_create.\
            assert_called_once_with(
                fe_filesystem['be_uid'],
                fe_create_snapshot['name'],
                fe_create_snapshot['id'])

        # Verify snapshot filesystem lookup
        self.handler.filesystem_handler._get_filesystem_by_name.\
            assert_any_call(fe_create_snapshot['name'])

        # Verify fileshare lookup
        self.handler.fileshare_handler._get_fileshare_by_name.\
            assert_called_once_with(
                be_share_name,
                fe_create_snapshot['name'],
                be_sharesetting_name)

        # Verify snapshot_online was NOT called (no mount support)
        self.handler.filesystem_handler.snapshot_online.assert_not_called()

        # Verify returned values
        self.assertEqual(fe_snap_fileshare, result_fileshare)
        self.assertEqual(fe_snap_filesystem, result_filesystem)

    def test_create_snapshot_success_with_mount_support(self):
        """Test successful snapshot creation with mount_snapshot_support."""

        # Configure frontend snapshot request with mount support enabled
        fe_create_snapshot = {
            'id': 'snap-id-2',
            'name': 'snap_name_2',
            'share': {'mount_snapshot_support': True}
        }
        be_share_name = 'be_share_1'
        be_filesystem_name = 'be_fs_1'
        be_sharesetting_name = 'be_sharesetting_1'

        # Configure mock responses
        fe_filesystem = {'be_uid': 'fs-uid-1', 'be_filesystem_name': 'be_fs_1'}
        fe_snap_filesystem = {
            'be_uid': 'snap-fs-uid-2',
            'be_filesystem_name': 'snap_name_2'
        }
        fe_snap_fileshare = {
            'be_uid': 'snap-share-uid-2',
            'host_ip': '10.0.0.1',
            'mount_path': '/mnt/snap2'
        }

        self.handler.validator.validate_create_snapshot_fe_req = mock.Mock()
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=[fe_filesystem, fe_snap_filesystem])
        self.handler.filesystem_handler.snapshot_create = mock.Mock()
        self.handler.filesystem_handler.snapshot_online = mock.Mock()
        self.handler.fileshare_handler._get_fileshare_by_name = mock.Mock(
            return_value=fe_snap_fileshare)

        # Execute create_snapshot
        result_fileshare, result_filesystem = self.handler.create_snapshot(
            fe_create_snapshot, be_share_name,
            be_filesystem_name, be_sharesetting_name)

        # Verify snapshot_online was called with snap filesystem uid
        self.handler.filesystem_handler.snapshot_online.\
            assert_called_once_with(fe_snap_filesystem['be_uid'])

        # Verify returned values
        self.assertEqual(fe_snap_fileshare, result_fileshare)
        self.assertEqual(fe_snap_filesystem, result_filesystem)

    def test_create_snapshot_online_fails_cleans_up_and_raises(self):
        """Test snapshot cleanup when snapshot_online fails."""

        # Configure frontend snapshot request with mount support enabled
        fe_create_snapshot = {
            'id': 'snap-id-3',
            'name': 'snap_name_3',
            'share': {'mount_snapshot_support': True}
        }
        be_share_name = 'be_share_1'
        be_filesystem_name = 'be_fs_1'
        be_sharesetting_name = 'be_sharesetting_1'

        # Configure mock responses
        fe_filesystem = {'be_uid': 'fs-uid-1', 'be_filesystem_name': 'be_fs_1'}
        fe_snap_filesystem = {
            'be_uid': 'snap-fs-uid-3',
            'be_filesystem_name': 'snap_name_3'
        }
        fe_snap_fileshare = {
            'be_uid': 'snap-share-uid-3',
            'host_ip': '10.0.0.1',
            'mount_path': '/mnt/snap3'
        }

        self.handler.validator.validate_create_snapshot_fe_req = mock.Mock()
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=[fe_filesystem, fe_snap_filesystem])
        self.handler.filesystem_handler.snapshot_create = mock.Mock()
        # snapshot_online fails (e.g. online snapshot limit reached)
        self.handler.filesystem_handler.snapshot_online = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                reason='Online snapshot limit reached'))
        self.handler.fileshare_handler._get_fileshare_by_name = mock.Mock(
            return_value=fe_snap_fileshare)
        self.handler.fileshare_handler.delete_fileshare_by_id = mock.Mock()

        # Execute create_snapshot and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.create_snapshot,
            fe_create_snapshot,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name
        )

        # Verify snapshot_online was attempted
        self.handler.filesystem_handler.snapshot_online.\
            assert_called_once_with(fe_snap_filesystem['be_uid'])

        # Verify cleanup deleted the snapshot fileshare
        self.handler.fileshare_handler.delete_fileshare_by_id.\
            assert_called_once_with(
                fe_create_snapshot['id'],
                fe_snap_fileshare['be_uid'])

    def test_create_snapshot_online_fails_cleanup_also_fails(self):
        """Test original error is raised when cleanup also fails."""

        # Configure frontend snapshot request with mount support enabled
        fe_create_snapshot = {
            'id': 'snap-id-4',
            'name': 'snap_name_4',
            'share': {'mount_snapshot_support': True}
        }
        be_share_name = 'be_share_1'
        be_filesystem_name = 'be_fs_1'
        be_sharesetting_name = 'be_sharesetting_1'

        # Configure mock responses
        fe_filesystem = {'be_uid': 'fs-uid-1', 'be_filesystem_name': 'be_fs_1'}
        fe_snap_filesystem = {
            'be_uid': 'snap-fs-uid-4',
            'be_filesystem_name': 'snap_name_4'
        }
        fe_snap_fileshare = {
            'be_uid': 'snap-share-uid-4',
            'host_ip': '10.0.0.1',
            'mount_path': '/mnt/snap4'
        }

        self.handler.validator.validate_create_snapshot_fe_req = mock.Mock()
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=[fe_filesystem, fe_snap_filesystem])
        self.handler.filesystem_handler.snapshot_create = mock.Mock()
        # snapshot_online fails
        self.handler.filesystem_handler.snapshot_online = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                reason='Online snapshot limit reached'))
        self.handler.fileshare_handler._get_fileshare_by_name = mock.Mock(
            return_value=fe_snap_fileshare)
        # Cleanup also fails
        self.handler.fileshare_handler.delete_fileshare_by_id = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                reason='Delete fileshare failed'))

        # Execute create_snapshot and expect exception is still raised
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.create_snapshot,
            fe_create_snapshot,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name
        )

        # Verify cleanup was attempted
        self.handler.fileshare_handler.delete_fileshare_by_id.\
            assert_called_once_with(
                fe_create_snapshot['id'],
                fe_snap_fileshare['be_uid'])

    def test_create_snapshot_filesystem_not_found(self):
        """Test create_snapshot raises exception when filesystem not found."""

        # Configure valid frontend snapshot request
        fe_create_snapshot = {
            'id': 'snap-id-5',
            'name': 'snap_name_5',
            'share': {'mount_snapshot_support': False}
        }

        # Configure filesystem lookup to raise exception
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                reason='Filesystem not found'))

        # Execute create_snapshot and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.create_snapshot,
            fe_create_snapshot,
            'be_share_1',
            'be_fs_1',
            'be_sharesetting_1'
        )

    def test_create_snapshot_poll_snap_filesystem_timeout(self):
        """Test create_snapshot exception filesystem poll time out."""

        fe_create_snapshot = {
            'id': 'snap-id-1',
            'name': 'snap_name_1',
            'share': {'mount_snapshot_support': False}
        }
        be_share_name = 'be_share_1'
        be_filesystem_name = 'be_fs_1'
        be_sharesetting_name = 'be_sharesetting_1'

        fe_filesystem = {'be_uid': 'fs-uid-1', 'be_filesystem_name': 'be_fs_1'}

        self.handler.validator.validate_create_snapshot_fe_req = mock.Mock()
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            return_value=fe_filesystem)
        self.handler.filesystem_handler.snapshot_create = mock.Mock()
        poll_timeout = exception.HPEAlletraB10000DriverException(
            reason='Timed out waiting for snapshot filesystem')
        self.mock_object(helpers, 'poll_for_resource',
                         mock.Mock(side_effect=poll_timeout))

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.create_snapshot,
            fe_create_snapshot,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name
        )

    # delete_snapshot()
    def test_delete_snapshot_success(self):
        """Test successful snapshot deletion."""

        fe_delete_snapshot = {'id': 'snap-id-1'}
        be_snap_share_id = 'be-snap-share-uid-1'

        self.handler.fileshare_handler.delete_fileshare_by_id = mock.Mock()

        self.handler.delete_snapshot(fe_delete_snapshot, be_snap_share_id)

        self.handler.fileshare_handler.delete_fileshare_by_id.\
            assert_called_once_with(
                fe_delete_snapshot['id'], be_snap_share_id)

    def test_delete_snapshot_fileshare_delete_fails(self):
        """Test delete_snapshot propagates exception from delete_fileshare."""

        fe_delete_snapshot = {'id': 'snap-id-2'}
        be_snap_share_id = 'be-snap-share-uid-2'

        self.handler.fileshare_handler.delete_fileshare_by_id = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                reason='Backend delete failed'))

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.delete_snapshot,
            fe_delete_snapshot,
            be_snap_share_id
        )

    # revert_to_snapshot()
    def test_revert_to_snapshot_success(self):
        """Test successful revert to snapshot."""

        fe_revert_snapshot = {
            'id': 'snap-id-1',
            'share': {'mount_snapshot_support': False}
        }
        be_filesystem_name = 'be_fs_1'
        be_snap_filesystem_name = 'snap_be_fs_1'
        fe_filesystem = {'be_uid': 'fs-uid-1'}
        fe_reverted_filesystem = {'be_uid': 'fs-uid-1',
                                  'be_filesystem_size': 10240}

        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=[fe_filesystem, fe_reverted_filesystem])
        self.handler.filesystem_handler.snapshot_restore = mock.Mock()
        self.handler.filesystem_handler.snapshot_online = mock.Mock()

        result = self.handler.revert_to_snapshot(
            fe_revert_snapshot, be_filesystem_name, be_snap_filesystem_name)

        # Verify the post-revert size is read back from the backend
        self.assertEqual(10240, result)
        self.handler.filesystem_handler._get_filesystem_by_name.\
            assert_has_calls([mock.call(be_filesystem_name),
                              mock.call(be_filesystem_name)])
        self.handler.filesystem_handler.snapshot_restore.\
            assert_called_once_with(
                fe_filesystem['be_uid'], be_snap_filesystem_name)

        # Verify snapshot_online was NOT called (no mount support)
        self.handler.filesystem_handler.snapshot_online.assert_not_called()

    def test_revert_to_snapshot_success_with_mount_support(self):
        """Test revert brings a mountable snapshot back online."""

        fe_revert_snapshot = {
            'id': 'snap-id-2',
            'share': {'mount_snapshot_support': True}
        }
        be_filesystem_name = 'be_fs_1'
        be_snap_filesystem_name = 'snap_be_fs_1'
        fe_filesystem = {'be_uid': 'fs-uid-1'}
        fe_snap_filesystem = {'be_uid': 'snap-fs-uid-1'}
        fe_reverted_filesystem = {'be_uid': 'fs-uid-1',
                                  'be_filesystem_size': 10240}

        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=[fe_filesystem, fe_snap_filesystem,
                         fe_reverted_filesystem])
        self.handler.filesystem_handler.snapshot_restore = mock.Mock()
        self.handler.filesystem_handler.snapshot_online = mock.Mock()

        result = self.handler.revert_to_snapshot(
            fe_revert_snapshot, be_filesystem_name, be_snap_filesystem_name)

        self.assertEqual(10240, result)
        self.handler.filesystem_handler.snapshot_restore.\
            assert_called_once_with(
                fe_filesystem['be_uid'], be_snap_filesystem_name)

        # Verify the snapshot filesystem was looked up and re-exported
        self.handler.filesystem_handler._get_filesystem_by_name.\
            assert_any_call(be_snap_filesystem_name)
        self.handler.filesystem_handler.snapshot_online.\
            assert_called_once_with(fe_snap_filesystem['be_uid'])

    def test_revert_to_snapshot_online_fails_is_logged_not_raised(self):
        """Test revert succeeds even when bringing snapshot online fails."""

        fe_revert_snapshot = {
            'id': 'snap-id-3',
            'share': {'mount_snapshot_support': True}
        }
        be_filesystem_name = 'be_fs_1'
        be_snap_filesystem_name = 'snap_be_fs_1'
        fe_filesystem = {'be_uid': 'fs-uid-1'}
        fe_snap_filesystem = {'be_uid': 'snap-fs-uid-1'}
        fe_reverted_filesystem = {'be_uid': 'fs-uid-1',
                                  'be_filesystem_size': 10240}

        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=[fe_filesystem, fe_snap_filesystem,
                         fe_reverted_filesystem])
        self.handler.filesystem_handler.snapshot_restore = mock.Mock()
        self.handler.filesystem_handler.snapshot_online = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                reason='Online snapshot limit reached'))

        # Should not raise
        self.handler.revert_to_snapshot(
            fe_revert_snapshot, be_filesystem_name, be_snap_filesystem_name)

        self.handler.filesystem_handler.snapshot_restore.\
            assert_called_once_with(
                fe_filesystem['be_uid'], be_snap_filesystem_name)
        self.handler.filesystem_handler.snapshot_online.\
            assert_called_once_with(fe_snap_filesystem['be_uid'])

    def test_revert_to_snapshot_snap_lookup_fails_is_logged_not_raised(self):
        """Test revert succeeds when snapshot filesystem lookup fails."""

        fe_revert_snapshot = {
            'id': 'snap-id-4',
            'share': {'mount_snapshot_support': True}
        }
        be_filesystem_name = 'be_fs_1'
        be_snap_filesystem_name = 'snap_be_fs_1'
        fe_filesystem = {'be_uid': 'fs-uid-1'}
        fe_reverted_filesystem = {'be_uid': 'fs-uid-1',
                                  'be_filesystem_size': 10240}

        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=[
                fe_filesystem,
                exception.HPEAlletraB10000DriverException(
                    reason='Filesystem not found'),
                fe_reverted_filesystem])
        self.handler.filesystem_handler.snapshot_restore = mock.Mock()
        self.handler.filesystem_handler.snapshot_online = mock.Mock()

        # Should not raise
        self.handler.revert_to_snapshot(
            fe_revert_snapshot, be_filesystem_name, be_snap_filesystem_name)

        self.handler.filesystem_handler.snapshot_online.assert_not_called()

    def test_revert_to_snapshot_filesystem_not_found(self):
        """Test raises exception when filesystem not found."""

        fe_revert_snapshot = {
            'id': 'snap-id-5',
            'share': {'mount_snapshot_support': False}
        }
        be_filesystem_name = 'be_fs_missing'
        be_snap_filesystem_name = 'snap_be_fs_1'

        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                reason='Filesystem not found'))

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.revert_to_snapshot,
            fe_revert_snapshot,
            be_filesystem_name,
            be_snap_filesystem_name
        )

    def test_revert_to_snapshot_restore_fails(self):
        """Test raises exception propagated from snapshot_restore."""

        fe_revert_snapshot = {
            'id': 'snap-id-6',
            'share': {'mount_snapshot_support': True}
        }
        be_filesystem_name = 'be_fs_1'
        be_snap_filesystem_name = 'snap_be_fs_1'
        fe_filesystem = {'be_uid': 'fs-uid-1'}

        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            return_value=fe_filesystem)
        self.handler.filesystem_handler.snapshot_restore = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                reason='Restore failed'))
        self.handler.filesystem_handler.snapshot_online = mock.Mock()

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.revert_to_snapshot,
            fe_revert_snapshot,
            be_filesystem_name,
            be_snap_filesystem_name
        )

        # Verify no attempt to re-export after a failed restore
        self.handler.filesystem_handler.snapshot_online.assert_not_called()

    # manage_snapshot()
    def _make_manage_snapshot_req(
        self, provider_location='snap_be_fs_1',
        mount_snapshot_support=False
    ):
        return {
            'provider_location': provider_location,
            'share': {'mount_snapshot_support': mount_snapshot_support}
        }

    def _make_snap_filesystem(
        self, be_uid='snap-fs-uid-1',
        parent='be_fs_1',
        size_mib=2048
    ):
        return {
            'be_uid': be_uid,
            'be_parent_filesystem_name': parent,
            'be_filesystem_size': size_mib
        }

    def _make_snap_fileshare(self, be_detailed_state='STATE_UNEXPORTED'):
        return {
            'be_uid': 'snap-share-uid-1',
            'be_detailed_state': be_detailed_state
        }

    def _setup_manage_mocks(
        self, fe_snap_filesystem, fe_snap_fileshare
    ):
        self.handler.filesystem_handler._get_filesystem_by_name = (
            mock.Mock(return_value=fe_snap_filesystem))
        self.handler.fileshare_handler\
            ._get_fileshare_by_filesystem_name = (
                mock.Mock(return_value=fe_snap_fileshare))

    def test_manage_snapshot_success_without_mount_support(self):
        """Test successful manage without mount_snapshot_support."""

        be_filesystem_name = 'be_fs_1'
        fe_manage_snapshot = self._make_manage_snapshot_req(
            mount_snapshot_support=False)
        fe_snap_filesystem = self._make_snap_filesystem()
        fe_snap_fileshare = self._make_snap_fileshare(
            be_detailed_state='STATE_UNEXPORTED')

        self._setup_manage_mocks(fe_snap_filesystem, fe_snap_fileshare)

        result_fileshare, result_filesystem = (
            self.handler.manage_snapshot(
                fe_manage_snapshot, be_filesystem_name))

        self.handler.filesystem_handler._get_filesystem_by_name\
            .assert_called_once_with(
                fe_manage_snapshot['provider_location'])
        self.handler.fileshare_handler\
            ._get_fileshare_by_filesystem_name\
            .assert_called_once_with(
                fe_manage_snapshot['provider_location'])
        self.assertEqual(fe_snap_fileshare, result_fileshare)
        self.assertEqual(fe_snap_filesystem, result_filesystem)

    def test_manage_snapshot_success_with_mount_support(self):
        """Test successful manage with mount_snapshot_support."""

        be_filesystem_name = 'be_fs_1'
        fe_manage_snapshot = self._make_manage_snapshot_req(
            mount_snapshot_support=True)
        fe_snap_filesystem = self._make_snap_filesystem()
        fe_snap_fileshare = self._make_snap_fileshare(
            be_detailed_state='STATE_NORMAL')

        self._setup_manage_mocks(fe_snap_filesystem, fe_snap_fileshare)

        result_fileshare, result_filesystem = (
            self.handler.manage_snapshot(
                fe_manage_snapshot, be_filesystem_name))

        self.assertEqual(fe_snap_fileshare, result_fileshare)
        self.assertEqual(fe_snap_filesystem, result_filesystem)

    def test_manage_snapshot_filesystem_not_found(self):
        """Test raises exception when snap filesystem is not found."""

        fe_manage_snapshot = self._make_manage_snapshot_req()

        self.handler.filesystem_handler._get_filesystem_by_name = (
            mock.Mock(
                side_effect=exception.HPEAlletraB10000DriverException(
                    reason='Filesystem not found')))

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_snapshot,
            fe_manage_snapshot,
            'be_fs_1'
        )

    def test_manage_snapshot_missing_parent_filesystem_name(self):
        """Test raises exception when be_parent_filesystem_name absent."""

        be_filesystem_name = 'be_fs_1'
        fe_manage_snapshot = self._make_manage_snapshot_req()
        fe_snap_filesystem = {
            'be_uid': 'snap-fs-uid-1',
            'be_filesystem_size': 2048
            # no 'be_parent_filesystem_name'
        }
        fe_snap_fileshare = self._make_snap_fileshare()

        self._setup_manage_mocks(fe_snap_filesystem, fe_snap_fileshare)

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_snapshot,
            fe_manage_snapshot,
            be_filesystem_name
        )

    def test_manage_snapshot_wrong_parent_filesystem(self):
        """Test raises exception when snapshot parent does not match."""

        be_filesystem_name = 'be_fs_1'
        fe_manage_snapshot = self._make_manage_snapshot_req()
        fe_snap_filesystem = self._make_snap_filesystem(
            parent='different_be_fs')
        fe_snap_fileshare = self._make_snap_fileshare()

        self._setup_manage_mocks(fe_snap_filesystem, fe_snap_fileshare)

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_snapshot,
            fe_manage_snapshot,
            be_filesystem_name
        )

    def test_manage_snapshot_state_mismatch_mount_support_not_normal(self):
        """Test raises exception when mount support True, not STATE_NORMAL."""

        be_filesystem_name = 'be_fs_1'
        fe_manage_snapshot = self._make_manage_snapshot_req(
            mount_snapshot_support=True)
        fe_snap_filesystem = self._make_snap_filesystem()
        fe_snap_fileshare = self._make_snap_fileshare(
            be_detailed_state='STATE_UNEXPORTED')

        self._setup_manage_mocks(fe_snap_filesystem, fe_snap_fileshare)

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_snapshot,
            fe_manage_snapshot,
            be_filesystem_name
        )

    def test_manage_snapshot_state_mismatch_no_mount_not_unexported(self):
        """Test raises exception no mount support, not STATE_UNEXPORTED."""

        be_filesystem_name = 'be_fs_1'
        fe_manage_snapshot = self._make_manage_snapshot_req(
            mount_snapshot_support=False)
        fe_snap_filesystem = self._make_snap_filesystem()
        fe_snap_fileshare = self._make_snap_fileshare(
            be_detailed_state='STATE_NORMAL')

        self._setup_manage_mocks(fe_snap_filesystem, fe_snap_fileshare)

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_snapshot,
            fe_manage_snapshot,
            be_filesystem_name
        )

    def test_manage_snapshot_size_not_multiple_of_1024(self):
        """Test exception snapshot filesystem size not multiple of 1024."""

        be_filesystem_name = 'be_fs_1'
        fe_manage_snapshot = self._make_manage_snapshot_req(
            mount_snapshot_support=False)
        fe_snap_filesystem = self._make_snap_filesystem(size_mib=1500)
        fe_snap_fileshare = self._make_snap_fileshare(
            be_detailed_state='STATE_UNEXPORTED')

        self._setup_manage_mocks(fe_snap_filesystem, fe_snap_fileshare)

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_snapshot,
            fe_manage_snapshot,
            be_filesystem_name
        )

    # _compare_values_with_be_snap()
    def test_compare_values_with_be_snap_success(self):
        """Test _compare_values_with_be_snap for fileshare_handler."""

        be_snap_share_id = 'snap-share-uid-1'
        be_snap_share_name = 'snap_share_1'
        be_snap_filesystem_name = 'snap_fs_1'
        be_snap_sharesetting_name = 'snap_sharesetting_1'

        self.handler.fileshare_handler._compare_values_with_be_share = (
            mock.Mock())

        self.handler._compare_values_with_be_snap(
            be_snap_share_id, be_snap_share_name,
            be_snap_filesystem_name, be_snap_sharesetting_name)

        self.handler.fileshare_handler._compare_values_with_be_share.\
            assert_called_once_with(
                be_snap_share_id, be_snap_share_name,
                be_snap_filesystem_name, be_snap_sharesetting_name)

    def test_compare_values_with_be_snap_propagates_exception(self):
        """Test _compare_values_with_be_snap propagates exceptions."""

        be_snap_share_id = 'snap-share-uid-1'
        be_snap_share_name = 'snap_share_1'
        be_snap_filesystem_name = 'snap_fs_1'
        be_snap_sharesetting_name = 'snap_sharesetting_1'

        self.handler.fileshare_handler._compare_values_with_be_share = (
            mock.Mock(
                side_effect=exception.HPEAlletraB10000DriverException(
                    reason='Value mismatch')))

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler._compare_values_with_be_snap,
            be_snap_share_id,
            be_snap_share_name,
            be_snap_filesystem_name,
            be_snap_sharesetting_name
        )


class SnapshotValidatorTestCase(test.TestCase):
    """Test case for SnapshotValidator class."""

    def setUp(self):
        """Test Setup"""
        super(SnapshotValidatorTestCase, self).setUp()

        self.mock_feature_support_handler = mock.Mock()
        self.validator = snapshot.SnapshotValidator(
            self.mock_feature_support_handler
        )

    def test_create_snapshot_validation_missing_name(self):
        """Test create_snapshot raises InvalidInput when name is missing."""

        fe_create_snapshot = {
            'id': 'snap-id-3',
            'share': {'mount_snapshot_support': False}
        }

        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_create_snapshot_fe_req,
            fe_create_snapshot
        )

    def test_create_snapshot_validation_missing_share(self):
        """Test create_snapshot raises InvalidInput when share is missing."""

        fe_create_snapshot = {
            'id': 'snap-id-4',
            'name': 'snap_name_4'
        }

        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_create_snapshot_fe_req,
            fe_create_snapshot
        )

    def test_delete_snapshot_validation_missing_id(self):
        """Test delete_snapshot raises InvalidInput when id is missing."""

        fe_delete_snapshot = {}

        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_delete_snapshot_fe_req,
            fe_delete_snapshot
        )

    def test_manage_snapshot_validation_missing_provider_location(self):
        """Test raises InvalidInput when provider_location is missing."""

        fe_manage_snapshot = {'share': {'mount_snapshot_support': False}}

        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_manage_snapshot_fe_req,
            fe_manage_snapshot
        )

    def test_manage_snapshot_validation_missing_share(self):
        """Test raises InvalidInput when share is missing."""

        fe_manage_snapshot = {'provider_location': 'snap_be_fs_1'}

        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_manage_snapshot_fe_req,
            fe_manage_snapshot
        )
