# Copyright (c) 2025 Hewlett Packard Enterprise Development LP
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
    filesystem_handler as filesystem)
from manila import test


@ddt.ddt
class FileSystemHandlerTestCase(test.TestCase):
    """Test case for FileSystemHandler class."""

    def setUp(self):
        """Test Setup"""
        super(FileSystemHandlerTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()
        self.mock_feature_support_handler = mock.Mock()
        self.mock_feature_support_handler\
            .check_min_r6_device_version.return_value = False

        # Initialize handler
        self.handler = filesystem.FileSystemHandler(
            self.mock_rest_client,
            self.mock_feature_support_handler
        )

    # get_filesystems()
    def test_get_filesystems_success(self):
        """Test successful filesystem retrieval."""

        # Configure mock backend response with valid data
        be_filesystems = {
            'members': {
                'uid1': {
                    'uid': 'uid1',
                    'name': 'filesystem1',
                    'vvSizeInMiB': 1024,
                    'reduce': True
                }
            }
        }
        self.mock_rest_client.get.return_value = (200, be_filesystems)

        # Execute get_filesystem
        result = self.handler.get_filesystems()

        # Verify rest client call
        self.mock_rest_client.get.assert_called_once_with('/filesystems')

        # Verify result structure
        self.assertEqual(1, len(result))
        filesystem_result = result[0]
        self.assertEqual('uid1', filesystem_result['be_uid'])
        self.assertEqual(
            'filesystem1',
            filesystem_result['be_filesystem_name'])
        self.assertEqual(1024, filesystem_result['be_filesystem_size'])
        self.assertTrue(filesystem_result['be_filesystem_reduce'])

    # snapshot_create()
    def test_snapshot_create_success(self):
        """Test successful snapshot creation."""
        self.handler._post_filesystem_by_id = mock.Mock()

        self.handler.snapshot_create('fs-uid-1', 'snap_name_1', 'snap-id-1')

        self.handler._post_filesystem_by_id.assert_called_once_with(
            'fs-uid-1',
            {
                'action': 'FILE_SYSTEM_SNAPSHOT_CREATE',
                'parameters': {'name': 'snap_name_1'}
            },
            'FILE_SYSTEM_SNAPSHOT_CREATE snap-id-1'
        )

    # snapshot_restore()
    def test_snapshot_restore_success(self):
        """Test successful snapshot restore."""
        self.handler._post_filesystem_by_id = mock.Mock()

        self.handler.snapshot_restore('fs-uid-1', 'snap_be_fs_1')

        self.handler._post_filesystem_by_id.assert_called_once_with(
            'fs-uid-1',
            {
                'action': 'FILE_SYSTEM_SNAPSHOT_RESTORE',
                'parameters': {'source': 'snap_be_fs_1'}
            },
            'FILE_SYSTEM_SNAPSHOT_RESTORE fs-uid-1 from snap_be_fs_1'
        )

    # snapshot_online()
    def test_snapshot_online_success(self):
        """Test successful snapshot online."""
        self.handler._post_filesystem_by_id = mock.Mock()

        self.handler.snapshot_online('snap-fs-uid-1')

        self.handler._post_filesystem_by_id.assert_called_once_with(
            'snap-fs-uid-1',
            {'action': 'FILE_SYSTEM_SNAPSHOT_ONLINE'},
            'FILE_SYSTEM_SNAPSHOT_ONLINE snap-fs-uid-1'
        )

    # _get_filesystem_by_name()
    def test_get_filesystem_by_name_success(self):
        """Test successful filesystem retrieval by name."""

        # Configure mock for get_filesystem
        expected_filesystem = {
            'be_uid': 'uid1',
            'be_filesystem_name': 'filesystem1',
            'be_filesystem_size': 1024,
            'be_filesystem_reduce': True
        }
        self.handler.get_filesystems = mock.Mock(
            return_value=[expected_filesystem])

        # Execute _get_filesystem_by_name
        result = self.handler._get_filesystem_by_name('filesystem1')

        # Verify get_filesystem was called
        self.handler.get_filesystems.assert_called_once()

        # Verify result
        self.assertEqual(expected_filesystem, result)

    def test_get_filesystem_by_name_not_found(self):
        """Test filesystem retrieval by name when not found."""

        # Configure mock for get_filesystem with different name
        self.handler.get_filesystems = mock.Mock(return_value=[{
            'be_uid': 'uid1',
            'be_filesystem_name': 'filesystem1',
            'be_filesystem_size': 1024,
            'be_filesystem_reduce': True
        }])

        # Execute _get_filesystem_by_name and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler._get_filesystem_by_name,
            'nonexistent_filesystem'
        )

    # _post_filesystem_by_id()
    def test_post_filesystem_by_id_success(self):
        """Test successful _post_filesystem_by_id call."""

        # Configure mock responses
        be_response_header = {'Task_uri': '/tasks/task-1'}
        be_response_body = {}
        self.mock_rest_client.post.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='task-1')

        mock_task_waiter = mock.Mock()
        mock_task_waiter.wait_for_task.return_value = {
            'state': 'COMPLETED', 'status': 1}
        self.handler.task._check_task_completion_status = mock.Mock()

        with mock.patch(
            'manila.share.drivers.hpe.alletra_mp_b10000.fileshare'
            '.helpers.TaskWaiter',
            return_value=mock_task_waiter
        ):
            req_body = {'action': 'FILE_SYSTEM_SNAPSHOT_CREATE',
                        'parameters': {'name': 'snap1'}}
            self.handler._post_filesystem_by_id(
                'fs-uid-1', req_body, 'FILE_SYSTEM_SNAPSHOT_CREATE snap-id-1')

        # Verify REST post called with correct URL and body
        self.mock_rest_client.post.assert_called_once_with(
            '/filesystems/fs-uid-1', body=req_body)

        # Verify task ID extracted and task completion checked
        self.handler.task._extract_task_id_from_header\
            .assert_called_once_with(be_response_header)
        self.handler.task._check_task_completion_status\
            .assert_called_once_with(
                mock_task_waiter.wait_for_task.return_value,
                'FILE_SYSTEM_SNAPSHOT_CREATE snap-id-1')

    def test_post_filesystem_by_id_task_fails(self):
        """Test exception for task completion check fail"""

        # Configure valid response header
        be_response_header = {'Task_uri': '/tasks/task-1'}
        self.mock_rest_client.post.return_value = (be_response_header, {})
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='task-1')

        mock_task_waiter = mock.Mock()
        final_task_status = {'state': 'FAILED', 'status': 0}
        mock_task_waiter.wait_for_task.return_value = final_task_status
        self.handler.task._check_task_completion_status = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                reason='Task failed'))

        with mock.patch(
            'manila.share.drivers.hpe.alletra_mp_b10000.fileshare'
            '.helpers.TaskWaiter',
            return_value=mock_task_waiter
        ):
            req_body = {'action': 'FILE_SYSTEM_SNAPSHOT_RESTORE',
                        'parameters': {'source': 'snap_be_fs_1'}}
            self.assertRaises(
                exception.HPEAlletraB10000DriverException,
                self.handler._post_filesystem_by_id,
                'fs-uid-1', req_body,
                'FILE_SYSTEM_SNAPSHOT_RESTORE fs-uid-1 from snap_be_fs_1')


@ddt.ddt
class FileSystemValidatorTestCase(test.TestCase):
    """Test case for FileSystemValidator class."""

    def setUp(self):
        """Test Setup"""
        super(FileSystemValidatorTestCase, self).setUp()

        # Initialize validator
        self.mock_feature_support_handler = mock.Mock()
        self.mock_feature_support_handler\
            .check_min_r6_device_version.return_value = False
        self.validator = filesystem.FileSystemValidator(
            self.mock_feature_support_handler)

    # validate_get_filesystems_be_resp()
    def test_validate_get_filesystems_be_resp_success(self):
        """Test successful validation of filesystems response."""

        # Configure valid backend response
        be_filesystems = {
            'members': {
                'uid1': {
                    'uid': 'uid1',
                    'name': 'filesystem1',
                    'vvSizeInMiB': 1024,
                    'reduce': True
                }
            }
        }

        # Execute validation - should not raise exception
        self.validator.validate_get_filesystems_be_resp(be_filesystems)

    def test_validate_get_filesystems_be_resp_none_response(self):
        """Test validation failure when response is None."""

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesystems_be_resp,
            None
        )

    def test_validate_get_filesystems_be_resp_missing_members(self):
        """Test validation failure when members field is missing."""

        # Configure response without members
        be_filesystems = {}

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesystems_be_resp,
            be_filesystems
        )

    def test_validate_get_filesystems(self):
        """Test validation of individual filesystem."""

        # Configure response with members containing invalid filesystem
        # (missing uid)
        be_filesystems = {
            'members': {
                'uid1': {
                    'name': 'filesystem1',
                    'vvSizeInMiB': 1024,
                    'reduce': True  # missing uid
                }
            }
        }

        # Execute validation and expect exception with wrapping message
        try:
            self.validator.validate_get_filesystems_be_resp(be_filesystems)
        except exception.HPEAlletraB10000DriverException as e:
            # Verify the exception message contains the wrapping text
            self.assertIn(
                "Failed to validate filesystem data from "
                "get filesystems call",
                str(e))
            self.assertIn(
                "Uid not found in get filesystem by id response", str(e))

    # validate_get_filesystem_by_id_be_resp()
    def test_validate_get_filesystem_by_id_be_resp_success(self):
        """Test successful validation of individual filesystem."""

        # Configure valid backend filesystem
        be_filesystem = {
            'uid': 'uid1',
            'name': 'filesystem1',
            'vvSizeInMiB': 1024,
            'reduce': True
        }

        # Execute validation - should not raise exception
        self.validator.validate_get_filesystem_by_id_be_resp(be_filesystem)

    def test_validate_get_filesystem_by_id_be_resp_none(self):
        """Test validation failure when filesystem is None."""

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesystem_by_id_be_resp,
            None
        )

    def test_validate_get_filesystem_by_id_be_resp_missing_uid(self):
        """Test validation failure when uid is missing."""

        # Configure filesystem without uid
        be_filesystem = {
            'name': 'filesystem1',
            'vvSizeInMiB': 1024,
            'reduce': True
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesystem_by_id_be_resp,
            be_filesystem
        )

    def test_validate_get_filesystem_by_id_be_resp_missing_name(self):
        """Test validation failure when name is missing."""

        # Configure filesystem without name
        be_filesystem = {
            'uid': 'uid1',
            'vvSizeInMiB': 1024,
            'reduce': True
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesystem_by_id_be_resp,
            be_filesystem
        )

    def test_validate_get_filesystem_by_id_be_resp_missing_vvSizeInMiB(self):
        """Test validation failure when vvSizeInMiB is missing."""

        # Configure filesystem without vvSizeInMiB
        be_filesystem = {
            'uid': 'uid1',
            'name': 'filesystem1',
            'reduce': True
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesystem_by_id_be_resp,
            be_filesystem
        )

    def test_validate_get_filesystem_by_id_be_resp_missing_reduce(self):
        """Test validation failure when reduce is missing."""

        # Configure filesystem without reduce
        be_filesystem = {
            'uid': 'uid1',
            'name': 'filesystem1',
            'vvSizeInMiB': 1024
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesystem_by_id_be_resp,
            be_filesystem
        )

    def test_validate_get_filesystem_by_id_be_resp_invalid_reduce(self):
        """Test validation failure when reduce is not boolean."""

        # Configure filesystem with invalid reduce
        be_filesystem = {
            'uid': 'uid1',
            'name': 'filesystem1',
            'vvSizeInMiB': 1024,
            'reduce': 'invalid'
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesystem_by_id_be_resp,
            be_filesystem
        )
    # validate_snapshot_create_fe_req()

    def test_validate_snapshot_create_fe_req_success(self):
        """Test successful validation of snapshot create request."""
        self.validator.validate_snapshot_create_fe_req(
            'fs-uid-1', 'snap_name_1', 'snap-id-1')

    def test_validate_snapshot_create_fe_req_missing_uid(self):
        """Test raises InvalidInput when be_filesystem_uid is None."""
        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_snapshot_create_fe_req,
            None, 'snap_name_1', 'snap-id-1'
        )

    def test_validate_snapshot_create_fe_req_missing_name(self):
        """Test raises InvalidInput when snapshot_name is None."""
        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_snapshot_create_fe_req,
            'fs-uid-1', None, 'snap-id-1'
        )

    def test_validate_snapshot_create_fe_req_missing_id(self):
        """Test raises InvalidInput when fe_snapshot_id is None."""
        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_snapshot_create_fe_req,
            'fs-uid-1', 'snap_name_1', None
        )

    # validate_snapshot_restore_fe_req()
    def test_validate_snapshot_restore_fe_req_success(self):
        """Test successful validation of snapshot restore request."""
        self.validator.validate_snapshot_restore_fe_req(
            'fs-uid-1', 'snap_be_fs_1')

    def test_validate_snapshot_restore_fe_req_missing_uid(self):
        """Test raises InvalidInput when be_filesystem_uid is None."""
        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_snapshot_restore_fe_req,
            None, 'snap_be_fs_1'
        )

    def test_validate_snapshot_restore_fe_req_missing_snap_name(self):
        """Test raises InvalidInput when be_snap_filesystem_name is None. """
        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_snapshot_restore_fe_req,
            'fs-uid-1', None
        )

    # validate_snapshot_online_fe_req()
    def test_validate_snapshot_online_fe_req_success(self):
        """Test successful validation of snapshot online request."""
        self.validator.validate_snapshot_online_fe_req('snap-fs-uid-1')

    def test_validate_snapshot_online_fe_req_missing_id(self):
        """Test raises InvalidInput when be_snap_filesystem_id is None."""
        self.assertRaises(
            exception.InvalidInput,
            self.validator.validate_snapshot_online_fe_req,
            None
        )

    # validate_filesystem_api_be_task_resp_header()
    def test_validate_filesystem_api_be_task_resp_header_success(self):
        """Test validation passes when Task_uri is present."""
        be_response_header = {'Task_uri': '/tasks/task-123'}
        # Should not raise
        self.validator.validate_filesystem_api_be_task_resp_header(
            be_response_header)

    def test_validate_filesystem_api_be_task_resp_header_missing(self):
        """Test validation raises when Task_uri is absent."""
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_filesystem_api_be_task_resp_header,
            {})


@ddt.ddt
class FileSystemModelConvertTestCase(test.TestCase):
    """Test case for FileSystemModelConvert class."""

    def setUp(self):
        """Test Setup"""
        super(FileSystemModelConvertTestCase, self).setUp()

        # Initialize converter
        self.mock_feature_support_handler = mock.Mock()
        self.mock_feature_support_handler\
            .check_min_r6_device_version.return_value = False
        self.converter = filesystem.FileSystemModelConvert(
            self.mock_feature_support_handler)

    # convert_filesystems_to_fe_model()
    def test_convert_filesystems_to_fe_model(self):
        """Test successful conversion of filesystems to FE model."""

        # Configure backend response
        be_filesystems = {
            'members': {
                'uid1': {
                    'uid': 'uid1',
                    'name': 'filesystem1',
                    'vvSizeInMiB': 1024,
                    'reduce': True
                },
                'uid2': {
                    'uid': 'uid2',
                    'name': 'filesystem2',
                    'vvSizeInMiB': 2048,
                    'reduce': False
                }
            }
        }

        # Execute conversion
        result = self.converter.convert_filesystems_to_fe_model(be_filesystems)

        # Verify result
        expected = [
            {
                'be_uid': 'uid1',
                'be_filesystem_name': 'filesystem1',
                'be_filesystem_size': 1024,
                'be_filesystem_reduce': True
            },
            {
                'be_uid': 'uid2',
                'be_filesystem_name': 'filesystem2',
                'be_filesystem_size': 2048,
                'be_filesystem_reduce': False
            }
        ]
        self.assertEqual(expected, result)

    # convert_filesystem_by_id_to_fe_model()
    def test_convert_filesystem_by_id_to_fe_model(self):
        """Test conversion without r6 — no be_parent_filesystem_name."""
        be_filesystem = {
            'uid': 'uid1',
            'name': 'filesystem1',
            'vvSizeInMiB': 1024,
            'reduce': True
        }

        result = self.converter.convert_filesystem_by_id_to_fe_model(
            be_filesystem)

        expected = {
            'be_uid': 'uid1',
            'be_filesystem_name': 'filesystem1',
            'be_filesystem_size': 1024,
            'be_filesystem_reduce': True
        }
        self.assertEqual(expected, result)
        self.assertNotIn('be_parent_filesystem_name', result)

    def test_convert_filesystem_by_id_to_fe_model_r6_with_snapshot_info(
            self):
        """Test r6 device snapshotInfo includes be_parent_filesystem_name. """
        self.mock_feature_support_handler\
            .check_min_r6_device_version.return_value = True

        be_filesystem = {
            'uid': 'snap-uid-1',
            'name': 'snap_fs_1',
            'vvSizeInMiB': 1024,
            'reduce': True,
            'snapshotInfo': {'copyOfName': 'parent_fs_1'}
        }

        result = self.converter.convert_filesystem_by_id_to_fe_model(
            be_filesystem)

        self.assertEqual('snap-uid-1', result['be_uid'])
        self.assertEqual('parent_fs_1', result['be_parent_filesystem_name'])

    def test_convert_filesystem_by_id_to_fe_model_r6_no_snapshot_info(self):
        """Test r6 dev without snapshotInfo - no be_parent_filesystem_name."""
        self.mock_feature_support_handler\
            .check_min_r6_device_version.return_value = True

        be_filesystem = {
            'uid': 'uid1',
            'name': 'filesystem1',
            'vvSizeInMiB': 1024,
            'reduce': True
        }

        result = self.converter.convert_filesystem_by_id_to_fe_model(
            be_filesystem)

        self.assertNotIn('be_parent_filesystem_name', result)

    def test_convert_filesystem_by_id_to_fe_model_r6_no_copy_of_name(self):
        """Test r6 device with snapshotInfo but no copyOfName."""
        self.mock_feature_support_handler\
            .check_min_r6_device_version.return_value = True

        be_filesystem = {
            'uid': 'uid1',
            'name': 'filesystem1',
            'vvSizeInMiB': 1024,
            'reduce': True,
            'snapshotInfo': {}
        }

        result = self.converter.convert_filesystem_by_id_to_fe_model(
            be_filesystem)

        self.assertNotIn('be_parent_filesystem_name', result)

    # convert_snapshot_create_to_be_model()
    def test_convert_snapshot_create_to_be_model(self):
        """Test conversion of snapshot create request to BE model."""
        result = self.converter.convert_snapshot_create_to_be_model(
            'snap_name_1')

        self.assertEqual('FILE_SYSTEM_SNAPSHOT_CREATE', result['action'])
        self.assertEqual('snap_name_1', result['parameters']['name'])

    # convert_snapshot_restore_to_be_model()
    def test_convert_snapshot_restore_to_be_model(self):
        """Test conversion of snapshot restore request to BE model."""
        result = self.converter.convert_snapshot_restore_to_be_model(
            'snap_be_fs_1')

        self.assertEqual('FILE_SYSTEM_SNAPSHOT_RESTORE', result['action'])
        self.assertEqual('snap_be_fs_1', result['parameters']['source'])

    # convert_snapshot_online_to_be_model()
    def test_convert_snapshot_online_to_be_model(self):
        """Test conversion of snapshot online request to BE model."""
        result = self.converter.convert_snapshot_online_to_be_model()

        self.assertEqual('FILE_SYSTEM_SNAPSHOT_ONLINE', result['action'])
        self.assertNotIn('parameters', result)
