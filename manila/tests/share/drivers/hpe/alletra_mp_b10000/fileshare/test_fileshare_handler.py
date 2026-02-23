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
    fileshare_handler as fileshare
)
import manila.share.drivers.hpe.alletra_mp_b10000.fileshare.helpers as helpers
from manila import test


# Test constants for backend fileshare operations
# Define prefixes first so they can be reused
BE_FILESHARE_PREFIX = 'share-'
BE_FILESYSTEM_PREFIX = 'manilafs-'
BE_SHARESETTING_PREFIX = 'manilass-'
BE_FILESHARE_NAME_LENGTH = 42  # 'share-' (6) + UUID (36)
BE_FILESYSTEM_NAME_LENGTH = 45  # 'manilafs-' (9) + UUID (36)
BE_SHARESETTING_NAME_LENGTH = 45  # 'manilass-' (9) + UUID (36)
# Primary test data
BE_FILESHARE_UID = '550e8400e29b41d4a716446655440000'
FE_SHARE_ID = '6a7b8c9d-e0f1-42a3-b456-789012345678'
BE_FILESHARE_NAME = BE_FILESHARE_PREFIX + FE_SHARE_ID
BE_FILESYSTEM_NAME = BE_FILESYSTEM_PREFIX + FE_SHARE_ID
BE_SHARESETTING_NAME = BE_SHARESETTING_PREFIX + FE_SHARE_ID
# Test data for create operations
FE_CREATE_SHARE_ID = '550e8400-e29b-41d4-a716-446655440000'
FE_CREATE_SHARE_NAME = BE_FILESHARE_PREFIX + FE_CREATE_SHARE_ID
# Test data for manage operations
FE_MANAGE_SHARE_ID = '9f8e7d6c-5b4a-3210-fedc-ba9876543210'
BE_HOST_IP = '192.168.1.1'
BE_MOUNT_PATH = '/file/' + BE_FILESYSTEM_NAME + '/' + BE_FILESHARE_NAME
# Test constants for validation test scenarios
BE_VALID_FILESHARE_NAME = BE_FILESHARE_PREFIX + 'validshare'
BE_VALID_FILESYSTEM_NAME = BE_FILESYSTEM_PREFIX + 'validshare'
BE_VALID_SHARESETTING_NAME = BE_SHARESETTING_PREFIX + 'validshare'
BE_VALID_MOUNT_PATH = ('/file/' + BE_VALID_FILESYSTEM_NAME + '/' +
                       BE_VALID_FILESHARE_NAME)
BE_INVALID_FILESHARE_NAME = BE_FILESHARE_PREFIX + 'invalidshare'
BE_INVALID_FILESYSTEM_NAME = BE_FILESYSTEM_PREFIX + 'invalidshare'
BE_MISSING_FILESHARE_NAME = BE_FILESHARE_PREFIX + 'missing'
BE_MISSING_FILESYSTEM_NAME = BE_FILESYSTEM_PREFIX + 'missing'
BE_MISSING_SHARESETTING_NAME = BE_SHARESETTING_PREFIX + 'missing'
BE_MISSING_MOUNT_PATH = ('/file/' + BE_MISSING_FILESYSTEM_NAME + '/' +
                         BE_MISSING_FILESHARE_NAME)
BE_DIFFERENT_FILESHARE_NAME = BE_FILESHARE_PREFIX + 'different'
BE_DIFFERENT_FILESYSTEM_NAME = BE_FILESYSTEM_PREFIX + 'different'
BE_DIFFERENT_SHARESETTING_NAME = BE_SHARESETTING_PREFIX + 'different'


@ddt.ddt
class FileShareHandlerCreateTestCase(test.TestCase):
    """Test case for FileShareHandler create_fileshare method."""

    def setUp(self):
        """Test Setup"""
        super(FileShareHandlerCreateTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()

        # Initialize handler
        self.handler = fileshare.FileShareHandler(
            self.mock_rest_client
        )

    # create_fileshare()
    def test_create_fileshare_success(self):
        """Test successful fileshare creation."""
        # Configure frontend request with proper UUID
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {}

        # Mock the backend response with realistic Task_uri format
        be_response_header = {
            'Task_uri': '/api/v3/tasks/06e45f0a78afaa2b9e5188a49f70d517'}
        be_response_body = {}

        # Mock the task waiter with STATE_FINISHED
        mock_task_waiter = mock.Mock()
        mock_task_waiter.wait_for_task.return_value = {
            'status': 'STATE_FINISHED'}

        # Configure mocks - don't mock convert and validate functions
        self.mock_rest_client.post.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='06e45f0a78afaa2b9e5188a49f70d517')
        self.handler.task._check_task_completion_status = mock.Mock()
        self.mock_object(
            helpers, 'TaskWaiter', mock.Mock(
                return_value=mock_task_waiter))

        # Execute create_fileshare
        be_fileshare_name, be_filesystem_name, be_sharesetting_name = (
            self.handler.create_fileshare(fe_create_fileshare, extra_specs))

        # Verify method calls - validator methods should be called naturally
        # The POST body should be the actual batch structure created by
        # convert_fileshare_to_be_model
        self.mock_rest_client.post.assert_called_once()
        post_call_args = self.mock_rest_client.post.call_args
        self.assertEqual('/fileshares', post_call_args[0][0])  # URL
        batch_body = post_call_args[1]['body']  # body parameter
        self.assertIn('batch', batch_body)
        self.assertIn('ordered', batch_body)
        self.assertIn('operations', batch_body)
        # CREATE_FILE_SHARE, CREATE_FILE_SYSTEM, CREATE_FILE_SHARE_SETTINGS
        self.assertEqual(3, len(batch_body['operations']))

        self.handler.task._extract_task_id_from_header.assert_called_once_with(
            be_response_header)
        mock_task_waiter.wait_for_task.assert_called_once()
        self.handler.task.\
            _check_task_completion_status.assert_called_once_with(
                {'status': 'STATE_FINISHED'},
                f"CREATE_FILESHARE {FE_CREATE_SHARE_ID}")

        # Verify result
        self.assertTrue(be_fileshare_name.startswith(BE_FILESHARE_PREFIX))
        self.assertEqual(len(be_fileshare_name), BE_FILESHARE_NAME_LENGTH)
        self.assertTrue(be_filesystem_name.startswith(BE_FILESYSTEM_PREFIX))
        self.assertEqual(len(be_filesystem_name), BE_FILESYSTEM_NAME_LENGTH)
        self.assertTrue(
            be_sharesetting_name.startswith(BE_SHARESETTING_PREFIX))
        self.assertEqual(
            len(be_sharesetting_name), BE_SHARESETTING_NAME_LENGTH)

    def test_create_fileshare_validation_failure(self):
        """Test fileshare creation failure during validation."""
        # Configure frontend request with invalid size (too small)
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 0  # Invalid: too small
        }
        extra_specs = {}

        # Execute create_fileshare and expect exception from natural validation
        self.assertRaises(
            exception.InvalidInput,
            self.handler.create_fileshare,
            fe_create_fileshare,
            extra_specs
        )

        # Verify post was not called due to validation failure
        self.mock_rest_client.post.assert_not_called()

    def test_create_fileshare_task_failure(self):
        """Test fileshare creation failure during task execution."""
        # Configure frontend request with proper UUID
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {}

        # Mock the backend response with realistic Task_uri format
        be_response_header = {
            'Task_uri': '/api/v3/tasks/06e45f0a78afaa2b9e5188a49f70d517'}
        be_response_body = {}

        # Mock the task waiter to return failed status
        mock_task_waiter = mock.Mock()
        mock_task_waiter.wait_for_task.return_value = {
            'status': 'STATE_FAILED'}

        # Configure mocks - don't mock convert and validate functions
        self.mock_rest_client.post.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='06e45f0a78afaa2b9e5188a49f70d517')
        self.handler.task._check_task_completion_status = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                "Task failed"))
        self.mock_object(
            helpers, 'TaskWaiter', mock.Mock(
                return_value=mock_task_waiter))

        # Execute create_fileshare and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.create_fileshare,
            fe_create_fileshare,
            extra_specs
        )

        # Verify task completion check was called and raised exception
        self.handler.task.\
            _check_task_completion_status.assert_called_once_with(
                {'status': 'STATE_FAILED'},
                f"CREATE_FILESHARE {FE_CREATE_SHARE_ID}")

    def test_create_fileshare_missing_task_uri(self):
        """Fileshare create fail Task_uri is missing from response header."""
        # Configure frontend request with proper UUID
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {}

        # Mock the backend response without Task_uri
        be_response_header = {}
        be_response_body = {}

        # Configure mocks - don't mock convert and validate functions
        self.mock_rest_client.post.return_value = (
            be_response_header, be_response_body)

        # Exec create_fileshare and expect exception from natural validation
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.create_fileshare,
            fe_create_fileshare,
            extra_specs
        )

        # Verify task header validation would be called naturally (not mocked)

    def test_create_fileshare_conversion_success(self):
        """Test fileshare creation with natural conversion"""
        # Configure frontend request with proper UUID
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {}

        # Mock the backend response with realistic Task_uri format
        be_response_header = {
            'Task_uri': '/api/v3/tasks/06e45f0a78afaa2b9e5188a49f70d517'}
        be_response_body = {}

        # Mock the task waiter with STATE_FINISHED
        mock_task_waiter = mock.Mock()
        mock_task_waiter.wait_for_task.return_value = {
            'status': 'STATE_FINISHED'}

        # Configure mocks - let convert and validate run naturally (no mocking)
        self.mock_rest_client.post.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='06e45f0a78afaa2b9e5188a49f70d517')
        self.handler.task._check_task_completion_status = mock.Mock()
        self.mock_object(
            helpers, 'TaskWaiter', mock.Mock(
                return_value=mock_task_waiter))

        # Execute create_fileshare
        be_fileshare_name, be_filesystem_name, be_sharesetting_name = (
            self.handler.create_fileshare(fe_create_fileshare, extra_specs))

        # Verify the result is the encoded share name (natural encoding)
        self.assertTrue(be_fileshare_name.startswith(BE_FILESHARE_PREFIX))
        self.assertIsInstance(be_fileshare_name, str)
        # The exact encoded value depends on UUID encoding, just verify it's
        # properly formatted
        self.assertEqual(len(be_fileshare_name), BE_FILESHARE_NAME_LENGTH)
        self.assertTrue(be_filesystem_name.startswith(BE_FILESYSTEM_PREFIX))
        self.assertEqual(len(be_filesystem_name), BE_FILESYSTEM_NAME_LENGTH)
        self.assertTrue(
            be_sharesetting_name.startswith(BE_SHARESETTING_PREFIX))
        self.assertEqual(
            len(be_sharesetting_name), BE_SHARESETTING_NAME_LENGTH)

    # Validation tests
    def test_validate_create_fileshare_success(self):
        """Test successful validation of create fileshare request."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {}

        # Should not raise any exception
        self.handler.validator.validate_create_fileshare_fe_req(
            fe_create_fileshare, extra_specs)

    def test_validate_create_fileshare_missing_size(self):
        """Test validation failure when size is missing."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_create_fileshare_fe_req,
            fe_create_fileshare,
            extra_specs
        )

    def test_validate_create_fileshare_invalid_size_type(self):
        """Test validation failure when size is not an integer."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': '10'
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_create_fileshare_fe_req,
            fe_create_fileshare,
            extra_specs
        )

    def test_validate_create_fileshare_size_too_small(self):
        """Test validation failure when size is too small."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 0
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_create_fileshare_fe_req,
            fe_create_fileshare,
            extra_specs
        )

    def test_validate_create_fileshare_size_too_large(self):
        """Test validation failure when size is too large."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 70000  # > 65536 GB
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_create_fileshare_fe_req,
            fe_create_fileshare,
            extra_specs
        )

    def test_validate_create_fileshare_missing_id(self):
        """Test validation failure when id is missing."""
        fe_create_fileshare = {
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_create_fileshare_fe_req,
            fe_create_fileshare,
            extra_specs
        )

    def test_validate_create_fileshare_missing_name(self):
        """Test validation failure when name is missing."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'size': 10
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_create_fileshare_fe_req,
            fe_create_fileshare,
            extra_specs
        )

    def test_validate_create_fileshare_invalid_reduce(self):
        """Test validation failure when reduce has invalid value."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'invalid'}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_create_fileshare_fe_req,
            fe_create_fileshare,
            extra_specs
        )

    # Conversion tests
    def test_convert_fileshare_to_be_model(self):
        """Test conversion of fileshare to backend model."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {}

        result = self.handler.convert.convert_fileshare_to_be_model(
            fe_create_fileshare, extra_specs)

        # Verify the structure
        self.assertIn('batch', result)
        self.assertIn('ordered', result)
        self.assertIn('operations', result)
        self.assertEqual(3, len(result['operations']))

        # Check operation types
        operations = result['operations']
        self.assertEqual('CREATE_FILE_SHARE', operations[0]['action'])
        self.assertEqual('CREATE_FILE_SYSTEM', operations[1]['action'])
        self.assertEqual('CREATE_FILE_SHARE_SETTINGS', operations[2]['action'])

        # Check filesystem operation
        fs_params = operations[1]['parameters']
        self.assertIn('name', fs_params)
        self.assertIn('sizeInMiB', fs_params)
        self.assertIn('reduce', fs_params)
        self.assertTrue(fs_params['name'].startswith(BE_FILESYSTEM_PREFIX))
        self.assertEqual(fs_params['sizeInMiB'], 10 * 1024)  # 10 GB in MiB

        # Check sharesettings operation
        ss_params = operations[2]['parameters']
        self.assertIn('name', ss_params)
        self.assertIn('clientInfo', ss_params)
        self.assertTrue(ss_params['name'].startswith(BE_SHARESETTING_PREFIX))

        # Check fileshare operation
        fsh_params = operations[0]['parameters']
        self.assertIn('name', fsh_params)
        self.assertIn('filesystem', fsh_params)
        self.assertIn('filesharesetting', fsh_params)
        self.assertTrue(fsh_params['name'].startswith(BE_FILESHARE_PREFIX))
        self.assertTrue(
            fsh_params['filesystem'].startswith(BE_FILESYSTEM_PREFIX))
        self.assertTrue(
            fsh_params['filesharesetting'].startswith(BE_SHARESETTING_PREFIX))
        self.assertEqual(fsh_params['filesystem'], fs_params['name'])
        self.assertEqual(fsh_params['filesharesetting'], ss_params['name'])

    def test_convert_fileshare_to_be_model_reduce_true(self):
        """Test conversion with reduce set to true."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'true'}

        result = self.handler.convert.convert_fileshare_to_be_model(
            fe_create_fileshare, extra_specs)

        # Verify reduce is set to True in filesystem operation
        operations = result['operations']
        fs_params = operations[1]['parameters']
        self.assertTrue(fs_params['reduce'])

    def test_convert_fileshare_to_be_model_reduce_false(self):
        """Test conversion with reduce set to false."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'false'}

        result = self.handler.convert.convert_fileshare_to_be_model(
            fe_create_fileshare, extra_specs)

        # Verify reduce is set to False in filesystem operation
        operations = result['operations']
        fs_params = operations[1]['parameters']
        self.assertFalse(fs_params['reduce'])

    def test_convert_fileshare_to_be_model_reduce_derived_from_dedupe_true(
            self):
        """Test reduce derived from dedupe/compression when reduce not set."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        # When reduce is not specified but dedupe/compression are,
        # reduce should be derived from their value
        extra_specs = {'dedupe': 'true', 'compression': 'true'}

        result = self.handler.convert.convert_fileshare_to_be_model(
            fe_create_fileshare, extra_specs)

        # Verify reduce is set to True (derived from dedupe)
        operations = result['operations']
        fs_params = operations[1]['parameters']
        self.assertTrue(fs_params['reduce'])

    def test_convert_fileshare_to_be_model_reduce_derived_from_dedupe_false(
            self):
        """Test reduce derived from dedupe/compression=false when not set."""
        fe_create_fileshare = {
            'id': FE_CREATE_SHARE_ID,
            'name': FE_CREATE_SHARE_NAME,
            'size': 10
        }
        # When reduce is not specified but dedupe/compression=false,
        # reduce should be False
        extra_specs = {'dedupe': 'false', 'compression': 'false'}

        result = self.handler.convert.convert_fileshare_to_be_model(
            fe_create_fileshare, extra_specs)

        # Verify reduce is set to False (derived from dedupe)
        operations = result['operations']
        fs_params = operations[1]['parameters']
        self.assertFalse(fs_params['reduce'])


@ddt.ddt
class FileShareHandlerGetTestCase(test.TestCase):
    """Test case for FileShareHandler get methods."""

    def setUp(self):
        """Test Setup"""
        super(FileShareHandlerGetTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()

        # Initialize handler
        self.handler = fileshare.FileShareHandler(
            self.mock_rest_client
        )

    # get_fileshares()
    def test_get_fileshares_success(self):
        """Test successful get fileshare."""
        # Mock the backend response
        be_response = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_response)

        # Execute get_fileshare
        result = self.handler.get_fileshares()

        # Verify method calls
        self.mock_rest_client.get.assert_called_once_with('/fileshares')

        # Verify result
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        share = result[0]
        self.assertEqual(share['be_uid'], BE_FILESHARE_UID)
        self.assertEqual(
            share['be_fileshare_name'],
            BE_FILESHARE_NAME)
        self.assertEqual(share['host_ip'], BE_HOST_IP)
        self.assertEqual(
            share['mount_path'],
            BE_MOUNT_PATH)

    def test_get_fileshare_validation_failure(self):
        """Test get fileshare with invalid response."""
        # Mock the backend response without members
        be_response = {}

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_response)

        # Execute get_fileshare and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.get_fileshares
        )

    # get_fileshare_by_id()
    def test_get_fileshare_by_id_success(self):
        """Test successful get fileshare by id."""
        be_fileshare_uid = BE_FILESHARE_UID

        # Mock the backend response
        be_response = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_response)

        # Execute get_fileshare_by_id
        result = self.handler.get_fileshare_by_id(be_fileshare_uid)

        # Verify method calls
        expected_url = f'/fileshares/{BE_FILESHARE_UID}'
        self.mock_rest_client.get.assert_called_once_with(expected_url)

        # Verify result
        self.assertIsInstance(result, dict)
        self.assertEqual(result['be_uid'], BE_FILESHARE_UID)
        self.assertEqual(
            result['be_fileshare_name'],
            BE_FILESHARE_NAME)
        self.assertEqual(result['host_ip'], BE_HOST_IP)
        self.assertEqual(
            result['mount_path'],
            BE_MOUNT_PATH)

    def test_get_fileshare_by_id_validation_failure(self):
        """Test get fileshare by id with invalid response."""
        be_fileshare_uid = BE_FILESHARE_UID

        # Mock the backend response without uid
        be_response = {}

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_response)

        # Execute get_fileshare_by_id and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.get_fileshare_by_id,
            be_fileshare_uid
        )

    # Validation tests for get methods
    def test_validate_get_fileshares_be_resp_success(self):
        """Test successful validation of get fileshares backend response."""
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Should not raise any exception
        self.handler.validator.validate_get_fileshares_be_resp(be_fileshares)

    def test_validate_get_fileshares_be_resp_failure_no_members(self):
        """Test validation failure when members key is missing."""
        be_fileshares = {}

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.validate_get_fileshares_be_resp,
            be_fileshares
        )

    def test_validate_get_fileshares_be_resp_failure_none(self):
        """Test validation failure when response is None."""
        be_fileshares = None

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.validate_get_fileshares_be_resp,
            be_fileshares
        )

    def test_validate_get_fileshares_be_resp_failure_invalid_member(self):
        """Test validation failure when a member fails validation."""
        be_fileshares = {
            'members': {
                'share1': {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_VALID_FILESHARE_NAME,
                    'filesystem': {'name': BE_VALID_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_VALID_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_VALID_MOUNT_PATH
                },
                'share2': {
                    # Missing required 'uid' field to trigger validation error
                    'name': BE_INVALID_FILESHARE_NAME,
                    'filesystem': {'name': BE_INVALID_FILESYSTEM_NAME}
                }
            }
        }

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.validate_get_fileshares_be_resp,
            be_fileshares
        )

    def test_validate_get_fileshare_by_id_be_resp_success(self):
        """Successful validation of get fileshare by id backend response."""
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        # Should not raise any exception
        self.handler.validator.validate_get_fileshare_by_id_be_resp(
            be_fileshare)

    def test_validate_get_fileshare_by_id_be_resp_failure_no_uid(self):
        """Test validation failure when uid is missing."""
        be_fileshare = {
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.
            validate_get_fileshare_by_id_be_resp,
            be_fileshare
        )

    def test_validate_get_fileshare_by_id_be_resp_failure_none(self):
        """Test validation failure when fileshare is None."""
        be_fileshare = None

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.
            validate_get_fileshare_by_id_be_resp,
            be_fileshare
        )

    def test_validate_get_fileshare_by_id_be_resp_failure_no_name(self):
        """Test validation failure when name is missing."""
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.
            validate_get_fileshare_by_id_be_resp,
            be_fileshare
        )

    def test_validate_get_fileshare_by_id_be_resp_failure_no_filesystem(self):
        """Test validation failure when filesystem object is missing."""
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.
            validate_get_fileshare_by_id_be_resp,
            be_fileshare
        )

    def test_validate_get_fileshare_by_id_be_resp_failure_no_filesystem_name(
            self):
        """Test validation failure when filesystem name is missing."""
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.
            validate_get_fileshare_by_id_be_resp,
            be_fileshare
        )

    def test_validate_get_fileshare_by_id_be_resp_failure_no_sharesettings(
            self):
        """Test validation failure when sharesettings object is missing."""
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.
            validate_get_fileshare_by_id_be_resp,
            be_fileshare
        )

    def test_validate_get_fileshare_by_id_be_rsp_fail_no_sharesettings_name(
            self):
        """Test validation failure when sharesettings name is missing."""
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.
            validate_get_fileshare_by_id_be_resp,
            be_fileshare
        )

    def test_validate_get_fileshare_by_id_be_resp_failure_no_hostip(self):
        """Test validation failure when hostip is missing."""
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'mountpath': BE_MOUNT_PATH
        }

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.
            validate_get_fileshare_by_id_be_resp,
            be_fileshare
        )

    def test_validate_get_fileshare_by_id_be_resp_failure_no_mountpath(self):
        """Test validation failure when mountpath is missing."""
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP
        }

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.
            validate_get_fileshare_by_id_be_resp,
            be_fileshare
        )

    # Conversion tests for get methods
    def test_convert_fileshares_to_fe_model(self):
        """Test conversion of fileshares backend response to fe model"""
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        result = self.handler.convert.convert_fileshares_to_fe_model(
            be_fileshares)

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        share = result[0]
        self.assertEqual(share['be_uid'], BE_FILESHARE_UID)
        self.assertEqual(
            share['be_fileshare_name'],
            BE_FILESHARE_NAME)
        self.assertEqual(
            share['be_filesystem_name'],
            BE_FILESYSTEM_NAME)
        self.assertEqual(
            share['be_sharesetting_name'],
            BE_SHARESETTING_NAME)
        self.assertEqual(share['host_ip'], BE_HOST_IP)
        self.assertEqual(
            share['mount_path'],
            BE_MOUNT_PATH)

    def test_convert_fileshare_by_id_to_fe_model(self):
        """Test conversion of fileshare by id backend response to fe model."""
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        result = self.handler.convert.convert_fileshare_by_id_to_fe_model(
            be_fileshare)

        self.assertIsInstance(result, dict)
        self.assertEqual(result['be_uid'], BE_FILESHARE_UID)
        self.assertEqual(
            result['be_fileshare_name'],
            BE_FILESHARE_NAME)
        self.assertEqual(
            result['be_filesystem_name'],
            BE_FILESYSTEM_NAME)
        self.assertEqual(
            result['be_sharesetting_name'],
            BE_SHARESETTING_NAME)
        self.assertEqual(result['host_ip'], BE_HOST_IP)
        self.assertEqual(
            result['mount_path'],
            BE_MOUNT_PATH)


@ddt.ddt
class FileShareHandlerDeleteTestCase(test.TestCase):
    """Test case for FileShareHandler delete_fileshare_by_id method."""

    def setUp(self):
        """Test Setup"""
        super(FileShareHandlerDeleteTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()

        # Initialize handler
        self.handler = fileshare.FileShareHandler(
            self.mock_rest_client
        )

    # delete_fileshare_by_id()
    def test_delete_fileshare_by_id_success(self):
        """Test successful fileshare deletion by id."""
        fe_fileshare_id = 'abcd5678-e29b-41d4-a716-446655441000'
        be_fileshare_uid = '12345678e29b41d4a716446655442000'

        # Mock the backend response with realistic Task_uri format
        be_response_header = {
            'Task_uri': '/api/v3/tasks/06e45f0a78afaa2b9e5188a49f70d517'}
        be_response_body = {}

        # Mock the task waiter with STATE_FINISHED
        mock_task_waiter = mock.Mock()
        mock_task_waiter.wait_for_task.return_value = {
            'status': 'STATE_FINISHED'}

        # Configure mocks
        self.mock_rest_client.delete.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='06e45f0a78afaa2b9e5188a49f70d517')
        self.handler.task._check_task_completion_status = mock.Mock()
        self.mock_object(
            helpers, 'TaskWaiter', mock.Mock(
                return_value=mock_task_waiter))

        # Execute delete_fileshare_by_id
        result = self.handler.delete_fileshare_by_id(
            fe_fileshare_id, be_fileshare_uid)

        # Verify method calls
        expected_url = '/fileshares/12345678e29b41d4a716446655442000'
        self.mock_rest_client.delete.assert_called_once_with(expected_url)
        self.handler.task.\
            _extract_task_id_from_header.assert_called_once_with(
                be_response_header)
        mock_task_waiter.wait_for_task.assert_called_once()
        self.handler.task.\
            _check_task_completion_status.assert_called_once_with(
                {'status': 'STATE_FINISHED'}, "DELETE_FILESHARE "
                "12345678e29b41d4a716446655442000")

        # Verify result - delete typically returns None or the uid
        self.assertIsNone(result)

    def test_delete_fileshare_by_id_task_failure(self):
        """Test fileshare deletion failure during task execution."""
        fe_fileshare_id = 'abcd5678-e29b-41d4-a716-446655441000'
        be_fileshare_uid = '12345678e29b41d4a716446655442000'

        # Mock the backend response with realistic Task_uri format
        be_response_header = {
            'Task_uri': '/api/v3/tasks/06e45f0a78afaa2b9e5188a49f70d517'}
        be_response_body = {}

        # Mock the task waiter to return failed status
        mock_task_waiter = mock.Mock()
        mock_task_waiter.wait_for_task.return_value = {
            'status': 'STATE_FAILED'}

        # Configure mocks
        self.mock_rest_client.delete.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='06e45f0a78afaa2b9e5188a49f70d517')
        self.handler.task._check_task_completion_status = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                "Task failed"))
        self.mock_object(
            helpers, 'TaskWaiter', mock.Mock(
                return_value=mock_task_waiter))

        # Execute delete_fileshare_by_id and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.delete_fileshare_by_id,
            fe_fileshare_id,
            be_fileshare_uid
        )

        # Verify task completion check was called and raised exception
        self.handler.task.\
            _check_task_completion_status.assert_called_once_with(
                {'status': 'STATE_FAILED'}, "DELETE_FILESHARE "
                "12345678e29b41d4a716446655442000")

    def test_delete_fileshare_by_id_missing_task_uri(self):
        """Test fileshare deletion failure Task_uri missing in resp header."""
        fe_fileshare_id = 'abcd5678-e29b-41d4-a716-446655441000'
        be_fileshare_uid = '12345678e29b41d4a716446655442000'

        # Mock the backend response without Task_uri
        be_response_header = {}
        be_response_body = {}

        # Configure mocks
        self.mock_rest_client.delete.return_value = (
            be_response_header, be_response_body)

        # Execute delete_fileshare_by_id and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.delete_fileshare_by_id,
            fe_fileshare_id,
            be_fileshare_uid
        )


@ddt.ddt
class FileShareHandlerEditTestCase(test.TestCase):
    """Test case for FileShareHandler edit_fileshare_by_id method."""

    def setUp(self):
        """Test Setup"""
        super(FileShareHandlerEditTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()

        # Initialize handler
        self.handler = fileshare.FileShareHandler(
            self.mock_rest_client
        )

    # edit_fileshare_by_id()
    def test_edit_fileshare_by_id_expand_filesystem_success(self):
        """Test successful fileshare edit with filesystem expansion."""
        fe_fileshare_id = 'abcd5678-e29b-41d4-a716-446655441000'
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        be_filesystem_name = BE_FILESYSTEM_NAME
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 20
        update_access_rules = False
        fe_new_access_rules = None

        # Mock the backend response with realistic Task_uri format
        be_response_header = mock.Mock()
        be_response_header.status = 200
        be_response_header.__getitem__ = mock.Mock(
            return_value='/api/v3/tasks/06e45f0a78afaa2b9e5188a49f70d517')
        be_response_header.__contains__ = mock.Mock(return_value=True)
        be_response_body = {}

        # Mock the task waiter with STATE_FINISHED
        mock_task_waiter = mock.Mock()
        mock_task_waiter.wait_for_task.return_value = {
            'status': 'STATE_FINISHED'}

        # Mock filesystem handler response
        fe_filesystem = {'be_filesystem_size': 10 * 1024}  # 10 GB in MiB
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            return_value=fe_filesystem)

        # Configure mocks
        self.mock_rest_client.post.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='06e45f0a78afaa2b9e5188a49f70d517')
        self.handler.task._check_task_completion_status = mock.Mock()
        self.mock_object(
            helpers, 'TaskWaiter', mock.Mock(
                return_value=mock_task_waiter))

        # Execute edit_fileshare_by_id
        result = self.handler.edit_fileshare_by_id(
            fe_fileshare_id, be_fileshare_uid, be_filesystem_name,
            extra_specs, expand_filesystem, fe_existing_size, fe_new_size,
            update_access_rules, fe_new_access_rules)

        # Verify method calls
        self.mock_rest_client.post.assert_called_once()
        post_call_args = self.mock_rest_client.post.call_args
        self.assertEqual('/fileshares', post_call_args[0][0])  # URL
        self.handler.task.\
            _extract_task_id_from_header.assert_called_once_with(
                be_response_header)
        mock_task_waiter.wait_for_task.assert_called_once()
        self.handler.task.\
            _check_task_completion_status.assert_called_once_with(
                {'status': 'STATE_FINISHED'}, "EDIT_FILESHARE "
                "12345678e29b41d4a716446655442000")

        # Verify result - edit typically returns None
        self.assertIsNone(result)

    def test_edit_fileshare_by_id_update_access_rules_success(self):
        """Test successful fileshare edit with access rules update."""
        fe_fileshare_id = 'abcd5678-e29b-41d4-a716-446655441000'
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        be_filesystem_name = BE_FILESYSTEM_NAME
        extra_specs = {'hpe_alletra_b10000:squash_option': 'root_squash'}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '192.168.1.0/24',
             'access_level': 'rw'}
        ]

        # Mock the backend response with realistic Task_uri format
        be_response_header = mock.Mock()
        be_response_header.status = 200
        be_response_header.__getitem__ = mock.Mock(
            return_value='/api/v3/tasks/06e45f0a78afaa2b9e5188a49f70d517')
        be_response_header.__contains__ = mock.Mock(return_value=True)
        be_response_body = {}

        # Mock the task waiter with STATE_FINISHED
        mock_task_waiter = mock.Mock()
        mock_task_waiter.wait_for_task.return_value = {
            'status': 'STATE_FINISHED'}

        # Configure mocks
        self.mock_rest_client.post.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='06e45f0a78afaa2b9e5188a49f70d517')
        self.handler.task._check_task_completion_status = mock.Mock()
        self.mock_object(
            helpers, 'TaskWaiter', mock.Mock(
                return_value=mock_task_waiter))

        # Execute edit_fileshare_by_id
        result = self.handler.edit_fileshare_by_id(
            fe_fileshare_id, be_fileshare_uid, be_filesystem_name,
            extra_specs, expand_filesystem, fe_existing_size, fe_new_size,
            update_access_rules, fe_new_access_rules)

        # Verify method calls
        self.mock_rest_client.post.assert_called_once()
        post_call_args = self.mock_rest_client.post.call_args
        self.assertEqual('/fileshares', post_call_args[0][0])  # URL
        batch_body = post_call_args[1]['body']  # body parameter
        self.assertIn('uuid', batch_body)
        self.assertEqual(batch_body['uuid'], be_fileshare_uid)

        # Verify result
        self.assertIsNone(result)

    def test_edit_fileshare_by_id_same_access_rules(self):
        """Test fileshare edit with same access rules (no-op scenario)."""
        fe_fileshare_id = 'abcd5678-e29b-41d4-a716-446655441000'
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        be_filesystem_name = BE_FILESYSTEM_NAME
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip',
             'access_to': '192.168.1.0/24', 'access_level': 'rw'}
        ]

        # Mock the backend response with status 200 (no Task_uri header)
        # This happens when the same access rules are sent again
        be_response_header = mock.Mock()
        be_response_header.status = 200
        be_response_header.__contains__ = mock.Mock(return_value=False)
        be_response_body = {}

        # Configure mocks - task check raises exception
        self.mock_rest_client.post.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock()
        self.handler.task._check_task_completion_status = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                "No task to check"))

        # Execute edit_fileshare_by_id - should not raise exception
        # because status is 200 (synchronous completion)
        result = self.handler.edit_fileshare_by_id(
            fe_fileshare_id, be_fileshare_uid, be_filesystem_name,
            extra_specs, expand_filesystem, fe_existing_size, fe_new_size,
            update_access_rules, fe_new_access_rules)

        # Verify result - edit typically returns None
        self.assertIsNone(result)

        # Verify rest client post was called
        self.mock_rest_client.post.assert_called_once()

    def test_edit_fileshare_by_id_task_failure(self):
        """Test fileshare edit failure during task execution."""
        fe_fileshare_id = 'abcd5678-e29b-41d4-a716-446655441000'
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        be_filesystem_name = BE_FILESYSTEM_NAME
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip',
             'access_to': '192.168.1.0/24', 'access_level': 'rw'}
        ]

        # Mock the backend response with realistic Task_uri format
        be_response_header = mock.Mock()
        be_response_header.status = 400
        be_response_header.__getitem__ = mock.Mock(
            return_value='/api/v3/tasks/06e45f0a78afaa2b9e5188a49f70d517')
        be_response_header.__contains__ = mock.Mock(return_value=True)
        be_response_body = {}

        # Mock the task waiter to return failed status
        mock_task_waiter = mock.Mock()
        mock_task_waiter.wait_for_task.return_value = {
            'status': 'STATE_FAILED'}

        # Configure mocks
        self.mock_rest_client.post.return_value = (
            be_response_header, be_response_body)
        self.handler.task._extract_task_id_from_header = mock.Mock(
            return_value='06e45f0a78afaa2b9e5188a49f70d517')
        self.handler.task._check_task_completion_status = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                "Task failed"))
        self.mock_object(
            helpers, 'TaskWaiter', mock.Mock(
                return_value=mock_task_waiter))

        # Execute edit_fileshare_by_id and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.edit_fileshare_by_id,
            fe_fileshare_id, be_fileshare_uid, be_filesystem_name,
            extra_specs, expand_filesystem, fe_existing_size, fe_new_size,
            update_access_rules, fe_new_access_rules)

        # Verify task completion check was called and raised exception
        self.handler.task.\
            _check_task_completion_status.assert_called_once_with(
                {'status': 'STATE_FAILED'}, "EDIT_FILESHARE"
                " 12345678e29b41d4a716446655442000")

    def test_edit_fileshare_by_id_filesystem_get_failure(self):
        """Test fileshare edit failure when getting filesystem fails."""
        fe_fileshare_id = 'abcd5678-e29b-41d4a716-446655441000'
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        be_filesystem_name = BE_FILESYSTEM_NAME
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 20
        update_access_rules = False
        fe_new_access_rules = None

        # Mock filesystem handler to raise exception
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                "Filesystem not found"))

        # Execute edit_fileshare_by_id and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.edit_fileshare_by_id,
            fe_fileshare_id, be_fileshare_uid, be_filesystem_name,
            extra_specs, expand_filesystem, fe_existing_size, fe_new_size,
            update_access_rules, fe_new_access_rules)

        # Verify filesystem handler was called
        self.handler.filesystem_handler.\
            _get_filesystem_by_name.assert_called_once_with(
                be_filesystem_name)

    def test_edit_fileshare_by_id_validation_failure(self):
        """Test fileshare edit failure during validation."""
        fe_fileshare_id = 'abcd5678-e29b-41d4-a716-446655441000'
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        be_filesystem_name = BE_FILESYSTEM_NAME
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = False
        fe_new_access_rules = None

        # Execute edit_fileshare_by_id and expect exception (no expand, no
        # rules)
        self.assertRaises(
            exception.InvalidInput,
            self.handler.edit_fileshare_by_id,
            fe_fileshare_id, be_fileshare_uid, be_filesystem_name,
            extra_specs, expand_filesystem, fe_existing_size, fe_new_size,
            update_access_rules, fe_new_access_rules)

    # Validation tests
    def test_validate_edit_fileshare_fe_req_empty_fileshare_uid(self):
        """Test validation failure when be_fileshare_uid is None."""
        be_fileshare_uid = None
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 20
        be_existing_filesystem_size = 10240
        update_access_rules = False
        fe_new_access_rules = []

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_no_operation_selected(self):
        """Validation fail neither expand nor update_access_rules is True."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        be_existing_filesystem_size = 10240
        update_access_rules = False
        fe_new_access_rules = None

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_empty_existing_size(self):
        """Test validation failure when fe_existing_size is None."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = None
        fe_new_size = 20
        be_existing_filesystem_size = 10240
        update_access_rules = False
        fe_new_access_rules = []

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_empty_new_size(self):
        """Test validation failure when fe_new_size is None."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = None
        be_existing_filesystem_size = 10240
        update_access_rules = False
        fe_new_access_rules = []

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_empty_be_existing_size(self):
        """Validation failure when be_existing_filesystem_size is None."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 20
        be_existing_filesystem_size = None
        update_access_rules = False
        fe_new_access_rules = []

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_size_mismatch(self):
        """Validation failure when FE and BE existing sizes don't match."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 20
        be_existing_filesystem_size = 20480
        update_access_rules = False
        fe_new_access_rules = []

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_new_size_not_greater(self):
        """Validation failure new size is not greater than existing size."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 20
        fe_new_size = 20
        be_existing_filesystem_size = 20480
        update_access_rules = False
        fe_new_access_rules = []

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_expand_too_small(self):
        """Test validation failure when expand size is less than 256 MB."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 10.1  # Only 102.4 MB increase (< 256 MB minimum)
        be_existing_filesystem_size = 10240
        update_access_rules = False
        fe_new_access_rules = []

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_new_size_exceeds_max(self):
        """Test validation failure when new size exceeds 64 TB limit."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 65537  # Exceeds 64 TB (65536 GB) limit
        be_existing_filesystem_size = 10240
        update_access_rules = False
        fe_new_access_rules = []

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_unsupported_access_type(self):
        """Test validation failure when access rule type is not 'ip'."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        be_existing_filesystem_size = 10240
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'user',
             'access_to': 'testuser', 'access_level': 'rw'}
        ]

        self.assertRaises(
            exception.OperationNotSupportedByDriverMode,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_invalid_squash_option(self):
        """Test validation failure when squash_option is invalid."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {'hpe_alletra_b10000:squash_option': 'invalid_squash'}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        be_existing_filesystem_size = 10240
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip',
             'access_to': '10.0.0.1', 'access_level': 'rw'}
        ]

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_edit_fileshare_fe_req,
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_expand_filesystem_success(self):
        """Test successful validation for expand filesystem."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 20
        be_existing_filesystem_size = 10240
        update_access_rules = False
        fe_new_access_rules = None

        # Should not raise any exception
        self.handler.validator.validate_edit_fileshare_fe_req(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_update_access_rules_success(self):
        """Test successful validation for update access rules."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {'hpe_alletra_b10000:squash_option': 'root_squash'}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        be_existing_filesystem_size = 10240
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip',
             'access_to': '10.0.0.1', 'access_level': 'rw'},
            {'access_type': 'ip',
             'access_to': '10.0.0.2/24', 'access_level': 'ro'}
        ]

        # Should not raise any exception
        self.handler.validator.validate_edit_fileshare_fe_req(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    def test_validate_edit_fileshare_fe_req_both_operations_success(self):
        """Successful validation for both expand and update access rules."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {'hpe_alletra_b10000:squash_option': 'no_root_squash'}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 20
        be_existing_filesystem_size = 10240
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '10.0.0.1',
             'access_level': 'rw'}
        ]

        # Should not raise any exception
        self.handler.validator.validate_edit_fileshare_fe_req(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, be_existing_filesystem_size,
            update_access_rules, fe_new_access_rules)

    # Conversion tests
    def test_convert_edit_fileshare_to_be_model_expand_filesystem_only(self):
        """Test conversion for expand filesystem operation only."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 20
        update_access_rules = False
        fe_new_access_rules = None

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify structure
        self.assertEqual(result['batch'], 'MODIFY_COMPLEX_FILE_SHARE')
        self.assertEqual(result['ordered'], True)
        self.assertEqual(result['uuid'], be_fileshare_uid)
        self.assertEqual(len(result['operations']), 1)

        # Verify expand filesystem operation
        expand_op = result['operations'][0]
        self.assertEqual(expand_op['action'], 'MODIFY_FILE_SYSTEM')
        self.assertEqual(
            expand_op['parameters']['sizeInMiB'],
            10240)  # (20-10) * 1024

    def test_convert_edit_fileshare_to_be_model_update_access_rules_only(
            self):
        """Test conversion for update access rules operation only."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '10.0.0.1',
             'access_level': 'rw'},
            {'access_type': 'ip', 'access_to': '10.0.0.2/24',
             'access_level': 'ro'}
        ]

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify structure
        self.assertEqual(result['batch'], 'MODIFY_COMPLEX_FILE_SHARE')
        self.assertEqual(result['ordered'], True)
        self.assertEqual(result['uuid'], be_fileshare_uid)
        self.assertEqual(len(result['operations']), 1)

        # Verify update access rules operation
        update_op = result['operations'][0]
        self.assertEqual(update_op['action'], 'MODIFY_FILE_SHARE_SETTINGS')
        self.assertEqual(len(update_op['parameters']['clientInfo']), 2)

        # Verify first client info
        client1 = update_op['parameters']['clientInfo'][0]
        self.assertEqual(client1['ipaddress'], '10.0.0.1')
        self.assertEqual(client1['access'], 'rw')
        self.assertEqual(client1['options'], 'root_squash')

        # Verify second client info
        client2 = update_op['parameters']['clientInfo'][1]
        self.assertEqual(client2['ipaddress'], '10.0.0.2/24')
        self.assertEqual(client2['access'], 'ro')
        self.assertEqual(client2['options'], 'root_squash')

    def test_convert_edit_fileshare_to_be_model_both_operations(self):
        """Conversion for both expand and update access rules operations."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {'hpe_alletra_b10000:squash_option': 'no_root_squash'}
        expand_filesystem = True
        fe_existing_size = 10
        fe_new_size = 25
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '10.0.0.1',
             'access_level': 'rw'}
        ]

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify structure
        self.assertEqual(result['batch'], 'MODIFY_COMPLEX_FILE_SHARE')
        self.assertEqual(result['ordered'], True)
        self.assertEqual(result['uuid'], be_fileshare_uid)
        self.assertEqual(len(result['operations']), 2)

        # Verify expand filesystem operation (should be first)
        expand_op = result['operations'][0]
        self.assertEqual(expand_op['action'], 'MODIFY_FILE_SYSTEM')
        self.assertEqual(
            expand_op['parameters']['sizeInMiB'],
            15360)  # (25-10) * 1024

        # Verify update access rules operation (should be second)
        update_op = result['operations'][1]
        self.assertEqual(update_op['action'], 'MODIFY_FILE_SHARE_SETTINGS')
        self.assertEqual(len(update_op['parameters']['clientInfo']), 1)

        # Verify client info with custom squash option
        client = update_op['parameters']['clientInfo'][0]
        self.assertEqual(client['ipaddress'], '10.0.0.1')
        self.assertEqual(client['access'], 'rw')
        self.assertEqual(client['options'], 'no_root_squash')

    def test_convert_edit_fileshare_to_be_model_wildcard_ip_conversion(self):
        """Test conversion of 0.0.0.0/0 to * for backend."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '0.0.0.0/0',
             'access_level': 'rw'}
        ]

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify wildcard conversion
        update_op = result['operations'][0]
        client = update_op['parameters']['clientInfo'][0]
        self.assertEqual(client['ipaddress'], '*')

    def test_convert_edit_fileshare_to_be_model_wildcard_ip_00_conversion(
            self):
        """Test conversion of 0.0.0.0/00 to * for backend."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '0.0.0.0/00',
             'access_level': 'ro'}
        ]

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify wildcard conversion
        update_op = result['operations'][0]
        client = update_op['parameters']['clientInfo'][0]
        self.assertEqual(client['ipaddress'], '*')
        self.assertEqual(client['access'], 'ro')

    def test_convert_edit_fileshare_to_be_model_all_squash_option(self):
        """Test conversion with all_squash option."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {'hpe_alletra_b10000:squash_option': 'all_squash'}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '192.168.1.0/24',
             'access_level': 'rw'}
        ]

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify all_squash option
        update_op = result['operations'][0]
        client = update_op['parameters']['clientInfo'][0]
        self.assertEqual(client['options'], 'all_squash')

    def test_convert_edit_fileshare_to_be_model_mixed_case_squash(self):
        """Test conv normalizes mixed case squash option to lowercase."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {'hpe_alletra_b10000:squash_option': 'Root_Squash'}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '192.168.1.0/24',
             'access_level': 'rw'}
        ]

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify squash option is converted to lowercase
        update_op = result['operations'][0]
        client = update_op['parameters']['clientInfo'][0]
        self.assertEqual(client['options'], 'root_squash')

    def test_convert_edit_fileshare_to_be_model_multiple_access_rules(self):
        """Test conversion with multiple access rules."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '10.0.0.1',
             'access_level': 'rw'},
            {'access_type': 'ip', 'access_to': '10.0.0.2',
             'access_level': 'ro'},
            {'access_type': 'ip', 'access_to': '192.168.1.0/24',
             'access_level': 'rw'},
            {'access_type': 'ip', 'access_to': '0.0.0.0/0',
             'access_level': 'ro'}
        ]

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify all access rules converted
        update_op = result['operations'][0]
        clients = update_op['parameters']['clientInfo']
        self.assertEqual(len(clients), 4)

        # Verify each rule
        self.assertEqual(clients[0]['ipaddress'], '10.0.0.1')
        self.assertEqual(clients[0]['access'], 'rw')
        self.assertEqual(clients[1]['ipaddress'], '10.0.0.2')
        self.assertEqual(clients[1]['access'], 'ro')
        self.assertEqual(clients[2]['ipaddress'], '192.168.1.0/24')
        self.assertEqual(clients[2]['access'], 'rw')
        self.assertEqual(clients[3]['ipaddress'], '*')
        self.assertEqual(clients[3]['access'], 'ro')

    def test_convert_edit_fileshare_to_be_model_empty_access_rules(self):
        """Test conversion with empty access rules defaults to secure rule."""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = []  # Empty list

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify default secure rule is applied
        update_op = result['operations'][0]
        clients = update_op['parameters']['clientInfo']
        self.assertEqual(len(clients), 1)

        # Verify default rule: 0.0.0.0 with ro access and root_squash
        self.assertEqual(clients[0]['ipaddress'], '0.0.0.0')
        self.assertEqual(clients[0]['access'], 'ro')
        self.assertEqual(clients[0]['options'], 'root_squash')

    def test_convert_edit_fileshare_to_be_model_non_ip_access_type_skipped(
            self):
        """Test conversion skips non-ip access types"""
        be_fileshare_uid = '12345678e29b41d4a716446655442000'
        extra_specs = {}
        expand_filesystem = False
        fe_existing_size = None
        fe_new_size = None
        update_access_rules = True
        fe_new_access_rules = [
            {'access_type': 'ip', 'access_to': '10.0.0.1',
             'access_level': 'rw'},
            {'access_type': 'user', 'access_to': 'testuser',
             'access_level': 'rw'},
            {'access_type': 'ip', 'access_to': '10.0.0.2',
             'access_level': 'ro'},
            {'access_type': 'cert', 'access_to': 'certname',
             'access_level': 'rw'}
        ]

        result = self.handler.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid, extra_specs, expand_filesystem,
            fe_existing_size, fe_new_size, update_access_rules,
            fe_new_access_rules)

        # Verify only ip type access rules are included
        update_op = result['operations'][0]
        clients = update_op['parameters']['clientInfo']

        # Should only have 2 rules (the ip types), non-ip types are skipped
        self.assertEqual(len(clients), 2)

        # Verify first ip rule
        self.assertEqual(clients[0]['ipaddress'], '10.0.0.1')
        self.assertEqual(clients[0]['access'], 'rw')
        self.assertEqual(clients[0]['options'], 'root_squash')

        # Verify second ip rule
        self.assertEqual(clients[1]['ipaddress'], '10.0.0.2')
        self.assertEqual(clients[1]['access'], 'ro')
        self.assertEqual(clients[1]['options'], 'root_squash')


@ddt.ddt
class FileShareHandlerManageTestCase(test.TestCase):
    """Test case for FileShareHandler manage_fileshare method."""

    def setUp(self):
        """Test Setup"""
        super(FileShareHandlerManageTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()

        # Initialize handler
        self.handler = fileshare.FileShareHandler(
            self.mock_rest_client
        )

    # manage_fileshare()
    def test_manage_fileshare_success(self):
        """Test successful fileshare management."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'false'}

        # Mock get_fileshare response
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Mock filesystem response
        fe_filesystem = {
            'be_filesystem_size': 10240,  # 10 GB in MiB
            'be_filesystem_reduce': False
        }

        # Mock filesharesetting response
        fe_filesharesetting = {
            'be_filesharesetting_clientinfo': None
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)
        self.handler.filesystem_handler.\
            _get_filesystem_by_name = mock.Mock(
                return_value=fe_filesystem)
        self.handler.filesharesetting_handler.\
            _get_filesharesetting_by_name = mock.Mock(
                return_value=fe_filesharesetting)
        self.handler.edit_fileshare_by_id = mock.Mock()

        # Execute manage_fileshare
        result_fileshare, result_size = self.handler.manage_fileshare(
            fe_manage_fileshare, extra_specs)

        # Verify method calls
        self.mock_rest_client.get.assert_called_once_with('/fileshares')
        self.handler.filesystem_handler.\
            _get_filesystem_by_name.assert_called_once_with(
                BE_FILESYSTEM_NAME)
        self.handler.filesharesetting_handler.\
            _get_filesharesetting_by_name.assert_called_once_with(
                BE_SHARESETTING_NAME)

        # Verify edit_fileshare_by_id was called to reset access rules
        self.handler.edit_fileshare_by_id.assert_called_once_with(
            FE_MANAGE_SHARE_ID,
            BE_FILESHARE_UID,
            BE_FILESYSTEM_NAME,
            extra_specs,
            False,
            None,
            None,
            True,
            [])

        # Verify result
        self.assertIsInstance(result_fileshare, dict)
        self.assertEqual(
            result_fileshare['be_uid'],
            BE_FILESHARE_UID)
        self.assertEqual(
            result_fileshare['be_fileshare_name'],
            BE_FILESHARE_NAME)
        self.assertEqual(result_size, 10240)

    def test_manage_fileshare_edit_access_rules_fails(self):
        """Test manage succeeds even if resetting access rules fails."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'false'}

        # Mock get_fileshare response
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Mock filesystem response
        fe_filesystem = {
            'be_filesystem_size': 10240,
            'be_filesystem_reduce': False
        }

        # Mock filesharesetting response
        fe_filesharesetting = {
            'be_filesharesetting_clientinfo': None
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)
        self.handler.filesystem_handler.\
            _get_filesystem_by_name = mock.Mock(
                return_value=fe_filesystem)
        self.handler.filesharesetting_handler.\
            _get_filesharesetting_by_name = mock.Mock(
                return_value=fe_filesharesetting)
        # Mock edit_fileshare_by_id to raise an exception
        self.handler.edit_fileshare_by_id = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                "Failed to reset access rules"))

        # Execute manage_fileshare - should succeed despite exception
        with mock.patch('manila.share.drivers.hpe.alletra_mp_b10000.'
                        'fileshare.fileshare_handler.LOG') as mock_log:
            result_fileshare, result_size = self.handler.manage_fileshare(
                fe_manage_fileshare, extra_specs)

            # Verify warning was logged
            mock_log.warning.assert_called_once()
            warning_msg = mock_log.warning.call_args[0][0]
            self.assertIn('Failed to reset access rules', warning_msg)
            warning_context = mock_log.warning.call_args[0][1]
            self.assertEqual(warning_context['share_id'], FE_MANAGE_SHARE_ID)
            self.assertIn('Failed to reset access rules',
                          str(warning_context['error']))

        # Verify edit_fileshare_by_id was called
        self.handler.edit_fileshare_by_id.assert_called_once_with(
            FE_MANAGE_SHARE_ID,
            BE_FILESHARE_UID,
            BE_FILESYSTEM_NAME,
            extra_specs,
            False,
            None,
            None,
            True,
            [])

        # Verify result - manage should still succeed
        self.assertIsInstance(result_fileshare, dict)
        self.assertEqual(
            result_fileshare['be_uid'],
            BE_FILESHARE_UID)
        self.assertEqual(
            result_fileshare['be_fileshare_name'],
            BE_FILESHARE_NAME)
        self.assertEqual(result_size, 10240)

    def test_manage_fileshare_fileshare_not_found(self):
        """Manage fileshare fail fileshare not found by hostip/mountpath."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MISSING_MOUNT_PATH}'}
            ]
        }
        extra_specs = {}

        # Mock get_fileshare response with no matching share
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)

        # Execute manage_fileshare and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_fileshare,
            fe_manage_fileshare,
            extra_specs
        )

    def test_manage_fileshare_filesystem_not_found(self):
        """Test manage fileshare failure when filesystem not found."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {}

        # Mock get_fileshare response
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            side_effect=exception.HPEAlletraB10000DriverException(
                "Filesystem not found"))

        # Execute manage_fileshare and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_fileshare,
            fe_manage_fileshare,
            extra_specs
        )

    def test_manage_fileshare_sharesetting_not_found(self):
        """Test manage fileshare failure when filesharesetting not found."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {}

        # Mock get_fileshare response
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Mock filesystem response
        fe_filesystem = {
            'be_filesystem_size': 10240,
            'be_filesystem_reduce': False
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)
        self.handler.filesystem_handler.\
            _get_filesystem_by_name = mock.Mock(
                return_value=fe_filesystem)
        self.handler.filesharesetting_handler.\
            _get_filesharesetting_by_name = mock.Mock(
                side_effect=exception.HPEAlletraB10000DriverException(
                    "Filesharesetting not found"))

        # Execute manage_fileshare and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_fileshare,
            fe_manage_fileshare,
            extra_specs
        )

    def test_manage_fileshare_reduce_mismatch(self):
        """Manage fileshare failure when reduce parameter doesn't match."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'false'}

        # Mock get_fileshare response
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Mock filesystem response with reduce=True
        fe_filesystem = {
            'be_filesystem_size': 10240,
            'be_filesystem_reduce': True
        }

        # Mock filesharesetting response
        fe_filesharesetting = {
            'be_filesharesetting_clientinfo': None
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            return_value=fe_filesystem)
        self.handler.filesharesetting_handler.\
            _get_filesharesetting_by_name = mock.Mock(
                return_value=fe_filesharesetting)

        # Execute manage_fileshare and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_fileshare,
            fe_manage_fileshare,
            extra_specs
        )

    def test_manage_fileshare_sharesetting_has_clientinfo(self):
        """Manage fileshare failure sharesetting has existing clientinfo."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'true'}

        # Mock get_fileshare response
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Mock filesystem response with matching reduce value
        fe_filesystem = {
            'be_filesystem_size': 10240,
            'be_filesystem_reduce': True
        }

        # Mock filesharesetting response with clientinfo
        fe_filesharesetting = {'be_filesharesetting_clientinfo': [
            {'ipaddress': '10.0.0.1', 'access': 'rw',
             'options': 'root_squash'}]}

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            return_value=fe_filesystem)
        self.handler.filesharesetting_handler.\
            _get_filesharesetting_by_name = mock.Mock(
                return_value=fe_filesharesetting)

        # Execute manage_fileshare and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_fileshare,
            fe_manage_fileshare,
            extra_specs
        )

    def test_manage_fileshare_sharesetting_has_default_clientinfo(self):
        """Manage fileshare success sharesetting has default clientinfo."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'true'}

        # Mock get_fileshare response
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Mock filesystem response with matching reduce value
        fe_filesystem = {
            'be_filesystem_size': 10240,  # Multiple of 1024
            'be_filesystem_reduce': True
        }

        # Mock filesharesetting response with default clientinfo
        fe_filesharesetting = {
            'be_filesharesetting_clientinfo': [
                {
                    'ipaddress': '0.0.0.0',
                    'access': 'ro',
                    'options': 'root_squash'
                }
            ]
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            return_value=fe_filesystem)
        self.handler.filesharesetting_handler.\
            _get_filesharesetting_by_name = mock.Mock(
                return_value=fe_filesharesetting)
        self.handler.edit_fileshare_by_id = mock.Mock()

        # Execute manage_fileshare - should succeed
        result_fileshare, result_size = self.handler.manage_fileshare(
            fe_manage_fileshare, extra_specs)

        # Verify method calls
        self.mock_rest_client.get.assert_called_once_with('/fileshares')
        self.handler.filesystem_handler.\
            _get_filesystem_by_name.assert_called_once_with(
                BE_FILESYSTEM_NAME)
        self.handler.filesharesetting_handler.\
            _get_filesharesetting_by_name.assert_called_once_with(
                BE_SHARESETTING_NAME)

        # Verify edit_fileshare_by_id was called to reset access rules
        self.handler.edit_fileshare_by_id.assert_called_once_with(
            FE_MANAGE_SHARE_ID,
            BE_FILESHARE_UID,
            BE_FILESYSTEM_NAME,
            extra_specs,
            False,
            None,
            None,
            True,
            [])

        # Verify result
        self.assertIsInstance(result_fileshare, dict)
        self.assertEqual(result_fileshare['be_uid'], BE_FILESHARE_UID)
        self.assertEqual(result_size, 10240)

    def test_manage_fileshare_filesystem_size_not_multiple_of_1024(self):
        """Manage fileshare fails when filesystem size not multiple 1024."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'false'}

        # Mock get_fileshare response
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Mock filesystem response with size NOT multiple of 1024
        # 2500 MiB is not divisible by 1024, next multiple is 3072
        fe_filesystem = {
            'be_filesystem_size': 2500,
            'be_filesystem_reduce': False
        }

        # Mock filesharesetting response
        fe_filesharesetting = {
            'be_filesharesetting_clientinfo': None
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)
        self.handler.filesystem_handler._get_filesystem_by_name = mock.Mock(
            return_value=fe_filesystem)
        self.handler.filesharesetting_handler.\
            _get_filesharesetting_by_name = mock.Mock(
                return_value=fe_filesharesetting)

        # Execute manage_fileshare and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.manage_fileshare,
            fe_manage_fileshare,
            extra_specs
        )

    # Validation tests
    def test_validate_manage_fileshare_fe_req_success(self):
        """Test successful validation of manage fileshare request."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'false',
                       'hpe_alletra_b10000:squash_option': 'root_squash'}

        # Should not raise any exception
        self.handler.validator.validate_manage_fileshare_fe_req(
            fe_manage_fileshare, extra_specs)

    def test_validate_manage_fileshare_fe_req_success_with_nfs_protocol(self):
        """Test successful validation with NFS protocol."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'false',
                       'hpe_alletra_b10000:squash_option': 'root_squash'}

        # Should not raise any exception
        self.handler.validator.validate_manage_fileshare_fe_req(
            fe_manage_fileshare, extra_specs)

    def test_validate_manage_fileshare_fe_req_missing_share_proto(self):
        """Test validation failure when share_proto is missing."""
        fe_manage_fileshare = {
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_invalid_protocol(self):
        """Test validation failure with unsupported protocol."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'CIFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.ManageInvalidShare,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_missing_export_locations(self):
        """Test validation failure when export_locations is missing."""
        fe_manage_fileshare = {
            'share_proto': 'NFS'
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_empty_export_locations(self):
        """Test validation failure when export_locations is empty."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': []
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_multiple_export_locations(self):
        """Validation failure when multiple export_locations provided."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'},
                {'path': f'192.168.1.2:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_missing_path(self):
        """Validation failure when path is missing from export_location."""
        fe_manage_fileshare = {
            'share_proto': 'NFS',
            'export_locations': [
                {}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_invalid_path_format(self):
        """Test validation failure when path format is invalid."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                # Missing colon
                {'path': (f'{BE_HOST_IP}/file/'
                          f'{BE_FILESHARE_NAME}/'
                          f'{BE_FILESHARE_NAME}')}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_invalid_path_separator(self):
        """Test validation failure when path has multiple colons."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                # Path has multiple colons (not covered by split(':', 1))
                {'path': (f'{BE_HOST_IP}::/file/'
                          f'{BE_FILESHARE_NAME}/'
                          f'{BE_FILESHARE_NAME}')}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_empty_ip_or_path(self):
        """Test validation failure when IP or mount path is empty."""
        # Test with empty IP address
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f':{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

        # Test with empty mount path
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:'}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_invalid_ip(self):
        """Test validation failure when IP address is invalid."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'invalid.ip:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_invalid_mount_path(self):
        """Validation failure when mount path doesn't start with /file/."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': (f'{BE_HOST_IP}:/share/{BE_FILESHARE_NAME}/'
                          f'{BE_FILESHARE_NAME}')}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_invalid_mount_path_components(
            self):
        """Mount path has wrong number of components."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                # Only 3 components instead of 4
                {'path': f'{BE_HOST_IP}:/file/{BE_FILESHARE_NAME}'}
            ]
        }
        extra_specs = {}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_invalid_reduce(self):
        """Test validation failure when reduce has invalid value."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'invalid'}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_manage_fileshare_fe_req_invalid_squash_option(self):
        """Test validation failure when squash_option is invalid."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:squash_option': 'invalid_squash'}

        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator.validate_manage_fileshare_fe_req,
            fe_manage_fileshare,
            extra_specs
        )

    def test_validate_is_default_clientinfo_not_default(self):
        """Test _is_default_clientinfo returns False for non-default rule."""
        # Test with multiple elements (len != 1)
        clientinfo = [
            {
                'ipaddress': '0.0.0.0',
                'access': 'ro',
                'options': 'root_squash'
            },
            {
                'ipaddress': '10.0.0.1',
                'access': 'rw',
                'options': 'root_squash'
            }
        ]
        result = self.handler.validator._is_default_clientinfo(clientinfo)
        self.assertFalse(result)

    # Conversion tests
    def test_convert_manage_fileshare_to_be_model(self):
        """Test conversion of manage fileshare to backend model."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'false',
                       'hpe_alletra_b10000:squash_option': 'root_squash'}

        result = self.handler.convert.convert_manage_fileshare_to_be_model(
            fe_manage_fileshare, extra_specs)

        # Verify structure
        self.assertIn('be_host_ip', result)
        self.assertIn('be_mount_path', result)
        self.assertIn('fe_reduce', result)
        self.assertIn('fe_squash_option', result)

        self.assertEqual(result['be_host_ip'], BE_HOST_IP)
        self.assertEqual(
            result['be_mount_path'],
            BE_MOUNT_PATH)
        self.assertEqual(result['fe_reduce'], False)
        self.assertEqual(result['fe_squash_option'], 'root_squash')

    def test_convert_manage_fileshare_to_be_model_wildcard_ip(self):
        """Test conversion with wildcard IP in export path."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'0.0.0.0:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {}

        result = self.handler.convert.convert_manage_fileshare_to_be_model(
            fe_manage_fileshare, extra_specs)

        self.assertEqual(result['be_host_ip'], '0.0.0.0')
        self.assertEqual(
            result['be_mount_path'],
            BE_MOUNT_PATH)
        self.assertEqual(result['fe_reduce'], True)  # Default
        self.assertEqual(result['fe_squash_option'], 'root_squash')  # Default

    def test_convert_manage_fileshare_to_be_model_reduce_true(self):
        """Test conversion with reduce=true."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:reduce': 'true'}

        result = self.handler.convert.convert_manage_fileshare_to_be_model(
            fe_manage_fileshare, extra_specs)

        self.assertEqual(result['fe_reduce'], True)

    def test_convert_manage_fileshare_to_be_model_custom_squash(self):
        """Test conversion with custom squash option."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:squash_option': 'no_root_squash'}

        result = self.handler.convert.convert_manage_fileshare_to_be_model(
            fe_manage_fileshare, extra_specs)

        self.assertEqual(result['fe_squash_option'], 'no_root_squash')

    def test_convert_manage_fileshare_to_be_model_mixed_case_squash(self):
        """Test conv normalizes mixed case squash option to lowercase."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        extra_specs = {'hpe_alletra_b10000:squash_option': 'NO_ROOT_SQUASH'}

        result = self.handler.convert.convert_manage_fileshare_to_be_model(
            fe_manage_fileshare, extra_specs)

        # Verify squash option is converted to lowercase
        self.assertEqual(result['fe_squash_option'], 'no_root_squash')

    def test_convert_manage_fileshare_to_be_model_reduce_from_dedupe_true(
            self):
        """Test reduce from dedupe/compression when reduce not set."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        # When reduce is not specified but dedupe/compression are,
        # reduce should be derived from their value
        extra_specs = {'dedupe': 'true', 'compression': 'true'}

        result = self.handler.convert.convert_manage_fileshare_to_be_model(
            fe_manage_fileshare, extra_specs)

        # Verify reduce is set to True (derived from dedupe)
        self.assertTrue(result['fe_reduce'])

    def test_convert_manage_fileshare_to_be_model_reduce_from_dedupe_false(
            self):
        """Test reduce from dedupe/compression=false when not set."""
        fe_manage_fileshare = {
            'id': FE_MANAGE_SHARE_ID,
            'share_proto': 'NFS',
            'export_locations': [
                {'path': f'{BE_HOST_IP}:{BE_MOUNT_PATH}'}
            ]
        }
        # When reduce is not specified but dedupe/compression=false,
        # reduce should be False
        extra_specs = {'dedupe': 'false', 'compression': 'false'}

        result = self.handler.convert.convert_manage_fileshare_to_be_model(
            fe_manage_fileshare, extra_specs)

        # Verify reduce is set to False (derived from dedupe)
        self.assertFalse(result['fe_reduce'])


@ddt.ddt
class FileShareHandlerHelpersTestCase(test.TestCase):
    """Test case for FileShareHandler helper methods."""

    def setUp(self):
        """Test Setup"""
        super(FileShareHandlerHelpersTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()

        # Initialize handler
        self.handler = fileshare.FileShareHandler(
            self.mock_rest_client
        )

    # _get_fileshare_by_name()
    def test_get_fileshare_by_name_success(self):
        """Test successful get fileshare by name."""
        be_fileshare_name = BE_FILESHARE_NAME
        be_filesystem_name = BE_FILESYSTEM_NAME
        be_sharesetting_name = BE_SHARESETTING_NAME

        # Mock get_fileshare response with matching share
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)

        # Execute _get_fileshare_by_name
        result = self.handler._get_fileshare_by_name(
            be_fileshare_name, be_filesystem_name, be_sharesetting_name)

        # Verify method calls
        self.mock_rest_client.get.assert_called_once_with('/fileshares')

        # Verify result
        self.assertIsInstance(result, dict)
        self.assertEqual(result['be_uid'], BE_FILESHARE_UID)
        self.assertEqual(
            result['be_fileshare_name'],
            BE_FILESHARE_NAME)
        self.assertEqual(
            result['be_filesystem_name'],
            BE_FILESYSTEM_NAME)
        self.assertEqual(
            result['be_sharesetting_name'],
            BE_SHARESETTING_NAME)

    def test_get_fileshare_by_name_not_found(self):
        """Test get fileshare by name when not found."""
        be_fileshare_name = BE_MISSING_FILESHARE_NAME
        be_filesystem_name = BE_MISSING_FILESYSTEM_NAME
        be_sharesetting_name = BE_MISSING_SHARESETTING_NAME

        # Mock get_fileshare response with no matching share
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)

        # Execute _get_fileshare_by_name and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler._get_fileshare_by_name,
            be_fileshare_name,
            be_filesystem_name,
            be_sharesetting_name
        )

    # _get_fileshare_by_hostip_mountpath()
    def test_get_fileshare_by_hostip_mountpath_success(self):
        """Test successful get fileshare by hostip and mountpath."""
        be_host_ip = BE_HOST_IP
        be_mount_path = BE_MOUNT_PATH

        # Mock get_fileshare response with matching share
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)

        # Execute _get_fileshare_by_hostip_mountpath
        result = self.handler._get_fileshare_by_hostip_mountpath(
            be_host_ip, be_mount_path)

        # Verify method calls
        self.mock_rest_client.get.assert_called_once_with('/fileshares')

        # Verify result
        self.assertIsInstance(result, dict)
        self.assertEqual(result['be_uid'],
                         BE_FILESHARE_UID)
        self.assertEqual(
            result['be_fileshare_name'],
            BE_FILESHARE_NAME)
        self.assertEqual(result['host_ip'], BE_HOST_IP)
        self.assertEqual(
            result['mount_path'],
            BE_MOUNT_PATH)

    def test_get_fileshare_by_hostip_mountpath_not_found(self):
        """Test get fileshare by hostip and mountpath when not found."""
        be_host_ip = '192.168.1.2'
        be_mount_path = BE_MISSING_MOUNT_PATH

        # Mock get_fileshare response with no matching share
        be_fileshares = {
            'members': {
                BE_FILESHARE_UID: {
                    'uid': BE_FILESHARE_UID,
                    'name': BE_FILESHARE_NAME,
                    'filesystem': {'name': BE_FILESYSTEM_NAME},
                    'sharesettings': {'name': BE_SHARESETTING_NAME},
                    'hostip': BE_HOST_IP,
                    'mountpath': BE_MOUNT_PATH
                }
            }
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshares)

        # Execute _get_fileshare_by_hostip_mountpath and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler._get_fileshare_by_hostip_mountpath,
            be_host_ip,
            be_mount_path
        )

    # _compare_values_with_be_share()
    def test_compare_values_with_be_share_success(self):
        """Test successful comparison of values with backend share."""
        be_share_id = BE_FILESHARE_UID
        be_share_name = BE_FILESHARE_NAME
        be_filesystem_name = BE_FILESYSTEM_NAME
        be_sharesetting_name = BE_SHARESETTING_NAME

        # Mock get_fileshare_by_id response with matching values
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshare)

        # Execute _compare_values_with_be_share - should not raise exception
        self.handler._compare_values_with_be_share(
            be_share_id, be_share_name, be_filesystem_name,
            be_sharesetting_name)

        # Verify method calls
        self.mock_rest_client.get.assert_called_once_with(
            f'/fileshares/{BE_FILESHARE_UID}')

    def test_compare_values_with_be_share_id_mismatch(self):
        """Test comparison failure when share ID doesn't match."""
        be_share_id = '99999999e29b41d4a716446655440000'
        be_share_name = BE_FILESHARE_NAME
        be_filesystem_name = BE_FILESYSTEM_NAME
        be_sharesetting_name = BE_SHARESETTING_NAME

        # Mock get_fileshare_by_id response with different ID
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshare)

        # Execute _compare_values_with_be_share and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler._compare_values_with_be_share,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name
        )

    def test_compare_values_with_be_share_name_mismatch(self):
        """Test comparison failure when share name doesn't match."""
        be_share_id = BE_FILESHARE_UID
        be_share_name = BE_DIFFERENT_FILESHARE_NAME
        be_filesystem_name = BE_FILESYSTEM_NAME
        be_sharesetting_name = BE_SHARESETTING_NAME

        # Mock get_fileshare_by_id response with different name
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshare)

        # Execute _compare_values_with_be_share and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler._compare_values_with_be_share,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name
        )

    def test_compare_values_with_be_share_filesystem_mismatch(self):
        """Test comparison failure when filesystem name doesn't match."""
        be_share_id = BE_FILESHARE_UID
        be_share_name = BE_FILESHARE_NAME
        be_filesystem_name = BE_DIFFERENT_FILESYSTEM_NAME
        be_sharesetting_name = BE_SHARESETTING_NAME

        # Mock get_fileshare_by_id response with different filesystem name
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshare)

        # Execute _compare_values_with_be_share and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler._compare_values_with_be_share,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name
        )

    def test_compare_values_with_be_share_sharesetting_mismatch(self):
        """Test comparison failure when sharesetting name doesn't match."""
        be_share_id = BE_FILESHARE_UID
        be_share_name = BE_FILESHARE_NAME
        be_filesystem_name = BE_FILESYSTEM_NAME
        be_sharesetting_name = BE_DIFFERENT_SHARESETTING_NAME

        # Mock get_fileshare_by_id response with different sharesetting name
        be_fileshare = {
            'uid': BE_FILESHARE_UID,
            'name': BE_FILESHARE_NAME,
            'filesystem': {'name': BE_FILESYSTEM_NAME},
            'sharesettings': {'name': BE_SHARESETTING_NAME},
            'hostip': BE_HOST_IP,
            'mountpath': BE_MOUNT_PATH
        }

        # Configure mocks
        self.mock_rest_client.get.return_value = (None, be_fileshare)

        # Execute _compare_values_with_be_share and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler._compare_values_with_be_share,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name
        )

    # _validate_be_share_values()
    def test_validate_be_share_values_success(self):
        """Test successful validation of backend share values."""
        be_share_id = BE_FILESHARE_UID
        be_share_name = BE_FILESHARE_NAME
        be_filesystem_name = BE_FILESYSTEM_NAME
        be_sharesetting_name = BE_SHARESETTING_NAME
        stored_be_share_id = BE_FILESHARE_UID
        stored_be_share_name = BE_FILESHARE_NAME
        stored_be_filesystem_name = BE_FILESYSTEM_NAME
        stored_be_sharesetting_name = BE_SHARESETTING_NAME

        # Should not raise any exception
        self.handler.validator._validate_be_share_values(
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name,
            stored_be_share_id,
            stored_be_share_name,
            stored_be_filesystem_name,
            stored_be_sharesetting_name)

    def test_validate_be_share_values_share_id_mismatch(self):
        """Test validation failure when share ID doesn't match."""
        be_share_id = '99999999e29b41d4a716446655440000'
        be_share_name = BE_FILESHARE_NAME
        be_filesystem_name = BE_FILESYSTEM_NAME
        be_sharesetting_name = BE_SHARESETTING_NAME
        stored_be_share_id = BE_FILESHARE_UID
        stored_be_share_name = BE_FILESHARE_NAME
        stored_be_filesystem_name = BE_FILESYSTEM_NAME
        stored_be_sharesetting_name = BE_SHARESETTING_NAME

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator._validate_be_share_values,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name,
            stored_be_share_id,
            stored_be_share_name,
            stored_be_filesystem_name,
            stored_be_sharesetting_name)

    def test_validate_be_share_values_share_name_mismatch(self):
        """Test validation failure when share name doesn't match."""
        be_share_id = BE_FILESHARE_UID
        be_share_name = BE_DIFFERENT_FILESHARE_NAME
        be_filesystem_name = BE_FILESYSTEM_NAME
        be_sharesetting_name = BE_SHARESETTING_NAME
        stored_be_share_id = BE_FILESHARE_UID
        stored_be_share_name = BE_FILESHARE_NAME
        stored_be_filesystem_name = BE_FILESYSTEM_NAME
        stored_be_sharesetting_name = BE_SHARESETTING_NAME

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator._validate_be_share_values,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name,
            stored_be_share_id,
            stored_be_share_name,
            stored_be_filesystem_name,
            stored_be_sharesetting_name)

    def test_validate_be_share_values_filesystem_name_mismatch(self):
        """Test validation failure when filesystem name doesn't match."""
        be_share_id = BE_FILESHARE_UID
        be_share_name = BE_FILESHARE_NAME
        be_filesystem_name = BE_DIFFERENT_FILESYSTEM_NAME
        be_sharesetting_name = BE_SHARESETTING_NAME
        stored_be_share_id = BE_FILESHARE_UID
        stored_be_share_name = BE_FILESHARE_NAME
        stored_be_filesystem_name = BE_FILESYSTEM_NAME
        stored_be_sharesetting_name = BE_SHARESETTING_NAME

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator._validate_be_share_values,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name,
            stored_be_share_id,
            stored_be_share_name,
            stored_be_filesystem_name,
            stored_be_sharesetting_name)

    def test_validate_be_share_values_sharesetting_name_mismatch(self):
        """Test validation failure when sharesetting name doesn't match."""
        be_share_id = BE_FILESHARE_UID
        be_share_name = BE_FILESHARE_NAME
        be_filesystem_name = BE_FILESYSTEM_NAME
        be_sharesetting_name = BE_DIFFERENT_SHARESETTING_NAME
        stored_be_share_id = BE_FILESHARE_UID
        stored_be_share_name = BE_FILESHARE_NAME
        stored_be_filesystem_name = BE_FILESYSTEM_NAME
        stored_be_sharesetting_name = BE_SHARESETTING_NAME

        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.validator._validate_be_share_values,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name,
            stored_be_share_id,
            stored_be_share_name,
            stored_be_filesystem_name,
            stored_be_sharesetting_name)


@ddt.ddt
class FileShareHandlerShareTypeValidationTestCase(test.TestCase):
    """Test case for FileShareHandler share type extra specs validation.

    This test class validates share type extra specs for both create_fileshare
    and manage_fileshare operations using a reusable validation method.
    """

    def setUp(self):
        """Test Setup"""
        super(FileShareHandlerShareTypeValidationTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()

        # Initialize handler
        self.handler = fileshare.FileShareHandler(
            self.mock_rest_client
        )

    # Reduce option validation
    def test_validate_share_type_reduce_true(self):
        """Test successful validation of reduce='true'."""
        extra_specs = {'hpe_alletra_b10000:reduce': 'true'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_reduce_false(self):
        """Test successful validation of reduce='false'."""
        extra_specs = {'hpe_alletra_b10000:reduce': 'false'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_reduce_invalid(self):
        """Test validation failure with invalid reduce value."""
        extra_specs = {'hpe_alletra_b10000:reduce': 'invalid'}
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    # Squash option validation
    def test_validate_share_type_squash_root_squash(self):
        """Test successful validation of squash_option='root_squash'."""
        extra_specs = {'hpe_alletra_b10000:squash_option': 'root_squash'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_squash_no_root_squash(self):
        """Test successful validation of squash_option='no_root_squash'."""
        extra_specs = {'hpe_alletra_b10000:squash_option': 'no_root_squash'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_squash_all_squash(self):
        """Test successful validation of squash_option='all_squash'."""
        extra_specs = {'hpe_alletra_b10000:squash_option': 'all_squash'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_squash_invalid(self):
        """Test validation failure with invalid squash_option."""
        extra_specs = {'hpe_alletra_b10000:squash_option': 'invalid_squash'}
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    # Dedupe validation
    def test_validate_share_type_dedupe_true(self):
        """Test successful validation of dedupe='true'."""
        extra_specs = {'dedupe': 'true', 'compression': 'true'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_dedupe_false(self):
        """Test successful validation of dedupe='false'."""
        extra_specs = {'dedupe': 'false', 'compression': 'false'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_dedupe_invalid(self):
        """Test validation failure with invalid dedupe value."""
        extra_specs = {'dedupe': 'invalid', 'compression': 'true'}
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    # Compression validation
    def test_validate_share_type_compression_true(self):
        """Test successful validation of compression='true'."""
        extra_specs = {'dedupe': 'true', 'compression': 'true'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_compression_false(self):
        """Test successful validation of compression='false'."""
        extra_specs = {'dedupe': 'false', 'compression': 'false'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_compression_invalid(self):
        """Test validation failure with invalid compression value."""
        extra_specs = {'dedupe': 'false', 'compression': 'invalid'}
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    # Dedupe and Compression combination validation
    def test_validate_share_type_dedupe_without_compression(self):
        """Test validation failure when dedupe specified but not comp."""
        extra_specs = {'dedupe': 'true'}
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    def test_validate_share_type_compression_without_dedupe(self):
        """Test validation failure when comp specified but not dedupe."""
        extra_specs = {'compression': 'true'}
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    def test_validate_share_type_dedupe_compression_mismatch_true_false(self):
        """Test validation failure when dedupe and compression differ."""
        extra_specs = {'dedupe': 'true', 'compression': 'false'}
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    def test_validate_share_type_dedupe_compression_mismatch_false_true(self):
        """Test validation failure when compression and dedupe differ."""
        extra_specs = {'dedupe': 'false', 'compression': 'true'}
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    # Thin provisioning validation
    def test_validate_share_type_thin_provisioning_true(self):
        """Test successful validation of thin_provisioning='true'."""
        extra_specs = {'thin_provisioning': 'true'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_thin_provisioning_false(self):
        """Test validation failure when thin_provisioning='false'."""
        extra_specs = {'thin_provisioning': 'false'}
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    # Reduce and Dedupe/Compression conflicts
    def test_validate_share_type_reduce_with_dedupe_conflict(self):
        """Test validation failure when reduce and dedupe both specified."""
        extra_specs = {
            'hpe_alletra_b10000:reduce': 'true',
            'dedupe': 'true',
            'compression': 'true'
        }
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    def test_validate_share_type_reduce_with_compression_conflict(self):
        """Test validation failure when reduce and comp both specified."""
        extra_specs = {
            'hpe_alletra_b10000:reduce': 'true',
            'compression': 'true'
        }
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    def test_validate_share_type_reduce_dedupe_comp_all_specified(self):
        """Test validation failure reduce and all other options specified."""
        extra_specs = {
            'hpe_alletra_b10000:reduce': 'false',
            'dedupe': 'false',
            'compression': 'false'
        }
        self.assertRaises(
            exception.InvalidInput,
            self.handler.validator._validate_share_type_extra_specs,
            extra_specs
        )

    # Complex valid combinations
    def test_validate_share_type_all_options_reduce_only(self):
        """Test valid: only reduce specified."""
        extra_specs = {'hpe_alletra_b10000:reduce': 'true'}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_all_options_dedupe_compression(self):
        """Test valid: dedupe and compression both specified."""
        extra_specs = {
            'dedupe': 'true',
            'compression': 'true',
            'hpe_alletra_b10000:squash_option': 'root_squash'
        }
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_all_options_all_fields(self):
        """Test valid: all options specified without conflicts."""
        extra_specs = {
            'hpe_alletra_b10000:reduce': 'true',
            'hpe_alletra_b10000:squash_option': 'all_squash',
            'thin_provisioning': 'true'
        }
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    def test_validate_share_type_empty_extra_specs(self):
        """Test valid: empty extra specs (all optional)."""
        extra_specs = {}
        # Should not raise any exception
        self.handler.validator._validate_share_type_extra_specs(extra_specs)

    # Case insensitivity tests
    @ddt.data(
        ('TRUE', 'ROOT_SQUASH'),
        ('True', 'Root_Squash'),
        ('FALSE', 'NO_ROOT_SQUASH'),
        ('False', 'No_Root_Squash'),
        ('true', 'ALL_SQUASH'),
        ('false', 'All_Squash'),
    )
    @ddt.unpack
    def test_validate_share_type_case_insensitive(self, reduce_val,
                                                  squash_val):
        """Test validation handles different case combinations.

        Reduce: true/false (any case)
        Squash option: root_squash/no_root_squash/all_squash (any case)
        """
        extra_specs = {
            'hpe_alletra_b10000:reduce': reduce_val,
            'hpe_alletra_b10000:squash_option': squash_val
        }
        # Should not raise any exception - validators use .lower()
        self.handler.validator._validate_share_type_extra_specs(extra_specs)
