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

        # Initialize handler
        self.handler = filesystem.FileSystemHandler(
            self.mock_rest_client
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


@ddt.ddt
class FileSystemValidatorTestCase(test.TestCase):
    """Test case for FileSystemValidator class."""

    def setUp(self):
        """Test Setup"""
        super(FileSystemValidatorTestCase, self).setUp()

        # Initialize validator
        self.validator = filesystem.FileSystemValidator()

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


@ddt.ddt
class FileSystemModelConvertTestCase(test.TestCase):
    """Test case for FileSystemModelConvert class."""

    def setUp(self):
        """Test Setup"""
        super(FileSystemModelConvertTestCase, self).setUp()

        # Initialize converter
        self.converter = filesystem.FileSystemModelConvert()

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
        """Test successful conversion of individual filesystem."""

        # Configure backend filesystem
        be_filesystem = {
            'uid': 'uid1',
            'name': 'filesystem1',
            'vvSizeInMiB': 1024,
            'reduce': True
        }

        # Execute conversion
        result = self.converter.convert_filesystem_by_id_to_fe_model(
            be_filesystem)

        # Verify result
        expected = {
            'be_uid': 'uid1',
            'be_filesystem_name': 'filesystem1',
            'be_filesystem_size': 1024,
            'be_filesystem_reduce': True
        }
        self.assertEqual(expected, result)
