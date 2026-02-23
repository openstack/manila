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
    filesharesetting_handler as filesharesetting)
from manila import test


@ddt.ddt
class FileSharesettingHandlerTestCase(test.TestCase):
    """Test case for FileSharesettingHandler class."""

    def setUp(self):
        """Test Setup"""
        super(FileSharesettingHandlerTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()

        # Initialize handler
        self.handler = filesharesetting.FileSharesettingHandler(
            self.mock_rest_client
        )

    # get_filesharesettings()
    def test_get_filesharesettings_success(self):
        """Test successful filesharesettings retrieval."""

        # Configure mock backend response with valid data
        be_filesharesettings = {
            'members': {
                'uid1': {
                    'uid': 'uid1',
                    'name': 'setting1',
                    'clientInfo': [
                        {
                            "ipaddress": "10.10.10.10/09",
                            "access": "rw",
                            "options": "root_squash"
                        }
                    ]
                }
            }
        }
        self.mock_rest_client.get.return_value = (200, be_filesharesettings)

        # Execute get_filesharesettings
        result = self.handler.get_filesharesettings()

        # Verify rest client call
        self.mock_rest_client.get.assert_called_once_with('/filesharesettings')

        # Verify result structure
        self.assertEqual(1, len(result))
        setting = result[0]
        self.assertEqual('uid1', setting['be_uid'])
        self.assertEqual('setting1', setting['be_filesharesetting_name'])
        expected_clientinfo = [
            {
                "ipaddress": "10.10.10.10/09",
                "access": "rw",
                "options": "root_squash"
            }
        ]
        self.assertEqual(expected_clientinfo,
                         setting['be_filesharesetting_clientinfo'])

    # _get_filesharesetting_by_name()
    def test_get_filesharesetting_by_name_success(self):
        """Test successful filesharesetting retrieval by name."""

        # Configure mock for get_filesharesettings
        expected_setting = {
            'be_uid': 'uid1',
            'be_filesharesetting_name': 'setting1',
            'be_filesharesetting_clientinfo': [
                {
                    "ipaddress": "10.10.10.10/09",
                    "access": "rw",
                    "options": "root_squash"
                }
            ]
        }
        self.handler.get_filesharesettings = mock.Mock(
            return_value=[expected_setting])

        # Execute _get_filesharesetting_by_name
        result = self.handler._get_filesharesetting_by_name('setting1')

        # Verify get_filesharesettings was called
        self.handler.get_filesharesettings.assert_called_once()

        # Verify result
        self.assertEqual(expected_setting, result)

    def test_get_filesharesetting_by_name_not_found(self):
        """Test filesharesetting retrieval by name when not found."""

        # Configure mock for get_filesharesettings with different name
        self.handler.get_filesharesettings = mock.Mock(return_value=[{
            'be_uid': 'uid1',
            'be_filesharesetting_name': 'setting1',
            'be_filesharesetting_clientinfo': [
                {
                    "ipaddress": "10.10.10.10/09",
                    "access": "rw",
                    "options": "root_squash"
                }
            ]
        }])

        # Execute _get_filesharesetting_by_name and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler._get_filesharesetting_by_name,
            'nonexistent_setting'
        )


@ddt.ddt
class FileSharesettingValidatorTestCase(test.TestCase):
    """Test case for FileSharesettingValidator class."""

    def setUp(self):
        """Test Setup"""
        super(FileSharesettingValidatorTestCase, self).setUp()

        # Initialize validator
        self.validator = filesharesetting.FileSharesettingValidator()

    # validate_get_filesharesettings_be_resp()
    def test_validate_get_filesharesettings_be_resp_success(self):
        """Test successful validation of filesharesettings response."""

        # Configure valid backend response
        be_filesharesettings = {
            'members': {
                'uid1': {
                    'uid': 'uid1',
                    'name': 'setting1'
                }
            }
        }

        # Execute validation - should not raise exception
        self.validator.validate_get_filesharesettings_be_resp(
            be_filesharesettings)

    def test_validate_get_filesharesettings_be_resp_none_response(self):
        """Test validation failure when response is None."""

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesharesettings_be_resp,
            None
        )

    def test_validate_get_filesharesettings_be_resp_missing_members(self):
        """Test validation failure when members field is missing."""

        # Configure response without members
        be_filesharesettings = {}

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesharesettings_be_resp,
            be_filesharesettings
        )

    def test_validate_get_filesharesettings(
            self):
        """Test validation of individual filesharesetting."""

        # Configure response with members containing invalid filesharesetting
        # (missing uid)
        be_filesharesettings = {
            'members': {
                'uid1': {
                    'name': 'setting1'  # missing uid
                }
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesharesettings_be_resp,
            be_filesharesettings
        )

    def test_validate_get_filesharesettings_by_id_be_resp_success(self):
        """Test successful validation of individual filesharesetting."""

        # Configure valid backend filesharesetting
        be_filesharesetting = {
            'uid': 'uid1',
            'name': 'setting1'
        }

        # Execute validation - should not raise exception
        self.validator.validate_get_filesharesettings_by_id_be_resp(
            be_filesharesetting)

    def test_validate_get_filesharesettings_by_id_be_resp_none(self):
        """Test validation failure when filesharesetting is None."""

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesharesettings_by_id_be_resp,
            None
        )

    def test_validate_get_filesharesettings_by_id_be_resp_missing_uid(self):
        """Test validation failure when uid is missing."""

        # Configure filesharesetting without uid
        be_filesharesetting = {
            'name': 'setting1'
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesharesettings_by_id_be_resp,
            be_filesharesetting
        )

    def test_validate_get_filesharesettings_by_id_be_resp_missing_name(self):
        """Test validation failure when name is missing."""

        # Configure filesharesetting without name
        be_filesharesetting = {
            'uid': 'uid1'
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_filesharesettings_by_id_be_resp,
            be_filesharesetting
        )


@ddt.ddt
class FileSharesettingModelConvertTestCase(test.TestCase):
    """Test case for FileSharesettingModelConvert class."""

    def setUp(self):
        """Test Setup"""
        super(FileSharesettingModelConvertTestCase, self).setUp()

        # Initialize converter
        self.converter = filesharesetting.FileSharesettingModelConvert()

    # convert_filesharesettings_to_fe_model()
    def test_convert_filesharesettings_to_fe_model(self):
        """Test successful conversion of filesharesettings to FE model."""

        # Configure backend response
        be_filesharesettings = {
            'members': {
                'uid1': {
                    'uid': 'uid1',
                    'name': 'setting1',
                    'clientInfo': [
                        {
                            "ipaddress": "10.10.10.10/09",
                            "access": "rw",
                            "options": "root_squash"
                        }
                    ]
                },
                'uid2': {
                    'uid': 'uid2',
                    'name': 'setting2'
                }
            }
        }

        # Execute conversion
        result = self.converter.convert_filesharesettings_to_fe_model(
            be_filesharesettings)

        # Verify result
        expected = [
            {
                'be_uid': 'uid1',
                'be_filesharesetting_name': 'setting1',
                'be_filesharesetting_clientinfo': [
                    {
                        "ipaddress": "10.10.10.10/09",
                        "access": "rw",
                        "options": "root_squash"
                    }
                ]
            },
            {
                'be_uid': 'uid2',
                'be_filesharesetting_name': 'setting2',
                'be_filesharesetting_clientinfo': None
            }
        ]
        self.assertEqual(expected, result)

    def test_convert_filesharesetting_with_client(self):
        """Test conversion of individual filesharesetting with clientInfo."""

        # Configure backend filesharesetting
        be_filesharesetting = {
            'uid': 'uid1',
            'name': 'setting1',
            'clientInfo': [
                {
                    "ipaddress": "10.10.10.10/09",
                    "access": "rw",
                    "options": "root_squash"
                }
            ]
        }

        # Execute conversion
        result = self.converter.convert_filesharesetting_by_id_to_fe_model(
            be_filesharesetting)

        # Verify result
        expected = {
            'be_uid': 'uid1',
            'be_filesharesetting_name': 'setting1',
            'be_filesharesetting_clientinfo': [
                {
                    "ipaddress": "10.10.10.10/09",
                    "access": "rw",
                    "options": "root_squash"
                }
            ]
        }
        self.assertEqual(expected, result)

    def test_convert_filesharesetting_no_client(self):
        """Test conversion of individual filesharesetting without client."""

        # Configure backend filesharesetting without clientInfo
        be_filesharesetting = {
            'uid': 'uid1',
            'name': 'setting1'
        }

        # Execute conversion
        result = self.converter.convert_filesharesetting_by_id_to_fe_model(
            be_filesharesetting)

        # Verify result
        expected = {
            'be_uid': 'uid1',
            'be_filesharesetting_name': 'setting1',
            'be_filesharesetting_clientinfo': None
        }
        self.assertEqual(expected, result)
