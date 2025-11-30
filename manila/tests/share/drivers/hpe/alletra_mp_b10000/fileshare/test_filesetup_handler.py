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
    filesetup_handler as filesetup)
from manila import test


@ddt.ddt
class FileSetupHandlerTestCase(test.TestCase):
    """Test case for FileSetupHandler class."""

    def setUp(self):
        """Test Setup"""
        super(FileSetupHandlerTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()

        # Initialize handler
        self.handler = filesetup.FileSetupHandler(
            self.mock_rest_client
        )

    # get_fileservice()
    def test_get_fileservice_success(self):
        """Test successful fileservice retrieval."""

        # Configure mock backend response with valid data
        be_fileservice = {
            'members': {
                'key1': {
                    'isFileServiceEnabled': True,
                    'capacitySummary': {
                        'availableCapacity': 2195865,
                        'usedCapacity': 2195866,
                        'totalCapacity': 4391731
                    }
                }
            }
        }
        self.mock_rest_client.get.return_value = (200, be_fileservice)

        # Execute get_fileservice
        result = self.handler.get_fileservice()

        # Verify rest client call
        self.mock_rest_client.get.assert_called_once_with('/fileservice')

        # Verify result structure
        self.assertTrue(result['be_is_fileservice_enabled'])
        self.assertEqual(2195865, result['be_available_capacity'])
        self.assertEqual(2195866, result['be_used_capacity'])
        self.assertEqual(4391731, result['be_total_capacity'])

    # get_systems()
    def test_get_systems_success(self):
        """Test successful systems retrieval."""

        # Configure mock backend response with valid data
        be_systems = {
            'members': {
                'key1': {
                    'version': {
                        'base': '10.5.0'
                    }
                }
            }
        }
        self.mock_rest_client.get.return_value = (200, be_systems)

        # Execute get_systems
        result = self.handler.get_systems()

        # Verify rest client call
        self.mock_rest_client.get.assert_called_once_with('/systems')

        # Verify result structure
        self.assertEqual('10.5.0', result['version'])

    # get_osinfo()
    def test_get_osinfo_success(self):
        """Test successful osinfo retrieval."""

        # Configure mock backend response with valid data
        be_osinfo = {
            'members': {
                'key1': {
                    'OsFVars': {
                        'isFileServiceSupported': True
                    }
                }
            }
        }
        self.mock_rest_client.get.return_value = (200, be_osinfo)

        # Execute get_osinfo
        result = self.handler.get_osinfo()

        # Verify rest client call
        self.mock_rest_client.get.assert_called_once_with('/osinfo')

        # Verify result structure
        self.assertTrue(result['be_is_fileservice_supported'])


@ddt.ddt
class FileSetupValidatorTestCase(test.TestCase):
    """Test case for FileSetupValidator class."""

    def setUp(self):
        """Test Setup"""
        super(FileSetupValidatorTestCase, self).setUp()

        # Initialize validator
        self.validator = filesetup.FileSetupValidator()

    # validate_get_fileservice_be_resp()
    def test_validate_get_fileservice_be_resp_success(self):
        """Test successful validation of fileservice response."""

        # Configure valid backend response
        be_fileservice = {
            'members': {
                'key1': {
                    'isFileServiceEnabled': True,
                    'capacitySummary': {
                        'availableCapacity': 2195865,
                        'usedCapacity': 2195866,
                        'totalCapacity': 4391731
                    }
                }
            }
        }

        # Execute validation - should not raise exception
        self.validator.validate_get_fileservice_be_resp(be_fileservice)

    def test_validate_get_fileservice_be_resp_none_response(self):
        """Test validation failure when response is None."""

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_fileservice_be_resp,
            None
        )

    def test_validate_get_fileservice_be_resp_missing_members(self):
        """Test validation failure when members field is missing."""

        # Configure response without members
        be_fileservice = {}

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_fileservice_be_resp,
            be_fileservice
        )

    def test_validate_get_fileservice_be_resp_empty_members(self):
        """Test validation failure when members field is empty."""

        # Configure response with empty members
        be_fileservice = {
            'members': {}
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_fileservice_be_resp,
            be_fileservice
        )

    def test_validate_get_fileservice_be_resp_multiple_members(self):
        """Test validation with multiple members (processes first)."""

        # Configure response with multiple members
        be_fileservice = {
            'members': {
                'key1': {
                    'isFileServiceEnabled': True,
                    'capacitySummary': {
                        'availableCapacity': 2195865,
                        'usedCapacity': 2195866,
                        'totalCapacity': 4391731
                    }
                },
                'key2': {
                    'isFileServiceEnabled': False,
                    'capacitySummary': {
                        'availableCapacity': 1000000,
                        'usedCapacity': 500000,
                        'totalCapacity': 1500000
                    }
                }
            }
        }

        # Execute validation - should not raise exception
        # (processes first member only)
        self.validator.validate_get_fileservice_be_resp(be_fileservice)

    def test_validate_get_fileservice_be_resp_missing_isFileServiceEnabled(
            self):
        """Validation failure when isFileServiceEnabled field is missing."""

        # Configure response without isFileServiceEnabled
        be_fileservice = {
            'members': {
                'key1': {
                    'capacitySummary': {
                        'availableCapacity': 1000,
                        'usedCapacity': 500,
                        'totalCapacity': 1500
                    }
                }
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_fileservice_be_resp,
            be_fileservice
        )

    def test_validate_get_fileservice_be_resp_missing_capacitySummary(self):
        """Test validation failure when capacitySummary field is missing."""

        # Configure response without capacitySummary
        be_fileservice = {
            'members': {
                'key1': {
                    'isFileServiceEnabled': True
                }
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_fileservice_be_resp,
            be_fileservice
        )

    def test_validate_get_fileservice_be_resp_missing_availableCapacity(self):
        """Test validation failure when availableCapacity field is missing."""

        # Configure response without availableCapacity
        be_fileservice = {
            'members': {
                'key1': {
                    'isFileServiceEnabled': True,
                    'capacitySummary': {
                        'usedCapacity': 2195866,
                        'totalCapacity': 4391731
                    }
                }
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_fileservice_be_resp,
            be_fileservice
        )

    def test_validate_get_fileservice_be_resp_missing_totalCapacity(self):
        """Test validation failure when totalCapacity field is missing."""

        # Configure response without totalCapacity
        be_fileservice = {
            'members': {
                'key1': {
                    'isFileServiceEnabled': True,
                    'capacitySummary': {
                        'availableCapacity': 2195865,
                        'usedCapacity': 2195866
                    }
                }
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_fileservice_be_resp,
            be_fileservice
        )

    def test_validate_get_fileservice_be_resp_missing_usedCapacity(self):
        """Test validation failure when usedCapacity field is missing."""

        # Configure response without usedCapacity
        be_fileservice = {
            'members': {
                'key1': {
                    'isFileServiceEnabled': True,
                    'capacitySummary': {
                        'availableCapacity': 2195865,
                        'totalCapacity': 4391731
                    }
                }
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_fileservice_be_resp,
            be_fileservice
        )

    # validate_get_systems_be_resp()
    def test_validate_get_systems_be_resp_success(self):
        """Test successful validation of systems response."""

        # Configure valid backend response
        be_systems = {
            'members': {
                'key1': {
                    'version': {
                        'base': '10.5.0'
                    }
                }
            }
        }

        # Execute validation - should not raise exception
        self.validator.validate_get_systems_be_resp(be_systems)

    def test_validate_get_systems_be_resp_none_response(self):
        """Test validation failure when response is None."""

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_systems_be_resp,
            None
        )

    def test_validate_get_systems_be_resp_missing_members(self):
        """Test validation failure when members field is missing."""

        # Configure response without members
        be_systems = {}

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_systems_be_resp,
            be_systems
        )

    def test_validate_get_systems_be_resp_empty_members(self):
        """Test validation failure when members field is empty."""

        # Configure response with empty members
        be_systems = {
            'members': {}
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_systems_be_resp,
            be_systems
        )

    def test_validate_get_systems_be_resp_multiple_members(self):
        """Test validation with multiple members (processes first)."""

        # Configure response with multiple members
        be_systems = {
            'members': {
                'key1': {
                    'version': {
                        'base': '10.5.0'
                    }
                },
                'key2': {
                    'version': {
                        'base': '9.4.0'
                    }
                }
            }
        }

        # Execute validation - should not raise exception
        # (processes first member only)
        self.validator.validate_get_systems_be_resp(be_systems)

    def test_validate_get_systems_be_resp_missing_version(self):
        """Test validation failure when version field is missing."""

        # Configure response without version
        be_systems = {
            'members': {
                'key1': {}
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_systems_be_resp,
            be_systems
        )

    def test_validate_get_systems_be_resp_missing_base(self):
        """Test validation failure when base field is missing."""

        # Configure response without base
        be_systems = {
            'members': {
                'key1': {
                    'version': {}
                }
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_systems_be_resp,
            be_systems
        )

    # validate_get_osinfo_be_resp()
    def test_validate_get_osinfo_be_resp_success(self):
        """Test successful validation of osinfo response."""

        # Configure valid backend response
        be_osinfo = {
            'members': {
                'key1': {
                    'OsFVars': {
                        'isFileServiceSupported': True
                    }
                }
            }
        }

        # Execute validation - should not raise exception
        self.validator.validate_get_osinfo_be_resp(be_osinfo)

    def test_validate_get_osinfo_be_resp_none_response(self):
        """Test validation failure when response is None."""

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_osinfo_be_resp,
            None
        )

    def test_validate_get_osinfo_be_resp_missing_members(self):
        """Test validation failure when members field is missing."""

        # Configure response without members
        be_osinfo = {}

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_osinfo_be_resp,
            be_osinfo
        )

    def test_validate_get_osinfo_be_resp_empty_members(self):
        """Test validation failure when members field is empty."""

        # Configure response with empty members
        be_osinfo = {
            'members': {}
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_osinfo_be_resp,
            be_osinfo
        )

    def test_validate_get_osinfo_be_resp_multiple_members(self):
        """Test validation with multiple members (processes first)."""

        # Configure response with multiple members
        be_osinfo = {
            'members': {
                'key1': {
                    'OsFVars': {
                        'isFileServiceSupported': True
                    }
                },
                'key2': {
                    'OsFVars': {
                        'isFileServiceSupported': False
                    }
                }
            }
        }

        # Execute validation - should not raise exception
        # (processes first member only)
        self.validator.validate_get_osinfo_be_resp(be_osinfo)

    def test_validate_get_osinfo_be_resp_missing_OsFVars(self):
        """Test validation failure when OsFVars field is missing."""

        # Configure response without OsFVars
        be_osinfo = {
            'members': {
                'key1': {}
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_osinfo_be_resp,
            be_osinfo
        )

    def test_validate_get_osinfo_be_resp_missing_isFileServiceSupported(
            self):
        """Validation failure when isFileServiceSupported field is missing."""

        # Configure response without isFileServiceSupported
        be_osinfo = {
            'members': {
                'key1': {
                    'OsFVars': {}
                }
            }
        }

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.validator.validate_get_osinfo_be_resp,
            be_osinfo
        )


@ddt.ddt
class FileSetupModelConvertTestCase(test.TestCase):
    """Test case for FileSetupModelConvert class."""

    def setUp(self):
        """Test Setup"""
        super(FileSetupModelConvertTestCase, self).setUp()

        # Initialize converter
        self.converter = filesetup.FileSetupModelConvert()

    # convert_fileservice_to_fe_model()
    def test_convert_fileservice_to_fe_model_success(self):
        """Test successful conversion of fileservice to FE model."""

        # Configure backend response
        be_fileservice = {
            'members': {
                'key1': {
                    'isFileServiceEnabled': True,
                    'capacitySummary': {
                        'availableCapacity': 2195865,
                        'usedCapacity': 2195866,
                        'totalCapacity': 4391731
                    }
                }
            }
        }

        # Execute conversion
        result = self.converter.convert_fileservice_to_fe_model(be_fileservice)

        # Verify result
        expected = {
            'be_is_fileservice_enabled': True,
            'be_available_capacity': 2195865,
            'be_used_capacity': 2195866,
            'be_total_capacity': 4391731
        }
        self.assertEqual(expected, result)

    def test_convert_fileservice_to_fe_model_failure_none(self):
        """Test conversion failure when fileservice is None."""

        # Execute conversion and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.converter.convert_fileservice_to_fe_model,
            None
        )

    def test_convert_fileservice_to_fe_model_failure_missing_members(self):
        """Test conversion failure when members field is missing."""

        # Configure response without members
        be_fileservice = {}

        # Execute conversion and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.converter.convert_fileservice_to_fe_model,
            be_fileservice
        )

    # convert_systems_to_fe_model()
    def test_convert_systems_to_fe_model_success(self):
        """Test successful conversion of systems to FE model."""

        # Configure backend response
        be_systems = {
            'members': {
                'key1': {
                    'version': {
                        'base': '10.5.0'
                    }
                }
            }
        }

        # Execute conversion
        result = self.converter.convert_systems_to_fe_model(be_systems)

        # Verify result
        expected = {
            'version': '10.5.0'
        }
        self.assertEqual(expected, result)

    def test_convert_systems_to_fe_model_failure_none(self):
        """Test conversion failure when systems is None."""

        # Execute conversion and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.converter.convert_systems_to_fe_model,
            None
        )

    def test_convert_systems_to_fe_model_failure_missing_members(self):
        """Test conversion failure when members field is missing."""

        # Configure response without members
        be_systems = {}

        # Execute conversion and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.converter.convert_systems_to_fe_model,
            be_systems
        )

    # convert_osinfo_to_fe_model()
    def test_convert_osinfo_to_fe_model_success(self):
        """Test successful conversion of osinfo to FE model."""

        # Configure backend response
        be_osinfo = {
            'members': {
                'key1': {
                    'OsFVars': {
                        'isFileServiceSupported': True
                    }
                }
            }
        }

        # Execute conversion
        result = self.converter.convert_osinfo_to_fe_model(be_osinfo)

        # Verify result
        expected = {
            'be_is_fileservice_supported': True
        }
        self.assertEqual(expected, result)

    def test_convert_osinfo_to_fe_model_failure_none(self):
        """Test conversion failure when osinfo is None."""

        # Execute conversion and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.converter.convert_osinfo_to_fe_model,
            None
        )

    def test_convert_osinfo_to_fe_model_failure_missing_members(self):
        """Test conversion failure when members field is missing."""

        # Configure response without members
        be_osinfo = {}

        # Execute conversion and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.converter.convert_osinfo_to_fe_model,
            be_osinfo
        )
