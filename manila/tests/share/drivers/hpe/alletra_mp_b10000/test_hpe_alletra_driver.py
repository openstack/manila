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
from manila.share.drivers.hpe.alletra_mp_b10000 import (
    hpe_alletra_driver as hpealletradriver)
from manila import test
from manila.tests.share.drivers.hpe.alletra_mp_b10000 import (
    test_hpe_alletra_driver_constants as constants)


@ddt.ddt
class HPEAlletraMPB10000ShareDriverTestCase(test.TestCase):

    def setUp(self):
        """Test Setup"""
        super(HPEAlletraMPB10000ShareDriverTestCase, self).setUp()

        # Create mock conf and safe_get()
        self.conf = mock.Mock()
        self.conf.driver_handles_share_servers = False
        self.conf.hpealletra_wsapi_url = constants.WSAPI_URL
        self.conf.hpealletra_username = constants.USERNAME
        self.conf.hpealletra_password = constants.PASSWORD
        self.conf.share_backend_name = constants.SHARE_BACKEND_NAME
        self.conf.hpealletra_debug = False

        def safe_get(attr):
            try:
                return self.conf.__getattribute__(attr)
            except AttributeError:
                return None
        self.conf.safe_get = safe_get

        # Create mock BE handler classes and mock instances for BE handlers
        self.mock_object(
            hpealletradriver.fileshare_handler,
            'FileShareHandler')
        self.mock_object(
            hpealletradriver.filesetup_handler,
            'FileSetupHandler')
        self.mock_object(
            hpealletradriver.rest_client,
            'HpeAlletraRestClient')
        self.mock_fileshare_handler = (
            hpealletradriver.fileshare_handler.FileShareHandler())
        self.mock_filesetup_handler = (
            hpealletradriver.filesetup_handler.FileSetupHandler())
        self.mock_rest_client = (
            hpealletradriver.rest_client.HpeAlletraRestClient())
        self.mock_private_storage = mock.Mock()

        # Init alletra b10000 driver
        self.driver = hpealletradriver.HPEAlletraMPB10000ShareDriver(
            configuration=self.conf)

        # Replace the private storage handler with mock
        self.driver.privatestorage_handler = mock.Mock()
        self.driver.privatestorage_handler.update_share_by_id = (
            self.mock_private_storage.update_share_by_id)
        self.driver.privatestorage_handler.get_share_by_id = (
            self.mock_private_storage.get_share_by_id)
        self.driver.privatestorage_handler.delete_share_by_id = (
            self.mock_private_storage.delete_share_by_id)

    def test_conf_safe_get_existing_attr(self):
        """Test safe_get returns value for existing attribute."""
        result = self.conf.safe_get('hpealletra_wsapi_url')
        self.assertEqual(constants.WSAPI_URL, result)

    def test_conf_safe_get_missing_attr(self):
        """Test safe_get returns None for missing attribute."""
        result = self.conf.safe_get('nonexistent_attribute')
        self.assertIsNone(result)

    def init_driver(self):
        """Helper to set up the driver with mock handlers for testing."""

        # Initialize mock handlers for rest, fileshare, filesetup. Real handler
        # for driverhelper
        self.driver.rest_client = self.mock_rest_client
        self.driver.fileshare_handler = self.mock_fileshare_handler
        self.driver.filesetup_handler = self.mock_filesetup_handler
        # Init actual driver helper object with mock rest_clints
        self.driver.driver_helper = (
            hpealletradriver.HPEAlletraMPB10000ShareDriverHelper(
                self.driver.rest_client))

        # To do: Check this. Mock share_types if the driver uses it
        self.mock_object(hpealletradriver, 'share_types')
        get_extra_specs = (
            hpealletradriver.share_types.get_extra_specs_from_share)
        get_extra_specs.return_value = {}  # Or use constants if available

    # do_setup()
    def test_driver_setup_success(self):
        """Test successful driver setup (do_setup)."""

        # Reset older mock counts
        hpealletradriver.rest_client.HpeAlletraRestClient.reset_mock()
        hpealletradriver.filesetup_handler.FileSetupHandler.reset_mock()
        hpealletradriver.fileshare_handler.FileShareHandler.reset_mock()

        # Configure mocks
        self.mock_rest_client.session_key = None
        self.mock_rest_client.authenticate.return_value = (True, 200)

        mock_systems = {'version': '10.5.0'}
        mock_osinfo = {'be_is_fileservice_supported': True}
        mock_fileservice = {'be_is_fileservice_enabled': True}
        self.mock_filesetup_handler.get_systems.return_value = (
            mock_systems)
        self.mock_filesetup_handler.get_osinfo.return_value = (
            mock_osinfo)
        self.mock_filesetup_handler.get_fileservice.return_value = (
            mock_fileservice)

        # Execute do_setup
        context = None
        self.driver.do_setup(context)

        # Verify BE calls
        hpealletradriver.rest_client.HpeAlletraRestClient \
            .assert_called_once_with(
                constants.WSAPI_URL, constants.USERNAME, constants.PASSWORD,
                debug=False)
        self.mock_rest_client.authenticate.assert_called_once()
        hpealletradriver.filesetup_handler.FileSetupHandler \
            .assert_called_once_with(
                self.mock_rest_client)
        hpealletradriver.fileshare_handler.FileShareHandler \
            .assert_called_once_with(
                self.mock_rest_client)
        self.mock_filesetup_handler.get_systems.assert_called_once()
        self.mock_filesetup_handler.get_osinfo.assert_called_once()
        self.mock_filesetup_handler.get_fileservice.assert_called_once()

    def test_driver_setup_with_existing_session_key(self):
        """Test successful driver(do_setup)"""

        # Reset older mock counts
        hpealletradriver.rest_client.HpeAlletraRestClient.reset_mock()
        hpealletradriver.filesetup_handler.FileSetupHandler.reset_mock()
        hpealletradriver.fileshare_handler.FileShareHandler \
            .reset_mock()

        # Set existing rest_client with session_key (simulating previous
        # do_setup)
        self.driver.rest_client = mock.Mock()
        self.driver.rest_client.session_key = 'existing_session_key'

        # Configure mocks - no authentication needed since reusing session
        mock_systems = {'version': '10.5.0'}
        mock_osinfo = {'be_is_fileservice_supported': True}
        mock_fileservice = {'be_is_fileservice_enabled': True}
        self.mock_filesetup_handler.get_systems.return_value = (
            mock_systems)
        self.mock_filesetup_handler.get_osinfo.return_value = (
            mock_osinfo)
        self.mock_filesetup_handler.get_fileservice.return_value = (
            mock_fileservice)

        # Execute do_setup
        context = None
        self.driver.do_setup(context)

        # Verify BE calls - rest client created but session key reused
        hpealletradriver.rest_client.HpeAlletraRestClient \
            .assert_called_once_with(
                constants.WSAPI_URL, constants.USERNAME, constants.PASSWORD,
                debug=False)
        # Authentication should not be called when reusing session key
        self.mock_rest_client.authenticate.assert_not_called()

        # Verify handlers were initialized
        hpealletradriver.filesetup_handler.FileSetupHandler \
            .assert_called_once_with(
                self.mock_rest_client)
        hpealletradriver.fileshare_handler.FileShareHandler \
            .assert_called_once_with(
                self.mock_rest_client)

        # Verify validation calls still happen
        self.mock_filesetup_handler.get_systems.assert_called_once()
        self.mock_filesetup_handler.get_osinfo.assert_called_once()
        self.mock_filesetup_handler.get_fileservice.assert_called_once()

    def test_driver_setup_with_debug_enabled(self):
        """Test driver setup with debug flag enabled."""

        # Reset older mock counts
        hpealletradriver.rest_client.HpeAlletraRestClient.reset_mock()

        # Enable debug flag in configuration
        self.conf.hpealletra_debug = True

        # Configure mocks
        self.mock_rest_client.session_key = None
        self.mock_rest_client.authenticate.return_value = (True, 200)

        mock_systems = {'version': '10.5.0'}
        mock_osinfo = {'be_is_fileservice_supported': True}
        mock_fileservice = {'be_is_fileservice_enabled': True}
        self.mock_filesetup_handler.get_systems.return_value = (
            mock_systems)
        self.mock_filesetup_handler.get_osinfo.return_value = (
            mock_osinfo)
        self.mock_filesetup_handler.get_fileservice.return_value = (
            mock_fileservice)

        # Execute do_setup
        context = None
        self.driver.do_setup(context)

        # Verify rest client was initialized with debug=True
        hpealletradriver.rest_client.HpeAlletraRestClient \
            .assert_called_once_with(
                constants.WSAPI_URL, constants.USERNAME, constants.PASSWORD,
                debug=True)
        self.mock_rest_client.authenticate.assert_called_once()

    @ddt.data('wsapi_url', 'username', 'password')
    def test_driver_setup_failure_empty_config(self, param):
        """Test driver setup failure when config parameters are empty."""

        # Set the specified config parameter to empty
        setattr(self.conf, f'hpealletra_{param}', '')

        # Execute do_setup and expect InvalidParameterValue exception
        self.assertRaises(exception.InvalidParameterValue,
                          self.driver.do_setup, None)

    def test_driver_setup_failure_authenticate(self):
        """Test driver setup failure when authentication fails."""

        # Reset older mock counts
        hpealletradriver.rest_client.HpeAlletraRestClient.reset_mock()

        # Configure mock to fail authentication
        self.mock_rest_client.authenticate.return_value = (False, 401)

        # Execute do_setup and expect HPEAlletraB10000DriverException
        self.assertRaises(exception.HPEAlletraB10000DriverException,
                          self.driver.do_setup, None)

    # create_share()
    def test_driver_create_share_success(self):
        """Test successful share creation."""

        # Configure
        self.init_driver()
        self.mock_fileshare_handler.create_fileshare.return_value = (
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )
        self.mock_fileshare_handler._get_fileshare_by_name.return_value = \
            constants.BACKEND_FILESHARE

        # Execute create_share
        context = None
        export_path = self.driver.create_share(context, constants.SHARE_INFO)

        # Verify BE handler calls
        self.mock_fileshare_handler.create_fileshare.assert_called_once_with(
            constants.SHARE_INFO,
            constants.EXPECTED_EXTRA_SPECS
        )

        self.mock_fileshare_handler._get_fileshare_by_name \
            .assert_called_once_with(
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME)

        # Verify private storage was updated with correct backend share details
        self.mock_private_storage.update_share_by_id \
            .assert_called_once_with(
                constants.EXPECTED_SHARE_ID,
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME
            )

        # Verify Return Value
        self.assertIn(constants.EXPECTED_HOST_IP, export_path[0]['path'])
        self.assertIn(constants.EXPECTED_MOUNT_PATH, export_path[0]['path'])

    def test_driver_create_share_failure_get_fileshare(self):
        """Test create_share failure when getting fileshare details fails."""

        # Configure
        self.init_driver()
        self.mock_fileshare_handler.create_fileshare.return_value = (
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )
        self.mock_fileshare_handler._get_fileshare_by_name.side_effect = \
            Exception(
                "Backend fileshare lookup failed")

        # Execute create_share and expect HPEAlletraB10000DriverException
        self.assertRaises(exception.HPEAlletraB10000DriverException,
                          self.driver.create_share, None, constants.SHARE_INFO)

    # delete_share()
    def test_driver_delete_share_success(self):
        """Test successful share deletion."""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )

        # Execute delete_share
        context = None
        self.driver.delete_share(context, constants.SHARE_INFO)

        # Verify BE and Private storage calls
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_called_once_with(
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME)
        self.mock_fileshare_handler.delete_fileshare_by_id \
            .assert_called_once_with(
                constants.EXPECTED_SHARE_ID, constants.EXPECTED_BE_SHARE_ID)

        self.mock_private_storage.delete_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )

    def test_driver_delete_share_failure_get_share_by_id(self):
        """Test delete_share when reading share from private storage fails"""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.side_effect = \
            Exception("Failed to retrieve share from private storage")

        # Execute delete_share - should not raise exception, logs error
        # and attempts to clear private storage
        context = None
        self.driver.delete_share(context, constants.SHARE_INFO)

        # Verify private storage was queried
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        # Verify comparison was not called (early return due to exception)
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_not_called()
        # Verify delete was not called (early return due to exception)
        self.mock_fileshare_handler.delete_fileshare_by_id \
            .assert_not_called()
        # Verify private storage delete was attempted despite failure
        self.mock_private_storage.delete_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )

    def test_driver_delete_share_failure_compare_be_share(self):
        """Test delete_share when BE share comparison fails."""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )
        self.mock_fileshare_handler \
            ._compare_values_with_be_share.side_effect = \
            Exception("Share not found on backend")

        # Execute delete_share - should not raise exception, logs warning
        # and clears private storage then returns
        context = None
        self.driver.delete_share(context, constants.SHARE_INFO)

        # Verify private storage was queried
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        # Verify comparison was attempted
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_called_once_with(
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME)
        # Verify delete from backend was not called (comparison failed)
        self.mock_fileshare_handler.delete_fileshare_by_id \
            .assert_not_called()
        # Verify private storage was cleared despite BE failure
        self.mock_private_storage.delete_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )

    def test_driver_delete_share_failure_delete_share_by_id(self):
        """Test delete_share when both get and private storage delete fail."""

        # Configure Mocks
        self.init_driver()
        # First, get_share_by_id fails
        self.mock_private_storage.get_share_by_id.side_effect = \
            Exception("Failed to retrieve share from private storage")
        # Then, the cleanup delete_share_by_id also fails
        self.mock_private_storage.delete_share_by_id.side_effect = \
            Exception("Failed to delete share from private storage")

        # Execute delete_share - should not raise exception, logs error
        # and attempts cleanup despite both failures
        context = None
        self.driver.delete_share(context, constants.SHARE_INFO)

        # Verify private storage was queried
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        # Verify comparison was not called (early return due to exception)
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_not_called()
        # Verify backend delete was not called (early return due to exception)
        self.mock_fileshare_handler.delete_fileshare_by_id \
            .assert_not_called()
        # Verify private storage delete was attempted despite get failure
        self.mock_private_storage.delete_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )

    # extend_share()
    def test_driver_extend_share_success(self):
        """Test successful share extension."""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )

        # Execute extend_share
        new_size = 4  # 4GB
        self.driver.extend_share(constants.SHARE_INFO, new_size)

        # Verify share_types.get_extra_specs_from_share was called
        hpealletradriver.share_types.get_extra_specs_from_share \
            .assert_called_once_with(constants.SHARE_INFO)

        # Verify Calls
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_called_once_with(
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME)
        self.mock_fileshare_handler.edit_fileshare_by_id \
            .assert_called_once_with(
                constants.EXPECTED_SHARE_ID,
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_EXTRA_SPECS,  # extra_specs
                True,  # is_extend
                constants.EXPECTED_SHARE_SIZE,  # old_size
                new_size,  # new_size
                False,  # is_access_update
                None  # access_rules
            )

    # update_access()
    def test_driver_update_access_success(self):
        """Test successful access rules update."""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )
        access_rules = [{'access_type': 'ip',
                         'access_to': '192.168.1.0/24',
                         'access_level': 'rw'}]

        # Execute update_access
        context = None
        self.driver.update_access(
            context,
            constants.SHARE_INFO,
            access_rules,
            [],
            [],
            [])

        # Verify BE and Private storage calls
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_called_once_with(
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME)
        self.mock_fileshare_handler.edit_fileshare_by_id \
            .assert_called_once_with(
                constants.EXPECTED_SHARE_ID,
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_EXTRA_SPECS,  # extra_specs
                False,  # is_extend
                None,  # old_size
                None,  # new_size
                True,  # is_access_update
                access_rules  # access_rules
            )

    def test_driver_update_access_failure_on_compare_normal_update(self):
        """Test update_access raises exception normal update."""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )
        self.mock_fileshare_handler._compare_values_with_be_share \
            .side_effect = exception.HPEAlletraB10000DriverException(
                reason="Share not found on backend")
        access_rules = [{'access_type': 'ip',
                         'access_to': '192.168.1.0/24',
                         'access_level': 'rw'}]

        # Execute update_access and expect exception
        context = None
        self.assertRaises(exception.HPEAlletraB10000DriverException,
                          self.driver.update_access,
                          context,
                          constants.SHARE_INFO,
                          access_rules,
                          [],
                          [],
                          [])

        # Verify edit was not called since compare failed
        self.mock_fileshare_handler.edit_fileshare_by_id.assert_not_called()

    def test_driver_update_access_failure_on_compare_during_deletion(self):
        """Test update_access suppresses error during deletion"""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )
        self.mock_fileshare_handler._compare_values_with_be_share \
            .side_effect = Exception("Share not found on backend")

        # Execute update_access with empty access_rules (deletion scenario)
        # Should not raise exception
        context = None
        self.driver.update_access(
            context,
            constants.SHARE_INFO,
            [],  # empty access_rules indicates deletion
            [],
            [],
            [])

        # Verify compare was attempted but edit was not called
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_called_once_with(
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME)
        self.mock_fileshare_handler.edit_fileshare_by_id.assert_not_called()

    # manage_existing()
    def test_driver_manage_existing_success(self):
        """Test successful manage existing share."""

        # Configure Mocks
        self.init_driver()
        be_filesystem_size_mib = 2048  # 2GB in MiB
        self.mock_fileshare_handler.manage_fileshare.return_value = (
            constants.BACKEND_FILESHARE,
            be_filesystem_size_mib
        )

        # Execute manage_existing
        result = self.driver.manage_existing(constants.SHARE_INFO, {})

        # Verify BE and Private storage call values
        self.mock_fileshare_handler.manage_fileshare.assert_called_once_with(
            constants.SHARE_INFO,
            constants.EXPECTED_EXTRA_SPECS
        )
        self.mock_private_storage.update_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID,
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )

        # Verify return value
        self.assertIn('size', result)
        self.assertIn('export_locations', result)
        self.assertEqual(2, result['size'])  # 2048 MiB = 2GB
        self.assertIn(
            constants.EXPECTED_HOST_IP,
            result['export_locations'][0]['path'])
        self.assertIn(
            constants.EXPECTED_MOUNT_PATH,
            result['export_locations'][0]['path'])

    # unmanage()
    def test_driver_unmanage_success(self):
        """Test successful unmanage share."""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )

        # Execute unmanage
        self.driver.unmanage(constants.SHARE_INFO)

        # Verify BE and Private storage call values
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_called_once_with(
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME)
        self.mock_private_storage.delete_share_by_id \
            .assert_called_once_with(
                constants.EXPECTED_SHARE_ID
            )

    def test_driver_unmanage_failure_private_storage(self):
        """Test unmanage when private storage retrieval fails."""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.side_effect = Exception(
            "Private storage read failed")

        # Execute unmanage - should not raise exception, just log warning and
        # return early
        self.driver.unmanage(constants.SHARE_INFO)

        # Verify private storage was queried
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        # Verify comparison was not called (early return)
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_not_called()
        # Verify private storage delete was not called (early return)
        self.mock_private_storage.delete_share_by_id.assert_not_called()

    def test_driver_unmanage_failure_be_comparison(self):
        """Test unmanage when BE comparison fails"""

        # Configure Mocks
        self.init_driver()
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )
        self.mock_fileshare_handler \
            ._compare_values_with_be_share.side_effect = \
            Exception("Share not found on backend")

        # Execute unmanage - should not raise exception, logs warning and
        # continues to delete
        self.driver.unmanage(constants.SHARE_INFO)

        # Verify private storage was queried
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        # Verify comparison was attempted
        self.mock_fileshare_handler._compare_values_with_be_share \
            .assert_called_once_with(
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME)
        # Verify private storage delete was still called (continues despite
        # BE failure)
        self.mock_private_storage.delete_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )

    # get_backend_info()
    def test_get_backend_info_returns_config_parameters(self):
        """Test get_backend_info returns all configuration parameters."""

        # Execute
        context = None
        result = self.driver.get_backend_info(context)

        # Verify all configuration parameters are returned
        expected_result = {
            'driver_version': (hpealletradriver.HPEAlletraMPB10000ShareDriver
                               .VERSION),
            'wsapi_url': constants.WSAPI_URL,
            'username': constants.USERNAME,
            'password': constants.PASSWORD,
            'debug': False,
        }
        self.assertEqual(expected_result, result)

    def test_get_backend_info_with_debug_enabled(self):
        """Test get_backend_info returns debug=True when enabled."""

        # Configure debug enabled
        self.conf.hpealletra_debug = True

        # Execute
        context = None
        result = self.driver.get_backend_info(context)

        # Verify debug is enabled in result
        self.assertTrue(result['debug'])
        self.assertEqual(result['driver_version'],
                         hpealletradriver.HPEAlletraMPB10000ShareDriver
                         .VERSION)
        self.assertEqual(result['wsapi_url'], constants.WSAPI_URL)

    # ensure_shares()
    def test_driver_ensure_shares_success(self):
        """Test successful ensure_shares with valid shares."""

        # Configure Mocks
        self.init_driver()
        backend_fileshares = [constants.BACKEND_FILESHARE]
        self.mock_fileshare_handler.get_fileshares.return_value = \
            backend_fileshares
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )
        self.mock_fileshare_handler.validator = mock.Mock()
        self.mock_fileshare_handler.validator \
            ._validate_be_share_values.return_value = None

        # Execute ensure_shares
        shares = [constants.SHARE_INFO]
        result = self.driver.ensure_shares(None, shares)

        # Verify BE and Private storage call values
        self.mock_fileshare_handler.get_fileshares.assert_called_once()
        self.mock_private_storage.get_share_by_id.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )
        self.mock_fileshare_handler.validator._validate_be_share_values \
            .assert_called_once_with(
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME,
                constants.EXPECTED_BE_SHARE_ID,
                constants.EXPECTED_BE_SHARE_NAME,
                constants.EXPECTED_BE_FILESYSTEM_NAME,
                constants.EXPECTED_BE_SHARESETTING_NAME)

        # Verify return value
        self.assertIn(constants.EXPECTED_SHARE_ID, result)
        share_update = result[constants.EXPECTED_SHARE_ID]
        self.assertEqual('available', share_update['status'])
        self.assertTrue(share_update['reapply_access_rules'])
        self.assertIn('export_locations', share_update)

    def test_driver_ensure_shares_share_not_found(self):
        """Test ensure_shares when share not found on backend."""

        # Configure Mocks
        self.init_driver()
        self.mock_fileshare_handler.get_fileshares.return_value = []
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )

        # Execute ensure_shares
        shares = [constants.SHARE_INFO]
        result = self.driver.ensure_shares(None, shares)

        # Verify result marks share as error
        self.assertIn(constants.EXPECTED_SHARE_ID, result)
        share_update = result[constants.EXPECTED_SHARE_ID]
        self.assertEqual('error', share_update['status'])
        self.assertFalse(share_update['reapply_access_rules'])

    def test_driver_ensure_shares_validation_failure(self):
        """Test ensure_shares when backend validation fails."""

        # Configure Mocks
        self.init_driver()
        backend_fileshares = [constants.BACKEND_FILESHARE]
        self.mock_fileshare_handler.get_fileshares.return_value = \
            backend_fileshares
        self.mock_private_storage.get_share_by_id.return_value = (
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )
        # Mock validator to raise exception
        self.mock_fileshare_handler.validator = mock.Mock()
        self.mock_fileshare_handler.validator \
            ._validate_be_share_values.side_effect = Exception(
                "Validation failed")

        # Execute ensure_shares
        shares = [constants.SHARE_INFO]
        result = self.driver.ensure_shares(None, shares)

        # Verify result marks share as error
        self.assertIn(constants.EXPECTED_SHARE_ID, result)
        share_update = result[constants.EXPECTED_SHARE_ID]
        self.assertEqual('error', share_update['status'])
        self.assertFalse(share_update['reapply_access_rules'])

    def test_driver_ensure_shares_private_storage_failure(self):
        """Test ensure_shares when private storage read fails."""

        # Configure Mocks
        self.init_driver()
        backend_fileshares = [constants.BACKEND_FILESHARE]
        self.mock_fileshare_handler.get_fileshares.return_value = \
            backend_fileshares
        self.mock_private_storage.get_share_by_id.side_effect = \
            Exception(
                "Private storage read failed")

        # Execute ensure_shares
        shares = [constants.SHARE_INFO]
        result = self.driver.ensure_shares(None, shares)

        # Verify share is not included in result (no update returned)
        self.assertNotIn(constants.EXPECTED_SHARE_ID, result)

    def test_driver_ensure_shares_backend_failure(self):
        """Test ensure_shares when backend fileshare retrieval fails."""

        # Configure Mocks
        self.init_driver()
        self.mock_fileshare_handler.get_fileshares.side_effect = Exception(
            "Backend connection failed")

        # Execute ensure_shares
        shares = [constants.SHARE_INFO]
        result = self.driver.ensure_shares(None, shares)

        # Verify empty result (no updates when backend fails)
        self.assertEqual({}, result)

    # _update_share_stats()
    def test_driver_update_share_stats(self):
        """Test successful share stats update."""

        # Configure Mocks
        self.init_driver()
        self.mock_filesetup_handler.get_fileservice.return_value = \
            constants.EXPECTED_FILESERVICE

        # Mock the parent class _update_share_stats method
        with mock.patch.object(hpealletradriver.driver.ShareDriver,
                               '_update_share_stats') as mock_super_update:
            # Execute _update_share_stats
            self.driver._update_share_stats()

            # Verify fileservice was queried
            self.mock_filesetup_handler.get_fileservice.assert_called_once()

            # Verify parent _update_share_stats was called with correct data
            expected_data = {
                'share_backend_name': constants.SHARE_BACKEND_NAME,
                'vendor_name': 'HPE',
                'driver_version': self.driver.VERSION,
                'storage_protocol': 'NFS',
                'total_capacity_gb': 100.0,  # 102400 MiB / 1024 = 100.0 GB
                'free_capacity_gb': 80.0,    # 81920 MiB / 1024 = 80.0 GB
                'provisioned_capacity_gb': 20.0,  # 20480 MiB / 1024 = 20.0 GB
                'max_over_subscription_ratio': 1,
                'reserved_percentage': None,
                'reserved_share_extend_percentage': None,
                'qos': False,
                'thin_provisioning': True,
                'dedupe': [True, False],
                'compression': [True, False],
                'pools': None,
                'snapshot_support': False,
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
            }
            mock_super_update.assert_called_once_with(expected_data)

    # get_network_allocations_number()
    def test_get_network_allocations_number(self):
        """Test get_network_allocations_number"""

        # Configure
        self.init_driver()

        # Execute get_network_allocations_number
        result = self.driver.get_network_allocations_number()

        # Verify return value
        self.assertEqual(0, result)


@ddt.ddt
class HPEAlletraPrivateStorageHandlerTestCase(test.TestCase):
    """Test case for HPEAlletraPrivateStorageHandler class."""

    def setUp(self):
        """Test Setup"""
        super(HPEAlletraPrivateStorageHandlerTestCase, self).setUp()

        # Create mock private storage
        self.mock_private_storage = mock.Mock()

        # Initialize handler
        self.handler = hpealletradriver.HPEAlletraPrivateStorageHandler(
            self.mock_private_storage
        )

    # update_share_by_id()
    def test_update_share_by_id_success(self):
        """Test successful update of share in private storage."""

        # Execute update_share_by_id
        self.handler.update_share_by_id(
            constants.EXPECTED_SHARE_ID,
            constants.EXPECTED_BE_SHARE_ID,
            constants.EXPECTED_BE_SHARE_NAME,
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            constants.EXPECTED_BE_SHARESETTING_NAME
        )

        # Verify private storage update was called with correct data
        expected_data = {
            'alletra_be_share_id': constants.EXPECTED_BE_SHARE_ID,
            'alletra_be_share_name': constants.EXPECTED_BE_SHARE_NAME,
            'alletra_be_filesystem_name':
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            'alletra_be_sharesetting_name':
            constants.EXPECTED_BE_SHARESETTING_NAME}
        self.mock_private_storage.update.assert_called_once_with(
            constants.EXPECTED_SHARE_ID,
            expected_data
        )

    # get_share_by_id()
    def test_get_share_by_id_success(self):
        """Test successful retrieval of share from private storage."""

        # Configure mock
        self.mock_private_storage.get.return_value = {
            'alletra_be_share_id': constants.EXPECTED_BE_SHARE_ID,
            'alletra_be_share_name': constants.EXPECTED_BE_SHARE_NAME,
            'alletra_be_filesystem_name':
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            'alletra_be_sharesetting_name':
            constants.EXPECTED_BE_SHARESETTING_NAME}

        # Execute get_share_by_id
        (be_share_id,
         be_share_name,
         be_filesystem_name,
         be_sharesetting_name) = self.handler.get_share_by_id(
            constants.EXPECTED_SHARE_ID)

        # Verify private storage get was called
        self.mock_private_storage.get.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )

        # Verify returned values
        self.assertEqual(constants.EXPECTED_BE_SHARE_ID, be_share_id)
        self.assertEqual(constants.EXPECTED_BE_SHARE_NAME, be_share_name)
        self.assertEqual(
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            be_filesystem_name)
        self.assertEqual(
            constants.EXPECTED_BE_SHARESETTING_NAME,
            be_sharesetting_name)

    def test_get_share_by_id_with_none_share_id(self):
        """Test get_share_by_id with None share_id raises InvalidInput."""

        # Execute and expect exception
        self.assertRaises(
            exception.InvalidInput,
            self.handler.get_share_by_id,
            None
        )

        # Verify private storage get was not called
        self.mock_private_storage.get.assert_not_called()

    def test_get_share_by_id_share_not_in_private_storage(self):
        """Test get_share_by_id when share not found in private storage."""

        # Configure mock to return None (key not found)
        self.mock_private_storage.get.return_value = None

        # Execute and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.get_share_by_id,
            constants.EXPECTED_SHARE_ID
        )

        # Verify private storage get was called
        self.mock_private_storage.get.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )

    def test_get_share_by_id_missing_be_share_id(self):
        """Test get_share_by_id when be_share_id is missing."""

        # Configure mock with missing be_share_id
        self.mock_private_storage.get.return_value = {
            'alletra_be_share_id': None,
            'alletra_be_share_name': constants.EXPECTED_BE_SHARE_NAME,
            'alletra_be_filesystem_name':
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            'alletra_be_sharesetting_name':
            constants.EXPECTED_BE_SHARESETTING_NAME}

        # Execute and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.get_share_by_id,
            constants.EXPECTED_SHARE_ID
        )

    def test_get_share_by_id_missing_be_share_name(self):
        """Test get_share_by_id when be_share_name is missing."""

        # Configure mock with missing be_share_name
        self.mock_private_storage.get.return_value = {
            'alletra_be_share_id': constants.EXPECTED_BE_SHARE_ID,
            'alletra_be_share_name': None,
            'alletra_be_filesystem_name':
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            'alletra_be_sharesetting_name':
            constants.EXPECTED_BE_SHARESETTING_NAME}

        # Execute and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.get_share_by_id,
            constants.EXPECTED_SHARE_ID
        )

    def test_get_share_by_id_missing_be_filesystem_name(self):
        """Test get_share_by_id when be_filesystem_name is missing."""

        # Configure mock with missing be_filesystem_name
        self.mock_private_storage.get.return_value = {
            'alletra_be_share_id': constants.EXPECTED_BE_SHARE_ID,
            'alletra_be_share_name': constants.EXPECTED_BE_SHARE_NAME,
            'alletra_be_filesystem_name': None,
            'alletra_be_sharesetting_name':
            constants.EXPECTED_BE_SHARESETTING_NAME}

        # Execute and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.get_share_by_id,
            constants.EXPECTED_SHARE_ID
        )

    def test_get_share_by_id_missing_be_sharesetting_name(self):
        """Test get_share_by_id when be_sharesetting_name is missing."""

        # Configure mock with missing be_sharesetting_name
        self.mock_private_storage.get.return_value = {
            'alletra_be_share_id': constants.EXPECTED_BE_SHARE_ID,
            'alletra_be_share_name': constants.EXPECTED_BE_SHARE_NAME,
            'alletra_be_filesystem_name':
            constants.EXPECTED_BE_FILESYSTEM_NAME,
            'alletra_be_sharesetting_name': None}

        # Execute and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.handler.get_share_by_id,
            constants.EXPECTED_SHARE_ID
        )

    # delete_share_by_id()
    def test_delete_share_by_id_success(self):
        """Test successful deletion of share from private storage."""

        # Execute delete_share_by_id
        self.handler.delete_share_by_id(constants.EXPECTED_SHARE_ID)

        # Verify private storage delete was called
        self.mock_private_storage.delete.assert_called_once_with(
            constants.EXPECTED_SHARE_ID
        )

    def test_delete_share_by_id_with_none_share_id(self):
        """Test delete_share_by_id with None share_id raises InvalidInput."""

        # Execute and expect exception
        self.assertRaises(
            exception.InvalidInput,
            self.handler.delete_share_by_id,
            None
        )

        # Verify private storage delete was not called
        self.mock_private_storage.delete.assert_not_called()


@ddt.ddt
class HPEAlletraMPB10000ShareDriverHelperTestCase(test.TestCase):
    """Test case for HPEAlletraMPB10000ShareDriverHelper class."""

    def setUp(self):
        """Test Setup"""
        super(HPEAlletraMPB10000ShareDriverHelperTestCase, self).setUp()

        # Create mock rest client
        self.mock_rest_client = mock.Mock()
        self.mock_rest_client.api_url = constants.WSAPI_URL

        # Initialize helper
        self.helper = hpealletradriver.HPEAlletraMPB10000ShareDriverHelper(
            self.mock_rest_client
        )

    # _validate_device_version()
    def test_validate_device_version_success(self):
        """Test successful device version validation."""

        # Configure mock systems data
        fe_systems = {'version': '10.5.0'}
        minimum_device_version = '10.5.0'

        # Execute validation - should not raise exception
        self.helper._validate_device_version(
            fe_systems, minimum_device_version)

    def test_validate_device_version_success_higher_version(self):
        """Test successful device version validation with higher version."""

        # Configure mock systems data with higher version
        fe_systems = {'version': '10.6.0'}
        minimum_device_version = '10.5.0'

        # Execute validation - should not raise exception
        self.helper._validate_device_version(
            fe_systems, minimum_device_version)

    def test_validate_device_version_failure_lower_major(self):
        """Test device version validation failure with lower major version."""

        # Configure mock systems data with lower major version
        fe_systems = {'version': '9.5.0'}
        minimum_device_version = '10.5.0'

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.helper._validate_device_version,
            fe_systems,
            minimum_device_version
        )

    def test_validate_device_version_failure_lower_minor(self):
        """Test device version validation failure with lower minor version."""

        # Configure mock systems data with lower minor version
        fe_systems = {'version': '10.4.0'}
        minimum_device_version = '10.5.0'

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.helper._validate_device_version,
            fe_systems,
            minimum_device_version
        )

    # _validate_is_file_service_supported()
    def test_validate_is_file_service_supported_success(self):
        """Test successful file service supported validation."""

        # Configure mock osinfo data
        fe_osinfo = {'be_is_fileservice_supported': True}

        # Execute validation - should not raise exception
        self.helper._validate_is_file_service_supported(fe_osinfo)

    def test_validate_is_file_service_supported_failure(self):
        """Test file service supported validation failure."""

        # Configure mock osinfo data with file service not supported
        fe_osinfo = {'be_is_fileservice_supported': False}

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.helper._validate_is_file_service_supported,
            fe_osinfo
        )

    # _validate_is_fileservice_enabled()
    def test_validate_is_fileservice_enabled_success(self):
        """Test successful fileservice enabled validation."""

        # Configure mock fileservice data
        fe_fileservice = {'be_is_fileservice_enabled': True}

        # Execute validation - should not raise exception
        self.helper._validate_is_fileservice_enabled(fe_fileservice)

    def test_validate_is_fileservice_enabled_failure(self):
        """Test fileservice enabled validation failure."""

        # Configure mock fileservice data with fileservice not enabled
        fe_fileservice = {'be_is_fileservice_enabled': False}

        # Execute validation and expect exception
        self.assertRaises(
            exception.HPEAlletraB10000DriverException,
            self.helper._validate_is_fileservice_enabled,
            fe_fileservice
        )

    # _build_create_share_resp()
    def test_build_create_share_resp(self):
        """Test successful create share response building."""

        # Execute build_create_share_resp
        result = self.helper._build_create_share_resp(
            constants.EXPECTED_HOST_IP,
            constants.EXPECTED_MOUNT_PATH
        )

        # Verify return value
        self.assertEqual(1, len(result))
        self.assertIn('path', result[0])
        self.assertIn(constants.EXPECTED_HOST_IP, result[0]['path'])
        self.assertIn(
            constants.EXPECTED_MOUNT_PATH, result[0]['path'])

    # _build_manage_share_resp()
    def test_build_manage_share_resp(self):
        """Test successful manage share response building."""

        # Configure test data
        existing_share_size_mib = 2048  # 2GB in MiB

        # Execute build_manage_share_resp
        result = self.helper._build_manage_share_resp(
            constants.EXPECTED_HOST_IP,
            constants.EXPECTED_MOUNT_PATH,
            existing_share_size_mib
        )

        # Verify return value
        self.assertIn('size', result)
        self.assertIn('export_locations', result)
        self.assertEqual(2, result['size'])  # 2048 MiB = 2GB (ceiled)
        self.assertEqual(1, len(result['export_locations']))
        self.assertIn('path', result['export_locations'][0])
        self.assertIn(
            constants.EXPECTED_HOST_IP,
            result['export_locations'][0]['path'])
        self.assertIn(
            constants.EXPECTED_MOUNT_PATH,
            result['export_locations'][0]['path'])

    def test_build_manage_share_resp_with_fractional_size(self):
        """Test manage share response building with fractional size."""

        # Configure test data with fractional size
        existing_share_size_mib = 2030  # 2GB in MiB

        # Execute build_manage_share_resp
        result = self.helper._build_manage_share_resp(
            constants.EXPECTED_HOST_IP,
            constants.EXPECTED_MOUNT_PATH,
            existing_share_size_mib
        )

        # Verify size is ceiled
        self.assertEqual(2, result['size'])  # 2030MiB ≈ 1.98GB, ceiled to 2GB

    # _build_export_data_resp()
    def test_build_export_data_resp(self):
        """Test successful export data response building."""

        # Execute build_export_data_resp
        result = self.helper._build_export_data_resp(
            constants.EXPECTED_HOST_IP,
            constants.EXPECTED_MOUNT_PATH
        )

        # Verify return value
        self.assertEqual(1, len(result))
        self.assertIn('path', result[0])
        expected_path = constants.EXPECTED_HOST_IP + ":" + \
            constants.EXPECTED_MOUNT_PATH
        self.assertEqual(expected_path, result[0]['path'])
