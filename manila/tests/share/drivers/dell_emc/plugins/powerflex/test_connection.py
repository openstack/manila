# Copyright (c) 2023 EMC Corporation.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

import ddt
from oslo_log import log
from oslo_utils import units

from manila.common import constants as const
from manila import exception
from manila.share.drivers.dell_emc.plugins.powerflex import connection
from manila import test

LOG = log.getLogger(__name__)


@ddt.ddt
class PowerFlexTest(test.TestCase):
    """Integration test for the PowerFlex Manila driver."""

    POWERFLEX_ADDR = "192.168.0.110"
    SHARE_NAME = "Manila-UT-filesystem"
    STORAGE_POOL_ID = "28515fee00000000"
    FILESYSTEM_ID = "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3"
    NFS_EXPORT_ID = "6433a2b2-6d60-f737-9f3b-2a50fb1ccff3"
    NFS_EXPORT_NAME = "Manila-UT-filesystem"
    SNAPSHOT_NAME = "Manila-UT-filesystem-snap"
    SNAPSHOT_PATH = "Manila-UT-filesystem"
    SNAPSHOT_ID = "75758d63-2946-4c07-9118-9a6c6027d5e7"
    NAS_SERVER_IP = "192.168.11.23"

    class MockConfig(object):
        def safe_get(self, value):
            if value == "dell_nas_backend_host":
                return "192.168.0.110"
            elif value == "dell_nas_backend_port":
                return "443"
            elif value == "dell_nas_login":
                return "admin"
            elif value == "dell_nas_password":
                return "pwd"
            elif value == "powerflex_storage_pool":
                return "Env8-SP-SW_SSD-1"
            elif value == "powerflex_protection_domain":
                return "Env8-PD-1"
            elif value == "dell_nas_server":
                return "env8nasserver"
            else:
                return None

    @mock.patch(
        "manila.share.drivers.dell_emc.plugins.powerflex.object_manager."
        "StorageObjectManager",
        autospec=True,
    )
    def setUp(self, mock_powerflex_manager):
        super(PowerFlexTest, self).setUp()

        self._mock_powerflex_manager = mock_powerflex_manager.return_value
        self.storage_connection = connection.PowerFlexStorageConnection(LOG)

        self.mock_context = mock.Mock("Context")
        self.mock_emc_driver = mock.Mock("EmcDriver")

        self._mock_config = self.MockConfig()
        self.mock_emc_driver.attach_mock(self._mock_config, "configuration")
        self.storage_connection.connect(
            self.mock_emc_driver, self.mock_context
        )

    @mock.patch(
        "manila.share.drivers.dell_emc.plugins.powerflex.object_manager."
        "StorageObjectManager",
        autospec=True,
    )
    def test_connect(self, mock_powerflex_manager):
        storage_connection = connection.PowerFlexStorageConnection(LOG)

        # execute method under test
        storage_connection.connect(self.mock_emc_driver, self.mock_context)

        # verify connect sets driver params appropriately
        mock_config = self.MockConfig()
        server_addr = mock_config.safe_get("dell_nas_backend_host")
        self.assertEqual(server_addr, storage_connection.rest_ip)
        expected_port = int(mock_config.safe_get("dell_nas_backend_port"))
        self.assertEqual(expected_port, storage_connection.rest_port)
        self.assertEqual(
            "https://{0}:{1}".format(server_addr, expected_port),
            storage_connection.host_url,
        )
        expected_username = mock_config.safe_get("dell_nas_login")
        self.assertEqual(expected_username, storage_connection.rest_username)
        expected_password = mock_config.safe_get("dell_nas_password")
        self.assertEqual(expected_password, storage_connection.rest_password)
        expected_erify_certificates = mock_config.safe_get(
            "dell_ssl_cert_verify"
        )
        self.assertEqual(
            expected_erify_certificates, storage_connection.verify_certificate
        )

    def test_create_share_nfs(self):
        self._mock_powerflex_manager.get_storage_pool_id.return_value = (
            self.STORAGE_POOL_ID
        )
        self._mock_powerflex_manager.create_filesystem.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerflex_manager.create_nfs_export.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerflex_manager.get_nfs_export_name.return_value = (
            self.NFS_EXPORT_NAME
        )
        self._mock_powerflex_manager.get_nas_server_interfaces.return_value = (
            [self.NAS_SERVER_IP]
        )

        self.assertFalse(
            self._mock_powerflex_manager.get_storage_pool_id.called
        )
        self.assertFalse(self._mock_powerflex_manager.create_filesystem.called)
        self.assertFalse(self._mock_powerflex_manager.create_nfs_export.called)
        self.assertFalse(
            self._mock_powerflex_manager.get_nfs_export_name.called
        )

        # create the share
        share = {"name": self.SHARE_NAME, "share_proto": "NFS", "size": 8}
        locations = self.storage_connection.create_share(
            self.mock_context, share, None
        )

        # verify location and API call made
        expected_locations = [{"path": "%s:/%s" % (
            self.NAS_SERVER_IP,
            self.SHARE_NAME,
        )}]
        self.assertEqual(expected_locations, locations)
        self._mock_powerflex_manager.get_storage_pool_id.assert_called_with(
            self._mock_config.safe_get("powerflex_protection_domain"),
            self._mock_config.safe_get("powerflex_storage_pool"),
        )
        self._mock_powerflex_manager.create_filesystem.assert_called_with(
            self.STORAGE_POOL_ID,
            self._mock_config.safe_get("dell_nas_server"),
            self.SHARE_NAME,
            8 * units.Gi,
        )
        self._mock_powerflex_manager.create_nfs_export.assert_called_with(
            self.FILESYSTEM_ID, self.SHARE_NAME
        )
        self._mock_powerflex_manager.get_nfs_export_name.assert_called_with(
            self.NFS_EXPORT_ID
        )

    def test_create_share_nfs_filesystem_id_not_found(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS", "size": 8}
        self._mock_powerflex_manager.create_filesystem.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share,
            self.mock_context,
            share,
            share_server=None,
        )

    def test_create_share_nfs_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS", "size": 8}
        self._mock_powerflex_manager.create_nfs_export.return_value = False

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share,
            self.mock_context,
            share,
            share_server=None,
        )

    def test_create_snapshot(self):
        self._mock_powerflex_manager.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerflex_manager.create_snapshot.return_value = True

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SNAPSHOT_PATH,
            "id": self.SNAPSHOT_ID,
        }
        self.storage_connection.create_snapshot(
            self.mock_context, snapshot, None
        )

        # verify the create snapshot API call is executed
        self._mock_powerflex_manager.get_fsid_from_export_name. \
            assert_called_with(
                self.SNAPSHOT_PATH
            )
        self._mock_powerflex_manager.create_snapshot.assert_called_with(
            self.SNAPSHOT_NAME, self.FILESYSTEM_ID
        )

    def test_create_snapshot_failure(self):
        self._mock_powerflex_manager.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerflex_manager.create_snapshot.return_value = False

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SNAPSHOT_PATH,
            "id": self.SNAPSHOT_ID,
        }
        self.storage_connection.create_snapshot(
            self.mock_context, snapshot, None
        )

    def test_delete_share_nfs(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        self._mock_powerflex_manager.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        self.assertFalse(self._mock_powerflex_manager.get_filesystem_id.called)
        self.assertFalse(self._mock_powerflex_manager.delete_filesystem.called)

        # delete the share
        self.storage_connection.delete_share(self.mock_context, share, None)

        # verify share delete
        self._mock_powerflex_manager.get_filesystem_id.assert_called_with(
            self.SHARE_NAME
        )
        self._mock_powerflex_manager.delete_filesystem.assert_called_with(
            self.FILESYSTEM_ID
        )

    def test_delete_nfs_share_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        self._mock_powerflex_manager.delete_filesystem.return_value = False
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.delete_share,
            self.mock_context,
            share,
            None,
        )

    def test_delete_nfs_share_share_does_not_exist(self):
        self._mock_powerflex_manager.get_filesystem_id.return_value = None
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        # verify the calling delete on a non-existent share returns and does
        # not throw exception
        self.storage_connection.delete_share(self.mock_context, share, None)
        self.assertTrue(self._mock_powerflex_manager.get_filesystem_id.called)
        self.assertFalse(self._mock_powerflex_manager.delete_filesystem.called)

    def test_delete_snapshot(self):
        self._mock_powerflex_manager.get_fsid_from_snapshot_name. \
            return_value = (
                self.FILESYSTEM_ID
            )

        self.assertFalse(
            self._mock_powerflex_manager.get_fsid_from_snapshot_name.called
        )
        self.assertFalse(self._mock_powerflex_manager.delete_filesystem.called)

        # delete the created snapshot
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SNAPSHOT_PATH,
            "id": self.SNAPSHOT_ID,
        }
        self.storage_connection.delete_snapshot(
            self.mock_context, snapshot, None
        )

        # verify the API call was made to delete the snapshot
        self._mock_powerflex_manager.get_fsid_from_snapshot_name. \
            assert_called_with(
                self.SNAPSHOT_NAME
            )
        self._mock_powerflex_manager.delete_filesystem.assert_called_with(
            self.FILESYSTEM_ID
        )

    def test_delete_snapshot_backend_failure(self):
        self._mock_powerflex_manager.get_fsid_from_snapshot_name. \
            return_value = (
                self.FILESYSTEM_ID
            )
        self._mock_powerflex_manager.delete_filesystem.return_value = False

        self.assertFalse(
            self._mock_powerflex_manager.get_fsid_from_snapshot_name.called
        )
        self.assertFalse(self._mock_powerflex_manager.delete_filesystem.called)

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SNAPSHOT_PATH,
            "id": self.SNAPSHOT_ID,
        }
        # verify the API call was made to delete the snapshot
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.delete_snapshot,
            self.mock_context,
            snapshot,
            None,
        )
        self._mock_powerflex_manager.get_fsid_from_snapshot_name. \
            assert_called_with(
                self.SNAPSHOT_NAME
            )
        self._mock_powerflex_manager.delete_filesystem.assert_called_with(
            self.FILESYSTEM_ID
        )

    def test_extend_share(self):
        new_share_size = 20
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": new_share_size,
        }
        self._mock_powerflex_manager.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self.assertFalse(self._mock_powerflex_manager.get_filesystem_id.called)

        self.storage_connection.extend_share(share, new_share_size)

        self._mock_powerflex_manager.get_filesystem_id.assert_called_with(
            self.SHARE_NAME
        )
        expected_quota_size = new_share_size * units.Gi
        self._mock_powerflex_manager.extend_export.assert_called_once_with(
            self.FILESYSTEM_ID, expected_quota_size
        )

    def test_update_access_add_nfs(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        self._mock_powerflex_manager.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerflex_manager.set_export_access.return_value = True

        self.assertFalse(self._mock_powerflex_manager.get_nfs_export_id.called)
        self.assertFalse(self._mock_powerflex_manager.set_export_access.called)

        nfs_rw_ip = "192.168.0.10"
        nfs_ro_ip = "192.168.0.11"
        nfs_access_rw = {
            "access_type": "ip",
            "access_to": nfs_rw_ip,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        nfs_access_ro = {
            "access_type": "ip",
            "access_to": nfs_ro_ip,
            "access_level": const.ACCESS_LEVEL_RO,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        access_rules = [nfs_access_rw, nfs_access_ro]

        self.storage_connection.update_access(
            self.mock_context,
            share,
            access_rules,
            add_rules=None,
            delete_rules=None,
            share_server=None,
        )

        self._mock_powerflex_manager.get_nfs_export_id.assert_called_once_with(
            self.SHARE_NAME
        )
        self._mock_powerflex_manager.set_export_access.assert_called_once_with(
            self.NFS_EXPORT_ID, {nfs_rw_ip}, {nfs_ro_ip}
        )

    def test_update_access_add_nfs_invalid_acess_type(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "display_name": "foo_display_name",
        }

        nfs_rw_ip = "192.168.0.10"
        nfs_ro_ip = "192.168.0.11"
        nfs_access_rw = {
            "access_type": "invalid_type",
            "access_to": nfs_rw_ip,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        nfs_access_ro = {
            "access_type": "invalid_type",
            "access_to": nfs_ro_ip,
            "access_level": const.ACCESS_LEVEL_RO,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd09",
        }
        access_rules = [nfs_access_rw, nfs_access_ro]

        self._mock_powerflex_manager.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )

        access_updates = self.storage_connection.update_access(
            self.mock_context,
            share,
            access_rules,
            add_rules=None,
            delete_rules=None,
            share_server=None,
        )

        self._mock_powerflex_manager.set_export_access.assert_called_once_with(
            self.NFS_EXPORT_ID, set(), set()
        )

        self.assertIsNotNone(access_updates)

    def test_update_access_add_nfs_backend_failure(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "display_name": "foo_display_name",
        }

        self._mock_powerflex_manager.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerflex_manager.set_export_access.return_value = False

        self.assertFalse(self._mock_powerflex_manager.get_nfs_export_id.called)
        self.assertFalse(self._mock_powerflex_manager.set_export_access.called)

        nfs_rw_ip = "192.168.0.10"
        nfs_ro_ip = "192.168.0.11"
        nfs_access_rw = {
            "access_type": "ip",
            "access_to": nfs_rw_ip,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        nfs_access_ro = {
            "access_type": "ip",
            "access_to": nfs_ro_ip,
            "access_level": const.ACCESS_LEVEL_RO,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        access_rules = [nfs_access_rw, nfs_access_ro]

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.update_access,
            self.mock_context,
            share,
            access_rules,
            add_rules=None,
            delete_rules=None,
            share_server=None,
        )

    def test_update_share_stats(self):
        data = dict(
            share_backend_name='powerflex',
            vendor_name='Dell EMC',
            storage_protocol='NFS_CIFS',
            snapshot_support=True,
            create_share_from_snapshot_support=True)
        stats = dict(
            maxCapacityInKb=4826330112,
            capacityInUseInKb=53217280,
            netUnusedCapacityInKb=1566080512,
            primaryVacInKb=184549376)

        self._mock_powerflex_manager.get_storage_pool_id.return_value = (
            self.STORAGE_POOL_ID
        )
        self._mock_powerflex_manager.get_storage_pool_statistic. \
            return_value = stats
        self.storage_connection.update_share_stats(data)
        self.assertEqual(data['storage_protocol'], 'NFS')
        self.assertEqual(data['create_share_from_snapshot_support'], False)
        self.assertEqual(data['driver_version'], connection.VERSION)
        self.assertIsNotNone(data['pools'])

    def test_get_default_filter_function(self):
        filter = self.storage_connection.get_default_filter_function()
        self.assertEqual(filter, "share.size >= 3")

    def test_create_share_from_snapshot(self):
        self.assertRaises(
            NotImplementedError,
            self.storage_connection.create_share_from_snapshot,
            self.mock_context,
            share=None,
            snapshot=None,
        )

    def test_allow_access(self):
        self.assertRaises(
            NotImplementedError,
            self.storage_connection.allow_access,
            self.mock_context,
            share=None,
            access=None,
            share_server=None,
        )

    def test_deny_access(self):
        self.assertRaises(
            NotImplementedError,
            self.storage_connection.deny_access,
            self.mock_context,
            share=None,
            access=None,
            share_server=None,
        )

    def test_setup_server(self):
        self.assertRaises(
            NotImplementedError,
            self.storage_connection.setup_server,
            network_info=None,
        )

    def test_teardown_server(self):
        self.assertRaises(
            NotImplementedError,
            self.storage_connection.teardown_server,
            server_details=None,
        )
