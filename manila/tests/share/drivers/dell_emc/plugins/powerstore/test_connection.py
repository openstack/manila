# Copyright (c) 2026 Dell Inc. or its subsidiaries.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import math
from unittest import mock

from oslo_log import log
from oslo_utils import units

from manila.common import constants as const
from manila import coordination
from manila import exception
from manila.share.drivers.dell_emc.plugins.powerstore import connection
from manila import test

LOG = log.getLogger(__name__)


class PowerStoreTest(test.TestCase):
    """Unit test for the PowerStore Manila driver."""

    REST_IP = "192.168.0.110"
    NAS_SERVER_NAME = "powerstore-nasserver"
    NAS_SERVER_ID = "6423d56e-eaf3-7424-be0b-1a9efb93188b"
    NAS_SERVER_IP = "192.168.11.23"
    SHARE_NAME = "powerstore-share"
    SHARE_SIZE_GB = 3
    SHARE_NEW_SIZE_GB = 6
    FILESYSTEM_ID = "6454e9a9-a698-e9bc-ca61-1a9efb93188b"
    NFS_EXPORT_ID = "6454ec18-7b8d-1532-1b8a-1a9efb93188b"
    SMB_SHARE_ID = "64927ae9-3403-6930-a784-f227b9987c54"
    RW_HOSTS = "192.168.1.10"
    RO_HOSTS = "192.168.1.11"
    RW_USERS = "user_1"
    RO_USERS = "user_2"
    SNAPSHOT_NAME = "powerstore-share-snap"
    SNAPSHOT_ID = "6454ea29-09c3-030e-cfc3-1a9efb93188b"
    CLONE_ID = "64560f05-e677-ec2a-7fcf-1a9efb93188b"
    CLONE_NAME = "powerstore-nfs-share-snap-clone"

    class MockConfig(object):
        def safe_get(self, value):
            if value == "dell_nas_backend_host":
                return "192.168.0.110"
            elif value == "dell_nas_login":
                return "admin"
            elif value == "dell_nas_password":
                return "pwd"
            elif value == "dell_nas_server":
                return "powerstore-nasserver"
            elif value == "dell_ad_domain":
                return "domain_name"
            elif value == "dell_ssl_cert_verify":
                return True
            elif value == "dell_ssl_cert_path":
                return "powerstore_cert_path"

    @mock.patch(
        "manila.share.drivers.dell_emc.plugins.powerstore.client."
        "PowerStoreClient",
        autospec=True,
    )
    def setUp(self, mock_powerstore_client):
        super(PowerStoreTest, self).setUp()

        self._mock_powerstore_client = mock_powerstore_client.return_value
        self.storage_connection = connection.PowerStoreStorageConnection(LOG)

        self.mock_context = mock.Mock("Context")
        self.mock_emc_driver = mock.Mock("EmcDriver")

        self._mock_config = self.MockConfig()
        self.mock_emc_driver.attach_mock(self._mock_config, "configuration")
        self.storage_connection.connect(
            self.mock_emc_driver, self.mock_context
        )

    def test_connect(self):
        storage_connection = connection.PowerStoreStorageConnection(LOG)

        # execute method under test
        storage_connection.connect(self.mock_emc_driver, self.mock_context)

        # verify connect sets driver params appropriately
        mock_config = self.MockConfig()
        server_addr = mock_config.safe_get("dell_nas_backend_host")
        self.assertEqual(server_addr, storage_connection.rest_ip)
        expected_username = mock_config.safe_get("dell_nas_login")
        self.assertEqual(expected_username, storage_connection.rest_username)
        expected_password = mock_config.safe_get("dell_nas_password")
        self.assertEqual(expected_password, storage_connection.rest_password)
        expected_nas_server = mock_config.safe_get("dell_nas_server")
        self.assertEqual(expected_nas_server, storage_connection.nas_server)
        expected_ad_domain = mock_config.safe_get("dell_ad_domain")
        self.assertEqual(expected_ad_domain, storage_connection.ad_domain)
        expected_verify_certificate = mock_config.safe_get(
            "dell_ssl_cert_verify"
        )
        self.assertEqual(
            expected_verify_certificate, storage_connection.verify_certificate
        )

    def test_create_share_nfs(self):
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.create_filesystem.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.create_nfs_export.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )

        self.assertFalse(self._mock_powerstore_client.get_nas_server_id.called)
        self.assertFalse(self._mock_powerstore_client.create_filesystem.called)
        self.assertFalse(self._mock_powerstore_client.create_nfs_export.called)
        self.assertFalse(
            self._mock_powerstore_client.get_nas_server_interfaces.called
        )

        # create the share
        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "size": self.SHARE_SIZE_GB}
        locations = self.storage_connection.create_share(
            self.mock_context,
            share,
            None
        )

        # verify location and API call made
        expected_locations = [
            {"path": "%s:/%s" % (
                self.NAS_SERVER_IP,
                self.SHARE_NAME,
                ),
             "metadata": {
                 "preferred": True}}]
        self.assertEqual(expected_locations, locations)
        self._mock_powerstore_client.get_nas_server_id.assert_called_with(
            self._mock_config.safe_get("dell_nas_server")
        )
        self._mock_powerstore_client.create_filesystem.assert_called_with(
            self.NAS_SERVER_ID,
            self.SHARE_NAME,
            self.SHARE_SIZE_GB * units.Gi,
        )
        self._mock_powerstore_client.create_nfs_export.assert_called_with(
            self.FILESYSTEM_ID, self.SHARE_NAME
        )
        self._mock_powerstore_client.get_nas_server_interfaces. \
            assert_called_with(
                self.NAS_SERVER_ID
            )

    def test_create_share_cifs(self):
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.create_filesystem.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.create_smb_share.return_value = (
            self.SMB_SHARE_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )

        self.assertFalse(self._mock_powerstore_client.get_nas_server_id.called)
        self.assertFalse(self._mock_powerstore_client.create_filesystem.called)
        self.assertFalse(self._mock_powerstore_client.create_smb_share.called)
        self.assertFalse(
            self._mock_powerstore_client.get_nas_server_interfaces.called
        )

        # create the share
        share = {"name": self.SHARE_NAME, "share_proto": "CIFS",
                 "size": self.SHARE_SIZE_GB}
        locations = self.storage_connection.create_share(
            self.mock_context,
            share,
            None
        )

        # verify location and API call made
        expected_locations = [
            {"path": "\\\\%s\\%s" % (
                self.NAS_SERVER_IP,
                self.SHARE_NAME),
             "metadata": {
                 "preferred": True}}]
        self.assertEqual(expected_locations, locations)
        self._mock_powerstore_client.get_nas_server_id.assert_called_with(
            self._mock_config.safe_get("dell_nas_server")
        )
        self._mock_powerstore_client.create_filesystem.assert_called_with(
            self.NAS_SERVER_ID,
            self.SHARE_NAME,
            self.SHARE_SIZE_GB * units.Gi,
        )
        self._mock_powerstore_client.create_smb_share.assert_called_with(
            self.FILESYSTEM_ID, self.SHARE_NAME
        )
        self._mock_powerstore_client.get_nas_server_interfaces. \
            assert_called_with(
                self.NAS_SERVER_ID
            )

    def test_create_share_filesystem_id_not_found(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "size": self.SHARE_SIZE_GB}
        self._mock_powerstore_client.create_filesystem.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share,
            self.mock_context,
            share,
            share_server=None
        )

    def test_create_share_nfs_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "size": self.SHARE_SIZE_GB}
        self._mock_powerstore_client.create_nfs_export.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share,
            self.mock_context,
            share,
            share_server=None
        )

    def test_create_share_cifs_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": "CIFS",
                 "size": self.SHARE_SIZE_GB}
        self._mock_powerstore_client.create_smb_share.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share,
            self.mock_context,
            share,
            share_server=None
        )

    def test_delete_share_nfs(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        self.assertFalse(self._mock_powerstore_client.get_filesystem_id.called)
        self.assertFalse(self._mock_powerstore_client.delete_filesystem.called)

        # delete the share
        self.storage_connection.delete_share(self.mock_context, share, None)

        # verify share delete
        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            self.SHARE_NAME
        )
        self._mock_powerstore_client.delete_filesystem.assert_called_with(
            self.FILESYSTEM_ID
        )

    def test_delete_nfs_share_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        self._mock_powerstore_client.delete_filesystem.return_value = False
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.delete_share,
            self.mock_context,
            share,
            None,
        )

    def test_delete_nfs_share_share_does_not_exist(self):
        self._mock_powerstore_client.get_filesystem_id.return_value = None
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            None
        )
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        # verify the calling delete on a non-existent share returns and does
        # not throw exception
        self.storage_connection.delete_share(self.mock_context, share, None)
        self.assertTrue(self._mock_powerstore_client.get_filesystem_id.called)
        self.assertFalse(self._mock_powerstore_client.delete_filesystem.called)

    def test_extend_share(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_NEW_SIZE_GB,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.resize_filesystem.return_value = (
            True, None
        )
        self.assertFalse(self._mock_powerstore_client.get_filesystem_id.called)

        self.storage_connection.extend_share(share, self.SHARE_NEW_SIZE_GB,
                                             self.NAS_SERVER_NAME)

        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            self.SHARE_NAME
        )
        expected_quota_size = self.SHARE_NEW_SIZE_GB * units.Gi
        self._mock_powerstore_client.resize_filesystem.assert_called_once_with(
            self.FILESYSTEM_ID, expected_quota_size
        )

    def test_shrink_share(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.resize_filesystem.return_value = (
            True, None
        )
        self.assertFalse(self._mock_powerstore_client.get_filesystem_id.called)

        self.storage_connection.shrink_share(share, self.SHARE_NEW_SIZE_GB,
                                             self.NAS_SERVER_NAME)

        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            self.SHARE_NAME
        )
        expected_quota_size = self.SHARE_NEW_SIZE_GB * units.Gi
        self._mock_powerstore_client.resize_filesystem.assert_called_once_with(
            self.FILESYSTEM_ID, expected_quota_size
        )

    def test_shrink_share_failure(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
            "id": self.CLONE_ID
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.resize_filesystem.return_value = (
            False, "msg"
        )

        self.assertRaises(
            exception.ShareShrinkingPossibleDataLoss,
            self.storage_connection.shrink_share,
            share,
            self.SHARE_NEW_SIZE_GB,
            self.NAS_SERVER_NAME
        )

    def test_shrink_share_backend_failure(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.resize_filesystem.return_value = (
            False, None
        )

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.shrink_share,
            share,
            self.SHARE_NEW_SIZE_GB,
            self.NAS_SERVER_NAME
        )

    def test_update_access_add_nfs(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.set_export_access.return_value = True

        self.assertFalse(self._mock_powerstore_client.get_nfs_export_id.called)
        self.assertFalse(self._mock_powerstore_client.set_export_access.called)

        nfs_access_rw = {
            "access_type": "ip",
            "access_to": self.RW_HOSTS,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        nfs_access_ro = {
            "access_type": "ip",
            "access_to": self.RO_HOSTS,
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

        self._mock_powerstore_client.get_nfs_export_id.assert_called_once_with(
            self.SHARE_NAME
        )
        self._mock_powerstore_client.set_export_access.assert_called_once_with(
            self.NFS_EXPORT_ID, {self.RW_HOSTS}, {self.RO_HOSTS}
        )

    def test_update_access_add_cifs(self):
        share = {"name": self.SHARE_NAME, "share_proto": "CIFS"}

        self._mock_powerstore_client.get_smb_share_id.return_value = (
            self.SMB_SHARE_ID
        )
        self._mock_powerstore_client.set_acl.return_value = True

        self.assertFalse(self._mock_powerstore_client.get_smb_share_id.called)
        self.assertFalse(self._mock_powerstore_client.set_acl.called)

        cifs_access_rw = {
            "access_type": "user",
            "access_to": self.RW_USERS,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        cifs_access_ro = {
            "access_type": "user",
            "access_to": self.RO_USERS,
            "access_level": const.ACCESS_LEVEL_RO,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        access_rules = [cifs_access_rw, cifs_access_ro]

        self.storage_connection.update_access(
            self.mock_context,
            share,
            access_rules,
            add_rules=None,
            delete_rules=None,
            share_server=None,
        )

        self._mock_powerstore_client.get_smb_share_id.assert_called_once_with(
            self.SHARE_NAME
        )
        self._mock_powerstore_client.set_acl.assert_called_once_with(
            self.SMB_SHARE_ID, {'domain_name\\user_1'}, {'domain_name\\user_2'}
        )

    def test_update_access_invalid_prefix(self):
        share = {"name": self.SHARE_NAME, "share_proto": "CIFS"}

        self._mock_powerstore_client.get_smb_share_id.return_value = (
            self.SMB_SHARE_ID
        )
        self._mock_powerstore_client.get_nas_server_smb_netbios. \
            return_value = None

        self.assertFalse(self._mock_powerstore_client.get_smb_share_id.called)
        self.assertFalse(self._mock_powerstore_client.set_acl.called)

        cifs_access_rw = {
            "access_type": "user",
            "access_to": self.RW_USERS,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        cifs_access_ro = {
            "access_type": "user",
            "access_to": self.RO_USERS,
            "access_level": const.ACCESS_LEVEL_RO,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        access_rules = [cifs_access_rw, cifs_access_ro]

        self.storage_connection.ad_domain = None

        access_updates = self.storage_connection.update_access(
            self.mock_context,
            share,
            access_rules,
            add_rules=None,
            delete_rules=None,
            share_server=None,
        )

        self._mock_powerstore_client.set_acl.assert_called_once_with(
            self.SMB_SHARE_ID, set(), set()
        )

        self.assertIsNotNone(access_updates)

    def test_update_access_add_nfs_invalid_acess_type(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "display_name": "foo_display_name",
        }

        nfs_access_rw = {
            "access_type": "invalid_type",
            "access_to": self.RW_HOSTS,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        nfs_access_ro = {
            "access_type": "invalid_type",
            "access_to": self.RO_HOSTS,
            "access_level": const.ACCESS_LEVEL_RO,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd09",
        }
        access_rules = [nfs_access_rw, nfs_access_ro]

        self._mock_powerstore_client.get_nfs_export_id.return_value = (
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

        self._mock_powerstore_client.set_export_access.assert_called_once_with(
            self.NFS_EXPORT_ID, set(), set()
        )

        self.assertIsNotNone(access_updates)

    def test_update_access_add_cifs_invalid_acess_type(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "CIFS",
            "display_name": "foo_display_name",
        }

        cifs_access_rw = {
            "access_type": "invalid_type",
            "access_to": self.RW_USERS,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        cifs_access_ro = {
            "access_type": "invalid_type",
            "access_to": self.RO_USERS,
            "access_level": const.ACCESS_LEVEL_RO,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd09",
        }
        access_rules = [cifs_access_rw, cifs_access_ro]

        self._mock_powerstore_client.get_smb_share_id.return_value = (
            self.SMB_SHARE_ID
        )

        access_updates = self.storage_connection.update_access(
            self.mock_context,
            share,
            access_rules,
            add_rules=None,
            delete_rules=None,
            share_server=None,
        )

        self._mock_powerstore_client.set_acl.assert_called_once_with(
            self.SMB_SHARE_ID, set(), set()
        )

        self.assertIsNotNone(access_updates)

    def test_update_access_add_nfs_backend_failure(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "display_name": "foo_display_name",
        }

        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.set_export_access.return_value = False

        self.assertFalse(self._mock_powerstore_client.get_nfs_export_id.called)
        self.assertFalse(self._mock_powerstore_client.set_export_access.called)

        nfs_access_rw = {
            "access_type": "ip",
            "access_to": self.RW_HOSTS,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        nfs_access_ro = {
            "access_type": "ip",
            "access_to": self.RO_HOSTS,
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

    def test_update_access_add_cifs_backend_failure(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "CIFS",
            "display_name": "foo_display_name",
        }

        self._mock_powerstore_client.set_acl.return_value = False

        cifs_access_rw = {
            "access_type": "user",
            "access_to": self.RW_USERS,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        cifs_access_ro = {
            "access_type": "user",
            "access_to": self.RO_USERS,
            "access_level": const.ACCESS_LEVEL_RO,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }
        access_rules = [cifs_access_rw, cifs_access_ro]

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

    def test_update_share_stats(self):
        data = dict(
            share_backend_name='powerstore',
            vendor_name='Dell EMC',
            storage_protocol='NFS_CIFS',
            snapshot_support=True,
            create_share_from_snapshot_support=True)
        self._mock_powerstore_client.get_cluster_id.return_value = "0"
        self._mock_powerstore_client. \
            retreive_cluster_capacity_metrics.return_value = \
            47345047046144, 366003363027
        self.storage_connection.update_share_stats(data)
        self.assertEqual(data['storage_protocol'], 'NFS_CIFS')
        self.assertEqual(data['driver_version'], connection.VERSION)
        self.assertEqual(data['total_capacity_gb'], 44093)
        self.assertEqual(data['free_capacity_gb'], 43752)

    def test_update_share_stats_failure(self):
        data = dict(
            share_backend_name='powerstore',
            vendor_name='Dell EMC',
            storage_protocol='NFS_CIFS',
            snapshot_support=True,
            create_share_from_snapshot_support=True)
        self._mock_powerstore_client. \
            retreive_cluster_capacity_metrics.return_value = \
            None, None
        self.storage_connection.update_share_stats(data)
        self.assertIsNone(data.get('total_capacity_gb'))
        self.assertIsNone(data.get('free_capacity_gb'))

    def test_create_snapshot(self):
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client. \
            create_snapshot.return_value = self.SNAPSHOT_ID

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SHARE_NAME
        }
        result = self.storage_connection.create_snapshot(
            self.mock_context, snapshot, None
        )

        self.assertEqual(self.SNAPSHOT_NAME, result['provider_location'])
        self._mock_powerstore_client.get_filesystem_id. \
            assert_called_with(
                self.SHARE_NAME
            )
        self._mock_powerstore_client.create_snapshot.assert_called_with(
            self.FILESYSTEM_ID, self.SNAPSHOT_NAME
        )

    def test_create_snapshot_invalid_filesystem_id(self):
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            None
        )

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SHARE_NAME
        }
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_snapshot,
            self.mock_context,
            snapshot,
            None
        )

    def test_create_snapshot_backend_failure(self):
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client. \
            create_snapshot.return_value = None

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SHARE_NAME,
            "share": {
                "share_proto": "NFS"
            }
        }
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_snapshot,
            self.mock_context,
            snapshot,
            None
        )

    def test_delete_snapshot(self):
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.delete_filesystem.return_value = True

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SHARE_NAME
        }
        self.storage_connection.delete_snapshot(
            self.mock_context, snapshot, None
        )

        self._mock_powerstore_client.get_filesystem_id. \
            assert_called_with(
                self.SNAPSHOT_NAME
            )
        self._mock_powerstore_client.delete_filesystem.assert_called_with(
            self.SNAPSHOT_ID
        )

    def test_delete_snapshot_backend_failure(self):
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.delete_filesystem.return_value = False

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SHARE_NAME
        }
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.delete_snapshot,
            self.mock_context,
            snapshot,
            None
        )

    def test_revert_to_snapshot(self):
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.restore_snapshot.return_value = True

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SHARE_NAME
        }
        self.storage_connection.revert_to_snapshot(
            self.mock_context, snapshot, None, None, None
        )

        self._mock_powerstore_client.get_filesystem_id. \
            assert_called_with(
                self.SNAPSHOT_NAME
            )
        self._mock_powerstore_client.restore_snapshot.assert_called_with(
            self.SNAPSHOT_ID
        )

    def test_revert_to_snapshot_backend_failure(self):
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.restore_snapshot.return_value = False

        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": self.SHARE_NAME
        }
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.revert_to_snapshot,
            self.mock_context,
            snapshot,
            None, None, None
        )

    def test_create_share_from_snapshot_nfs(self):
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.clone_snapshot.return_value = (
            self.CLONE_ID
        )
        self._mock_powerstore_client.create_nfs_export.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )
        self._mock_powerstore_client.resize_filesystem.return_value = (
            True, None
        )
        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "size": self.SHARE_NEW_SIZE_GB}
        snapshot = {"name": self.SNAPSHOT_NAME, "size": self.SHARE_SIZE_GB}
        locations = self.storage_connection.create_share_from_snapshot(
            self.mock_context,
            share,
            snapshot
        )
        expected_locations = [
            {"path": "%s:/%s" % (
                self.NAS_SERVER_IP,
                self.SHARE_NAME,
                ),
             "metadata": {
                 "preferred": True}}]
        self.assertEqual(expected_locations, locations)
        self._mock_powerstore_client.get_nas_server_id.assert_called_with(
            self._mock_config.safe_get("dell_nas_server")
        )
        self._mock_powerstore_client.clone_snapshot.assert_called_with(
            self.SNAPSHOT_ID,
            self.SHARE_NAME
        )
        self._mock_powerstore_client.create_nfs_export.assert_called_with(
            self.CLONE_ID,
            self.SHARE_NAME
        )
        self._mock_powerstore_client.get_nas_server_interfaces. \
            assert_called_with(
                self.NAS_SERVER_ID
            )

    def test_create_share_from_snapshot_cifs(self):
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.clone_snapshot.return_value = (
            self.CLONE_ID
        )
        self._mock_powerstore_client.create_smb_share.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )
        self._mock_powerstore_client.resize_filesystem.return_value = (
            True, None
        )

        share = {"name": self.SHARE_NAME, "share_proto": "CIFS",
                 "size": self.SHARE_NEW_SIZE_GB}
        snapshot = {"name": self.SNAPSHOT_NAME, "size": self.SHARE_SIZE_GB}
        locations = self.storage_connection.create_share_from_snapshot(
            self.mock_context,
            share,
            snapshot
        )
        expected_locations = [
            {"path": "\\\\%s\\%s" % (
                self.NAS_SERVER_IP,
                self.SHARE_NAME),
             "metadata": {
                 "preferred": True}}]
        self.assertEqual(expected_locations, locations)
        self._mock_powerstore_client.get_nas_server_id.assert_called_with(
            self._mock_config.safe_get("dell_nas_server")
        )
        self._mock_powerstore_client.clone_snapshot.assert_called_with(
            self.SNAPSHOT_ID,
            self.SHARE_NAME
        )
        self._mock_powerstore_client.create_smb_share.assert_called_with(
            self.CLONE_ID,
            self.SHARE_NAME
        )
        self._mock_powerstore_client.get_nas_server_interfaces. \
            assert_called_with(
                self.NAS_SERVER_ID
            )

    def test_create_share_from_snapshot_clone_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}
        snapshot = {"name": self.SNAPSHOT_NAME}
        self._mock_powerstore_client.clone_snapshot.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share_from_snapshot,
            self.mock_context,
            share,
            snapshot
        )

    def test_create_share_from_snapshot_export_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}
        snapshot = {"name": self.SNAPSHOT_NAME}
        self._mock_powerstore_client.create_nfs_export.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share_from_snapshot,
            self.mock_context,
            share,
            snapshot
        )

    def test_create_share_from_snapshot_share_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": "CIFS"}
        snapshot = {"name": self.SNAPSHOT_NAME}
        self._mock_powerstore_client.create_smb_share.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share_from_snapshot,
            self.mock_context,
            share,
            snapshot
        )

    def test_get_default_filter_function(self):
        filter = self.storage_connection.get_default_filter_function()
        self.assertEqual(filter, "share.size >= 3 or share.size == 0")

    # QoS tests

    def test_qos_type_support_flag(self):
        self.assertTrue(self.storage_connection.qos_type_support)

    def test_generate_qos_rule_name(self):
        name = self.storage_connection._generate_qos_rule_name(
            "fake-qos-type-id")
        self.assertEqual(name, "manila_qos_rule_fake-qos-type-id")

    def test_generate_qos_policy_name(self):
        name = self.storage_connection._generate_qos_policy_name(
            "fake-qos-type-id")
        self.assertEqual(name, "manila_qos_policy_fake-qos-type-id")

    def test_validate_qos_specs_valid(self):
        specs = {'max_bw': '100'}
        # Should not raise
        self.storage_connection._validate_qos_specs(specs)

    def test_validate_qos_specs_empty(self):
        # Should not raise for empty specs
        self.storage_connection._validate_qos_specs({})

    def test_validate_qos_specs_missing_max_bw(self):
        specs = {'some_key': 'value'}
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            specs
        )

    def test_validate_qos_specs_invalid_max_bw_not_integer(self):
        specs = {'max_bw': 'abc'}
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            specs
        )

    def test_validate_qos_specs_max_bw_too_low(self):
        specs = {'max_bw': '0'}
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            specs
        )

    def test_validate_qos_specs_max_bw_too_high(self):
        specs = {'max_bw': '1000001'}
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            specs
        )

    @mock.patch.object(coordination.LOCK_COORDINATOR, 'get_lock')
    def test_get_or_create_qos_policy_new(self, mock_get_lock):
        """Test creating new rule and policy when none exist."""
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_io_limit_rule.\
            return_value = "rule-id-123"
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_performance_policy.\
            return_value = "policy-id-456"

        policy_id = self.storage_connection._get_or_create_qos_policy(
            "fake-qos-type-id", 100)

        self.assertEqual(policy_id, "policy-id-456")
        self._mock_powerstore_client.create_file_io_limit_rule.\
            assert_called_with("manila_qos_rule_fake-qos-type-id", 100)
        self._mock_powerstore_client.create_file_performance_policy.\
            assert_called_with("manila_qos_policy_fake-qos-type-id",
                               "rule-id-123")

    @mock.patch.object(coordination.LOCK_COORDINATOR, 'get_lock')
    def test_get_or_create_qos_policy_existing(self, mock_get_lock):
        """Test reusing existing rule and policy."""
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = {'id': 'rule-id-123', 'max_bw': 100}
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = {'id': 'policy-id-456'}

        policy_id = self.storage_connection._get_or_create_qos_policy(
            "fake-qos-type-id", 100)

        self.assertEqual(policy_id, "policy-id-456")
        self._mock_powerstore_client.create_file_io_limit_rule.\
            assert_not_called()
        self._mock_powerstore_client.modify_file_io_limit_rule.\
            assert_not_called()
        self._mock_powerstore_client.create_file_performance_policy.\
            assert_not_called()

    @mock.patch.object(coordination.LOCK_COORDINATOR, 'get_lock')
    def test_get_or_create_qos_policy_update_rule(self, mock_get_lock):
        """Test updating existing rule when max_bw changed."""
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = {'id': 'rule-id-123', 'max_bw': 50}
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = {'id': 'policy-id-456'}

        policy_id = self.storage_connection._get_or_create_qos_policy(
            "fake-qos-type-id", 100)

        self.assertEqual(policy_id, "policy-id-456")
        self._mock_powerstore_client.modify_file_io_limit_rule.\
            assert_called_with('rule-id-123', 100)

    @mock.patch.object(coordination.LOCK_COORDINATOR, 'get_lock')
    def test_get_or_create_qos_policy_rule_creation_failure(
            self, mock_get_lock):
        """Test failure when rule creation fails."""
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_io_limit_rule.\
            return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection._get_or_create_qos_policy,
            "fake-qos-type-id", 100
        )

    @mock.patch.object(coordination.LOCK_COORDINATOR, 'get_lock')
    def test_get_or_create_qos_policy_policy_creation_failure(
            self, mock_get_lock):
        """Test failure when policy creation fails."""
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_io_limit_rule.\
            return_value = "rule-id-123"
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_performance_policy.\
            return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection._get_or_create_qos_policy,
            "fake-qos-type-id", 100
        )

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_create_share_nfs_with_qos(self, mock_qos_specs):
        """Test creating NFS share with QoS applied."""
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.create_filesystem.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.create_nfs_export.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )
        # QoS mocks
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_io_limit_rule.\
            return_value = "rule-id-123"
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_performance_policy.\
            return_value = "policy-id-456"
        self._mock_powerstore_client.set_filesystem_performance_policy.\
            return_value = True

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "size": self.SHARE_SIZE_GB,
                 "qos_type_id": "fake-qos-type-id"}
        locations = self.storage_connection.create_share(
            self.mock_context, share, None)

        self.assertEqual(len(locations), 1)
        self._mock_powerstore_client.set_filesystem_performance_policy.\
            assert_called_with(self.FILESYSTEM_ID, "policy-id-456")

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_create_share_qos_apply_failure(self, mock_qos_specs):
        """Test share creation fails when QoS policy cannot be applied.

        Verifies that the filesystem is cleaned up when QoS application
        fails during share creation.
        """
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.create_filesystem.return_value = (
            self.FILESYSTEM_ID
        )
        # QoS mocks - policy creation succeeds but apply fails
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = {'id': 'rule-id-123', 'max_bw': 100}
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = {'id': 'policy-id-456'}
        self._mock_powerstore_client.set_filesystem_performance_policy.\
            return_value = False

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "size": self.SHARE_SIZE_GB,
                 "qos_type_id": "fake-qos-type-id"}

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share,
            self.mock_context, share, None
        )
        # Verify filesystem is cleaned up on QoS failure
        self._mock_powerstore_client.delete_filesystem.assert_called_with(
            self.FILESYSTEM_ID)

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_delete_share_with_qos_cleanup(self, mock_qos_specs):
        """Test share deletion triggers QoS cleanup when unused."""
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.delete_filesystem.return_value = True
        # QoS cleanup mocks - policy is no longer used
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = {'id': 'policy-id-456'}
        self._mock_powerstore_client.get_policy_filesystems.\
            return_value = []
        self._mock_powerstore_client.delete_policy.return_value = True
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = {'id': 'rule-id-123'}
        self._mock_powerstore_client.delete_file_io_limit_rule.\
            return_value = True

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "qos_type_id": "fake-qos-type-id"}
        self.storage_connection.delete_share(
            self.mock_context, share, None)

        self._mock_powerstore_client.delete_policy.assert_called_with(
            'policy-id-456')
        self._mock_powerstore_client.delete_file_io_limit_rule.\
            assert_called_with('rule-id-123')

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_delete_share_qos_still_in_use(self, mock_qos_specs):
        """Test share deletion skips QoS cleanup when still in use."""
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.delete_filesystem.return_value = True
        # QoS cleanup mocks - policy is still used by another filesystem
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = {'id': 'policy-id-456'}
        self._mock_powerstore_client.get_policy_filesystems.\
            return_value = [{'id': 'other-fs-id'}]

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "qos_type_id": "fake-qos-type-id"}
        self.storage_connection.delete_share(
            self.mock_context, share, None)

        self._mock_powerstore_client.delete_policy.assert_not_called()
        self._mock_powerstore_client.delete_file_io_limit_rule.\
            assert_not_called()

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_create_share_from_snapshot_with_qos(self, mock_qos_specs):
        """Test clone from snapshot with QoS applied."""
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.clone_snapshot.return_value = (
            self.CLONE_ID
        )
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.create_nfs_export.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )
        # QoS mocks
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = {'id': 'rule-id-123', 'max_bw': 100}
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = {'id': 'policy-id-456'}
        self._mock_powerstore_client.set_filesystem_performance_policy.\
            return_value = True

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "size": self.SHARE_SIZE_GB,
                 "qos_type_id": "fake-qos-type-id"}
        snapshot = {"name": self.SNAPSHOT_NAME,
                    "size": self.SHARE_SIZE_GB}

        locations = self.storage_connection.create_share_from_snapshot(
            self.mock_context, share, snapshot)

        self.assertEqual(len(locations), 1)
        self._mock_powerstore_client.set_filesystem_performance_policy.\
            assert_called_with(self.CLONE_ID, "policy-id-456")

    def test_update_share_stats_qos_support(self):
        """Test that stats report qos_type_support."""
        self._mock_powerstore_client.get_cluster_id.return_value = "0"
        self._mock_powerstore_client.retreive_cluster_capacity_metrics.\
            return_value = (100 * units.Gi, 50 * units.Gi)

        stats_dict = {}
        self.storage_connection.update_share_stats(stats_dict)

        self.assertTrue(stats_dict['qos_type_support'])

    # QoS Validation Tests (U-001 to U-015)

    def test_validate_qos_specs_valid_bw_only(self):
        """Test QoS spec validation with only max_bw."""
        qos_specs = {"max_bw": "500"}

        # Should not raise any exception
        self.storage_connection._validate_qos_specs(qos_specs)

        # Validation should pass (no exception raised)

    def test_validate_qos_specs_empty_specs(self):
        """Test QoS spec validation with empty specs."""
        qos_specs = {}

        # Should return None for empty specs (no exception raised)
        result = self.storage_connection._validate_qos_specs(qos_specs)
        self.assertIsNone(result)

    def test_validate_qos_specs_negative_bw(self):
        """Test QoS spec validation with negative max_bw."""
        qos_specs = {"max_bw": "-1"}
        # Should raise InvalidQosTypeSpec
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            qos_specs
        )

    def test_validate_qos_specs_zero_bw(self):
        """Test QoS spec validation with zero max_bw."""
        qos_specs = {"max_bw": "0"}
        # Should raise InvalidQosTypeSpec
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            qos_specs
        )

    def test_validate_qos_specs_non_numeric_bw(self):
        """Test QoS spec validation with non-numeric max_bw."""
        qos_specs = {"max_bw": "invalid"}
        # Should raise InvalidQosTypeSpec
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            qos_specs
        )

    def test_validate_qos_specs_unsupported_key(self):
        """Test QoS spec validation with unsupported key."""
        qos_specs = {"max_bw": "500", "max_iops": "10000"}
        # Should raise InvalidQosTypeSpec
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            qos_specs
        )

    def test_validate_qos_specs_out_of_range_bw_low(self):
        """Test QoS spec validation with max_bw below range."""
        qos_specs = {"max_bw": "0"}
        # Should raise InvalidQosTypeSpec
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            qos_specs
        )

    def test_validate_qos_specs_out_of_range_bw_high(self):
        """Test QoS spec validation with max_bw above range."""
        qos_specs = {"max_bw": "1000001"}
        # Should raise InvalidQosTypeSpec
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            qos_specs
        )

    # ----------------------------------------------------------------
    # Additional QoS tests: edge cases, race conditions, cleanup safety
    # ----------------------------------------------------------------

    def test_validate_qos_specs_none_input(self):
        """Test QoS spec validation with None input."""
        result = self.storage_connection._validate_qos_specs(None)
        self.assertIsNone(result)

    def test_validate_qos_specs_boundary_min(self):
        """Test QoS spec validation with minimum valid max_bw (1)."""
        specs = {'max_bw': '1'}
        # Should not raise
        self.storage_connection._validate_qos_specs(specs)

    def test_validate_qos_specs_boundary_max(self):
        """Test QoS spec validation with maximum valid max_bw (1000000)."""
        specs = {'max_bw': '1000000'}
        # Should not raise
        self.storage_connection._validate_qos_specs(specs)

    def test_validate_qos_specs_float_string(self):
        """Test QoS spec validation with float string max_bw."""
        specs = {'max_bw': '100.5'}
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            specs
        )

    def test_validate_qos_specs_empty_string_max_bw(self):
        """Test QoS spec validation with empty string max_bw."""
        specs = {'max_bw': ''}
        self.assertRaises(
            exception.InvalidQosTypeSpec,
            self.storage_connection._validate_qos_specs,
            specs
        )

    @mock.patch.object(coordination.LOCK_COORDINATOR, 'get_lock')
    def test_get_or_create_qos_policy_lock_key_per_qos_type(
            self, mock_get_lock):
        """Test that the lock name is keyed on qos_type_id.

        Each distinct QoS type must acquire a distinct lock so that
        concurrent creates for different types don't block each other,
        while concurrent creates for the *same* type are serialised.
        """
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_io_limit_rule.\
            return_value = "rule-id-123"
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_performance_policy.\
            return_value = "policy-id-456"

        self.storage_connection._get_or_create_qos_policy(
            "fake-qos-type-id", 100)

        expected_lock_name = 'powerstore-qos-fake-qos-type-id'
        mock_get_lock.assert_called_once_with(expected_lock_name)

    @mock.patch.object(coordination.LOCK_COORDINATOR, 'get_lock')
    def test_cleanup_qos_lock_key_per_qos_type(self, mock_get_lock):
        """Test that _cleanup_qos_on_delete uses the same lock key.

        The create and delete paths must share the same lock name so that
        a delete cannot race a concurrent create for the same QoS type.
        """
        with mock.patch('manila.share.qos_types.get_specs_from_share',
                        return_value={'max_bw': '100'}):
            self._mock_powerstore_client.get_policy_by_name.\
                return_value = {'id': 'policy-id-456'}
            self._mock_powerstore_client.get_policy_filesystems.\
                return_value = []
            self._mock_powerstore_client.delete_policy.return_value = True
            self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
                return_value = {'id': 'rule-id-123'}
            self._mock_powerstore_client.delete_file_io_limit_rule.\
                return_value = True

            share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                     "qos_type_id": "fake-qos-type-id"}
            self.storage_connection._cleanup_qos_on_delete(share)

        expected_lock_name = 'powerstore-qos-fake-qos-type-id'
        mock_get_lock.assert_called_once_with(expected_lock_name)

    @mock.patch.object(coordination.LOCK_COORDINATOR, 'get_lock')
    def test_get_or_create_qos_policy_modify_rule_failure(
            self, mock_get_lock):
        """Test failure when modifying existing rule fails."""
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = {'id': 'rule-id-123', 'max_bw': 50}
        self._mock_powerstore_client.modify_file_io_limit_rule.\
            return_value = False

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection._get_or_create_qos_policy,
            "fake-qos-type-id", 100
        )
        self._mock_powerstore_client.modify_file_io_limit_rule.\
            assert_called_with('rule-id-123', 100)

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        side_effect=Exception("QoS type not found")
    )
    def test_cleanup_qos_get_specs_exception(self, mock_qos_specs):
        """Test cleanup is safe when get_specs_from_share raises."""
        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "qos_type_id": "fake-qos-type-id"}

        # Should not raise - cleanup should be exception-safe
        self.storage_connection._cleanup_qos_on_delete(share)

        # Backend cleanup methods should not be called
        self._mock_powerstore_client.get_policy_by_name.assert_not_called()

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_cleanup_qos_backend_exception(self, mock_qos_specs):
        """Test cleanup is safe when backend call raises."""
        self._mock_powerstore_client.get_policy_by_name.\
            side_effect = Exception("Connection error")

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "qos_type_id": "fake-qos-type-id"}

        # Should not raise - cleanup should be exception-safe
        self.storage_connection._cleanup_qos_on_delete(share)

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={}
    )
    def test_cleanup_qos_no_qos_specs(self, mock_qos_specs):
        """Test cleanup returns early when no QoS specs."""
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        self.storage_connection._cleanup_qos_on_delete(share)

        self._mock_powerstore_client.get_policy_by_name.assert_not_called()

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_cleanup_qos_no_qos_type_id(self, mock_qos_specs):
        """Test cleanup returns early when share has no qos_type_id."""
        share = {"name": self.SHARE_NAME, "share_proto": "NFS"}

        self.storage_connection._cleanup_qos_on_delete(share)

        self._mock_powerstore_client.get_policy_by_name.assert_not_called()

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_cleanup_qos_policy_not_found(self, mock_qos_specs):
        """Test cleanup returns early when policy doesn't exist."""
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = None

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "qos_type_id": "fake-qos-type-id"}

        self.storage_connection._cleanup_qos_on_delete(share)

        self._mock_powerstore_client.delete_policy.assert_not_called()

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_cleanup_qos_rule_not_found_after_policy_delete(
            self, mock_qos_specs):
        """Test cleanup handles missing rule after policy deletion."""
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = {'id': 'policy-id-456'}
        self._mock_powerstore_client.get_policy_filesystems.\
            return_value = []
        self._mock_powerstore_client.delete_policy.return_value = True
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = None

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "qos_type_id": "fake-qos-type-id"}

        self.storage_connection._cleanup_qos_on_delete(share)

        self._mock_powerstore_client.delete_policy.assert_called_with(
            'policy-id-456')
        self._mock_powerstore_client.delete_file_io_limit_rule.\
            assert_not_called()

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_cleanup_qos_policy_delete_failure(self, mock_qos_specs):
        """Test cleanup stops rule deletion when policy delete fails."""
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = {'id': 'policy-id-456'}
        self._mock_powerstore_client.get_policy_filesystems.\
            return_value = []
        self._mock_powerstore_client.delete_policy.return_value = False

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "qos_type_id": "fake-qos-type-id"}

        self.storage_connection._cleanup_qos_on_delete(share)

        self._mock_powerstore_client.delete_file_io_limit_rule.\
            assert_not_called()

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_create_share_cifs_with_qos(self, mock_qos_specs):
        """Test creating CIFS share with QoS applied."""
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.create_filesystem.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.create_smb_share.return_value = (
            self.SMB_SHARE_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )
        self._mock_powerstore_client.get_nas_server_smb_netbios.\
            return_value = "OPENSTACK"
        # QoS mocks
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_io_limit_rule.\
            return_value = "rule-id-123"
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = None
        self._mock_powerstore_client.create_file_performance_policy.\
            return_value = "policy-id-456"
        self._mock_powerstore_client.set_filesystem_performance_policy.\
            return_value = True

        share = {"name": self.SHARE_NAME, "share_proto": "CIFS",
                 "size": self.SHARE_SIZE_GB,
                 "qos_type_id": "fake-qos-type-id"}
        locations = self.storage_connection.create_share(
            self.mock_context, share, None)

        self.assertEqual(len(locations), 1)
        self._mock_powerstore_client.set_filesystem_performance_policy.\
            assert_called_with(self.FILESYSTEM_ID, "policy-id-456")

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        return_value={'max_bw': '100'}
    )
    def test_create_share_from_snapshot_qos_failure_cleans_filesystem(
            self, mock_qos_specs):
        """Test snapshot clone cleans filesystem on QoS failure."""
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.clone_snapshot.return_value = (
            self.CLONE_ID
        )
        # QoS mocks - policy creation succeeds but apply fails
        self._mock_powerstore_client.get_file_io_limit_rule_by_name.\
            return_value = {'id': 'rule-id-123', 'max_bw': 100}
        self._mock_powerstore_client.get_policy_by_name.\
            return_value = {'id': 'policy-id-456'}
        self._mock_powerstore_client.set_filesystem_performance_policy.\
            return_value = False

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "size": self.SHARE_SIZE_GB,
                 "qos_type_id": "fake-qos-type-id"}
        snapshot = {"name": self.SNAPSHOT_NAME,
                    "size": self.SHARE_SIZE_GB}

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share_from_snapshot,
            self.mock_context, share, snapshot, None
        )
        # Verify cloned filesystem is cleaned up on QoS failure
        self._mock_powerstore_client.delete_filesystem.assert_called_with(
            self.CLONE_ID)

    @mock.patch(
        "manila.share.qos_types.get_specs_from_share",
        side_effect=Exception("QoS type deleted")
    )
    def test_delete_share_with_qos_cleanup_exception_safe(
            self, mock_qos_specs):
        """Test share deletion succeeds even when QoS cleanup raises."""
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.delete_filesystem.return_value = True

        share = {"name": self.SHARE_NAME, "share_proto": "NFS",
                 "qos_type_id": "fake-qos-type-id"}

        # Should not raise - share deletion must succeed despite
        # QoS cleanup failure
        self.storage_connection.delete_share(
            self.mock_context, share, None)

        self._mock_powerstore_client.delete_filesystem.assert_called_with(
            self.FILESYSTEM_ID)

    def test_manage_existing_nfs_success(self):
        original_name = "fs_external_data"
        manila_name = self.SHARE_NAME
        share = {
            "name": manila_name,
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, original_name)}
            ],
        }

        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.get_filesystem_size.return_value = (
            self.SHARE_SIZE_GB * units.Gi
        )
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )

        result = self.storage_connection.manage_existing(
            share, driver_options={}
        )

        self.assertEqual(self.SHARE_SIZE_GB, result['size'])
        # Export locations use original backend name (no rename)
        expected_locations = [
            {"path": "%s:/%s" % (self.NAS_SERVER_IP, original_name),
             "metadata": {"preferred": True}}
        ]
        self.assertEqual(expected_locations, result['export_locations'])
        self._mock_powerstore_client.get_nfs_export_id.assert_called_with(
            original_name
        )
        self._mock_powerstore_client.get_fsid_from_export_name. \
            assert_called_with(original_name)
        self._mock_powerstore_client.get_filesystem_size.assert_called_with(
            self.FILESYSTEM_ID
        )

    def test_manage_existing_cifs_success(self):
        original_name = "smb_external_data"
        manila_name = self.SHARE_NAME
        share = {
            "name": manila_name,
            "share_proto": "CIFS",
            "export_locations": [
                {"path": "\\\\%s\\%s" % (self.NAS_SERVER_IP, original_name)}
            ],
        }

        self._mock_powerstore_client.get_smb_share_id.return_value = (
            self.SMB_SHARE_ID
        )
        self._mock_powerstore_client.get_fsid_from_share_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.get_filesystem_size.return_value = (
            self.SHARE_SIZE_GB * units.Gi
        )
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )

        result = self.storage_connection.manage_existing(
            share, driver_options={}
        )

        self.assertEqual(self.SHARE_SIZE_GB, result['size'])
        # Export locations use original backend name (no rename)
        expected_locations = [
            {"path": "\\\\%s\\%s" % (self.NAS_SERVER_IP, original_name),
             "metadata": {"preferred": True}}
        ]
        self.assertEqual(expected_locations, result['export_locations'])
        self._mock_powerstore_client.get_smb_share_id.assert_called_with(
            original_name
        )
        self._mock_powerstore_client.get_fsid_from_share_name. \
            assert_called_with(original_name)

    def test_manage_existing_nfs_export_not_found(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/missing_export" % self.NAS_SERVER_IP}
            ],
        }
        self._mock_powerstore_client.get_nfs_export_id.return_value = None

        self.assertRaises(
            exception.ManageInvalidShare,
            self.storage_connection.manage_existing,
            share,
            driver_options={},
        )

    def test_manage_existing_cifs_share_not_found(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "CIFS",
            "export_locations": [
                {"path": "\\\\%s\\missing_share" % self.NAS_SERVER_IP}
            ],
        }
        self._mock_powerstore_client.get_smb_share_id.return_value = None

        self.assertRaises(
            exception.ManageInvalidShare,
            self.storage_connection.manage_existing,
            share,
            driver_options={},
        )

    def test_manage_existing_nfs_filesystem_not_found(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/fs_data" % self.NAS_SERVER_IP}
            ],
        }
        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            None
        )

        self.assertRaises(
            exception.ManageInvalidShare,
            self.storage_connection.manage_existing,
            share,
            driver_options={},
        )

    def test_manage_existing_filesystem_size_not_found(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/fs_data" % self.NAS_SERVER_IP}
            ],
        }
        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.get_filesystem_size.return_value = None

        self.assertRaises(
            exception.ManageInvalidShare,
            self.storage_connection.manage_existing,
            share,
            driver_options={},
        )

    def test_manage_existing_no_export_path(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
        }

        self.assertRaises(
            exception.ManageInvalidShare,
            self.storage_connection.manage_existing,
            share,
            driver_options={},
        )

    def test_manage_existing_unsupported_protocol(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "GLUSTERFS",
            "export_locations": [
                {"path": "10.0.0.1:/vol/share1"}
            ],
        }

        self.assertRaises(
            exception.ManageInvalidShare,
            self.storage_connection.manage_existing,
            share,
            driver_options={},
        )

    def test_manage_existing_nfs_export_location_string_fallback(self):
        """Test fallback when export_locations contains plain strings."""
        original_name = "fs_external"
        manila_name = self.SHARE_NAME
        share = {
            "name": manila_name,
            "share_proto": "NFS",
            "export_locations": [
                "%s:/%s" % (self.NAS_SERVER_IP, original_name)
            ],
        }

        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.get_filesystem_size.return_value = (
            5 * units.Gi
        )
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )

        result = self.storage_connection.manage_existing(
            share, driver_options={}
        )

        self.assertEqual(5, result['size'])
        self._mock_powerstore_client.get_nfs_export_id.assert_called_with(
            original_name
        )

    def test_manage_existing_hasattr_export_location(self):
        """manage_existing handles ORM-like objects with 'path' attribute."""
        original_name = "fs_orm_style"
        mock_el = mock.MagicMock()
        mock_el.__getitem__ = mock.Mock(
            side_effect=lambda k: "%s:/%s" % (
                self.NAS_SERVER_IP, original_name)
            if k == 'path' else None)
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "export_locations": [mock_el],
        }

        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.get_filesystem_size.return_value = (
            4 * units.Gi
        )
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )

        result = self.storage_connection.manage_existing(
            share, driver_options={}
        )

        self.assertEqual(4, result['size'])
        self._mock_powerstore_client.get_nfs_export_id.assert_called_with(
            original_name
        )

    def test_manage_existing_export_location_fallback(self):
        """Test fallback to share['export_location'] when no list."""
        original_name = "fs_fallback"
        manila_name = self.SHARE_NAME
        share = {
            "name": manila_name,
            "share_proto": "NFS",
            "export_location": "%s:/%s" % (self.NAS_SERVER_IP, original_name),
        }

        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.get_filesystem_size.return_value = (
            4 * units.Gi
        )
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )

        result = self.storage_connection.manage_existing(
            share, driver_options={}
        )

        self.assertEqual(4, result['size'])
        self._mock_powerstore_client.get_nfs_export_id.assert_called_with(
            original_name
        )

    def test_get_backend_share_name_nfs_from_export_locations(self):
        """_get_backend_share_name extracts name from NFS export path."""
        share = {
            "name": "manila-generated-name",
            "share_proto": "NFS",
            "export_locations": [
                {"path": "10.0.0.1:/original_backend_name"}
            ],
        }
        result = self.storage_connection._get_backend_share_name(share)
        self.assertEqual("original_backend_name", result)

    def test_get_backend_share_name_cifs_from_export_locations(self):
        """_get_backend_share_name extracts name from CIFS export path."""
        share = {
            "name": "manila-generated-name",
            "share_proto": "CIFS",
            "export_locations": [
                {"path": "\\\\10.0.0.1\\original_smb_share"}
            ],
        }
        result = self.storage_connection._get_backend_share_name(share)
        self.assertEqual("original_smb_share", result)

    def test_get_backend_share_name_fallback_to_share_name(self):
        """Falls back to share['name'] when no export_locations."""
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
        }
        result = self.storage_connection._get_backend_share_name(share)
        self.assertEqual(self.SHARE_NAME, result)

    def test_delete_managed_nfs_share(self):
        """Delete resolves backend name from export_locations."""
        backend_name = "original_fs"
        share = {
            "name": "manila-name",
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, backend_name)}
            ],
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.delete_filesystem.return_value = True

        self.storage_connection.delete_share(self.mock_context, share, None)

        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            backend_name
        )

    def test_extend_managed_nfs_share(self):
        """Extend resolves backend name from export_locations."""
        backend_name = "original_fs"
        share = {
            "name": "manila-name",
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, backend_name)}
            ],
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.resize_filesystem.return_value = (
            True, None
        )

        self.storage_connection.extend_share(
            share, self.SHARE_NEW_SIZE_GB, None
        )

        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            backend_name
        )

    def test_update_access_managed_nfs_share(self):
        """Access update resolves backend name from export_locations."""
        backend_name = "original_fs"
        share = {
            "name": "manila-name",
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, backend_name)}
            ],
        }
        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.set_export_access.return_value = True

        nfs_access = {
            "access_type": "ip",
            "access_to": self.RW_HOSTS,
            "access_level": const.ACCESS_LEVEL_RW,
            "access_id": "09960614-8574-4e03-89cf-7cf267b0bd08",
        }

        self.storage_connection.update_access(
            self.mock_context, share, [nfs_access],
            add_rules=None, delete_rules=None, share_server=None,
        )

        self._mock_powerstore_client.get_nfs_export_id.assert_called_with(
            backend_name
        )

    def test_create_snapshot_managed_share(self):
        """Snapshot creation resolves parent share backend name."""
        backend_name = "original_fs"
        share = {
            "name": "manila-name",
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, backend_name)}
            ],
        }
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": "manila-name",
            "share": share,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.create_snapshot.return_value = (
            self.SNAPSHOT_ID
        )

        result = self.storage_connection.create_snapshot(
            self.mock_context, snapshot, None
        )

        self.assertEqual(self.SNAPSHOT_NAME, result['provider_location'])
        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            backend_name
        )

    def test_get_filesystem_id_nfs_fallback(self):
        """_get_filesystem_id falls back to NFS export lookup."""
        backend_name = "original_export"
        share = {
            "name": "manila-name",
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, backend_name)}
            ],
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = None
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )

        result = self.storage_connection._get_filesystem_id(share)

        self.assertEqual(self.FILESYSTEM_ID, result)
        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            backend_name
        )
        self._mock_powerstore_client.get_fsid_from_export_name.\
            assert_called_with(backend_name)

    def test_get_filesystem_id_cifs_fallback(self):
        """_get_filesystem_id falls back to SMB share lookup."""
        backend_name = "original_smb"
        share = {
            "name": "manila-name",
            "share_proto": "CIFS",
            "export_locations": [
                {"path": "\\\\%s\\%s" % (self.NAS_SERVER_IP, backend_name)}
            ],
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = None
        self._mock_powerstore_client.get_fsid_from_share_name.return_value = (
            self.FILESYSTEM_ID
        )

        result = self.storage_connection._get_filesystem_id(share)

        self.assertEqual(self.FILESYSTEM_ID, result)
        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            backend_name
        )
        self._mock_powerstore_client.get_fsid_from_share_name.\
            assert_called_with(backend_name)

    def test_delete_managed_nfs_share_fallback(self):
        """Delete uses NFS export fallback when filesystem name differs."""
        backend_name = "original_export"
        share = {
            "name": "manila-name",
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, backend_name)}
            ],
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = None
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.delete_filesystem.return_value = True

        self.storage_connection.delete_share(self.mock_context, share, None)

        self._mock_powerstore_client.get_fsid_from_export_name.\
            assert_called_with(backend_name)
        self._mock_powerstore_client.delete_filesystem.assert_called_with(
            self.FILESYSTEM_ID
        )

    def test_extend_managed_nfs_share_fallback(self):
        """Extend uses NFS export fallback when filesystem name differs."""
        backend_name = "original_export"
        share = {
            "name": "manila-name",
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, backend_name)}
            ],
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = None
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.resize_filesystem.return_value = (
            True, None
        )

        self.storage_connection.extend_share(
            share, self.SHARE_NEW_SIZE_GB, None
        )

        self._mock_powerstore_client.get_fsid_from_export_name.\
            assert_called_with(backend_name)
        expected_quota_size = self.SHARE_NEW_SIZE_GB * units.Gi
        self._mock_powerstore_client.resize_filesystem.assert_called_once_with(
            self.FILESYSTEM_ID, expected_quota_size
        )

    def test_create_snapshot_managed_share_fallback(self):
        """Snapshot uses NFS export fallback when filesystem name differs."""
        backend_name = "original_export"
        share = {
            "name": "manila-name",
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, backend_name)}
            ],
        }
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "share_name": "manila-name",
            "share": share,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = None
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.create_snapshot.return_value = (
            self.SNAPSHOT_ID
        )

        result = self.storage_connection.create_snapshot(
            self.mock_context, snapshot, None
        )

        self.assertEqual(self.SNAPSHOT_NAME, result['provider_location'])
        self._mock_powerstore_client.get_fsid_from_export_name.\
            assert_called_with(backend_name)
        self._mock_powerstore_client.create_snapshot.assert_called_with(
            self.FILESYSTEM_ID, self.SNAPSHOT_NAME
        )

    def test_get_backend_share_name_object_with_path_attr(self):
        """_get_backend_share_name handles objects with a 'path' attribute."""
        mock_el = mock.MagicMock()
        mock_el.__getitem__ = mock.Mock(
            side_effect=lambda k: "10.0.0.1:/my_export" if k == 'path'
            else None)
        share = {
            "name": "manila-name",
            "share_proto": "NFS",
            "export_locations": [mock_el],
        }
        result = self.storage_connection._get_backend_share_name(share)
        self.assertEqual("my_export", result)

    def test_get_backend_share_name_str_fallback(self):
        """_get_backend_share_name uses str() for non-dict non-object els."""
        share = {
            "name": "fallback_name",
            "share_proto": "NFS",
            "export_locations": [None],
        }
        result = self.storage_connection._get_backend_share_name(share)
        self.assertEqual("fallback_name", result)

    def test_get_backend_share_name_exception_fallback(self):
        """_get_backend_share_name falls back to share name on exception."""
        share = {
            "name": "fallback_name",
            "share_proto": "NFS",
            "export_locations": True,
        }
        result = self.storage_connection._get_backend_share_name(share)
        self.assertEqual("fallback_name", result)

    def test_parse_share_name_from_path_nfs(self):
        """_parse_share_name_from_path extracts name from NFS path."""
        result = connection.PowerStoreStorageConnection.\
            _parse_share_name_from_path(
                "10.0.0.1:/my_share", "NFS")
        self.assertEqual("my_share", result)

    def test_parse_share_name_from_path_cifs(self):
        """_parse_share_name_from_path extracts name from CIFS path."""
        result = connection.PowerStoreStorageConnection.\
            _parse_share_name_from_path(
                "\\\\10.0.0.1\\my_smb_share", "CIFS")
        self.assertEqual("my_smb_share", result)

    def test_parse_share_name_from_path_unknown_protocol(self):
        """_parse_share_name_from_path returns empty for unknown protocol."""
        result = connection.PowerStoreStorageConnection.\
            _parse_share_name_from_path(
                "10.0.0.1:/my_share", "GLUSTERFS")
        self.assertEqual("", result)

    def test_parse_share_name_from_path_no_separator(self):
        """_parse_share_name_from_path returns empty when no separator."""
        result = connection.PowerStoreStorageConnection.\
            _parse_share_name_from_path(
                "just_a_name", "NFS")
        self.assertEqual("", result)

    def test_get_export_path_dict(self):
        """_get_export_path extracts path from dict export location."""
        share = {
            "export_locations": [{"path": "10.0.0.1:/share1"}],
        }
        result = self.storage_connection._get_export_path(share)
        self.assertEqual("10.0.0.1:/share1", result)

    def test_get_export_path_hasattr(self):
        """_get_export_path extracts path from ORM-like object."""
        mock_el = mock.MagicMock()
        mock_el.__getitem__ = mock.Mock(
            side_effect=lambda k: "10.0.0.1:/share2" if k == 'path'
            else None)
        share = {"export_locations": [mock_el]}
        result = self.storage_connection._get_export_path(share)
        self.assertEqual("10.0.0.1:/share2", result)

    def test_get_export_path_str_fallback(self):
        """_get_export_path uses str() for plain string elements."""
        share = {
            "export_locations": ["10.0.0.1:/share3"],
        }
        result = self.storage_connection._get_export_path(share)
        self.assertEqual("10.0.0.1:/share3", result)

    def test_get_export_path_export_location_fallback(self):
        """_get_export_path falls back to share['export_location']."""
        share = {
            "export_location": "10.0.0.1:/fallback_share",
        }
        result = self.storage_connection._get_export_path(share)
        self.assertEqual("10.0.0.1:/fallback_share", result)

    def test_get_export_path_empty(self):
        """_get_export_path returns empty string when nothing available."""
        share = {}
        result = self.storage_connection._get_export_path(share)
        self.assertEqual("", result)

    def test_manage_existing_size_rounds_up(self):
        """manage_existing uses math.ceil so 3.5 GiB reports as 4 GB."""
        original_name = "fs_fractional"
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "export_locations": [
                {"path": "%s:/%s" % (self.NAS_SERVER_IP, original_name)}
            ],
        }
        fractional_bytes = int(3.5 * units.Gi)
        self._mock_powerstore_client.get_nfs_export_id.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_fsid_from_export_name.return_value = (
            self.FILESYSTEM_ID
        )
        self._mock_powerstore_client.get_filesystem_size.return_value = (
            fractional_bytes
        )
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )

        result = self.storage_connection.manage_existing(
            share, driver_options={}
        )

        self.assertEqual(math.ceil(fractional_bytes / units.Gi),
                         result['size'])
        self.assertEqual(4, result['size'])

    def test_manage_existing_unparseable_name(self):
        """manage_existing raises when name cannot be parsed from path."""
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "export_locations": [
                {"path": "just_a_bare_name_no_separator"}
            ],
        }

        self.assertRaises(
            exception.ManageInvalidShare,
            self.storage_connection.manage_existing,
            share,
            driver_options={},
        )

    def test_get_backend_share_name_exception_logs_debug(self):
        """_get_backend_share_name logs debug message on exception."""
        share = {
            "name": "fallback_name",
            "share_proto": "NFS",
            "export_locations": True,
        }
        with mock.patch.object(connection.LOG, 'debug') as mock_debug:
            result = self.storage_connection._get_backend_share_name(share)
        self.assertEqual("fallback_name", result)
        mock_debug.assert_called_once()

    def test_resize_filesystem_not_found(self):
        """_resize_filesystem raises when filesystem cannot be resolved."""
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "id": "fake-share-id",
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = None
        self._mock_powerstore_client.get_fsid_from_export_name.\
            return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.extend_share,
            share, self.SHARE_NEW_SIZE_GB, None
        )

    def test_manage_existing_snapshot_success(self):
        """Successfully manage an existing snapshot."""
        backend_snap_name = "backend_snap_001"
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
        }
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
            "share": share,
        }

        self._mock_powerstore_client.get_snapshot_filesystem.return_value = {
            "id": self.SNAPSHOT_ID,
            "parent_id": self.FILESYSTEM_ID,
            "size_total": self.SHARE_SIZE_GB * units.Gi,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        result = self.storage_connection.manage_existing_snapshot(
            snapshot, driver_options={}
        )

        self.assertEqual(self.SHARE_SIZE_GB, result['size'])
        self.assertEqual(backend_snap_name, result['provider_location'])
        self._mock_powerstore_client.get_snapshot_filesystem.\
            assert_called_with(backend_snap_name)

    def test_manage_existing_snapshot_with_driver_options_size(self):
        """Backend size takes precedence over driver_options size."""
        backend_snap_name = "backend_snap_001"
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
        }
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
            "share": share,
        }

        self._mock_powerstore_client.get_snapshot_filesystem.return_value = {
            "id": self.SNAPSHOT_ID,
            "parent_id": self.FILESYSTEM_ID,
            "size_total": self.SHARE_SIZE_GB * units.Gi,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        result = self.storage_connection.manage_existing_snapshot(
            snapshot, driver_options={"size": "10"}
        )

        self.assertEqual(self.SHARE_SIZE_GB, result['size'])

    def test_manage_existing_snapshot_no_provider_location(self):
        """Fails when provider_location is not provided."""
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
        }

        self.assertRaises(
            exception.ManageInvalidShareSnapshot,
            self.storage_connection.manage_existing_snapshot,
            snapshot,
            driver_options={},
        )

    def test_manage_existing_snapshot_not_found(self):
        """Fails when snapshot is not found on the backend."""
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": "missing_snap",
        }
        self._mock_powerstore_client.get_snapshot_filesystem.return_value = (
            None
        )

        self.assertRaises(
            exception.ManageInvalidShareSnapshot,
            self.storage_connection.manage_existing_snapshot,
            snapshot,
            driver_options={},
        )

    def test_manage_existing_snapshot_not_a_snapshot(self):
        """Fails when the filesystem has no parent (not a snapshot)."""
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": "regular_filesystem",
        }
        self._mock_powerstore_client.get_snapshot_filesystem.return_value = {
            "id": self.FILESYSTEM_ID,
            "parent_id": None,
            "size_total": self.SHARE_SIZE_GB * units.Gi,
        }

        self.assertRaises(
            exception.ManageInvalidShareSnapshot,
            self.storage_connection.manage_existing_snapshot,
            snapshot,
            driver_options={},
        )

    def test_manage_existing_snapshot_parent_mismatch(self):
        """Fails when snapshot's parent doesn't match the share."""
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
        }
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": "snap_wrong_parent",
            "share": share,
        }
        self._mock_powerstore_client.get_snapshot_filesystem.return_value = {
            "id": self.SNAPSHOT_ID,
            "parent_id": "wrong-parent-id",
            "size_total": self.SHARE_SIZE_GB * units.Gi,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        self.assertRaises(
            exception.ManageInvalidShareSnapshot,
            self.storage_connection.manage_existing_snapshot,
            snapshot,
            driver_options={},
        )

    def test_manage_existing_snapshot_invalid_size(self):
        """Backend size_total takes precedence; invalid driver ignored."""
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
        }
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": "backend_snap",
            "share": share,
        }
        self._mock_powerstore_client.get_snapshot_filesystem.return_value = {
            "id": self.SNAPSHOT_ID,
            "parent_id": self.FILESYSTEM_ID,
            "size_total": self.SHARE_SIZE_GB * units.Gi,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        result = self.storage_connection.manage_existing_snapshot(
            snapshot,
            driver_options={"size": "abc"},
        )

        self.assertEqual(self.SHARE_SIZE_GB, result['size'])
        self.assertEqual("backend_snap", result['provider_location'])

    def test_manage_existing_snapshot_invalid_size_no_backend_size(self):
        """Fails when driver_options size is invalid AND no backend size."""
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
        }
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": "backend_snap",
            "share": share,
        }
        # Backend has NO size_total
        self._mock_powerstore_client.get_snapshot_filesystem.return_value = {
            "id": self.SNAPSHOT_ID,
            "parent_id": self.FILESYSTEM_ID,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        self.assertRaises(
            exception.ManageInvalidShareSnapshot,
            self.storage_connection.manage_existing_snapshot,
            snapshot,
            driver_options={"size": "invalid"},
        )

    def test_manage_existing_snapshot_size_from_backend(self):
        """Uses backend-reported size when no size in driver_options."""
        backend_snap_name = "backend_snap_001"
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": 5,
        }
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
            "share": share,
        }
        self._mock_powerstore_client.get_snapshot_filesystem.return_value = {
            "id": self.SNAPSHOT_ID,
            "parent_id": self.FILESYSTEM_ID,
            "size_total": 5 * units.Gi,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        result = self.storage_connection.manage_existing_snapshot(
            snapshot, driver_options={}
        )

        self.assertEqual(5, result['size'])

    def test_manage_existing_snapshot_size_not_available(self):
        """Returns 0 when backend doesn't provide size_total and no user size.

        The Manila manager framework will fall back to using the parent share's
        size.
        """
        backend_snap_name = "backend_snap_001"
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": 5,
        }
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
            "share": share,
        }
        self._mock_powerstore_client.get_snapshot_filesystem.return_value = {
            "id": self.SNAPSHOT_ID,
            "parent_id": self.FILESYSTEM_ID,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        result = self.storage_connection.manage_existing_snapshot(
            snapshot,
            driver_options={}
        )

        self.assertEqual(0, result['size'])
        self.assertEqual(backend_snap_name, result['provider_location'])

    def test_manage_existing_snapshot_user_size_as_fallback(self):
        """Uses driver_options size when backend doesn't provide size_total."""
        backend_snap_name = "backend_snap_001"
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": 5,
        }
        snapshot = {
            "id": "fake-snap-id",
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
            "share": share,
        }
        self._mock_powerstore_client.get_snapshot_filesystem.return_value = {
            "id": self.SNAPSHOT_ID,
            "parent_id": self.FILESYSTEM_ID,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.FILESYSTEM_ID
        )

        result = self.storage_connection.manage_existing_snapshot(
            snapshot,
            driver_options={"size": "15"}
        )

        self.assertEqual(15, result['size'])
        self.assertEqual(backend_snap_name, result['provider_location'])

    def test_get_snapshot_filesystem_id_uses_provider_location(self):
        """Uses provider_location to resolve snapshot filesystem ID."""
        backend_snap_name = "backend_snap"
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )

        result = self.storage_connection._get_snapshot_filesystem_id(snapshot)

        self.assertEqual(self.SNAPSHOT_ID, result)
        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            backend_snap_name
        )

    def test_get_snapshot_filesystem_id_fallback_to_name(self):
        """Falls back to snapshot name when provider_location not found."""
        snapshot = {
            "name": self.SNAPSHOT_NAME,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )

        result = self.storage_connection._get_snapshot_filesystem_id(snapshot)

        self.assertEqual(self.SNAPSHOT_ID, result)
        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            self.SNAPSHOT_NAME
        )

    def test_get_snapshot_filesystem_id_provider_location_not_found(self):
        """Falls back to name when provider_location lookup returns None."""
        backend_snap_name = "stale_backend_name"
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
        }
        self._mock_powerstore_client.get_filesystem_id.side_effect = [
            None,
            self.SNAPSHOT_ID,
        ]

        result = self.storage_connection._get_snapshot_filesystem_id(snapshot)

        self.assertEqual(self.SNAPSHOT_ID, result)
        calls = self._mock_powerstore_client.get_filesystem_id.call_args_list
        self.assertEqual(mock.call(backend_snap_name), calls[0])
        self.assertEqual(mock.call(self.SNAPSHOT_NAME), calls[1])

    def test_delete_managed_snapshot(self):
        """Delete uses provider_location to find backend snapshot."""
        backend_snap_name = "backend_snap"
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
            "share_name": self.SHARE_NAME,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.delete_filesystem.return_value = True

        self.storage_connection.delete_snapshot(
            self.mock_context, snapshot, None
        )

        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            backend_snap_name
        )
        self._mock_powerstore_client.delete_filesystem.assert_called_with(
            self.SNAPSHOT_ID
        )

    def test_revert_managed_snapshot(self):
        """Revert uses provider_location to find backend snapshot."""
        backend_snap_name = "backend_snap"
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
            "share_name": self.SHARE_NAME,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.restore_snapshot.return_value = True

        self.storage_connection.revert_to_snapshot(
            self.mock_context, snapshot, None, None, None
        )

        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            backend_snap_name
        )
        self._mock_powerstore_client.restore_snapshot.assert_called_with(
            self.SNAPSHOT_ID
        )

    def test_create_share_from_managed_snapshot(self):
        """Create share from snapshot uses provider_location."""
        backend_snap_name = "backend_snap"
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "provider_location": backend_snap_name,
            "size": self.SHARE_SIZE_GB,
        }
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = (
            self.SNAPSHOT_ID
        )
        self._mock_powerstore_client.clone_snapshot.return_value = (
            self.CLONE_ID
        )
        self._mock_powerstore_client.get_nas_server_id.return_value = (
            self.NAS_SERVER_ID
        )
        self._mock_powerstore_client.create_nfs_export.return_value = (
            self.NFS_EXPORT_ID
        )
        self._mock_powerstore_client.get_nas_server_interfaces.return_value = (
            [{"ip": self.NAS_SERVER_IP, "preferred": True}]
        )

        locations = self.storage_connection.create_share_from_snapshot(
            self.mock_context, share, snapshot
        )

        self._mock_powerstore_client.get_filesystem_id.assert_called_with(
            backend_snap_name
        )
        self._mock_powerstore_client.clone_snapshot.assert_called_with(
            self.SNAPSHOT_ID, self.SHARE_NAME
        )
        expected_locations = [
            {"path": "%s:/%s" % (self.NAS_SERVER_IP, self.SHARE_NAME),
             "metadata": {"preferred": True}}
        ]
        self.assertEqual(expected_locations, locations)

    def test_delete_snapshot_not_found_on_backend(self):
        """Delete should succeed silently if snapshot not on backend."""
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "provider_location": "gone_snap",
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = None

        self.storage_connection.delete_snapshot(
            self.mock_context, snapshot, None
        )

        self._mock_powerstore_client.delete_filesystem.assert_not_called()

    def test_revert_snapshot_not_found_on_backend(self):
        """Revert should raise if snapshot not found on backend."""
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "provider_location": "gone_snap",
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.revert_to_snapshot,
            self.mock_context, snapshot, None, None, None
        )

    def test_create_share_from_snapshot_not_found_on_backend(self):
        """Create from snapshot should raise if snapshot not on backend."""
        snapshot = {
            "name": self.SNAPSHOT_NAME,
            "provider_location": "gone_snap",
            "size": self.SHARE_SIZE_GB,
        }
        share = {
            "name": self.SHARE_NAME,
            "share_proto": "NFS",
            "size": self.SHARE_SIZE_GB,
        }
        self._mock_powerstore_client.get_filesystem_id.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share_from_snapshot,
            self.mock_context, share, snapshot
        )
