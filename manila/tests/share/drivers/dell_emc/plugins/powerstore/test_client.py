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

import json
import os

import requests_mock

from manila.share.drivers.dell_emc.plugins.powerstore import client
from manila import test


class TestClient(test.TestCase):

    REST_IP = "192.168.0.110"
    NAS_SERVER_NAME = "powerstore-nasserver"
    NAS_SERVER_ID = "6423d56e-eaf3-7424-be0b-1a9efb93188b"
    NAS_SERVER_IP = "192.168.11.23"
    NFS_EXPORT_NAME = "powerstore-nfs-share"
    NFS_EXPORT_SIZE = 3221225472
    NFS_EXPORT_NEW_SIZE = 6221225472
    FILESYSTEM_ID = "6454e9a9-a698-e9bc-ca61-1a9efb93188b"
    NFS_EXPORT_ID = "6454ec18-7b8d-1532-1b8a-1a9efb93188b"
    RW_HOSTS = "192.168.1.10"
    RO_HOSTS = "192.168.1.11"
    SMB_SHARE_NAME = "powerstore-smb-share"
    SMB_SHARE_ID = "64927ae9-3403-6930-a784-f227b9987c54"
    RW_USERS = "user1"
    RO_USERS = "user2"
    SNAPSHOT_NAME = "powerstore-nfs-share-snap"
    SNAPSHOT_ID = "6454ea29-09c3-030e-cfc3-1a9efb93188b"
    CLONE_ID = "64560f05-e677-ec2a-7fcf-1a9efb93188b"
    CLONE_NAME = "powerstore-nfs-share-snap-clone"
    CLUSTER_ID = "0"
    QOS_RULE_NAME = "manila_qos_rule_gold"
    QOS_RULE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    QOS_POLICY_NAME = "manila_qos_policy_gold"
    QOS_POLICY_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    QOS_MAX_BW = 100

    CLIENT_OPTIONS = {
        "rest_ip": REST_IP,
        "rest_username": "admin",
        "rest_password": "pwd",
        "verify_certificate": False,
        "certificate_path": None
    }

    def setUp(self):
        super(TestClient, self).setUp()

        self._mock_url = "https://%s/api/rest" % self.REST_IP
        self.client = client.PowerStoreClient(**self.CLIENT_OPTIONS)
        self.mockup_file_base = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'mockup')

    def _getJsonFile(self, filename):
        f = open(os.path.join(self.mockup_file_base, filename))
        data = json.load(f)
        f.close()
        return data

    def test__verify_cert(self):
        verify_cert = self.client.verify_certificate
        certificate_path = self.client.certificate_path
        self.client.verify_certificate = True
        self.client.certificate_path = "fake_certificate_path"
        self.assertEqual(self.client._verify_cert,
                         self.client.certificate_path)
        self.client.verify_certificate = verify_cert
        self.client.certificate_path = certificate_path

    @requests_mock.mock()
    def test__send_request(self, m):
        url = "{0}/fake_res".format(self._mock_url)
        m.get(url, status_code=200)
        self.client._send_get_request("/fake_res", None, None, False)

    @requests_mock.mock()
    def test_get_nas_server_id(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_id_response(
            m, self.NAS_SERVER_NAME,
            self._getJsonFile("get_nas_server_id_response.json")
        )
        id = self.client.get_nas_server_id(self.NAS_SERVER_NAME)
        self.assertEqual(id, self.NAS_SERVER_ID)

    def _add_get_nas_server_id_response(self, m, nas_server, json_str):
        url = "{0}/nas_server?name=eq.{1}".format(
            self._mock_url, nas_server
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_nas_server_id_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_id_response_failure(
            m, self.NAS_SERVER_NAME
        )
        id = self.client.get_nas_server_id(self.NAS_SERVER_NAME)
        self.assertIsNone(id)

    def _add_get_nas_server_id_response_failure(self, m, nas_server):
        url = "{0}/nas_server?name=eq.{1}".format(
            self._mock_url, nas_server
        )
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_get_nas_server_interfaces(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_interfaces_response(
            m, self.NAS_SERVER_ID,
            self._getJsonFile("get_nas_server_interfaces_response.json")
        )
        interfaces = self.client.get_nas_server_interfaces(self.NAS_SERVER_ID)
        self.assertEqual(interfaces[0]['ip'], self.NAS_SERVER_IP)
        self.assertEqual(interfaces[0]['preferred'], True)

    def _add_get_nas_server_interfaces_response(self, m, nas_server_id,
                                                json_str):
        url = "{0}/nas_server/{1}?select=" \
            "current_preferred_IPv4_interface_id," \
            "current_preferred_IPv6_interface_id," \
            "file_interfaces(id,ip_address)".format(
                self._mock_url, nas_server_id
            )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_nas_server_interfaces_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_interfaces_response_failure(
            m, self.NAS_SERVER_ID
        )
        interfaces = self.client.get_nas_server_interfaces(self.NAS_SERVER_ID)
        self.assertIsNone(interfaces)

    def _add_get_nas_server_interfaces_response_failure(self, m,
                                                        nas_server_id):
        url = "{0}/nas_server/{1}?select=" \
            "current_preferred_IPv4_interface_id," \
            "current_preferred_IPv6_interface_id," \
            "file_interfaces(id,ip_address)".format(
                self._mock_url, nas_server_id
            )
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_create_filesystem(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_filesystem_response(
            m, self._getJsonFile("create_filesystem_response.json")
        )
        id = self.client.create_filesystem(
            self.NAS_SERVER_ID,
            self.NFS_EXPORT_NAME,
            self.NFS_EXPORT_SIZE
        )
        self.assertEqual(id, self.FILESYSTEM_ID)

    def _add_create_filesystem_response(self, m, json_str):
        url = "{0}/file_system".format(self._mock_url)
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_create_filesystem_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_filesystem_response_failure(m)
        id = self.client.create_filesystem(
            self.NAS_SERVER_ID,
            self.NFS_EXPORT_NAME,
            self.NFS_EXPORT_SIZE
        )
        self.assertIsNone(id)

    def _add_create_filesystem_response_failure(self, m):
        url = "{0}/file_system".format(self._mock_url)
        m.post(url, status_code=400)

    @requests_mock.mock()
    def test_create_nfs_export(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_nfs_export_response(
            m, self._getJsonFile("create_nfs_export_response.json")
        )
        id = self.client.create_nfs_export(self.FILESYSTEM_ID,
                                           self.NFS_EXPORT_NAME)
        self.assertEqual(id, self.NFS_EXPORT_ID)

    def _add_create_nfs_export_response(self, m, json_str):
        url = "{0}/nfs_export".format(self._mock_url)
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_create_nfs_export_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_nfs_export_response_failure(m)
        id = self.client.create_nfs_export(self.FILESYSTEM_ID,
                                           self.NFS_EXPORT_NAME)
        self.assertIsNone(id)

    def _add_create_nfs_export_response_failure(self, m):
        url = "{0}/nfs_export".format(self._mock_url)
        m.post(url, status_code=400)

    @requests_mock.mock()
    def test_delete_filesystem(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_delete_filesystem_response(m, self.FILESYSTEM_ID)
        result = self.client.delete_filesystem(self.FILESYSTEM_ID)
        self.assertEqual(result, True)

    def _add_delete_filesystem_response(self, m, filesystem_id):
        url = "{0}/file_system/{1}".format(
            self._mock_url, filesystem_id
        )
        m.delete(url, status_code=204)

    @requests_mock.mock()
    def test_get_nfs_export_name(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nfs_export_name_response(
            m,
            self.NFS_EXPORT_ID,
            self._getJsonFile("get_nfs_export_name_response.json"),
        )
        name = self.client.get_nfs_export_name(self.NFS_EXPORT_ID)
        self.assertEqual(name, self.NFS_EXPORT_NAME)

    def _add_get_nfs_export_name_response(self, m, export_id, json_str):
        url = "{0}/nfs_export/{1}?select=name".format(
            self._mock_url, export_id
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_nfs_export_name_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nfs_export_name_response_failure(m, self.NFS_EXPORT_ID)
        name = self.client.get_nfs_export_name(self.NFS_EXPORT_ID)
        self.assertIsNone(name)

    def _add_get_nfs_export_name_response_failure(self,
                                                  m, export_id):
        url = "{0}/nfs_export/{1}?select=name".format(
            self._mock_url, export_id
        )
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_get_nfs_export_id(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nfs_export_id_response(
            m, self.NFS_EXPORT_NAME,
            self._getJsonFile("get_nfs_export_id_response.json")
        )
        id = self.client.get_nfs_export_id(self.NFS_EXPORT_NAME)
        self.assertEqual(id, self.NFS_EXPORT_ID)

    def _add_get_nfs_export_id_response(self, m, name, json_str):
        url = "{0}/nfs_export?select=id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_nfs_export_id_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nfs_export_id_response_failure(m, self.NFS_EXPORT_NAME)
        id = self.client.get_nfs_export_id(self.NFS_EXPORT_NAME)
        self.assertIsNone(id)

    def _add_get_nfs_export_id_response_failure(self, m, name):
        url = "{0}/nfs_export?select=id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_get_filesystem_id(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_filesystem_id_response(
            m, self.NFS_EXPORT_NAME,
            self._getJsonFile("get_fileystem_id_response.json")
        )
        id = self.client.get_filesystem_id(self.NFS_EXPORT_NAME)
        self.assertEqual(id, self.FILESYSTEM_ID)

    def _add_get_filesystem_id_response(self, m, name, json_str):
        url = "{0}/file_system?name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_filesystem_id_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_filesystem_id_response_failure(m, self.NFS_EXPORT_NAME)
        id = self.client.get_filesystem_id(self.NFS_EXPORT_NAME)
        self.assertIsNone(id)

    def _add_get_filesystem_id_response_failure(self, m, name):
        url = "{0}/file_system?name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_set_export_access(self, m):

        self.assertEqual(0, len(m.request_history))
        self._add_set_export_access_response(m, self.NFS_EXPORT_ID)
        result = self.client.set_export_access(self.NFS_EXPORT_ID,
                                               self.RW_HOSTS,
                                               self.RO_HOSTS)
        self.assertEqual(result, True)

    def _add_set_export_access_response(self, m, export_id):
        url = "{0}/nfs_export/{1}".format(self._mock_url, export_id)
        m.patch(url, status_code=204)

    @requests_mock.mock()
    def test_resize_filesystem(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_resize_filesystem_response(m, self.FILESYSTEM_ID)
        result, detail = self.client.resize_filesystem(
            self.FILESYSTEM_ID, self.NFS_EXPORT_NEW_SIZE)
        self.assertTrue(result)
        self.assertIsNone(detail)

    def _add_resize_filesystem_response(self, m, filesystem_id):
        url = "{0}/file_system/{1}".format(
            self._mock_url, filesystem_id
        )
        m.patch(url, status_code=204)

    @requests_mock.mock()
    def test_resize_filesystem_shrink_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_resize_filesystem_shrink_failure_response(
            m, self.FILESYSTEM_ID,
            self._getJsonFile(
                "resize_filesystem_shrink_failure_response.json"))
        result, detail = self.client.resize_filesystem(
            self.FILESYSTEM_ID, self.NFS_EXPORT_NEW_SIZE)
        self.assertFalse(result)
        self.assertIsNotNone(detail)

    def _add_resize_filesystem_shrink_failure_response(
            self, m, filesystem_id, json_str):
        url = "{0}/file_system/{1}".format(
            self._mock_url, filesystem_id
        )
        m.patch(url, status_code=422, json=json_str)

    @requests_mock.mock()
    def test_get_fsid_from_export_name(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_fsid_from_export_name_response(
            m, self.NFS_EXPORT_NAME,
            self._getJsonFile("get_fsid_from_export_name_response.json")
        )
        id = self.client.get_fsid_from_export_name(self.NFS_EXPORT_NAME)
        self.assertEqual(id, self.FILESYSTEM_ID)

    def _add_get_fsid_from_export_name_response(self, m, name, json_str):
        url = "{0}/nfs_export?select=file_system_id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_fsid_from_export_name_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_fsid_from_export_name_response_failure(
            m, self.NFS_EXPORT_NAME
        )
        id = self.client.get_fsid_from_export_name(self.NFS_EXPORT_NAME)
        self.assertIsNone(id)

    def _add_get_fsid_from_export_name_response_failure(self, m, name):
        url = "{0}/nfs_export?select=file_system_id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_get_fsid_from_export_name_empty_response(self, m):
        self.assertEqual(0, len(m.request_history))
        url = "{0}/nfs_export?select=file_system_id&name=eq.{1}".format(
            self._mock_url, self.NFS_EXPORT_NAME
        )
        m.get(url, status_code=200, json=[])
        id = self.client.get_fsid_from_export_name(self.NFS_EXPORT_NAME)
        self.assertIsNone(id)

    @requests_mock.mock()
    def test_create_snapshot(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_snapshot_response(
            m, self.FILESYSTEM_ID,
            self._getJsonFile("create_snapshot_response.json")
        )
        id = self.client.create_snapshot(self.FILESYSTEM_ID,
                                         self.SNAPSHOT_NAME)
        self.assertEqual(id, self.SNAPSHOT_ID)

    def _add_create_snapshot_response(self, m, filesystem_id, json_str):
        url = "{0}/file_system/{1}/snapshot".format(self._mock_url,
                                                    filesystem_id)
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_create_snapshot_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_snapshot_response_failure(m, self.FILESYSTEM_ID)
        id = self.client.create_snapshot(self.FILESYSTEM_ID,
                                         self.SNAPSHOT_NAME)
        self.assertIsNone(id)

    def _add_create_snapshot_response_failure(self, m, filesystem_id):
        url = "{0}/file_system/{1}/snapshot".format(self._mock_url,
                                                    filesystem_id)
        m.post(url, status_code=400)

    @requests_mock.mock()
    def test_restore_snapshot(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_restore_snapshot_response(
            m, self.SNAPSHOT_ID
        )
        result = self.client.restore_snapshot(self.SNAPSHOT_ID)
        self.assertEqual(result, True)

    def _add_restore_snapshot_response(self, m, snapshot_id):
        url = "{0}/file_system/{1}/restore".format(self._mock_url,
                                                   snapshot_id)
        m.post(url, status_code=204)

    @requests_mock.mock()
    def test_restore_snapshot_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_restore_snapshot_response_failure(
            m, self.SNAPSHOT_ID
        )
        result = self.client.restore_snapshot(self.SNAPSHOT_ID)
        self.assertEqual(result, False)

    def _add_restore_snapshot_response_failure(self, m, snapshot_id):
        url = "{0}/file_system/{1}/restore".format(self._mock_url,
                                                   snapshot_id)
        m.post(url, status_code=400)

    @requests_mock.mock()
    def test_clone_snapshot(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_clone_snapshot_response(
            m, self.SNAPSHOT_ID,
            self._getJsonFile("clone_snapshot_response.json")
        )
        id = self.client.clone_snapshot(self.SNAPSHOT_ID,
                                        self.CLONE_NAME)
        self.assertEqual(id, self.CLONE_ID)

    def _add_clone_snapshot_response(self, m, snapshot_id, json_str):
        url = "{0}/file_system/{1}/clone".format(self._mock_url,
                                                 snapshot_id)
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_clone_snapshot_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_clone_snapshot_response_failure(
            m, self.SNAPSHOT_ID
        )
        id = self.client.clone_snapshot(self.SNAPSHOT_ID,
                                        self.CLONE_NAME)
        self.assertIsNone(id)

    def _add_clone_snapshot_response_failure(self, m, snapshot_id):
        url = "{0}/file_system/{1}/clone".format(self._mock_url,
                                                 snapshot_id)
        m.post(url, status_code=400)

    @requests_mock.mock()
    def test_get_cluster_id(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_cluster_id_response(
            m,
            self._getJsonFile("get_cluster_id_response.json")
        )
        id = self.client.get_cluster_id()
        self.assertEqual(id, self.CLUSTER_ID)

    def _add_get_cluster_id_response(self, m, json_str):
        url = "{0}/cluster".format(self._mock_url)
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_cluster_id_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_cluster_id_response_failure(m)
        id = self.client.get_cluster_id()
        self.assertIsNone(id)

    def _add_get_cluster_id_response_failure(self, m):
        url = "{0}/cluster".format(self._mock_url)
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_retreive_cluster_capacity_metrics(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_retreive_cluster_capacity_metrics_response(
            m,
            self._getJsonFile(
                "retreive_cluster_capacity_metrics_response.json")
        )
        total, used = self.client.retreive_cluster_capacity_metrics(
            self.CLUSTER_ID)
        self.assertEqual(total, 47345047046144)
        self.assertEqual(used, 366003363027)

    def _add_retreive_cluster_capacity_metrics_response(self, m, json_str):
        url = "{0}/metrics/generate?order=timestamp".format(self._mock_url)
        m.post(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_retreive_cluster_capacity_metrics_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_retreive_cluster_capacity_metrics_response_failure(m)
        total, used = self.client.retreive_cluster_capacity_metrics(
            self.CLUSTER_ID)
        self.assertIsNone(total)
        self.assertIsNone(used)

    def _add_retreive_cluster_capacity_metrics_response_failure(self, m):
        url = "{0}/metrics/generate?order=timestamp".format(self._mock_url)
        m.post(url, status_code=400)

    @requests_mock.mock()
    def test_create_smb_share(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_smb_share_response(
            m, self._getJsonFile("create_smb_share_response.json")
        )
        id = self.client.create_smb_share(self.FILESYSTEM_ID,
                                          self.SMB_SHARE_NAME)
        self.assertEqual(id, self.SMB_SHARE_ID)

    def _add_create_smb_share_response(self, m, json_str):
        url = "{0}/smb_share".format(self._mock_url)
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_create_smb_share_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_smb_share_response_failure(m)
        id = self.client.create_smb_share(self.FILESYSTEM_ID,
                                          self.SMB_SHARE_NAME)
        self.assertIsNone(id)

    def _add_create_smb_share_response_failure(self, m):
        url = "{0}/smb_share".format(self._mock_url)
        m.post(url, status_code=400)

    @requests_mock.mock()
    def test_get_fsid_from_share_name(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_fsid_from_share_name_response(
            m, self.NFS_EXPORT_NAME,
            self._getJsonFile("get_fsid_from_share_name_response.json")
        )
        id = self.client.get_fsid_from_share_name(self.NFS_EXPORT_NAME)
        self.assertEqual(id, self.FILESYSTEM_ID)

    def _add_get_fsid_from_share_name_response(self, m, name, json_str):
        url = "{0}/smb_share?select=file_system_id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_fsid_from_share_name_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_fsid_from_share_name_response_failure(
            m, self.SMB_SHARE_NAME
        )
        id = self.client.get_fsid_from_share_name(self.SMB_SHARE_NAME)
        self.assertIsNone(id)

    def _add_get_fsid_from_share_name_response_failure(self, m, name):
        url = "{0}/smb_share?select=file_system_id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_get_fsid_from_share_name_empty_response(self, m):
        self.assertEqual(0, len(m.request_history))
        url = "{0}/smb_share?select=file_system_id&name=eq.{1}".format(
            self._mock_url, self.SMB_SHARE_NAME
        )
        m.get(url, status_code=200, json=[])
        id = self.client.get_fsid_from_share_name(self.SMB_SHARE_NAME)
        self.assertIsNone(id)

    @requests_mock.mock()
    def test_get_smb_share_id(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_smb_share_id_response(
            m, self.SMB_SHARE_NAME,
            self._getJsonFile("get_smb_share_id_response.json")
        )
        id = self.client.get_smb_share_id(self.SMB_SHARE_NAME)
        self.assertEqual(id, self.SMB_SHARE_ID)

    def _add_get_smb_share_id_response(self, m, name, json_str):
        url = "{0}/smb_share?select=id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_smb_share_id_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_smb_share_id_response_failure(
            m, self.SMB_SHARE_NAME
        )
        id = self.client.get_smb_share_id(self.SMB_SHARE_NAME)
        self.assertIsNone(id)

    def _add_get_smb_share_id_response_failure(self, m, name):
        url = "{0}/smb_share?select=id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_get_nas_server_smb_netbios(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_smb_netbios_response(
            m, self.SMB_SHARE_NAME,
            self._getJsonFile("get_nas_server_smb_netbios_response.json")
        )
        id = self.client.get_nas_server_smb_netbios(self.SMB_SHARE_NAME)
        self.assertEqual(id, "OPENSTACK")

    def _add_get_nas_server_smb_netbios_response(self, m, name, json_str):
        url = "{0}/nas_server?select=smb_servers" \
            "(is_standalone,netbios_name)&name=eq.{1}".format(
                self._mock_url, name
            )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_nas_server_smb_netbios_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_smb_netbios_response_failure(
            m, self.SMB_SHARE_NAME
        )
        id = self.client.get_nas_server_smb_netbios(self.SMB_SHARE_NAME)
        self.assertIsNone(id)

    def _add_get_nas_server_smb_netbios_response_failure(self, m, name):
        url = "{0}/nas_server?select=smb_servers" \
            "(is_standalone,netbios_name)&name=eq.{1}".format(
                self._mock_url, name
            )
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_get_snapshot_filesystem(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_snapshot_filesystem_response(
            m, self.SNAPSHOT_NAME,
            self._getJsonFile("get_snapshot_filesystem_response.json")
        )
        result = self.client.get_snapshot_filesystem(self.SNAPSHOT_NAME)
        self.assertEqual(result['id'], self.SNAPSHOT_ID)
        self.assertEqual(result['parent_id'], self.FILESYSTEM_ID)
        self.assertEqual(result['size_total'], self.NFS_EXPORT_SIZE)

    def _add_get_snapshot_filesystem_response(self, m, name, json_str):
        url = ("{0}/file_system?name=eq.{1}"
               "&select=id,parent_id,size_total".format(
                   self._mock_url, name))
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_snapshot_filesystem_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_snapshot_filesystem_response_failure(
            m, self.SNAPSHOT_NAME
        )
        result = self.client.get_snapshot_filesystem(self.SNAPSHOT_NAME)
        self.assertIsNone(result)

    def _add_get_snapshot_filesystem_response_failure(self, m, name):
        url = ("{0}/file_system?name=eq.{1}"
               "&select=id,parent_id,size_total".format(
                   self._mock_url, name))
        m.get(url, status_code=400)

    @requests_mock.mock()
    def test_get_snapshot_filesystem_empty_response(self, m):
        self.assertEqual(0, len(m.request_history))
        url = ("{0}/file_system?name=eq.{1}"
               "&select=id,parent_id,size_total".format(
                   self._mock_url, self.SNAPSHOT_NAME))
        m.get(url, status_code=200, json=[])
        result = self.client.get_snapshot_filesystem(self.SNAPSHOT_NAME)
        self.assertIsNone(result)

    @requests_mock.mock()
    def test_set_acl(self, m):

        self.assertEqual(0, len(m.request_history))
        self._add_set_acl_response(m, self.SMB_SHARE_ID)
        result = self.client.set_acl(self.SMB_SHARE_ID,
                                     self.RW_USERS,
                                     self.RO_USERS)
        self.assertEqual(result, True)

    def _add_set_acl_response(self, m, share_id):
        url = "{0}/smb_share/{1}/set_acl".format(self._mock_url, share_id)
        m.post(url, status_code=204)

    @requests_mock.mock()
    def test_get_filesystem_size(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_filesystem_size_response(
            m, self.FILESYSTEM_ID, {"size_total": self.NFS_EXPORT_SIZE}
        )
        size = self.client.get_filesystem_size(self.FILESYSTEM_ID)
        self.assertEqual(size, self.NFS_EXPORT_SIZE)

    def _add_get_filesystem_size_response(self, m, filesystem_id, json_str):
        url = "{0}/file_system/{1}?select=size_total".format(
            self._mock_url, filesystem_id
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_filesystem_size_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_filesystem_size_response_failure(
            m, self.FILESYSTEM_ID
        )
        size = self.client.get_filesystem_size(self.FILESYSTEM_ID)
        self.assertIsNone(size)

    def _add_get_filesystem_size_response_failure(self, m, filesystem_id):
        url = "{0}/file_system/{1}?select=size_total".format(
            self._mock_url, filesystem_id
        )
        m.get(url, status_code=400)

    # QoS client tests

    @requests_mock.mock()
    def test_create_file_io_limit_rule(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_file_io_limit_rule_response(
            m, {"id": self.QOS_RULE_ID}
        )
        rule_id = self.client.create_file_io_limit_rule(
            self.QOS_RULE_NAME, self.QOS_MAX_BW)
        self.assertEqual(rule_id, self.QOS_RULE_ID)

    def _add_create_file_io_limit_rule_response(self, m, json_str):
        url = "{0}/file_io_limit_rule".format(self._mock_url)
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_create_file_io_limit_rule_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_file_io_limit_rule_response_failure(m)
        rule_id = self.client.create_file_io_limit_rule(
            self.QOS_RULE_NAME, self.QOS_MAX_BW)
        self.assertIsNone(rule_id)

    def _add_create_file_io_limit_rule_response_failure(self, m):
        url = "{0}/file_io_limit_rule".format(self._mock_url)
        m.post(url, status_code=400)

    @requests_mock.mock()
    def test_get_file_io_limit_rule_by_name(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_file_io_limit_rule_by_name_response(
            m, self.QOS_RULE_NAME,
            [{
                "id": self.QOS_RULE_ID,
                "name": self.QOS_RULE_NAME,
                "max_bw": self.QOS_MAX_BW
            }]
        )
        rule = self.client.get_file_io_limit_rule_by_name(self.QOS_RULE_NAME)
        self.assertEqual(rule['id'], self.QOS_RULE_ID)
        self.assertEqual(rule['name'], self.QOS_RULE_NAME)
        self.assertEqual(rule['max_bw'], self.QOS_MAX_BW)

    def _add_get_file_io_limit_rule_by_name_response(self, m, name, json_str):
        url = "{0}/file_io_limit_rule?name=eq.{1}".format(
            self._mock_url, name)
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_file_io_limit_rule_by_name_not_found(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_file_io_limit_rule_by_name_empty_response(
            m, self.QOS_RULE_NAME)
        rule = self.client.get_file_io_limit_rule_by_name(self.QOS_RULE_NAME)
        self.assertIsNone(rule)

    def _add_get_file_io_limit_rule_by_name_empty_response(self, m, name):
        url = "{0}/file_io_limit_rule?name=eq.{1}".format(
            self._mock_url, name)
        m.get(url, status_code=200, json=[])

    @requests_mock.mock()
    def test_modify_file_io_limit_rule(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_modify_file_io_limit_rule_response(m, self.QOS_RULE_ID)
        result = self.client.modify_file_io_limit_rule(
            self.QOS_RULE_ID, 200)
        self.assertTrue(result)

    def _add_modify_file_io_limit_rule_response(self, m, rule_id):
        url = "{0}/file_io_limit_rule/{1}".format(self._mock_url, rule_id)
        m.patch(url, status_code=204)

    @requests_mock.mock()
    def test_modify_file_io_limit_rule_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_modify_file_io_limit_rule_response_failure(
            m, self.QOS_RULE_ID)
        result = self.client.modify_file_io_limit_rule(
            self.QOS_RULE_ID, 200)
        self.assertFalse(result)

    def _add_modify_file_io_limit_rule_response_failure(self, m, rule_id):
        url = "{0}/file_io_limit_rule/{1}".format(self._mock_url, rule_id)
        m.patch(url, status_code=400)

    @requests_mock.mock()
    def test_delete_file_io_limit_rule(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_delete_file_io_limit_rule_response(m, self.QOS_RULE_ID)
        result = self.client.delete_file_io_limit_rule(self.QOS_RULE_ID)
        self.assertTrue(result)

    def _add_delete_file_io_limit_rule_response(self, m, rule_id):
        url = "{0}/file_io_limit_rule/{1}".format(self._mock_url, rule_id)
        m.delete(url, status_code=204)

    @requests_mock.mock()
    def test_delete_file_io_limit_rule_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_delete_file_io_limit_rule_response_failure(
            m, self.QOS_RULE_ID)
        result = self.client.delete_file_io_limit_rule(self.QOS_RULE_ID)
        self.assertFalse(result)

    def _add_delete_file_io_limit_rule_response_failure(self, m, rule_id):
        url = "{0}/file_io_limit_rule/{1}".format(self._mock_url, rule_id)
        m.delete(url, status_code=400)

    @requests_mock.mock()
    def test_create_file_performance_policy(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_file_performance_policy_response(
            m, {"id": self.QOS_POLICY_ID}
        )
        policy_id = self.client.create_file_performance_policy(
            self.QOS_POLICY_NAME, self.QOS_RULE_ID)
        self.assertEqual(policy_id, self.QOS_POLICY_ID)

    def _add_create_file_performance_policy_response(self, m, json_str):
        url = "{0}/policy".format(self._mock_url)
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_create_file_performance_policy_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_create_file_performance_policy_response_failure(m)
        policy_id = self.client.create_file_performance_policy(
            self.QOS_POLICY_NAME, self.QOS_RULE_ID)
        self.assertIsNone(policy_id)

    def _add_create_file_performance_policy_response_failure(self, m):
        url = "{0}/policy".format(self._mock_url)
        m.post(url, status_code=400)

    @requests_mock.mock()
    def test_get_policy_by_name(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_policy_by_name_response(
            m, self.QOS_POLICY_NAME,
            [{"id": self.QOS_POLICY_ID, "name": self.QOS_POLICY_NAME}]
        )
        policy = self.client.get_policy_by_name(self.QOS_POLICY_NAME)
        self.assertEqual(policy['id'], self.QOS_POLICY_ID)

    def _add_get_policy_by_name_response(self, m, name, json_str):
        url = "{0}/policy?name=eq.{1}".format(self._mock_url, name)
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_policy_by_name_not_found(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_policy_by_name_empty_response(
            m, self.QOS_POLICY_NAME)
        policy = self.client.get_policy_by_name(self.QOS_POLICY_NAME)
        self.assertIsNone(policy)

    def _add_get_policy_by_name_empty_response(self, m, name):
        url = "{0}/policy?name=eq.{1}".format(self._mock_url, name)
        m.get(url, status_code=200, json=[])

    @requests_mock.mock()
    def test_get_policy_filesystems(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_policy_filesystems_response(
            m, self.QOS_POLICY_ID,
            {"file_systems_with_qos": [{"id": self.FILESYSTEM_ID}]}
        )
        fs_list = self.client.get_policy_filesystems(self.QOS_POLICY_ID)
        self.assertEqual(len(fs_list), 1)
        self.assertEqual(fs_list[0]['id'], self.FILESYSTEM_ID)

    def _add_get_policy_filesystems_response(self, m, policy_id, json_str):
        url = "{0}/policy/{1}?select=file_systems_with_qos(id)".format(
            self._mock_url, policy_id)
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_policy_filesystems_empty(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_get_policy_filesystems_response(
            m, self.QOS_POLICY_ID,
            {"file_systems_with_qos": []}
        )
        fs_list = self.client.get_policy_filesystems(self.QOS_POLICY_ID)
        self.assertEqual(len(fs_list), 0)

    @requests_mock.mock()
    def test_delete_policy(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_delete_policy_response(m, self.QOS_POLICY_ID)
        result = self.client.delete_policy(self.QOS_POLICY_ID)
        self.assertTrue(result)

    def _add_delete_policy_response(self, m, policy_id):
        url = "{0}/policy/{1}".format(self._mock_url, policy_id)
        m.delete(url, status_code=204)

    @requests_mock.mock()
    def test_delete_policy_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_delete_policy_response_failure(m, self.QOS_POLICY_ID)
        result = self.client.delete_policy(self.QOS_POLICY_ID)
        self.assertFalse(result)

    def _add_delete_policy_response_failure(self, m, policy_id):
        url = "{0}/policy/{1}".format(self._mock_url, policy_id)
        m.delete(url, status_code=400)

    @requests_mock.mock()
    def test_set_filesystem_performance_policy(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_set_filesystem_performance_policy_response(
            m, self.FILESYSTEM_ID)
        result = self.client.set_filesystem_performance_policy(
            self.FILESYSTEM_ID, self.QOS_POLICY_ID)
        self.assertTrue(result)

    def _add_set_filesystem_performance_policy_response(self, m, fs_id):
        url = "{0}/file_system/{1}".format(self._mock_url, fs_id)
        m.patch(url, status_code=204)

    @requests_mock.mock()
    def test_set_filesystem_performance_policy_failure(self, m):
        self.assertEqual(0, len(m.request_history))
        self._add_set_filesystem_performance_policy_response_failure(
            m, self.FILESYSTEM_ID)
        result = self.client.set_filesystem_performance_policy(
            self.FILESYSTEM_ID, self.QOS_POLICY_ID)
        self.assertFalse(result)

    def _add_set_filesystem_performance_policy_response_failure(
            self, m, fs_id):
        url = "{0}/file_system/{1}".format(self._mock_url, fs_id)
        m.patch(url, status_code=400)
