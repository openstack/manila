# Copyright (c) 2023 Dell Inc. or its subsidiaries.
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

from http import client as http_client
import json
import pathlib

import ddt
import requests_mock

from manila import exception
from manila.share.drivers.dell_emc.plugins.powerflex import (
    object_manager as manager
)
from manila import test


@ddt.ddt
class StorageObjectManagerTestCase(test.TestCase):
    def setUp(self):
        super(StorageObjectManagerTestCase, self).setUp()

        self._mock_url = "https://192.168.0.110:443"
        self.manager = manager.StorageObjectManager(
            self._mock_url, username="admin", password="pwd", export_path=None
        )
        self.mockup_file_base = (
            str(pathlib.Path.cwd())
            + "/manila/tests/share/drivers/dell_emc/plugins/powerflex/mockup/"
        )

    @ddt.data(False, True)
    def test__get_headers(self, got_token):
        self.manager.got_token = got_token
        self.manager.rest_token = "token_str"
        self.assertEqual(
            self.manager._get_headers().get("Authorization") is not None,
            got_token,
        )

    def _getJsonFile(self, filename):
        f = open(self.mockup_file_base + filename)
        data = json.load(f)
        f.close()
        return data

    @requests_mock.mock()
    def test_get_nas_server_id(self, m):
        nas_server = "env8nasserver"
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_id_response(
            m, nas_server, self._getJsonFile("get_nas_server_id_response.json")
        )
        id = self.manager.get_nas_server_id(nas_server)
        self.assertEqual(id, "64132f37-d33e-9d4a-89ba-d625520a4779")

    def _add_get_nas_server_id_response(self, m, nas_server, json_str):
        url = "{0}/rest/v1/nas-servers?select=id&name=eq.{1}".format(
            self._mock_url, nas_server
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_create_filesystem(self, m):
        nas_server = "env8nasserver"
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_id_response(
            m, nas_server, self._getJsonFile("get_nas_server_id_response.json")
        )
        storage_pool_id = "8515fee00000000"
        self._add_create_filesystem_response(
            m, self._getJsonFile("create_filesystem_response.json")
        )
        id = self.manager.create_filesystem(
            storage_pool_id,
            nas_server,
            name="Manila-filesystem",
            size=3221225472,
        )
        self.assertEqual(id, "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3")

    def _add_create_filesystem_response(self, m, json_str):
        url = "{0}/rest/v1/file-systems".format(self._mock_url)
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_create_nfs_export(self, m):
        filesystem_id = "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3"
        name = "Manila-UT-filesystem"
        self.assertEqual(0, len(m.request_history))
        self._add_create_nfs_export_response(
            m, self._getJsonFile("create_nfs_export_response.json")
        )
        id = self.manager.create_nfs_export(filesystem_id, name)
        self.assertEqual(id, "6433a2b2-6d60-f737-9f3b-2a50fb1ccff3")

    def _add_create_nfs_export_response(self, m, json_str):
        url = "{0}/rest/v1/nfs-exports".format(self._mock_url)
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_delete_filesystem(self, m):
        filesystem_id = "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3"
        self.assertEqual(0, len(m.request_history))
        self._add_delete_filesystem_response(m, filesystem_id)
        result = self.manager.delete_filesystem(filesystem_id)
        self.assertEqual(result, True)

    def _add_delete_filesystem_response(self, m, filesystem_id):
        url = "{0}/rest/v1/file-systems/{1}".format(
            self._mock_url, filesystem_id
        )
        m.delete(url, status_code=204)

    @requests_mock.mock()
    def test_create_snapshot(self, m):
        name = "Manila-UT-filesystem-snap"
        filesystem_id = "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3"
        self.assertEqual(0, len(m.request_history))
        self._add_create_snapshot_response(
            m,
            filesystem_id,
            self._getJsonFile("create_nfs_snapshot_response.json"),
        )
        result = self.manager.create_snapshot(name, filesystem_id)
        self.assertEqual(result, True)

    def _add_create_snapshot_response(self, m, filesystem_id, json_str):
        url = "{0}/rest/v1/file-systems/{1}/snapshot".format(
            self._mock_url, filesystem_id
        )
        m.post(url, status_code=201, json=json_str)

    @requests_mock.mock()
    def test_get_nfs_export_name(self, m):
        export_id = "6433a2b2-6d60-f737-9f3b-2a50fb1ccff3"
        self.assertEqual(0, len(m.request_history))
        self._add_get_nfs_export_name_response(
            m,
            export_id,
            self._getJsonFile("get_nfs_export_name_response.json"),
        )
        name = self.manager.get_nfs_export_name(export_id)
        self.assertEqual(name, "Manila-UT-filesystem")

    def _add_get_nfs_export_name_response(self, m, export_id, json_str):
        url = "{0}/rest/v1/nfs-exports/{1}?select=*".format(
            self._mock_url, export_id
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_filesystem_id(self, m):
        name = "Manila-UT-filesystem"
        self.assertEqual(0, len(m.request_history))
        self._add_get_filesystem_id_response(
            m, name, self._getJsonFile("get_fileystem_id_response.json")
        )
        id = self.manager.get_filesystem_id(name)
        self.assertEqual(id, "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3")

    def _add_get_filesystem_id_response(self, m, name, json_str):
        url = "{0}/rest/v1/file-systems?select=id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_nfs_export_id(self, m):
        name = "Manila-UT-filesystem"
        self.assertEqual(0, len(m.request_history))
        self._add_get_nfs_export_id_response(
            m, name, self._getJsonFile("get_nfs_export_id_response.json")
        )
        id = self.manager.get_nfs_export_id(name)
        self.assertEqual(id, "6433a2b2-6d60-f737-9f3b-2a50fb1ccff3")

    def _add_get_nfs_export_id_response(self, m, name, json_str):
        url = "{0}/rest/v1/nfs-exports?select=id&name=eq.{1}".format(
            self._mock_url, name
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_storage_pool_id(self, m):
        protection_domain_name = "Env8-PD-1"
        storage_pool_name = "Env8-SP-SW_SSD-1"
        self.assertEqual(0, len(m.request_history))
        self._add_get_storage_pool_id_response(
            m, self._getJsonFile("get_storage_pool_id_response.json")
        )
        id = self.manager.get_storage_pool_id(
            protection_domain_name, storage_pool_name
        )
        self.assertEqual(id, "28515fee00000000")

    def _add_get_storage_pool_id_response(self, m, json_str):
        url = "{0}/api/types/StoragePool/instances/action/queryIdByKey".format(
            self._mock_url
        )
        m.post(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_set_export_access(self, m):
        export_id = "6433a2b2-6d60-f737-9f3b-2a50fb1ccff3"
        rw_hosts = "192.168.1.110"
        ro_hosts = "192.168.1.111"
        self.assertEqual(0, len(m.request_history))
        self._add_set_export_access_response(m, export_id)
        result = self.manager.set_export_access(export_id, rw_hosts, ro_hosts)
        self.assertEqual(result, True)

    def _add_set_export_access_response(self, m, export_id):
        url = "{0}/rest/v1/nfs-exports/{1}".format(self._mock_url, export_id)
        m.patch(url, status_code=204)

    @requests_mock.mock()
    def test_extend_export(self, m):
        filesystem_id = "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3"
        new_size = 6441225472
        self.assertEqual(0, len(m.request_history))
        self._add_extend_export_response(m, filesystem_id)
        result = self.manager.extend_export(filesystem_id, new_size)
        self.assertEqual(result, True)

    def _add_extend_export_response(self, m, filesystem_id):
        url = "{0}/rest/v1/file-systems/{1}".format(
            self._mock_url, filesystem_id
        )
        m.patch(url, status_code=204)

    @requests_mock.mock()
    def test_get_fsid_from_export_name(self, m):
        name = "Manila-UT-filesystem"
        self.assertEqual(0, len(m.request_history))
        self._add_get_fsid_from_export_name_response(
            m,
            name,
            self._getJsonFile("get_fsid_from_export_name_response.json"),
        )
        id = self.manager.get_fsid_from_export_name(name)
        self.assertEqual(id, "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3")

    def _add_get_fsid_from_export_name_response(self, m, name, json_str):
        url = (
            "{0}/rest/v1/nfs-exports?select=file_system_id&name=eq.{1}".format(
                self._mock_url, name
            )
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_fsid_from_snapshot_name(self, m):
        snapshot_name = "Manila-UT-filesystem-snap"
        self.assertEqual(0, len(m.request_history))
        self._add_get_fsid_from_snapshot_name_response(
            m,
            snapshot_name,
            self._getJsonFile("get_fsid_from_snapshot_name_response.json"),
        )
        id = self.manager.get_fsid_from_snapshot_name(snapshot_name)
        self.assertEqual(id, "6433b635-6c1f-878e-6467-2a50fb1ccff3")

    def _add_get_fsid_from_snapshot_name_response(
        self, m, snapshot_name, json_str
    ):
        url = "{0}/rest/v1/file-systems?select=id&name=eq.{1}".format(
            self._mock_url, snapshot_name
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_check_response_with_login_get(self, m):
        nas_server = "env8nasserver"
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_id_response_list(m, nas_server)
        self._add_login_success_response(m)
        id = self.manager.get_nas_server_id(nas_server)
        self.assertEqual(id, "64132f37-d33e-9d4a-89ba-d625520a4779")

    def _add_get_nas_server_id_response_list(self, m, nas_server):
        url = "{0}/rest/v1/nas-servers?select=id&name=eq.{1}".format(
            self._mock_url, nas_server
        )
        m.get(
            url,
            [
                {"status_code": http_client.UNAUTHORIZED},
                {
                    "status_code": 200,
                    "json": self._getJsonFile(
                        "get_nas_server_id_response.json"
                    ),
                },
            ],
        )

    def _add_login_success_response(self, m):
        url = "{0}/rest/auth/login".format(self._mock_url)
        m.post(
            url, status_code=200, json=self._getJsonFile("login_response.json")
        )

    @requests_mock.mock()
    def test_check_response_with_login_post(self, m):
        filesystem_id = "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3"
        name = "Manila-UT-filesystem"
        self.assertEqual(0, len(m.request_history))
        self._add_create_nfs_export_response_list(m)
        self._add_login_success_response(m)
        id = self.manager.create_nfs_export(filesystem_id, name)
        self.assertEqual(id, "6433a2b2-6d60-f737-9f3b-2a50fb1ccff3")

    def _add_create_nfs_export_response_list(self, m):
        url = "{0}/rest/v1/nfs-exports".format(self._mock_url)
        m.post(
            url,
            [
                {"status_code": http_client.UNAUTHORIZED},
                {
                    "status_code": 201,
                    "json": self._getJsonFile(
                        "create_nfs_export_response.json"
                    ),
                },
            ],
        )

    @requests_mock.mock()
    def test_check_response_with_login_delete(self, m):
        filesystem_id = "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3"
        self.assertEqual(0, len(m.request_history))
        self._add_delete_filesystem_response_list(m, filesystem_id)
        self._add_login_success_response(m)
        result = self.manager.delete_filesystem(filesystem_id)
        self.assertEqual(result, True)

    def _add_delete_filesystem_response_list(self, m, filesystem_id):
        url = "{0}/rest/v1/file-systems/{1}".format(
            self._mock_url, filesystem_id
        )
        m.delete(
            url,
            [{"status_code": http_client.UNAUTHORIZED}, {"status_code": 204}],
        )

    @requests_mock.mock()
    def test_check_response_with_login_patch(self, m):
        filesystem_id = "6432b79e-1cc3-0414-3ffd-2a50fb1ccff3"
        new_size = 6441225472
        self.assertEqual(0, len(m.request_history))
        self._add_extend_export_response_list(m, filesystem_id)
        self._add_login_success_response(m)
        result = self.manager.extend_export(filesystem_id, new_size)
        self.assertEqual(result, True)

    def _add_extend_export_response_list(self, m, filesystem_id):
        url = "{0}/rest/v1/file-systems/{1}".format(
            self._mock_url, filesystem_id
        )
        m.patch(
            url,
            [{"status_code": http_client.UNAUTHORIZED}, {"status_code": 204}],
        )

    @requests_mock.mock()
    def test_check_response_with_invalid_credential(self, m):
        nas_server = "env8nasserver"
        self.assertEqual(0, len(m.request_history))
        self._add_get_nas_server_id_unauthorized_response(m, nas_server)
        self._add_login_fail_response(m)
        self.assertRaises(
            exception.NotAuthorized, self.manager.get_nas_server_id, nas_server
        )

    def _add_get_nas_server_id_unauthorized_response(self, m, nas_server):
        url = "{0}/rest/v1/nas-servers?select=id&name=eq.{1}".format(
            self._mock_url, nas_server
        )
        m.get(url, status_code=http_client.UNAUTHORIZED)

    def _add_login_fail_response(self, m):
        url = "{0}/rest/auth/login".format(self._mock_url)
        m.post(url, status_code=http_client.UNAUTHORIZED)

    @requests_mock.mock()
    def test_execute_powerflex_post_request_with_no_param(self, m):
        url = self._mock_url + "/fake_url"
        self.assertEqual(0, len(m.request_history))
        m.post(url, status_code=201)
        res, response = self.manager.execute_powerflex_post_request(url)
        self.assertEqual(res.status_code, 201)

    @requests_mock.mock()
    def test_execute_powerflex_patch_request_with_no_param(self, m):
        url = self._mock_url + "/fake_url"
        self.assertEqual(0, len(m.request_history))
        m.patch(url, status_code=204)
        res = self.manager.execute_powerflex_patch_request(url)
        self.assertEqual(res.status_code, 204)

    @requests_mock.mock()
    def test_get_storage_pool_spare_percentage(self, m):
        storage_pool_id = "28515fee00000000"
        self.assertEqual(0, len(m.request_history))
        self._add_get_storage_pool_spare_percentage(
            m,
            storage_pool_id,
            self._getJsonFile("get_storage_pool_spare_percentage.json"),
        )
        spare = self.manager.get_storage_pool_spare_percentage(storage_pool_id)
        self.assertEqual(spare, 34)

    def _add_get_storage_pool_spare_percentage(self, m, storage_pool_id,
                                               json_str):
        url = (
            "{0}/api/instances/StoragePool::{1}".format(
                self._mock_url, storage_pool_id
            )
        )
        m.get(url, status_code=200, json=json_str)

    @requests_mock.mock()
    def test_get_storage_pool_statistic(self, m):
        storage_pool_id = "28515fee00000000"
        self.assertEqual(0, len(m.request_history))
        self._add_get_storage_pool_statistic(
            m,
            storage_pool_id,
            self._getJsonFile("get_storage_pool_statistic.json"),
        )
        statistic = self.manager.get_storage_pool_statistic(storage_pool_id)
        self.assertEqual(statistic['maxCapacityInKb'], 4826330112)
        self.assertEqual(statistic['capacityInUseInKb'], 53217280)
        self.assertEqual(statistic['netUnusedCapacityInKb'], 1566080512)
        self.assertEqual(statistic['primaryVacInKb'], 184549376)

    def _add_get_storage_pool_statistic(self, m, storage_pool_id,
                                        json_str):
        url = (
            ("{0}/api/instances/StoragePool::{1}/relationships/" +
             "Statistics").format(
                self._mock_url, storage_pool_id
            )
        )
        m.get(url, status_code=200, json=json_str)
