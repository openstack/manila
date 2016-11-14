# Copyright (c) 2016 EMC Corporation.
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

from manila import exception
from manila import test
from manila.tests.share.drivers.dell_emc.plugins.unity import res_mock


class TestClient(test.TestCase):
    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_cifs_share__existed_expt(self, client, mocked_input):
        resource = mocked_input['filesystem']
        share = mocked_input['cifs_share']

        new_share = client.create_cifs_share(resource, share.name)

        self.assertEqual(share.name, new_share.name)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_nfs_share__existed_expt(self, client, mocked_input):
        resource = mocked_input['filesystem']
        share = mocked_input['nfs_share']
        new_share = client.create_nfs_share(resource, share.name)

        self.assertEqual(share.name, new_share.name)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_nfs_filesystem_and_share(self, client, mocked_input):
        pool = mocked_input['pool']
        nas_server = mocked_input['nas_server']
        share = mocked_input['nfs_share']

        client.create_nfs_filesystem_and_share(
            pool, nas_server, share.name,
            share.size)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_get_share_with_invalid_proto(self, client, mocked_input):
        share = mocked_input['share']

        self.assertRaises(exception.BadConfigurationException,
                          client.get_share,
                          share.name,
                          'fake_proto')

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_filesystem__existed_expt(self, client, mocked_input):
        pool = mocked_input['pool']
        nas_server = mocked_input['nas_server']
        filesystem = mocked_input['filesystem']

        new_filesystem = client.create_filesystem(pool,
                                                  nas_server,
                                                  filesystem.name,
                                                  filesystem.size,
                                                  filesystem.proto)

        self.assertEqual(filesystem.name, new_filesystem.name)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_delete_filesystem__nonexistent_expt(self, client, mocked_input):
        filesystem = mocked_input['filesystem']

        client.delete_filesystem(filesystem)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_nas_server__existed_expt(self, client, mocked_input):
        sp = mocked_input['sp']
        pool = mocked_input['pool']
        nas_server = mocked_input['nas_server']

        new_nas_server = client.create_nas_server(nas_server.name, sp, pool)

        self.assertEqual(nas_server.name, new_nas_server.name)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_delete_nas_server__nonexistent_expt(self, client, mocked_input):
        nas_server = mocked_input['nas_server']

        client.delete_nas_server(nas_server.name)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_dns_server__existed_expt(self, client, mocked_input):
        nas_server = mocked_input['nas_server']

        client.create_dns_server(nas_server, 'fake_domain', 'fake_dns_ip')

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_interface__existed_expt(self, client, mocked_input):
        nas_server = mocked_input['nas_server']
        port_set = ('fake_port',)

        self.assertRaises(exception.IPAddressInUse, client.create_interface,
                          nas_server, 'fake_ip_addr', 'fake_mask',
                          'fake_gateway', ports=port_set)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_enable_cifs_service__existed_expt(self, client, mocked_input):
        nas_server = mocked_input['nas_server']

        client.enable_cifs_service(
            nas_server, 'domain_name', 'fake_user', 'fake_passwd')

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_enable_nfs_service__existed_expt(self, client, mocked_input):
        nas_server = mocked_input['nas_server']

        client.enable_nfs_service(nas_server)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_snapshot__existed_expt(self, client, mocked_input):
        nas_server = mocked_input['filesystem']
        exp_snap = mocked_input['snapshot']

        client.create_snapshot(nas_server, exp_snap.name)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_snap_of_snap__existed_expt(self, client, mocked_input):
        snapshot = mocked_input['src_snapshot']
        dest_snap = mocked_input['dest_snapshot']

        new_snap = client.create_snap_of_snap(
            snapshot, dest_snap.name, 'checkpoint')

        self.assertEqual(dest_snap.name, new_snap.name)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_delete_snapshot__nonexistent_expt(self, client, mocked_input):
        snapshot = mocked_input['snapshot']

        client.delete_snapshot(snapshot)

    @res_mock.patch_client
    def test_nfs_deny_access__nonexistent_expt(self, client):
        client.nfs_deny_access('fake_share_name', 'fake_ip_addr')

    @res_mock.patch_client
    def test_get_storage_processor(self, client):
        sp = client.get_storage_processor(sp_id='SPA')

        self.assertEqual('SPA', sp.name)
