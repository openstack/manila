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

import ddt
import mock
from oslo_utils import units

from manila import exception
from manila import test
from manila.tests.share.drivers.dell_emc.plugins.unity import fake_exceptions
from manila.tests.share.drivers.dell_emc.plugins.unity import res_mock


@ddt.ddt
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
        self.assertRaises(exception.IPAddressInUse, client.create_interface,
                          nas_server, 'fake_ip_addr', 'fake_mask',
                          'fake_gateway', port_id='fake_port_id')

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

        new_snap = client.create_snap_of_snap(snapshot, dest_snap.name)

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

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_extend_filesystem(self, client, mocked_input):
        fs = mocked_input['fs']

        size = client.extend_filesystem(fs, 5)

        self.assertEqual(5 * units.Gi, size)

    @res_mock.patch_client
    def test_get_file_ports(self, client):
        ports = client.get_file_ports()
        self.assertEqual(2, len(ports))

    @res_mock.patch_client
    def test_get_tenant(self, client):
        tenant = client.get_tenant('test', 5)
        self.assertEqual('tenant_1', tenant.id)

    @res_mock.patch_client
    def test_get_tenant_preexist(self, client):
        tenant = client.get_tenant('test', 6)
        self.assertEqual('tenant_1', tenant.id)

    @res_mock.patch_client
    def test_get_tenant_name_inuse_but_vlan_not_used(self, client):
        self.assertRaises(fake_exceptions.UnityTenantNameInUseError,
                          client.get_tenant, 'test', 7)

    @res_mock.patch_client
    def test_get_tenant_for_vlan_0(self, client):
        tenant = client.get_tenant('tenant', 0)
        self.assertIsNone(tenant)

    @res_mock.patch_client
    def test_get_tenant_for_vlan_already_has_interfaces(self, client):
        tenant = client.get_tenant('tenant', 3)
        self.assertEqual('tenant_1', tenant.id)

    @res_mock.mock_client_input
    @res_mock.patch_client
    def test_create_file_interface_ipv6(self, client, mocked_input):
        mock_nas_server = mock.Mock()
        mock_nas_server.create_file_interface = mock.Mock(return_value=None)
        mock_file_interface = mocked_input['file_interface']
        mock_port_id = mock.Mock()
        client.create_interface(mock_nas_server,
                                mock_file_interface.ip_addr,
                                netmask=None,
                                gateway=mock_file_interface.gateway,
                                port_id=mock_port_id,
                                vlan_id=mock_file_interface.vlan_id,
                                prefix_length=mock_file_interface.prefix_length
                                )
        mock_nas_server.create_file_interface.assert_called_once_with(
            mock_port_id,
            mock_file_interface.ip_addr,
            netmask=None,
            v6_prefix_length=mock_file_interface.prefix_length,
            gateway=mock_file_interface.gateway,
            vlan_id=mock_file_interface.vlan_id)
