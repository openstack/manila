# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
"""
Mock unit tests for the NetApp driver protocols NFS class module.
"""

import copy

import mock

from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila import test
from manila.tests.share.drivers.netapp.dataontap.protocols \
    import fakes as fake


class NetAppClusteredNFSHelperTestCase(test.TestCase):

    def setUp(self):
        super(NetAppClusteredNFSHelperTestCase, self).setUp()
        self.mock_object(nfs_cmode, 'LOG')

        self.mock_context = mock.Mock()

        self.mock_client = mock.Mock()
        self.helper = nfs_cmode.NetAppCmodeNFSHelper()
        self.helper.set_client(self.mock_client)

    def test_create_share(self):

        self.mock_client.get_volume_junction_path.return_value = (
            fake.NFS_SHARE_PATH)

        result = self.helper.create_share(fake.SHARE_NAME, fake.SHARE_ADDRESS)

        self.mock_client.add_nfs_export_rules.assert_called_once_with(
            fake.NFS_SHARE_PATH, ['localhost'])
        self.assertEqual(':'.join([fake.SHARE_ADDRESS, fake.NFS_SHARE_PATH]),
                         result)

    def test_delete_share(self):

        self.helper.delete_share(fake.NFS_SHARE)

        self.mock_client.remove_nfs_export_rules.assert_called_once_with(
            fake.NFS_SHARE_PATH)

    def test_allow_access(self):

        mock_modify_rule = self.mock_object(self.helper, '_modify_rule')
        self.mock_client.get_nfs_export_rules.return_value = ['localhost']

        self.helper.allow_access(
            self.mock_context, fake.NFS_SHARE, fake.ACCESS)

        mock_modify_rule.assert_called_once_with(
            fake.NFS_SHARE, ['localhost'] + fake.ACCESS['access_to'])

    def test_allow_access_single_host(self):

        mock_modify_rule = self.mock_object(self.helper, '_modify_rule')
        self.mock_client.get_nfs_export_rules.return_value = ['localhost']
        fake_access = copy.deepcopy(fake.ACCESS)
        fake_access['access_to'] = fake.CLIENT_ADDRESS_1

        self.helper.allow_access(
            self.mock_context, fake.NFS_SHARE, fake_access)

        mock_modify_rule.assert_called_once_with(
            fake.NFS_SHARE, ['localhost'] + fake.ACCESS['access_to'])

    def test_allow_access_api_error(self):

        mock_modify_rule = self.mock_object(self.helper, '_modify_rule')
        mock_modify_rule.side_effect = [netapp_api.NaApiError, None]
        self.mock_client.get_nfs_export_rules.return_value = ['localhost']

        self.helper.allow_access(
            self.mock_context, fake.NFS_SHARE, fake.ACCESS)

        mock_modify_rule.assert_has_calls([
            mock.call(
                fake.NFS_SHARE, ['localhost'] + fake.ACCESS['access_to']),
            mock.call(fake.NFS_SHARE, ['localhost'])
        ])

    def test_deny_access(self):

        mock_modify_rule = self.mock_object(self.helper, '_modify_rule')
        existing_hosts = [fake.CLIENT_ADDRESS_1, fake.CLIENT_ADDRESS_2]
        self.mock_client.get_nfs_export_rules.return_value = existing_hosts

        fake_access = fake.ACCESS.copy()
        fake_access['access_to'] = [fake.CLIENT_ADDRESS_2]
        self.helper.deny_access(
            self.mock_context, fake.NFS_SHARE, fake_access)

        mock_modify_rule.assert_called_once_with(
            fake.NFS_SHARE, [fake.CLIENT_ADDRESS_1])

    def test_deny_access_single_host(self):

        mock_modify_rule = self.mock_object(self.helper, '_modify_rule')
        existing_hosts = [fake.CLIENT_ADDRESS_1, fake.CLIENT_ADDRESS_2]
        self.mock_client.get_nfs_export_rules.return_value = existing_hosts

        fake_access = fake.ACCESS.copy()
        fake_access['access_to'] = fake.CLIENT_ADDRESS_2
        self.helper.deny_access(
            self.mock_context, fake.NFS_SHARE, fake_access)

        mock_modify_rule.assert_called_once_with(
            fake.NFS_SHARE, [fake.CLIENT_ADDRESS_1])

    def test_get_target(self):

        target = self.helper.get_target(fake.NFS_SHARE)
        self.assertEqual(fake.SHARE_ADDRESS, target)

    def test_get_target_missing_location(self):

        target = self.helper.get_target({'export_location': ''})
        self.assertEqual('', target)

    def test_modify_rule(self):

        access_rules = [fake.CLIENT_ADDRESS_1, fake.CLIENT_ADDRESS_2]

        self.helper._modify_rule(fake.NFS_SHARE, access_rules)

        self.mock_client.add_nfs_export_rules.assert_called_once_with(
            fake.NFS_SHARE_PATH, access_rules)

    def test_get_existing_rules(self):

        self.mock_client.get_nfs_export_rules.return_value = (
            fake.NFS_ACCESS_HOSTS)

        result = self.helper._get_existing_rules(fake.NFS_SHARE)

        self.mock_client.get_nfs_export_rules.assert_called_once_with(
            fake.NFS_SHARE_PATH)
        self.assertEqual(fake.NFS_ACCESS_HOSTS, result)

    def test_get_export_location(self):

        host_ip, export_path = self.helper._get_export_location(
            fake.NFS_SHARE)
        self.assertEqual(fake.SHARE_ADDRESS, host_ip)
        self.assertEqual('/' + fake.SHARE_NAME, export_path)

    def test_get_export_location_missing_location(self):

        fake_share = fake.NFS_SHARE.copy()
        fake_share['export_location'] = ''

        host_ip, export_path = self.helper._get_export_location(fake_share)

        self.assertEqual('', host_ip)
        self.assertEqual('', export_path)