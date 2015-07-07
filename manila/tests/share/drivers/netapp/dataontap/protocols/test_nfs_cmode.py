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

from manila.common import constants
from manila import exception
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila import test
from manila.tests.share.drivers.netapp.dataontap.protocols \
    import fakes as fake


class NetAppClusteredNFSHelperTestCase(test.TestCase):

    def setUp(self):
        super(NetAppClusteredNFSHelperTestCase, self).setUp()

        self.mock_context = mock.Mock()
        self.mock_client = mock.Mock()
        self.helper = nfs_cmode.NetAppCmodeNFSHelper()
        self.helper.set_client(self.mock_client)

    def test_create_share(self):

        mock_ensure_export_policy = self.mock_object(self.helper,
                                                     '_ensure_export_policy')
        self.mock_client.get_volume_junction_path.return_value = (
            fake.NFS_SHARE_PATH)

        result = self.helper.create_share(fake.NFS_SHARE,
                                          fake.SHARE_NAME,
                                          [fake.SHARE_ADDRESS_1])

        expected = [':'.join([fake.SHARE_ADDRESS_1, fake.NFS_SHARE_PATH])]
        self.assertEqual(expected, result)
        self.mock_client.clear_nfs_export_policy_for_volume.\
            assert_called_once_with(fake.SHARE_NAME)
        self.assertTrue(mock_ensure_export_policy.called)

    def test_create_share_multiple(self):

        mock_ensure_export_policy = self.mock_object(self.helper,
                                                     '_ensure_export_policy')
        self.mock_client.get_volume_junction_path.return_value = (
            fake.NFS_SHARE_PATH)

        result = self.helper.create_share(fake.NFS_SHARE,
                                          fake.SHARE_NAME,
                                          [fake.SHARE_ADDRESS_1,
                                           fake.SHARE_ADDRESS_2])

        expected = [':'.join([fake.SHARE_ADDRESS_1, fake.NFS_SHARE_PATH]),
                    ':'.join([fake.SHARE_ADDRESS_2, fake.NFS_SHARE_PATH])]
        self.assertEqual(expected, result)
        self.mock_client.clear_nfs_export_policy_for_volume.\
            assert_called_once_with(fake.SHARE_NAME)
        self.assertTrue(mock_ensure_export_policy.called)

    def test_delete_share(self):

        self.helper.delete_share(fake.NFS_SHARE, fake.SHARE_NAME)

        self.mock_client.clear_nfs_export_policy_for_volume.\
            assert_called_once_with(fake.SHARE_NAME)
        self.mock_client.soft_delete_nfs_export_policy.assert_called_once_with(
            fake.EXPORT_POLICY_NAME)

    def test_allow_access(self):

        mock_ensure_export_policy = self.mock_object(self.helper,
                                                     '_ensure_export_policy')

        self.helper.allow_access(self.mock_context,
                                 fake.NFS_SHARE,
                                 fake.SHARE_NAME,
                                 fake.IP_ACCESS)

        self.assertTrue(mock_ensure_export_policy.called)
        self.mock_client.add_nfs_export_rule.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.CLIENT_ADDRESS_1, False)

    def test_allow_access_readonly(self):

        ip_access = copy.deepcopy(fake.IP_ACCESS)
        ip_access['access_level'] = constants.ACCESS_LEVEL_RO

        mock_ensure_export_policy = self.mock_object(self.helper,
                                                     '_ensure_export_policy')

        self.helper.allow_access(self.mock_context,
                                 fake.NFS_SHARE,
                                 fake.SHARE_NAME,
                                 ip_access)

        self.assertTrue(mock_ensure_export_policy.called)
        self.mock_client.add_nfs_export_rule.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.CLIENT_ADDRESS_1, True)

    def test_allow_access_invalid_level(self):

        ip_access = copy.deepcopy(fake.IP_ACCESS)
        ip_access['access_level'] = 'fake_level'

        self.assertRaises(exception.InvalidShareAccessLevel,
                          self.helper.allow_access,
                          self.mock_context,
                          fake.NFS_SHARE,
                          fake.SHARE_NAME,
                          ip_access)

    def test_allow_access_invalid_type(self):

        ip_access = copy.deepcopy(fake.IP_ACCESS)
        ip_access['access_type'] = 'user'

        self.assertRaises(exception.InvalidShareAccess,
                          self.helper.allow_access,
                          self.mock_context,
                          fake.NFS_SHARE,
                          fake.SHARE_NAME,
                          ip_access)

    def test_deny_access(self):

        mock_ensure_export_policy = self.mock_object(self.helper,
                                                     '_ensure_export_policy')

        self.helper.deny_access(self.mock_context,
                                fake.NFS_SHARE,
                                fake.SHARE_NAME,
                                fake.IP_ACCESS)

        self.assertTrue(mock_ensure_export_policy.called)
        self.mock_client.remove_nfs_export_rule.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.CLIENT_ADDRESS_1)

    def test_deny_access_invalid_type(self):

        ip_access = copy.deepcopy(fake.IP_ACCESS)
        ip_access['access_type'] = 'user'

        mock_ensure_export_policy = self.mock_object(self.helper,
                                                     '_ensure_export_policy')

        self.helper.deny_access(self.mock_context,
                                fake.NFS_SHARE,
                                fake.SHARE_NAME,
                                ip_access)

        self.assertFalse(mock_ensure_export_policy.called)
        self.assertFalse(self.mock_client.remove_nfs_export_rule.called)

    def test_get_target(self):

        target = self.helper.get_target(fake.NFS_SHARE)
        self.assertEqual(fake.SHARE_ADDRESS_1, target)

    def test_get_share_name_for_share(self):

        self.mock_client.get_volume_at_junction_path.return_value = (
            fake.VOLUME)

        share_name = self.helper.get_share_name_for_share(fake.NFS_SHARE)

        self.assertEqual(fake.SHARE_NAME, share_name)
        self.mock_client.get_volume_at_junction_path.assert_called_once_with(
            fake.NFS_SHARE_PATH)

    def test_get_share_name_for_share_not_found(self):

        self.mock_client.get_volume_at_junction_path.return_value = None

        share_name = self.helper.get_share_name_for_share(fake.NFS_SHARE)

        self.assertIsNone(share_name)
        self.mock_client.get_volume_at_junction_path.assert_called_once_with(
            fake.NFS_SHARE_PATH)

    def test_get_target_missing_location(self):

        target = self.helper.get_target({'export_location': ''})
        self.assertEqual('', target)

    def test_get_export_location(self):

        host_ip, export_path = self.helper._get_export_location(
            fake.NFS_SHARE)
        self.assertEqual(fake.SHARE_ADDRESS_1, host_ip)
        self.assertEqual('/' + fake.SHARE_NAME, export_path)

    def test_get_export_location_missing_location(self):

        fake_share = fake.NFS_SHARE.copy()
        fake_share['export_location'] = ''

        host_ip, export_path = self.helper._get_export_location(fake_share)

        self.assertEqual('', host_ip)
        self.assertEqual('', export_path)

    def test_get_export_policy_name(self):

        result = self.helper._get_export_policy_name(fake.NFS_SHARE)
        self.assertEqual(fake.EXPORT_POLICY_NAME, result)

    def test_ensure_export_policy_equal(self):

        self.mock_client.get_nfs_export_policy_for_volume.return_value = (
            fake.EXPORT_POLICY_NAME)

        self.helper._ensure_export_policy(fake.NFS_SHARE, fake.SHARE_NAME)

        self.assertFalse(self.mock_client.create_nfs_export_policy.called)
        self.assertFalse(self.mock_client.rename_nfs_export_policy.called)

    def test_ensure_export_policy_default(self):

        self.mock_client.get_nfs_export_policy_for_volume.return_value = (
            'default')

        self.helper._ensure_export_policy(fake.NFS_SHARE, fake.SHARE_NAME)

        self.mock_client.create_nfs_export_policy.assert_called_once_with(
            fake.EXPORT_POLICY_NAME)
        self.mock_client.set_nfs_export_policy_for_volume.\
            assert_called_once_with(fake.SHARE_NAME, fake.EXPORT_POLICY_NAME)
        self.assertFalse(self.mock_client.rename_nfs_export_policy.called)

    def test_ensure_export_policy_rename(self):

        self.mock_client.get_nfs_export_policy_for_volume.return_value = 'fake'

        self.helper._ensure_export_policy(fake.NFS_SHARE, fake.SHARE_NAME)

        self.assertFalse(self.mock_client.create_nfs_export_policy.called)
        self.mock_client.rename_nfs_export_policy.assert_called_once_with(
            'fake', fake.EXPORT_POLICY_NAME)
