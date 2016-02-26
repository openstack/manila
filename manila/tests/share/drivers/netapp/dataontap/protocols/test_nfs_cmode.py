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
import uuid

import ddt
import mock
import netaddr

from manila import exception
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila import test
from manila.tests.share.drivers.netapp.dataontap.protocols \
    import fakes as fake


@ddt.ddt
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

        result = self.helper.create_share(fake.NFS_SHARE, fake.SHARE_NAME)

        export_addresses = [fake.SHARE_ADDRESS_1, fake.SHARE_ADDRESS_2]
        export_paths = [result(address) for address in export_addresses]
        expected_paths = [
            fake.SHARE_ADDRESS_1 + ":" + fake.NFS_SHARE_PATH,
            fake.SHARE_ADDRESS_2 + ":" + fake.NFS_SHARE_PATH,
        ]
        self.assertEqual(expected_paths, export_paths)
        (self.mock_client.clear_nfs_export_policy_for_volume.
            assert_called_once_with(fake.SHARE_NAME))
        self.assertTrue(mock_ensure_export_policy.called)

    def test_delete_share(self):

        self.helper.delete_share(fake.NFS_SHARE, fake.SHARE_NAME)

        self.mock_client.clear_nfs_export_policy_for_volume.\
            assert_called_once_with(fake.SHARE_NAME)
        self.mock_client.soft_delete_nfs_export_policy.assert_called_once_with(
            fake.EXPORT_POLICY_NAME)

    def test_update_access(self):

        self.mock_object(self.helper, '_ensure_export_policy')
        self.mock_object(self.helper,
                         '_get_export_policy_name',
                         mock.Mock(return_value='fake_export_policy'))
        self.mock_object(self.helper,
                         '_get_temp_export_policy_name',
                         mock.Mock(side_effect=['fake_new_export_policy',
                                                'fake_old_export_policy']))

        self.helper.update_access(fake.CIFS_SHARE,
                                  fake.SHARE_NAME,
                                  [fake.IP_ACCESS])

        self.mock_client.create_nfs_export_policy.assert_called_once_with(
            'fake_new_export_policy')
        self.mock_client.add_nfs_export_rule.assert_called_once_with(
            'fake_new_export_policy', fake.CLIENT_ADDRESS_1, False)
        (self.mock_client.set_nfs_export_policy_for_volume.
            assert_called_once_with(fake.SHARE_NAME, 'fake_new_export_policy'))
        (self.mock_client.soft_delete_nfs_export_policy.
            assert_called_once_with('fake_old_export_policy'))
        self.mock_client.rename_nfs_export_policy.assert_has_calls([
            mock.call('fake_export_policy', 'fake_old_export_policy'),
            mock.call('fake_new_export_policy', 'fake_export_policy'),
        ])

    def test_validate_access_rule(self):

        result = self.helper._validate_access_rule(fake.IP_ACCESS)

        self.assertIsNone(result)

    def test_validate_access_rule_invalid_type(self):

        rule = copy.copy(fake.IP_ACCESS)
        rule['access_type'] = 'user'

        self.assertRaises(exception.InvalidShareAccess,
                          self.helper._validate_access_rule,
                          rule)

    def test_validate_access_rule_invalid_level(self):

        rule = copy.copy(fake.IP_ACCESS)
        rule['access_level'] = 'none'

        self.assertRaises(exception.InvalidShareAccessLevel,
                          self.helper._validate_access_rule,
                          rule)

    def test_get_sorted_access_rule_addresses(self):

        result = self.helper._get_sorted_access_rule_addresses(
            fake.NEW_NFS_RULES)

        expected = [
            '10.10.20.10',
            '10.10.20.0/24',
            '10.10.10.10',
            '10.10.10.0/30',
            '10.10.10.0/24',
        ]
        self.assertEqual(expected, result)

    @ddt.data({'rule': '1.2.3.4', 'out': netaddr.IPAddress('1.2.3.4')},
              {'rule': '1.2.3.4/32', 'out': netaddr.IPNetwork('1.2.3.4/32')})
    @ddt.unpack
    def test_get_network_object_from_rule(self, rule, out):

        result = self.helper._get_network_object_from_rule(rule)

        self.assertEqual(out, result)

    def test_get_network_object_from_rule_invalid(self):

        self.assertRaises(netaddr.AddrFormatError,
                          self.helper._get_network_object_from_rule,
                          'invalid')

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

    def test_get_temp_export_policy_name(self):

        self.mock_object(uuid, 'uuid1', mock.Mock(return_value='fake-uuid'))

        result = self.helper._get_temp_export_policy_name()

        self.assertEqual('temp_fake_uuid', result)

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
