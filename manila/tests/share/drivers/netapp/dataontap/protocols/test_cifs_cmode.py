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
Mock unit tests for the NetApp driver protocols CIFS class module.
"""

import copy

import ddt
import mock

from manila.common import constants
from manila import exception
from manila.share.drivers.netapp.dataontap.protocols import cifs_cmode
from manila import test
from manila.tests.share.drivers.netapp.dataontap.protocols \
    import fakes as fake


@ddt.ddt
class NetAppClusteredCIFSHelperTestCase(test.TestCase):

    def setUp(self):
        super(NetAppClusteredCIFSHelperTestCase, self).setUp()

        self.mock_context = mock.Mock()

        self.mock_client = mock.Mock()
        self.helper = cifs_cmode.NetAppCmodeCIFSHelper()
        self.helper.set_client(self.mock_client)

    def test_create_share(self):

        result = self.helper.create_share(fake.CIFS_SHARE, fake.SHARE_NAME)

        export_addresses = [fake.SHARE_ADDRESS_1, fake.SHARE_ADDRESS_2]
        export_paths = [result(address) for address in export_addresses]
        expected_paths = [
            r'\\%s\%s' % (fake.SHARE_ADDRESS_1, fake.SHARE_NAME),
            r'\\%s\%s' % (fake.SHARE_ADDRESS_2, fake.SHARE_NAME),
        ]
        self.assertEqual(expected_paths, export_paths)
        self.mock_client.create_cifs_share.assert_called_once_with(
            fake.SHARE_NAME)
        self.mock_client.remove_cifs_share_access.assert_called_once_with(
            fake.SHARE_NAME, 'Everyone')
        self.mock_client.set_volume_security_style.assert_called_once_with(
            fake.SHARE_NAME, security_style='ntfs')

    def test_delete_share(self):

        self.helper.delete_share(fake.CIFS_SHARE, fake.SHARE_NAME)

        self.mock_client.remove_cifs_share.assert_called_once_with(
            fake.SHARE_NAME)

    def test_update_access(self):

        mock_validate_access_rule = self.mock_object(self.helper,
                                                     '_validate_access_rule')
        mock_get_access_rules = self.mock_object(
            self.helper, '_get_access_rules',
            mock.Mock(return_value=fake.EXISTING_CIFS_RULES))
        mock_handle_added_rules = self.mock_object(self.helper,
                                                   '_handle_added_rules')
        mock_handle_ro_to_rw_rules = self.mock_object(self.helper,
                                                      '_handle_ro_to_rw_rules')
        mock_handle_rw_to_ro_rules = self.mock_object(self.helper,
                                                      '_handle_rw_to_ro_rules')
        mock_handle_deleted_rules = self.mock_object(self.helper,
                                                     '_handle_deleted_rules')

        self.helper.update_access(fake.CIFS_SHARE,
                                  fake.SHARE_NAME,
                                  [fake.USER_ACCESS])

        new_rules = {'fake_user': constants.ACCESS_LEVEL_RW}
        mock_validate_access_rule.assert_called_once_with(fake.USER_ACCESS)
        mock_get_access_rules.assert_called_once_with(fake.CIFS_SHARE,
                                                      fake.SHARE_NAME)
        mock_handle_added_rules.assert_called_once_with(
            fake.SHARE_NAME, fake.EXISTING_CIFS_RULES, new_rules)
        mock_handle_ro_to_rw_rules.assert_called_once_with(
            fake.SHARE_NAME, fake.EXISTING_CIFS_RULES, new_rules)
        mock_handle_rw_to_ro_rules.assert_called_once_with(
            fake.SHARE_NAME, fake.EXISTING_CIFS_RULES, new_rules)
        mock_handle_deleted_rules.assert_called_once_with(
            fake.SHARE_NAME, fake.EXISTING_CIFS_RULES, new_rules)

    def test_validate_access_rule(self):

        result = self.helper._validate_access_rule(fake.USER_ACCESS)

        self.assertIsNone(result)

    def test_validate_access_rule_invalid_type(self):

        rule = copy.copy(fake.USER_ACCESS)
        rule['access_type'] = 'ip'

        self.assertRaises(exception.InvalidShareAccess,
                          self.helper._validate_access_rule,
                          rule)

    def test_validate_access_rule_invalid_level(self):

        rule = copy.copy(fake.USER_ACCESS)
        rule['access_level'] = 'none'

        self.assertRaises(exception.InvalidShareAccessLevel,
                          self.helper._validate_access_rule,
                          rule)

    def test_handle_added_rules(self):

        self.helper._handle_added_rules(fake.SHARE_NAME,
                                        fake.EXISTING_CIFS_RULES,
                                        fake.NEW_CIFS_RULES)

        self.mock_client.add_cifs_share_access.assert_has_calls([
            mock.call(fake.SHARE_NAME, 'user5', False),
            mock.call(fake.SHARE_NAME, 'user6', True),
        ], any_order=True)

    def test_handle_ro_to_rw_rules(self):

        self.helper._handle_ro_to_rw_rules(fake.SHARE_NAME,
                                           fake.EXISTING_CIFS_RULES,
                                           fake.NEW_CIFS_RULES)

        self.mock_client.modify_cifs_share_access.assert_has_calls([
            mock.call(fake.SHARE_NAME, 'user2', False)
        ])

    def test_handle_rw_to_ro_rules(self):

        self.helper._handle_rw_to_ro_rules(fake.SHARE_NAME,
                                           fake.EXISTING_CIFS_RULES,
                                           fake.NEW_CIFS_RULES)

        self.mock_client.modify_cifs_share_access.assert_has_calls([
            mock.call(fake.SHARE_NAME, 'user3', True)
        ])

    def test_handle_deleted_rules(self):

        self.helper._handle_deleted_rules(fake.SHARE_NAME,
                                          fake.EXISTING_CIFS_RULES,
                                          fake.NEW_CIFS_RULES)

        self.mock_client.remove_cifs_share_access.assert_has_calls([
            mock.call(fake.SHARE_NAME, 'user4')
        ])

    def test_get_access_rules(self):

        self.mock_client.get_cifs_share_access = (
            mock.Mock(return_value='fake_rules'))

        result = self.helper._get_access_rules(fake.CIFS_SHARE,
                                               fake.SHARE_NAME)

        self.assertEqual('fake_rules', result)
        self.mock_client.get_cifs_share_access.assert_called_once_with(
            fake.SHARE_NAME)

    def test_get_target(self):

        target = self.helper.get_target(fake.CIFS_SHARE)
        self.assertEqual(fake.SHARE_ADDRESS_1, target)

    def test_get_target_missing_location(self):

        target = self.helper.get_target({'export_location': ''})
        self.assertEqual('', target)

    def test_get_share_name_for_share(self):

        share_name = self.helper.get_share_name_for_share(fake.CIFS_SHARE)

        self.assertEqual(fake.SHARE_NAME, share_name)

    @ddt.data(
        {
            'location': r'\\%s\%s' % (fake.SHARE_ADDRESS_1, fake.SHARE_NAME),
            'ip': fake.SHARE_ADDRESS_1,
            'share_name': fake.SHARE_NAME,
        }, {
            'location': r'//%s/%s' % (fake.SHARE_ADDRESS_1, fake.SHARE_NAME),
            'ip': fake.SHARE_ADDRESS_1,
            'share_name': fake.SHARE_NAME,
        },
        {'location': '', 'ip': '', 'share_name': ''},
        {'location': 'invalid', 'ip': '', 'share_name': ''},
    )
    @ddt.unpack
    def test_get_export_location(self, location, ip, share_name):

        share = fake.CIFS_SHARE.copy()
        share['export_location'] = location

        result_ip, result_share_name = self.helper._get_export_location(share)

        self.assertEqual(ip, result_ip)
        self.assertEqual(share_name, result_share_name)
