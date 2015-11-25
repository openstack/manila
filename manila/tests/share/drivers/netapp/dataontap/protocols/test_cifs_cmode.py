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
from oslo_log import log

from manila.common import constants
from manila import exception
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.protocols import cifs_cmode
from manila import test
from manila.tests.share.drivers.netapp.dataontap.protocols \
    import fakes as fake


@ddt.ddt
class NetAppClusteredCIFSHelperTestCase(test.TestCase):

    def setUp(self):
        super(NetAppClusteredCIFSHelperTestCase, self).setUp()

        # Mock loggers as themselves to allow logger arg validation
        mock_logger = log.getLogger('mock_logger')
        self.mock_object(cifs_cmode.LOG,
                         'error',
                         mock.Mock(side_effect=mock_logger.error))

        self.mock_context = mock.Mock()

        self.mock_client = mock.Mock()
        self.helper = cifs_cmode.NetAppCmodeCIFSHelper()
        self.helper.set_client(self.mock_client)

    def test_create_share(self):

        result = self.helper.create_share(fake.CIFS_SHARE,
                                          fake.SHARE_NAME,
                                          [fake.SHARE_ADDRESS_1])

        expected = [r'\\%s\%s' % (fake.SHARE_ADDRESS_1, fake.SHARE_NAME)]
        self.assertEqual(expected, result)
        self.mock_client.create_cifs_share.assert_called_once_with(
            fake.SHARE_NAME)
        self.mock_client.remove_cifs_share_access.assert_called_once_with(
            fake.SHARE_NAME, 'Everyone')

    def test_create_share_multiple(self):

        result = self.helper.create_share(fake.CIFS_SHARE,
                                          fake.SHARE_NAME,
                                          [fake.SHARE_ADDRESS_1,
                                           fake.SHARE_ADDRESS_2])

        expected = [r'\\%s\%s' % (fake.SHARE_ADDRESS_1, fake.SHARE_NAME),
                    r'\\%s\%s' % (fake.SHARE_ADDRESS_2, fake.SHARE_NAME)]
        self.assertEqual(expected, result)
        self.mock_client.create_cifs_share.assert_called_once_with(
            fake.SHARE_NAME)
        self.mock_client.remove_cifs_share_access.assert_called_once_with(
            fake.SHARE_NAME, 'Everyone')

    def test_delete_share(self):

        self.helper.delete_share(fake.CIFS_SHARE, fake.SHARE_NAME)

        self.mock_client.remove_cifs_share.assert_called_once_with(
            fake.SHARE_NAME)

    def test_allow_access(self):

        self.helper.allow_access(self.mock_context,
                                 fake.CIFS_SHARE,
                                 fake.SHARE_NAME,
                                 fake.USER_ACCESS)

        self.mock_client.add_cifs_share_access.assert_called_once_with(
            fake.SHARE_NAME, fake.USER_ACCESS['access_to'], False)

    def test_allow_access_readonly(self):

        user_access = copy.deepcopy(fake.USER_ACCESS)
        user_access['access_level'] = constants.ACCESS_LEVEL_RO

        self.helper.allow_access(self.mock_context,
                                 fake.CIFS_SHARE,
                                 fake.SHARE_NAME,
                                 user_access)

        self.mock_client.add_cifs_share_access.assert_called_once_with(
            fake.SHARE_NAME, fake.USER_ACCESS['access_to'], True)

    def test_allow_access_preexisting(self):

        self.mock_client.add_cifs_share_access.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EDUPLICATEENTRY))

        self.assertRaises(exception.ShareAccessExists,
                          self.helper.allow_access,
                          self.mock_context,
                          fake.CIFS_SHARE,
                          fake.SHARE_NAME,
                          fake.USER_ACCESS)

    def test_allow_access_api_error(self):

        self.mock_client.add_cifs_share_access.side_effect = (
            netapp_api.NaApiError())

        self.assertRaises(netapp_api.NaApiError,
                          self.helper.allow_access,
                          self.mock_context,
                          fake.CIFS_SHARE,
                          fake.SHARE_NAME,
                          fake.USER_ACCESS)

    def test_allow_access_invalid_level(self):

        user_access = copy.deepcopy(fake.USER_ACCESS)
        user_access['access_level'] = 'fake_level'

        self.assertRaises(exception.InvalidShareAccessLevel,
                          self.helper.allow_access,
                          self.mock_context,
                          fake.NFS_SHARE,
                          fake.SHARE_NAME,
                          user_access)

    def test_allow_access_invalid_type(self):

        fake_access = fake.USER_ACCESS.copy()
        fake_access['access_type'] = 'group'
        self.assertRaises(exception.InvalidShareAccess,
                          self.helper.allow_access,
                          self.mock_context,
                          fake.CIFS_SHARE,
                          fake.SHARE_NAME,
                          fake_access)

    def test_deny_access(self):

        self.helper.deny_access(self.mock_context,
                                fake.CIFS_SHARE,
                                fake.SHARE_NAME,
                                fake.USER_ACCESS)

        self.mock_client.remove_cifs_share_access.assert_called_once_with(
            fake.SHARE_NAME, fake.USER_ACCESS['access_to'])

    def test_deny_access_nonexistent_user(self):

        self.mock_client.remove_cifs_share_access.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EONTAPI_EINVAL))

        self.helper.deny_access(self.mock_context,
                                fake.CIFS_SHARE,
                                fake.SHARE_NAME,
                                fake.USER_ACCESS)

        self.mock_client.remove_cifs_share_access.assert_called_once_with(
            fake.SHARE_NAME, fake.USER_ACCESS['access_to'])
        self.assertEqual(1, cifs_cmode.LOG.error.call_count)

    def test_deny_access_nonexistent_rule(self):

        self.mock_client.remove_cifs_share_access.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND))

        self.helper.deny_access(self.mock_context,
                                fake.CIFS_SHARE,
                                fake.SHARE_NAME,
                                fake.USER_ACCESS)

        self.mock_client.remove_cifs_share_access.assert_called_once_with(
            fake.SHARE_NAME, fake.USER_ACCESS['access_to'])
        self.assertEqual(1, cifs_cmode.LOG.error.call_count)

    def test_deny_access_api_error(self):

        self.mock_client.remove_cifs_share_access.side_effect = (
            netapp_api.NaApiError())

        self.assertRaises(netapp_api.NaApiError,
                          self.helper.deny_access,
                          self.mock_context,
                          fake.CIFS_SHARE,
                          fake.SHARE_NAME,
                          fake.USER_ACCESS)

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
