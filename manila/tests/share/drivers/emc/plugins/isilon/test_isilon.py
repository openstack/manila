# Copyright (c) 2015 EMC Corporation.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import ddt
import mock
from oslo_log import log
from oslo_utils import units
import six

from manila.common import constants as const
from manila import exception
from manila.share.drivers.emc.plugins.isilon import isilon
from manila.share.drivers.emc.plugins.isilon.isilon_api import SmbPermission
from manila import test

LOG = log.getLogger(__name__)


@ddt.ddt
class IsilonTest(test.TestCase):
    """Integration test for the Isilon Manila driver."""

    ISILON_ADDR = '10.0.0.1'
    API_URL = 'https://%s:8080' % ISILON_ADDR
    AUTH = ('admin', 'admin')

    ROOT_DIR = '/ifs/manila-test'
    SHARE_NAME = 'share-foo'
    SHARE_DIR = ROOT_DIR + '/' + SHARE_NAME
    ADMIN_HOME_DIR = '/ifs/home/admin'
    CLONE_DIR = ROOT_DIR + '/clone-dir'

    class MockConfig(object):

        def safe_get(self, value):
            if value == 'emc_nas_server':
                return '10.0.0.1'
            elif value == 'emc_nas_server_port':
                return '8080'
            elif value == 'emc_nas_login':
                return 'admin'
            elif value == 'emc_nas_password':
                return 'a'
            elif value == 'emc_nas_root_dir':
                return '/ifs/manila-test'
            else:
                return None

    @mock.patch(
        'manila.share.drivers.emc.plugins.isilon.isilon.isilon_api.IsilonApi',
        autospec=True)
    def setUp(self, mock_isi_api):
        super(IsilonTest, self).setUp()

        self._mock_isilon_api = mock_isi_api.return_value
        self.storage_connection = isilon.IsilonStorageConnection(LOG)

        self.mock_context = mock.Mock('Context')
        self.mock_emc_driver = mock.Mock('EmcDriver')

        self.mock_emc_driver.attach_mock(self.MockConfig(), 'configuration')
        self.storage_connection.connect(
            self.mock_emc_driver, self.mock_context)

    def test_allow_access_single_ip_nfs(self):
        # setup
        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {'access_type': 'ip', 'access_to': '10.1.1.10',
                  'access_level': const.ACCESS_LEVEL_RW}
        share_server = None
        fake_export_id = 1
        self._mock_isilon_api.lookup_nfs_export.return_value = fake_export_id
        self._mock_isilon_api.get_nfs_export.return_value = {
            'clients': []}
        self.assertFalse(self._mock_isilon_api.request.called)

        # call method under test
        self.storage_connection.allow_access(self.mock_context, share, access,
                                             share_server)

        # verify expected REST API call is executed
        expected_url = (self.API_URL + '/platform/1/protocols/nfs/exports/' +
                        str(fake_export_id))
        expected_data = {'clients': ['10.1.1.10']}
        self._mock_isilon_api.request.assert_called_once_with(
            'PUT', expected_url, data=expected_data)

    def test_allow_access_with_nfs_readonly(self):
        # setup
        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {'access_type': 'ip', 'access_to': '10.1.1.10',
                  'access_level': const.ACCESS_LEVEL_RO}
        fake_export_id = 70
        self._mock_isilon_api.lookup_nfs_export.return_value = fake_export_id
        self._mock_isilon_api.get_nfs_export.return_value = {
            'read_only_clients': []}
        self.assertFalse(self._mock_isilon_api.request.called)

        self.storage_connection.allow_access(
            self.mock_context, share, access, None)

        # verify expected REST API call is executed
        expected_url = (self.API_URL + '/platform/1/protocols/nfs/exports/' +
                        six.text_type(fake_export_id))
        expected_data = {'read_only_clients': ['10.1.1.10']}
        self._mock_isilon_api.request.assert_called_once_with(
            'PUT', expected_url, data=expected_data)

    def test_allow_access_with_nfs_readwrite(self):
        # setup
        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {'access_type': 'ip', 'access_to': '10.1.1.10',
                  'access_level': const.ACCESS_LEVEL_RW}
        fake_export_id = 70
        self._mock_isilon_api.lookup_nfs_export.return_value = fake_export_id
        self._mock_isilon_api.get_nfs_export.return_value = {
            'clients': []}
        self.assertFalse(self._mock_isilon_api.request.called)

        self.storage_connection.allow_access(
            self.mock_context, share, access, None)

        # verify expected REST API call is executed
        expected_url = (self.API_URL + '/platform/1/protocols/nfs/exports/' +
                        six.text_type(fake_export_id))
        expected_data = {'clients': ['10.1.1.10']}
        self._mock_isilon_api.request.assert_called_once_with(
            'PUT', expected_url, data=expected_data)

    def test_allow_access_with_cifs_ip_readonly(self):
        # Note: Driver does not currently support readonly access for "ip" type
        share = {'name': self.SHARE_NAME, 'share_proto': 'CIFS'}
        access = {'access_type': 'ip', 'access_to': '10.1.1.10',
                  'access_level': const.ACCESS_LEVEL_RO}

        self.assertRaises(
            exception.InvalidShareAccess, self.storage_connection.allow_access,
            self.mock_context, share, access, None)

    def test_deny_access__ip_nfs_readwrite(self):
        """Verifies that an IP will be remove from a whitelist."""
        fake_export_id = 1
        self._mock_isilon_api.lookup_nfs_export.return_value = fake_export_id
        # simulate an IP added to the whitelist
        ip_addr = '10.0.0.4'
        self._mock_isilon_api.get_nfs_export.return_value = {
            'clients': [ip_addr]}

        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {'access_type': 'ip', 'access_to': ip_addr,
                  'access_level': const.ACCESS_LEVEL_RW}
        share_server = None

        # call method under test
        self.assertFalse(self._mock_isilon_api.request.called)
        self.storage_connection.deny_access(self.mock_context, share, access,
                                            share_server)

        # verify that a call is made to remove an existing IP from the list
        expected_url = (self.API_URL + '/platform/1/protocols/nfs/exports/' +
                        str(fake_export_id))
        expected_data = {'clients': []}
        self._mock_isilon_api.request.assert_called_once_with(
            'PUT', expected_url, data=expected_data
        )

    def test_deny_access__nfs_ip_readonly(self):
        fake_export_id = 1
        self._mock_isilon_api.lookup_nfs_export.return_value = fake_export_id
        # simulate an IP added to the whitelist
        ip_addr = '10.0.0.4'
        self._mock_isilon_api.get_nfs_export.return_value = {
            'read_only_clients': [ip_addr]}

        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {'access_type': 'ip', 'access_to': ip_addr,
                  'access_level': const.ACCESS_LEVEL_RO}
        share_server = None

        # call method under test
        self.assertFalse(self._mock_isilon_api.request.called)
        self.storage_connection.deny_access(self.mock_context, share, access,
                                            share_server)

        # verify that a call is made to remove an existing IP from the list
        expected_url = (self.API_URL + '/platform/1/protocols/nfs/exports/' +
                        six.text_type(fake_export_id))
        expected_data = {'read_only_clients': []}
        self._mock_isilon_api.request.assert_called_once_with(
            'PUT', expected_url, data=expected_data
        )

    def test_deny_access_ip_cifs(self):
        """Verifies that an IP will be remove from a whitelist.

        Precondition: the IP to be removed exists in the whitelist. Otherwise,
        do nothing.
        """

        # setup
        ip_addr = '10.1.1.10'
        share = {'name': self.SHARE_NAME, 'share_proto': 'CIFS'}
        self._mock_isilon_api.lookup_smb_share.return_value = {
            'host_acl': ['allow:' + ip_addr]}
        self.assertFalse(self._mock_isilon_api.request.called)

        # call method under test
        access = {'access_type': 'ip', 'access_to': ip_addr,
                  'access_level': const.ACCESS_LEVEL_RW}
        share_server = None
        self.storage_connection.deny_access(self.mock_context, share, access,
                                            share_server)

        # verify API call is made to remove IP is removed from whitelist
        expected_url = (self.API_URL + '/platform/1/protocols/smb/shares/' +
                        self.SHARE_NAME)
        expected_data = {'host_acl': []}
        self._mock_isilon_api.request.assert_called_once_with(
            'PUT', expected_url, data=expected_data)

    def test_deny_access_nfs_invalid_access_type(self):
        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {'access_type': 'foo_access_type', 'access_to': '10.0.0.1'}

        # This operation should return silently
        self.storage_connection.deny_access(
            self.mock_context, share, access, None)

    def test_deny_access_cifs_invalid_access_type(self):
        share = {'name': self.SHARE_NAME, 'share_proto': 'CIFS'}
        access = {'access_type': 'foo_access_type', 'access_to': '10.0.0.1'}

        # This operation should return silently
        self.storage_connection.deny_access(self.mock_context, share, access,
                                            None)

    def test_deny_access_invalid_share_protocol(self):
        share = {'name': self.SHARE_NAME, 'share_proto': 'FOO'}
        access = {'access_type': 'ip', 'access_to': '10.0.0.1',
                  'access_level': const.ACCESS_LEVEL_RW}

        # This operation should return silently
        self.storage_connection.deny_access(
            self.mock_context, share, access, None)

    def test_deny_access_nfs_export_does_not_exist(self):
        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {'access_type': 'ip', 'access_to': '10.0.0.1',
                  'access_level': const.ACCESS_LEVEL_RW}
        self._mock_isilon_api.lookup_nfs_export.return_value = 1
        self._mock_isilon_api.get_nfs_export.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.deny_access,
            self.mock_context, share, access, None
        )

    def test_deny_access_nfs_share_does_not_exist(self):
        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {'access_type': 'ip', 'access_to': '10.0.0.1',
                  'access_level': const.ACCESS_LEVEL_RW}
        self._mock_isilon_api.lookup_nfs_export.return_value = None

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.deny_access,
            self.mock_context, share, access, None)

    def test_deny_access_nfs_share_does_not_contain_required_key(self):
        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {
            'access_type': 'ip',
            'access_to': '10.0.0.1',
            'access_level': const.ACCESS_LEVEL_RW,
        }
        self._mock_isilon_api.get_nfs_export.return_value = {}
        self.assertRaises(exception.ShareBackendException,
                          self.storage_connection.deny_access,
                          self.mock_context, share, access, None)

    def test_allow_access_multiple_ip_nfs(self):
        """Verifies adding an IP to a whitelist with pre-existing ips.

        Verifies that when adding an additional IP to a whitelist which already
        contains IPs, the Isilon driver successfully appends the IP to the
        whitelist.
        """

        # setup
        fake_export_id = 42
        new_allowed_ip = '10.7.7.8'
        self._mock_isilon_api.lookup_nfs_export.return_value = fake_export_id
        existing_ips = ['10.0.0.1', '10.1.1.1', '10.0.0.2']
        export_json = {
            'clients': existing_ips,
            'access_level': const.ACCESS_LEVEL_RW,
        }
        self._mock_isilon_api.get_nfs_export.return_value = export_json
        self.assertFalse(self._mock_isilon_api.request.called)

        # call method under test
        share = {'name': self.SHARE_NAME, 'share_proto': 'NFS'}
        access = {'access_type': 'ip', 'access_to': new_allowed_ip,
                  'access_level': const.ACCESS_LEVEL_RW}
        share_server = None
        self.storage_connection.allow_access(
            self.mock_context, share, access, share_server)

        # verify access rule is applied
        expected_url = (self.API_URL + '/platform/1/protocols/nfs/exports/' +
                        str(fake_export_id))
        self.assertTrue(self._mock_isilon_api.request.called)
        args, kwargs = self._mock_isilon_api.request.call_args
        action, url = args
        self.assertEqual('PUT', action)
        self.assertEqual(expected_url, url)
        self.assertEqual(1, len(kwargs))
        self.assertTrue('data' in kwargs)
        actual_clients = set(kwargs['data']['clients'])
        expected_clients = set(existing_ips)
        expected_clients.add(new_allowed_ip)
        self.assertEqual(expected_clients, actual_clients)

    def test_allow_access_multiple_ip_cifs(self):
        """Verifies adding an IP to a whitelist with pre-existing ips.

        Verifies that when adding an additional IP to a whitelist which already
        contains IPs, the Isilon driver successfully appends the IP to the
        whitelist.
        """

        # setup
        share_name = self.SHARE_NAME
        new_allowed_ip = '10.101.1.1'
        existing_ips = ['allow:10.0.0.1', 'allow:10.1.1.1', 'allow:10.0.0.2']
        share_json = {'name': share_name, 'host_acl': existing_ips}
        self._mock_isilon_api.lookup_smb_share.return_value = share_json
        self.assertFalse(self._mock_isilon_api.request.called)

        # call method under test
        share = {'name': share_name, 'share_proto': 'CIFS'}
        access = {'access_type': 'ip', 'access_to': new_allowed_ip,
                  'access_level': const.ACCESS_LEVEL_RW}
        share_server = None
        self.storage_connection.allow_access(self.mock_context, share,
                                             access,
                                             share_server)

        # verify access rule is applied
        expected_url = (self.API_URL + '/platform/1/protocols/smb/shares/' +
                        share_name)
        self.assertTrue(self._mock_isilon_api.request.called)
        args, kwargs = self._mock_isilon_api.request.call_args
        action, url = args
        self.assertEqual('PUT', action)
        self.assertEqual(expected_url, url)
        self.assertEqual(1, len(kwargs))
        self.assertTrue('data' in kwargs)
        actual_clients = set(kwargs['data']['host_acl'])
        expected_clients = set(existing_ips)
        expected_clients.add('allow:' + new_allowed_ip)
        self.assertEqual(expected_clients, actual_clients)

    def test_allow_access_single_ip_cifs(self):
        # setup
        share_name = self.SHARE_NAME
        share = {'name': share_name, 'share_proto': 'CIFS'}
        allow_ip = '10.1.1.10'
        access = {'access_type': 'ip', 'access_to': allow_ip,
                  'access_level': const.ACCESS_LEVEL_RW}
        share_server = None
        self._mock_isilon_api.lookup_smb_share.return_value = {
            'name': share_name, 'host_acl': []}
        self.assertFalse(self._mock_isilon_api.request.called)

        # call method under test
        self.storage_connection.allow_access(self.mock_context, share, access,
                                             share_server)

        # verify access rule is applied
        expected_url = (self.API_URL + '/platform/1/protocols/smb/shares/' +
                        self.SHARE_NAME)
        expected_data = {'host_acl': ['allow:' + allow_ip]}
        self._mock_isilon_api.request.assert_called_once_with(
            'PUT', expected_url, data=expected_data)

    @ddt.data(
        ('foo', const.ACCESS_LEVEL_RW, SmbPermission.rw),
        ('testuser', const.ACCESS_LEVEL_RO, SmbPermission.ro),
    )
    def test_allow_access_with_cifs_user(self, data):
        # setup
        share_name = self.SHARE_NAME
        user, access_level, expected_smb_perm = data
        share = {'name': share_name, 'share_proto': 'CIFS'}
        access = {'access_type': 'user',
                  'access_to': user,
                  'access_level': access_level}

        self.storage_connection.allow_access(self.mock_context, share,
                                             access, None)

        self._mock_isilon_api.smb_permissions_add.assert_called_once_with(
            share_name, user, expected_smb_perm)

    def test_allow_access_with_cifs_user_invalid_access_level(self):
        share = {'name': self.SHARE_NAME, 'share_proto': 'CIFS'}
        access = {
            'access_type': 'user',
            'access_to': 'foo',
            'access_level': 'everything',
        }

        self.assertRaises(exception.InvalidShareAccess,
                          self.storage_connection.allow_access,
                          self.mock_context, share, access, None)

    def test_allow_access_with_cifs_invalid_access_type(self):
        share_name = self.SHARE_NAME
        share = {'name': share_name, 'share_proto': 'CIFS'}
        access = {'access_type': 'fooaccesstype',
                  'access_to': 'testuser',
                  'access_level': const.ACCESS_LEVEL_RW}

        self.assertRaises(exception.InvalidShareAccess,
                          self.storage_connection.allow_access,
                          self.mock_context, share, access, None)

    def test_deny_access_with_cifs_user(self):
        share_name = self.SHARE_NAME
        user_to_remove = 'testuser'
        share = {'name': share_name, 'share_proto': 'CIFS'}
        access = {'access_type': 'user',
                  'access_to': user_to_remove,
                  'access_level': const.ACCESS_LEVEL_RW}
        self.assertFalse(self._mock_isilon_api.smb_permissions_remove.called)

        self.storage_connection.deny_access(self.mock_context, share, access,
                                            None)

        self._mock_isilon_api.smb_permissions_remove.assert_called_with(
            share_name, user_to_remove)

    def test_allow_access_invalid_access_type(self):
        # setup
        share_name = self.SHARE_NAME
        share = {'name': share_name, 'share_proto': 'NFS'}
        allow_ip = '10.1.1.10'
        access = {'access_type': 'foo_access_type', 'access_to': allow_ip}

        # verify method under test throws the expected exception
        self.assertRaises(
            exception.InvalidShareAccess,
            self.storage_connection.allow_access,
            self.mock_context, share, access, None)

    def test_allow_access_invalid_share_protocol(self):
        # setup
        share_name = self.SHARE_NAME
        share = {'name': share_name, 'share_proto': 'FOO_PROTOCOL'}
        allow_ip = '10.1.1.10'
        access = {'access_type': 'ip', 'access_to': allow_ip}

        # verify method under test throws the expected exception
        self.assertRaises(
            exception.InvalidShare, self.storage_connection.allow_access,
            self.mock_context, share, access, None)

    def test_create_share_nfs(self):
        share_path = self.SHARE_DIR
        self.assertFalse(self._mock_isilon_api.create_directory.called)
        self.assertFalse(self._mock_isilon_api.create_nfs_export.called)

        # create the share
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS', "size": 8}
        location = self.storage_connection.create_share(self.mock_context,
                                                        share, None)

        # verify location and API call made
        expected_location = '%s:%s' % (self.ISILON_ADDR, self.SHARE_DIR)
        self.assertEqual(expected_location, location)
        self._mock_isilon_api.create_directory.assert_called_with(share_path)
        self._mock_isilon_api.create_nfs_export.assert_called_with(share_path)

        # verify directory quota call made
        self._mock_isilon_api.quota_create.assert_called_with(
            share_path, 'directory', 8 * units.Gi)

    def test_create_share_cifs(self):
        self.assertFalse(self._mock_isilon_api.create_directory.called)
        self.assertFalse(self._mock_isilon_api.create_smb_share.called)

        # create the share
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS', "size": 8}
        location = self.storage_connection.create_share(self.mock_context,
                                                        share, None)

        expected_location = '\\\\{0}\\{1}'.format(
            self.ISILON_ADDR, self.SHARE_NAME)
        self.assertEqual(expected_location, location)
        self._mock_isilon_api.create_directory.assert_called_once_with(
            self.SHARE_DIR)
        self._mock_isilon_api.create_smb_share.assert_called_once_with(
            self.SHARE_NAME, self.SHARE_DIR)

        # verify directory quota call made
        self._mock_isilon_api.quota_create.assert_called_with(
            self.SHARE_DIR, 'directory', 8 * units.Gi)

    def test_create_share_invalid_share_protocol(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'FOO_PROTOCOL'}

        self.assertRaises(
            exception.InvalidShare, self.storage_connection.create_share,
            self.mock_context, share, share_server=None)

    def test_create_share_nfs_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS'}
        self._mock_isilon_api.create_nfs_export.return_value = False

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share,
            self.mock_context, share, share_server=None)

    def test_create_snapshot(self):

        # create snapshot
        snapshot_name = "snapshot01"
        snapshot_path = '/ifs/home/admin'
        snapshot = {'name': snapshot_name, 'share_name': snapshot_path}
        self.storage_connection.create_snapshot(self.mock_context, snapshot,
                                                None)

        # verify the create snapshot API call is executed
        self._mock_isilon_api.create_snapshot.assert_called_with(snapshot_name,
                                                                 snapshot_path)

    def test_create_share_from_snapshot_nfs(self):
        # assertions
        self.assertFalse(self._mock_isilon_api.create_nfs_export.called)
        self.assertFalse(self._mock_isilon_api.clone_snapshot.called)

        snapshot_name = "snapshot01"
        snapshot_path = '/ifs/home/admin'

        # execute method under test
        snapshot = {'name': snapshot_name, 'share_name': snapshot_path}
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS', 'size': 5}
        location = self.storage_connection.create_share_from_snapshot(
            self.mock_context, share, snapshot, None)

        # verify NFS export created at expected location
        self._mock_isilon_api.create_nfs_export.assert_called_with(
            self.SHARE_DIR)

        # verify clone_directory(container_path) method called
        self._mock_isilon_api.clone_snapshot.assert_called_once_with(
            snapshot_name, self.SHARE_DIR)
        expected_location = '{0}:{1}'.format(
            self.ISILON_ADDR, self.SHARE_DIR)
        self.assertEqual(expected_location, location)

        # verify directory quota call made
        self._mock_isilon_api.quota_create.assert_called_with(
            self.SHARE_DIR, 'directory', 5 * units.Gi)

    def test_create_share_from_snapshot_cifs(self):
        # assertions
        self.assertFalse(self._mock_isilon_api.create_smb_share.called)
        self.assertFalse(self._mock_isilon_api.clone_snapshot.called)
        # setup
        snapshot_name = "snapshot01"
        snapshot_path = '/ifs/home/admin'
        new_share_name = 'clone-dir'

        # execute method under test
        snapshot = {'name': snapshot_name, 'share_name': snapshot_path}
        share = {"name": new_share_name, "share_proto": 'CIFS', "size": 2}
        location = self.storage_connection.create_share_from_snapshot(
            self.mock_context, share, snapshot, None)

        # verify call made to create new CIFS share
        self._mock_isilon_api.create_smb_share.assert_called_once_with(
            new_share_name, self.CLONE_DIR)
        self._mock_isilon_api.clone_snapshot.assert_called_once_with(
            snapshot_name, self.CLONE_DIR)
        expected_location = '\\\\{0}\\{1}'.format(self.ISILON_ADDR,
                                                  new_share_name)
        self.assertEqual(expected_location, location)

        # verify directory quota call made
        expected_share_path = '{0}/{1}'.format(self.ROOT_DIR, new_share_name)
        self._mock_isilon_api.quota_create.assert_called_with(
            expected_share_path, 'directory', 2 * units.Gi)

    def test_delete_share_nfs(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS'}
        fake_share_num = 42
        self._mock_isilon_api.lookup_nfs_export.return_value = fake_share_num
        self.assertFalse(self._mock_isilon_api.delete_nfs_share.called)

        # delete the share
        self.storage_connection.delete_share(self.mock_context, share, None)

        # verify share delete
        self._mock_isilon_api.delete_nfs_share.assert_called_with(
            fake_share_num)

    def test_delete_share_cifs(self):
        self.assertFalse(self._mock_isilon_api.delete_smb_share.called)

        # delete the share
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS'}
        self.storage_connection.delete_share(self.mock_context, share, None)

        # verify share deleted
        self._mock_isilon_api.delete_smb_share.assert_called_with(
            self.SHARE_NAME)

    def test_delete_share_invalid_share_proto(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'FOO_PROTOCOL'}
        self.assertRaises(
            exception.InvalidShare, self.storage_connection.delete_share,
            self.mock_context, share, None
        )

    def test_delete_nfs_share_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS'}

        self._mock_isilon_api.delete_nfs_share.return_value = False
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.delete_share,
            self.mock_context, share, None
        )

    def test_delete_nfs_share_share_does_not_exist(self):
        self._mock_isilon_api.lookup_nfs_export.return_value = None
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS'}

        # verify the calling delete on a non-existent share returns and does
        # not throw exception
        self.storage_connection.delete_share(self.mock_context, share, None)

    def test_delete_cifs_share_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS'}

        self._mock_isilon_api.delete_smb_share.return_value = False
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.delete_share,
            self.mock_context, share, None
        )

    def test_delete_cifs_share_share_does_not_exist(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS'}
        self._mock_isilon_api.lookup_smb_share.return_value = None

        # verify the calling delete on a non-existent share returns and does
        # not throw exception
        self.storage_connection.delete_share(self.mock_context, share, None)

    def test_delete_snapshot(self):
        # create a snapshot
        snapshot_name = "snapshot01"
        snapshot_path = '/ifs/home/admin'
        snapshot = {'name': snapshot_name, 'share_name': snapshot_path}
        self.assertFalse(self._mock_isilon_api.delete_snapshot.called)

        # delete the created snapshot
        self.storage_connection.delete_snapshot(self.mock_context, snapshot,
                                                None)

        # verify the API call was made to delete the snapshot
        self._mock_isilon_api.delete_snapshot.assert_called_once_with(
            snapshot_name)

    def test_ensure_share(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS'}
        self.storage_connection.ensure_share(self.mock_context, share, None)

    @mock.patch(
        'manila.share.drivers.emc.plugins.isilon.isilon.isilon_api.IsilonApi',
        autospec=True)
    def test_connect(self, mock_isi_api):
        storage_connection = isilon.IsilonStorageConnection(LOG)

        # execute method under test
        storage_connection.connect(
            self.mock_emc_driver, self.mock_context)

        # verify connect sets driver params appropriately
        mock_config = self.MockConfig()
        server_addr = mock_config.safe_get('emc_nas_server')
        self.assertEqual(server_addr, storage_connection._server)
        expected_port = int(mock_config.safe_get('emc_nas_server_port'))
        self.assertEqual(expected_port, storage_connection._port)
        self.assertEqual('https://{0}:{1}'.format(server_addr, expected_port),
                         storage_connection._server_url)
        expected_username = mock_config.safe_get('emc_nas_login')
        self.assertEqual(expected_username, storage_connection._username)
        expected_password = mock_config.safe_get('emc_nas_password')
        self.assertEqual(expected_password, storage_connection._password)
        self.assertFalse(storage_connection._verify_ssl_cert)

    @mock.patch(
        'manila.share.drivers.emc.plugins.isilon.isilon.isilon_api.IsilonApi',
        autospec=True)
    def test_connect_root_dir_does_not_exist(self, mock_isi_api):
        mock_isilon_api = mock_isi_api.return_value
        mock_isilon_api.is_path_existent.return_value = False
        storage_connection = isilon.IsilonStorageConnection(LOG)

        # call method under test
        storage_connection.connect(self.mock_emc_driver, self.mock_context)

        mock_isilon_api.create_directory.assert_called_once_with(
            self.ROOT_DIR, recursive=True)

    def test_update_share_stats(self):
        stats_dict = {}
        self.storage_connection.update_share_stats(stats_dict)

        expected_version = isilon.VERSION
        self.assertEqual({'driver_version': expected_version}, stats_dict)

    def test_get_network_allocations_number(self):
        # call method under test
        num = self.storage_connection.get_network_allocations_number()

        self.assertEqual(0, num)

    def test_extend_share(self):
        quota_id = 'abcdef'
        new_share_size = 8
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'NFS',
            "size": new_share_size
        }
        self._mock_isilon_api.quota_get.return_value = {'id': quota_id}
        self.assertFalse(self._mock_isilon_api.quota_set.called)

        self.storage_connection.extend_share(share, new_share_size)

        share_path = '{0}/{1}'.format(self.ROOT_DIR, self.SHARE_NAME)
        expected_quota_size = new_share_size * units.Gi
        self._mock_isilon_api.quota_set.assert_called_once_with(
            share_path, 'directory', expected_quota_size)
