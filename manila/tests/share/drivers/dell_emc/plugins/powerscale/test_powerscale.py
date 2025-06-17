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

from unittest import mock

import ddt
from oslo_log import log
from oslo_utils import units

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.plugins.powerscale import powerscale
from manila import test

LOG = log.getLogger(__name__)


@ddt.ddt
class PowerScaleTest(test.TestCase):
    """Integration test for the PowerScale Manila driver."""

    POWERSCALE_ADDR = '10.0.0.1'
    API_URL = 'https://%s:8080' % POWERSCALE_ADDR
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
            elif value == 'powerscale_dir_permission':
                return '0777'
            else:
                return None

    class MockInvalidConfig(object):

        def safe_get(self, value):
            if value == 'emc_nas_server':
                return '10.0.0.1'
            elif value == 'emc_nas_server_port':
                return '8080'
            elif value == 'emc_nas_login':
                return 'admin'
            elif value == 'emc_nas_root_dir':
                return '/ifs/manila-test'
            else:
                return None

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.'
        'powerscale_api.PowerScaleApi', autospec=True)
    def setUp(self, mock_isi_api):
        super(PowerScaleTest, self).setUp()

        self._mock_powerscale_api = mock_isi_api.return_value
        self.storage_connection = powerscale.PowerScaleStorageConnection(LOG)

        self.mock_context = mock.Mock('Context')
        self.mock_emc_driver = mock.Mock('EmcDriver')

        self.mock_emc_driver.attach_mock(self.MockConfig(), 'configuration')
        self.storage_connection.connect(
            self.mock_emc_driver, self.mock_context)

    def test_allow_access(self):
        self.assertRaises(
            NotImplementedError,
            self.storage_connection.allow_access,
            self.mock_context,
            share=None,
            access=None,
            share_server=None,
        )

    def test_deny_access(self):
        self.assertRaises(
            NotImplementedError,
            self.storage_connection.deny_access,
            self.mock_context,
            share=None,
            access=None,
            share_server=None,
        )

    def test_create_share_nfs(self):
        share_path = self.SHARE_DIR
        self.assertFalse(self._mock_powerscale_api.create_directory.called)
        self.assertFalse(self._mock_powerscale_api.create_nfs_export.called)

        # create the share
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS', "size": 8}
        location = self.storage_connection.create_share(self.mock_context,
                                                        share, None)

        # verify location and API call made
        path = '%s:%s' % (self.POWERSCALE_ADDR, self.SHARE_DIR)
        expected_location = [{'is_admin_only': False,
                              'metadata': {"preferred": True},
                              'path': path}]

        self.assertEqual(expected_location, location)
        self._mock_powerscale_api.create_directory.assert_called_with(
            share_path, False)
        self._mock_powerscale_api.create_nfs_export.assert_called_with(
            share_path)

        # verify directory quota call made
        self._mock_powerscale_api.quota_create.assert_called_with(
            share_path, 'directory', 8 * units.Gi)

    def test_create_share_cifs(self):
        self.assertFalse(self._mock_powerscale_api.create_directory.called)
        self.assertFalse(self._mock_powerscale_api.create_smb_share.called)

        # create the share
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS', "size": 8}
        location = self.storage_connection.create_share(self.mock_context,
                                                        share, None)
        path = '\\\\{0}\\{1}'.format(self.POWERSCALE_ADDR, self.SHARE_NAME)
        expected_location = [{'is_admin_only': False,
                              'metadata': {"preferred": True},
                              'path': path}]

        self.assertEqual(expected_location, location)
        self._mock_powerscale_api.create_directory.assert_called_once_with(
            self.SHARE_DIR, False)
        self._mock_powerscale_api.create_smb_share.assert_called_once_with(
            self.SHARE_NAME, self.SHARE_DIR)

        # verify directory quota call made
        self._mock_powerscale_api.quota_create.assert_called_with(
            self.SHARE_DIR, 'directory', 8 * units.Gi)

    def test_create_share_invalid_share_protocol(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'FOO_PROTOCOL'}

        self.assertRaises(
            exception.InvalidShare, self.storage_connection.create_share,
            self.mock_context, share, share_server=None)

    def test_create_share_nfs_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS'}
        self._mock_powerscale_api.create_nfs_export.return_value = False

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share,
            self.mock_context, share, share_server=None)

    def test_create_share_cifs_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS'}
        self._mock_powerscale_api.create_smb_share.return_value = False

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_share,
            self.mock_context, share, share_server=None)

    def test_create_directory_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS'}
        self._mock_powerscale_api.create_directory.return_value = False

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
        self._mock_powerscale_api.create_snapshot.assert_called_with(
            snapshot_name, snapshot_path)

    def test_create_snapshot_backend_failure(self):
        snapshot_name = "snapshot01"
        snapshot_path = '/ifs/home/admin'
        snapshot = {'name': snapshot_name, 'share_name': snapshot_path}
        self._mock_powerscale_api.create_snapshot.return_value = False

        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.create_snapshot,
            self.mock_context, snapshot, None)

    def test_create_share_from_snapshot_nfs(self):
        # assertions
        self.assertFalse(self._mock_powerscale_api.create_nfs_export.called)
        self.assertFalse(self._mock_powerscale_api.clone_snapshot.called)

        snapshot_name = "snapshot01"
        snapshot_path = '/ifs/home/admin'

        # execute method under test
        snapshot = {'name': snapshot_name, 'share_name': snapshot_path}
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS', 'size': 5}
        location = self.storage_connection.create_share_from_snapshot(
            self.mock_context, share, snapshot, None)

        # verify NFS export created at expected location
        self._mock_powerscale_api.create_nfs_export.assert_called_with(
            self.SHARE_DIR)

        # verify clone_directory(container_path) method called
        self._mock_powerscale_api.clone_snapshot.assert_called_once_with(
            snapshot_name, self.SHARE_DIR)
        path = '{0}:{1}'.format(
            self.POWERSCALE_ADDR, self.SHARE_DIR)
        expected_location = {'is_admin_only': False,
                             'metadata': {"preferred": True},
                             'path': path}

        self.assertEqual(expected_location, location[0])

        # verify directory quota call made
        self._mock_powerscale_api.quota_create.assert_called_with(
            self.SHARE_DIR, 'directory', 5 * units.Gi)

    def test_create_share_from_snapshot_cifs(self):
        # assertions
        self.assertFalse(self._mock_powerscale_api.create_smb_share.called)
        self.assertFalse(self._mock_powerscale_api.clone_snapshot.called)
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
        self._mock_powerscale_api.create_smb_share.assert_called_once_with(
            new_share_name, self.CLONE_DIR)
        self._mock_powerscale_api.clone_snapshot.assert_called_once_with(
            snapshot_name, self.CLONE_DIR)
        path = '\\\\{0}\\{1}'.format(self.POWERSCALE_ADDR, new_share_name)
        expected_location = {'is_admin_only': False,
                             'metadata': {"preferred": True},
                             'path': path}
        self.assertEqual(expected_location, location[0])

        # verify directory quota call made
        expected_share_path = '{0}/{1}'.format(self.ROOT_DIR, new_share_name)
        self._mock_powerscale_api.quota_create.assert_called_with(
            expected_share_path, 'directory', 2 * units.Gi)

    def test_delete_share_nfs(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS'}
        fake_share_num = 42
        self._mock_powerscale_api.lookup_nfs_export.return_value = (
            fake_share_num)
        self.assertFalse(self._mock_powerscale_api.delete_nfs_share.called)

        # delete the share
        self.storage_connection.delete_share(self.mock_context, share, None)

        # verify share delete
        self._mock_powerscale_api.delete_nfs_share.assert_called_with(
            fake_share_num)

    def test_delete_share_cifs(self):
        self.assertFalse(self._mock_powerscale_api.delete_smb_share.called)

        # delete the share
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS'}
        self.storage_connection.delete_share(self.mock_context, share, None)

        # verify share deleted
        self._mock_powerscale_api.delete_smb_share.assert_called_with(
            self.SHARE_NAME)

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.LOG')
    def test_delete_share_invalid_share_proto(self, mock_log):
        share = {"name": self.SHARE_NAME, "share_proto": 'FOO_PROTOCOL'}

        self.storage_connection.delete_share(self.mock_context, share, None)
        mock_log.warning.assert_called_once_with(
            'Unsupported share type: FOO_PROTOCOL.')

    def test_delete_nfs_share_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS'}

        self._mock_powerscale_api.delete_nfs_share.return_value = False
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.delete_share,
            self.mock_context, share, None
        )

    def test_delete_nfs_share_share_does_not_exist(self):
        self._mock_powerscale_api.lookup_nfs_export.return_value = None
        share = {"name": self.SHARE_NAME, "share_proto": 'NFS'}

        # verify the calling delete on a non-existent share returns and does
        # not throw exception
        self.storage_connection.delete_share(self.mock_context, share, None)

    def test_delete_cifs_share_backend_failure(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS'}

        self._mock_powerscale_api.delete_smb_share.return_value = False
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.delete_share,
            self.mock_context, share, None
        )

    def test_delete_cifs_share_share_does_not_exist(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS'}
        self._mock_powerscale_api.lookup_smb_share.return_value = None

        # verify the calling delete on a non-existent share returns and does
        # not throw exception
        self.storage_connection.delete_share(self.mock_context, share, None)

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.LOG'
    )
    def test_delete_quota_success(self, mock_log):
        path = '/path/to/quota'
        quota_id = '123'
        quota_data = {'id': quota_id}
        self._mock_powerscale_api.quota_get.return_value = quota_data
        self._mock_powerscale_api.delete_quota.return_value = True
        self.storage_connection._delete_quota(path)
        self._mock_powerscale_api.quota_get.assert_called_once_with(
            path, 'directory')
        self._mock_powerscale_api.delete_quota.assert_called_once_with(
            quota_id)
        mock_log.debug.assert_called_once_with(f'Removing quota {quota_id}')
        mock_log.warning.assert_not_called()

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.LOG'
    )
    def test_delete_quota_failure(self, mock_log):
        path = '/path/to/quota'
        quota_id = '123'
        quota_data = {'id': quota_id}
        self._mock_powerscale_api.quota_get.return_value = quota_data
        self._mock_powerscale_api.delete_quota.return_value = False
        self.storage_connection._delete_quota(path)
        self._mock_powerscale_api.quota_get.assert_called_once_with(
            path, 'directory')
        self._mock_powerscale_api.delete_quota.assert_called_once_with(
            quota_id)
        mock_log.debug.assert_called_once_with(f'Removing quota {quota_id}')
        mock_log.error.assert_called_once_with(
            _('Failed to delete quota "%(quota_id)s" for '
              'directory "%(dir)s".') %
            {'quota_id': quota_id, 'dir': path})
        mock_log.warning.assert_not_called()

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.LOG'
    )
    def test_delete_quota_not_found(self, mock_log):
        path = '/path/to/quota'
        self._mock_powerscale_api.quota_get.return_value = None
        self.storage_connection._delete_quota(path)
        self._mock_powerscale_api.quota_get.assert_called_once_with(
            path, 'directory')
        self._mock_powerscale_api.delete_quota.assert_not_called()
        mock_log.debug.assert_not_called()
        mock_log.warning.assert_called_once_with(f'Quota not found for {path}')

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.LOG'
    )
    def test_delete_directory_success(self, mock_log):
        path = '/path/to/directory'
        self._mock_powerscale_api.is_path_existent.return_value = True
        self._mock_powerscale_api.delete_path.return_value = True
        self.storage_connection._delete_directory(path)
        self._mock_powerscale_api.delete_path.assert_called_once_with(
            path, recursive=True)
        mock_log.debug.assert_called_once_with(f'Removing directory {path}')
        mock_log.warning.assert_not_called()

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.LOG'
    )
    def test_delete_directory_failure(self, mock_log):
        path = '/path/to/directory'
        self._mock_powerscale_api.is_path_existent.return_value = True
        self._mock_powerscale_api.delete_path.return_value = False
        self.storage_connection._delete_directory(path)
        self._mock_powerscale_api.delete_path.assert_called_once_with(
            path, recursive=True)
        mock_log.debug.assert_called_once_with(f'Removing directory {path}')
        mock_log.error.assert_called_once_with(
            _('Failed to delete directory "%(dir)s".') %
            {'dir': path})
        mock_log.warning.assert_not_called()

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.LOG'
    )
    def test_delete_directory_not_found(self, mock_log):
        path = '/path/to/directory'
        self._mock_powerscale_api.is_path_existent.return_value = False
        self.storage_connection._delete_directory(path)
        self._mock_powerscale_api.delete_path.assert_not_called()
        mock_log.warning.assert_called_once_with(
            _('Directory not found for %s') % path)

    def test_delete_snapshot(self):
        # create a snapshot
        snapshot_name = "snapshot01"
        snapshot_path = '/ifs/home/admin'
        snapshot = {'name': snapshot_name, 'share_name': snapshot_path}
        self.assertFalse(self._mock_powerscale_api.delete_snapshot.called)

        # delete the created snapshot
        self.storage_connection.delete_snapshot(self.mock_context, snapshot,
                                                None)

        # verify the API call was made to delete the snapshot
        self._mock_powerscale_api.delete_snapshot.assert_called_once_with(
            snapshot_name)

    def test_delete_snapshot_failure(self):
        snapshot = {'name': 'test_snapshot'}
        self._mock_powerscale_api.delete_snapshot.return_value = False
        self.assertRaises(
            exception.ShareBackendException,
            self.storage_connection.delete_snapshot,
            self.mock_context, snapshot, None)
        self._mock_powerscale_api.delete_snapshot.assert_called_once_with(
            snapshot['name'])

    def test_ensure_share(self):
        share = {"name": self.SHARE_NAME, "share_proto": 'CIFS'}
        self.assertRaises(NotImplementedError,
                          self.storage_connection.ensure_share,
                          self.mock_context, share, None)

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.'
        'powerscale_api.PowerScaleApi', autospec=True)
    def test_connect(self, mock_isi_api):
        storage_connection = powerscale.PowerScaleStorageConnection(LOG)

        # execute method under test
        storage_connection.connect(
            self.mock_emc_driver, self.mock_context)

        # verify connect sets driver params appropriately
        mock_config = self.MockConfig()
        server_addr = mock_config.safe_get('emc_nas_server')
        self.assertEqual(server_addr, storage_connection._server)
        expected_port = mock_config.safe_get('emc_nas_server_port')
        self.assertEqual(expected_port, storage_connection._port)
        self.assertEqual('https://{0}:{1}'.format(server_addr, expected_port),
                         storage_connection._server_url)
        expected_username = mock_config.safe_get('emc_nas_login')
        self.assertEqual(expected_username, storage_connection._username)
        expected_password = mock_config.safe_get('emc_nas_password')
        self.assertEqual(expected_password, storage_connection._password)
        self.assertFalse(storage_connection._verify_ssl_cert)
        expected_dir_permission = mock_config.safe_get(
            'powerscale_dir_permission')
        self.assertEqual(expected_dir_permission,
                         storage_connection._dir_permission)

    @mock.patch(
        'manila.share.drivers.dell_emc.plugins.powerscale.powerscale.'
        'powerscale_api.PowerScaleApi', autospec=True)
    def test_connect_root_dir_does_not_exist(self, mock_isi_api):
        mock_powerscale_api = mock_isi_api.return_value
        mock_powerscale_api.is_path_existent.return_value = False
        storage_connection = powerscale.PowerScaleStorageConnection(LOG)

        # call method under test
        storage_connection.connect(self.mock_emc_driver, self.mock_context)

        mock_powerscale_api.create_directory.assert_called_once_with(
            self.ROOT_DIR, recursive=True)

    def test_connect_invalid_config(self):
        mock_emc_driver = mock.Mock('EmcDriver')
        mock_emc_driver.attach_mock(self.MockInvalidConfig(), 'configuration')

        self.assertRaises(exception.BadConfigurationException,
                          self.storage_connection.connect,
                          mock_emc_driver,
                          self.mock_context
                          )

    def test_update_share_stats(self):
        self._mock_powerscale_api.get_space_stats.return_value = {
            'total': 1000 * units.Gi,
            'free': 100 * units.Gi,
        }
        self._mock_powerscale_api.get_allocated_space.return_value = 2110.0
        stats_dict = {'share_backend_name': 'PowerScale_backend'}
        self.storage_connection.update_share_stats(stats_dict)

        expected_pool_stats = {
            'pool_name': 'PowerScale_backend',
            'reserved_percentage': 0,
            'reserved_snapshot_percentage': 0,
            'reserved_share_extend_percentage': 0,
            'max_over_subscription_ratio': None,
            'thin_provisioning': True,
            'total_capacity_gb': 1000,
            'free_capacity_gb': 100,
            'allocated_capacity_gb': 2110.0,
            'qos': False,
        }
        expected_stats = {
            'share_backend_name': 'PowerScale_backend',
            'driver_version': powerscale.VERSION,
            'storage_protocol': 'NFS_CIFS',
            'pools': [expected_pool_stats]
        }
        self.assertEqual(expected_stats, stats_dict)

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
        self._mock_powerscale_api.quota_get.return_value = {'id': quota_id}
        self.assertFalse(self._mock_powerscale_api.quota_set.called)

        self.storage_connection.extend_share(share, new_share_size)

        share_path = '{0}/{1}'.format(self.ROOT_DIR, self.SHARE_NAME)
        expected_quota_size = new_share_size * units.Gi
        self._mock_powerscale_api.quota_set.assert_called_once_with(
            share_path, 'directory', expected_quota_size)

    def test_update_access_add_nfs(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'NFS',
        }
        fake_export_id = 4
        self._mock_powerscale_api.lookup_nfs_export.return_value = (
            fake_export_id)
        self._mock_powerscale_api.get_nfs_export.return_value = {
            'clients': [],
            'read_only_clients': []
        }
        nfs_access = {
            'access_type': 'ip',
            'access_to': '10.1.1.10',
            'access_level': const.ACCESS_LEVEL_RW,
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [nfs_access]
        self._mock_powerscale_api.modify_nfs_export_access.return_value = True
        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [],
            [], share_server=None)
        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'active'
            }
        }
        self._mock_powerscale_api.modify_nfs_export_access. \
            assert_called_once_with(fake_export_id, [], ['10.1.1.10'])
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_add_cifs(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'CIFS',
        }
        access = {
            'access_type': 'user',
            'access_to': 'foo',
            'access_level': const.ACCESS_LEVEL_RW,
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [access]

        self._mock_powerscale_api.get_user_sid.return_value = {
            'id': 'SID:S-1-5-22',
            'name': 'foo',
            'type': 'user',
        }
        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        expected_permissions = [
            {
                "permission": "change",
                "permission_type": "allow",
                "trustee": {
                    "id": "SID:S-1-5-22",
                    "name": "foo",
                    "type": "user"
                }
            }
        ]
        self._mock_powerscale_api.modify_smb_share_access.\
            assert_called_once_with(
                self.SHARE_NAME, host_acl=[], permissions=expected_permissions)
        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'active'
            }
        }
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_delete_nfs(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'NFS',
        }
        fake_export_id = 4
        self._mock_powerscale_api.lookup_nfs_export.return_value = (
            fake_export_id)
        # simulate an IP added to the whitelist
        ip_addr = '10.0.0.4'
        ip_addr_ro = '10.0.0.50'
        self._mock_powerscale_api.get_nfs_export.return_value = {
            'clients': [ip_addr], 'read_only_clients': [ip_addr_ro]}
        access_rules = []
        self._mock_powerscale_api.modify_nfs_export_access.return_value = True

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        self._mock_powerscale_api.modify_nfs_export_access. \
            assert_called_once_with(fake_export_id, [], [])
        self.assertEqual({}, rule_map)

    def test_update_access_delete_cifs(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'CIFS',
        }
        access_rules = []
        self._mock_powerscale_api.lookup_smb_share.return_value = {
            'permissions': [
                {
                    'permission': 'change',
                    'permission_type': 'allow',
                    'trustee': {
                        'id': 'SID:S-1-5-21',
                        'name': 'newuser',
                        'type': 'user',
                    }

                }
            ]
        }

        self._mock_powerscale_api.modify_smb_share_access.return_value = None
        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        self._mock_powerscale_api.modify_smb_share_access.\
            assert_called_once_with(
                self.SHARE_NAME, host_acl=[], permissions=[])
        self.assertEqual({}, rule_map)

    def test_update_access_nfs_share_not_found(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'NFS',
        }
        access = {
            'access_type': 'user',
            'access_to': 'foouser',
            'access_level': const.ACCESS_LEVEL_RW,
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [access]
        self._mock_powerscale_api.lookup_nfs_export.return_value = None

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'error'
            }
        }
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_nfs_http_error_on_clear_rules(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'NFS',
        }
        access = {
            'access_type': 'user',
            'access_to': 'foouser',
            'access_level': const.ACCESS_LEVEL_RW,
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [access]
        self._mock_powerscale_api.modify_nfs_export_access.return_value = False

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'error'
            }
        }
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_cifs_http_error_on_clear_rules(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'CIFS',
        }
        access = {
            'access_type': 'user',
            'access_to': 'foo',
            'access_level': const.ACCESS_LEVEL_RW,
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [access]
        self._mock_powerscale_api.modify_smb_share_access.return_value = False

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, None, None)

        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'error'
            }
        }
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_cifs_invalid_user_access_level(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'CIFS',
        }
        access = {
            'access_type': 'user',
            'access_to': 'foo',
            'access_level': 'fake',
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [access]
        self._mock_powerscale_api.modify_smb_share_access.return_value = True

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'error'
            }
        }
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_cifs_user_not_found(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'CIFS',
        }
        access = {
            'access_type': 'user',
            'access_to': 'foo',
            'access_level': const.ACCESS_LEVEL_RW,
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [access]
        self._mock_powerscale_api.get_user_sid.return_value = None
        self._mock_powerscale_api.modify_smb_share_access.return_value = True

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'error'
            }
        }
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_cifs_invalid_access_type(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'CIFS',
        }
        access = {
            'access_type': 'foo',
            'access_to': 'foo',
            'access_level': const.ACCESS_LEVEL_RW,
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [access]

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'error'
            }
        }
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_recover_nfs(self):
        # verify that new ips are added and ips not in rules are removed
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'NFS',
        }
        fake_export_id = 4
        self._mock_powerscale_api.lookup_nfs_export.return_value = (
            fake_export_id)
        self._mock_powerscale_api.get_nfs_export.return_value = {
            'clients': ['10.1.1.8'],
            'read_only_clients': ['10.2.0.2']
        }
        nfs_access_1 = {
            'access_type': 'ip',
            'access_to': '10.1.1.10',
            'access_level': const.ACCESS_LEVEL_RW,
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        nfs_access_2 = {
            'access_type': 'ip',
            'access_to': '10.1.1.2',
            'access_level': const.ACCESS_LEVEL_RO,
            'access_id': '19960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [nfs_access_1, nfs_access_2]

        self._mock_powerscale_api.modify_nfs_export_access.return_value = True

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'active'
            },
            '19960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'active'
            }
        }
        self._mock_powerscale_api.modify_nfs_export_access. \
            assert_called_once_with(fake_export_id,
                                    ['10.1.1.2'],
                                    ['10.1.1.10'])
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_recover_cifs(self):
        share = {
            "name": self.SHARE_NAME,
            "share_proto": 'CIFS',
        }
        self._mock_powerscale_api.get_user_sid.return_value = {
            'id': 'SID:S-1-5-22',
            'name': 'testuser',
            'type': 'user',
        }
        self._mock_powerscale_api.modify_smb_share_access.return_value = True
        access_1 = {
            'access_type': 'ip',
            'access_to': '10.1.1.10',
            'access_level': const.ACCESS_LEVEL_RW,
            'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_2 = {
            'access_type': 'user',
            'access_to': 'testuser',
            'access_level': const.ACCESS_LEVEL_RO,
            'access_id': '19960614-8574-4e03-89cf-7cf267b0bd08'
        }
        access_rules = [access_1, access_2]

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, access_rules, [], [])

        expected_data = {
            'host_acl': ['allow:10.1.1.10'],
            'permissions': [
                {
                    'permission': 'read',
                    'permission_type': 'allow',
                    'trustee': {
                        'id': 'SID:S-1-5-22',
                        'name': 'testuser',
                        'type': 'user',
                    }
                }
            ]
        }
        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'active'
            },
            '19960614-8574-4e03-89cf-7cf267b0bd08': {
                'state': 'active'
            }
        }
        self._mock_powerscale_api.lookup_smb_share.assert_not_called()
        self._mock_powerscale_api.get_user_sid.assert_called_once_with(
            'testuser')
        self._mock_powerscale_api.modify_smb_share_access.\
            assert_called_once_with(
                self.SHARE_NAME,
                host_acl=expected_data['host_acl'],
                permissions=expected_data['permissions']
            )
        self.assertEqual(expected_rule_map, rule_map)

    def test_update_access_with_cifs_ip_readonly(self):
        # Note: Driver does not currently support readonly access for "ip" type
        share = {'name': self.SHARE_NAME, 'share_proto': 'CIFS'}
        access = {'access_type': 'ip', 'access_to': '10.1.1.10',
                  'access_level': const.ACCESS_LEVEL_RO,
                  'access_id': '09960614-8574-4e03-89cf-7cf267b0bd08'}

        rule_map = self.storage_connection.update_access(
            self.mock_context, share, [access], None, None)
        expected_rule_map = {
            '09960614-8574-4e03-89cf-7cf267b0bd08': {'state': 'error'}}
        self.assertEqual(expected_rule_map, rule_map)

    def test_delete_quota_when_quota_exists(self):
        path = '/path/to/quota'
        quota_id = '123'
        quota_data = {'id': quota_id}
        self._mock_powerscale_api.quota_get.return_value = quota_data
        self._mock_powerscale_api.delete_quota.return_value = True

        self.storage_connection._delete_quota(path)

        self._mock_powerscale_api.quota_get.assert_called_once_with(
            path, 'directory')
        self._mock_powerscale_api.delete_quota.assert_called_once_with(
            quota_id)

    def test_delete_quota_when_quota_does_not_exist(self):
        path = '/path/to/quota'
        self._mock_powerscale_api.quota_get.return_value = None

        self.storage_connection._delete_quota(path)

        self._mock_powerscale_api.quota_get.assert_called_once_with(
            path, 'directory')
        self._mock_powerscale_api.delete_quota.assert_not_called()

    def test_delete_directory_when_path_exists(self):
        path = '/path/to/directory'
        self.storage_connection._delete_directory(path)
        self._mock_powerscale_api.is_path_existent.assert_called_with(path)
        self._mock_powerscale_api.delete_path.assert_called_with(
            path, recursive=True)

    def test_delete_directory_when_path_does_not_exist(self):
        path = '/path/to/directory'
        self._mock_powerscale_api.is_path_existent.return_value = False
        self.storage_connection._delete_directory(path)
        self._mock_powerscale_api.is_path_existent.assert_called_with(path)
        self._mock_powerscale_api.delete_path.assert_not_called()

    def test_get_backend_info(self):
        self._mock_powerscale_api.get_cluster_version.return_value = '1.0'
        result = self.storage_connection.get_backend_info(None)
        expected_info = {
            'driver_version': powerscale.VERSION,
            'cluster_version': '1.0',
            'rest_server': self.POWERSCALE_ADDR,
            'rest_port': '8080',
        }
        self.assertEqual(expected_info, result)

    def test_ensure_shares_nfs_share_exists(self):
        share = {
            'id': '123',
            'share_proto': 'NFS',
            'name': 'my_share',
        }
        container_path = '/ifs/my_share'
        location = '10.0.0.1:/ifs/my_share'
        self.storage_connection._get_container_path = mock.MagicMock(
            return_value=container_path)
        self._mock_powerscale_api.lookup_nfs_export.return_value = '123'

        result = self.storage_connection.ensure_shares(None, [share])
        expected_result = {
            '123': {
                'export_locations': [location],
                'status': 'available',
                'reapply_access_rules': True,
            }
        }
        self.assertEqual(result, expected_result)

    def test_ensure_shares_cifs_share_exists(self):
        share = {
            'id': '123',
            'share_proto': 'CIFS',
            'name': 'my_share',
        }
        location = '\\\\10.0.0.1\\my_share'
        self._mock_powerscale_api.lookup_smb_share.return_value = share

        result = self.storage_connection.ensure_shares(None, [share])
        expected_result = {
            '123': {
                'export_locations': [location],
                'status': 'available',
                'reapply_access_rules': True,
            }
        }
        self.assertEqual(result, expected_result)

    def test_ensure_shares_nfs_share_does_not_exist(self):
        share = {
            'id': '123',
            'share_proto': 'NFS',
            'name': 'my_share',
        }
        self._mock_powerscale_api.lookup_nfs_export.return_value = None
        result = self.storage_connection.ensure_shares(None, [share])
        expected_result = {
            '123': {
                'export_locations': [],
                'status': 'error',
                'reapply_access_rules': False,
            }
        }
        self.assertEqual(result, expected_result)

    def test_ensure_shares_cifs_share_does_not_exist(self):
        share = {
            'id': '123',
            'share_proto': 'CIFS',
            'name': 'my_share',
        }
        self._mock_powerscale_api.lookup_smb_share.return_value = None
        result = self.storage_connection.ensure_shares(None, [share])
        expected_result = {
            '123': {
                'export_locations': [],
                'status': 'error',
                'reapply_access_rules': False,
            }
        }
        self.assertEqual(result, expected_result)
