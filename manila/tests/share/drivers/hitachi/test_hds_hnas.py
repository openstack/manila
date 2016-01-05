# Copyright (c) 2015 Hitachi Data Systems, Inc.
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
from oslo_config import cfg

from manila import exception
import manila.share.configuration
import manila.share.driver
from manila.share.drivers.hitachi import hds_hnas
from manila.share.drivers.hitachi import ssh
from manila import test

CONF = cfg.CONF

share = {
    'id': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'name': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'size': 50,
    'host': 'hnas',
    'share_proto': 'NFS',
    'share_type_id': 1,
    'share_network_id': 'bb329e24-3bdb-491d-acfd-dfe70c09b98d',
    'share_server_id': 'cc345a53-491d-acfd-3bdb-dfe70c09b98d',
    'export_locations': [{'path': '172.24.44.10:/shares/'
                                  'aa4a7710-f326-41fb-ad18-b4ad587fc87a'}],
}

share_invalid_host = {
    'id': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'name': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'size': 50,
    'host': 'invalid',
    'share_proto': 'NFS',
    'share_type_id': 1,
    'share_network_id': 'bb329e24-3bdb-491d-acfd-dfe70c09b98d',
    'share_server_id': 'cc345a53-491d-acfd-3bdb-dfe70c09b98d',
    'export_locations': [{'path': '172.24.44.10:/shares/'
                                  'aa4a7710-f326-41fb-ad18-b4ad587fc87a'}],
}

access = {
    'id': 'acdc7172b-fe07-46c4-b78f-df3e0324ccd0',
    'access_type': 'ip',
    'access_to': '172.24.44.200',
    'access_level': 'rw',
    'state': 'active',
}

snapshot = {
    'id': 'abba6d9b-f29c-4bf7-aac1-618cda7aaf0f',
    'share_id': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
}

invalid_share = {
    'id': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'name': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'size': 100,
    'host': 'hnas',
    'share_proto': 'CIFS',
}

invalid_access_type = {
    'id': 'acdc7172b-fe07-46c4-b78f-df3e0324ccd0',
    'access_type': 'user',
    'access_to': 'manila_user',
    'access_level': 'rw',
    'state': 'active',
}

invalid_access_level = {
    'id': 'acdc7172b-fe07-46c4-b78f-df3e0324ccd0',
    'access_type': 'ip',
    'access_to': 'manila_user',
    'access_level': '777',
    'state': 'active',
}


@ddt.ddt
class HDSHNASTestCase(test.TestCase):
    def setUp(self):
        super(HDSHNASTestCase, self).setUp()
        CONF.set_default('driver_handles_share_servers', False)
        CONF.hds_hnas_evs_id = '2'
        CONF.hds_hnas_evs_ip = '172.24.44.10'
        CONF.hds_hnas_ip = '172.24.44.1'
        CONF.hds_hnas_ip_port = 'hds_hnas_ip_port'
        CONF.hds_hnas_user = 'hds_hnas_user'
        CONF.hds_hnas_password = 'hds_hnas_password'
        CONF.hds_hnas_file_system = 'file_system'
        CONF.hds_hnas_ssh_private_key = 'private_key'
        CONF.hds_hnas_cluster_admin_ip0 = None
        CONF.hds_hnas_stalled_job_timeout = 10
        CONF.hds_hnas_driver_helper = ('manila.share.drivers.hitachi.ssh.'
                                       'HNASSSHBackend')
        self.fake_conf = manila.share.configuration.Configuration(None)

        self.fake_private_storage = mock.Mock()
        self.mock_object(self.fake_private_storage, 'get',
                         mock.Mock(return_value=None))
        self.mock_object(self.fake_private_storage, 'delete',
                         mock.Mock(return_value=None))

        self._driver = hds_hnas.HDSHNASDriver(
            private_storage=self.fake_private_storage,
            configuration=self.fake_conf)
        self._driver.backend_name = "hnas"
        self.mock_log = self.mock_object(hds_hnas, 'LOG')

    @ddt.data('hds_hnas_driver_helper', 'hds_hnas_evs_id', 'hds_hnas_evs_ip',
              'hds_hnas_ip', 'hds_hnas_user')
    def test_init_invalid_conf_parameters(self, attr_name):
        self.mock_object(manila.share.driver.ShareDriver,
                         '__init__')
        setattr(CONF, attr_name, None)

        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.__init__)

    def test_init_invalid_credentials(self):
        self.mock_object(manila.share.driver.ShareDriver,
                         '__init__')
        CONF.hds_hnas_password = None
        CONF.hds_hnas_ssh_private_key = None

        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.__init__)

    def test_allow_access(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_host_list", mock.Mock(
            return_value=['127.0.0.1 (rw)']))
        self.mock_object(ssh.HNASSSHBackend, "update_access_rule", mock.Mock())

        self._driver.allow_access('context', share, access)

        ssh.HNASSSHBackend.update_access_rule.assert_called_once_with(
            share['id'], ['127.0.0.1 (rw)', access['access_to'] + '(' +
                          access['access_level'] + ')'])
        ssh.HNASSSHBackend.get_host_list.assert_called_once_with(share['id'])
        self.assertTrue(self.mock_log.info.called)

    def test_allow_access_wrong_permission(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_host_list", mock.Mock(
            return_value=['127.0.0.1 (rw)']))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.allow_access, 'context', share,
                          invalid_access_level)
        ssh.HNASSSHBackend.get_host_list.assert_called_once_with(share['id'])

    def test_allow_access_host_allowed(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_host_list", mock.Mock(
            return_value=['172.24.44.200(rw)']))

        self._driver.allow_access('context', share, access)

        ssh.HNASSSHBackend.get_host_list.assert_called_once_with(share['id'])
        self.assertTrue(self.mock_log.debug.called)

    def test_allow_access_host_allowed_different_permission(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_host_list", mock.Mock(
            return_value=['172.24.44.200(ro)']))
        self.mock_object(ssh.HNASSSHBackend, "update_access_rule", mock.Mock())

        self._driver.allow_access('context', share, access)

        ssh.HNASSSHBackend.get_host_list.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.update_access_rule.assert_called_once_with(
            share['id'], [access['access_to'] + '(' + access['access_level']
                          + ')'])

    def test_allow_access_invalid_access_type(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_allow_access", mock.Mock())

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.allow_access, 'context', invalid_share,
                          invalid_access_type)

    def test_deny_access(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_host_list", mock.Mock(
            return_value=['172.24.44.200(rw)']))
        self.mock_object(ssh.HNASSSHBackend, "update_access_rule", mock.Mock())

        self._driver.deny_access('context', share, access)

        ssh.HNASSSHBackend.get_host_list.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.update_access_rule.assert_called_once_with(
            share['id'], [])

    def test_deny_access_already_not_allowed(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_host_list", mock.Mock(
            return_value=[]))

        self._driver.deny_access('context', share, access)

        ssh.HNASSSHBackend.get_host_list.assert_called_once_with(share['id'])
        self.assertTrue(self.mock_log.debug.called)

    def test_deny_access_invalid_access_level(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_host_list", mock.Mock(
            return_value=[]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.deny_access, 'context', share,
                          invalid_access_level)
        ssh.HNASSSHBackend.get_host_list.assert_called_once_with(share['id'])

    def test_deny_access_invalid_access_type(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_deny_access", mock.Mock())

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.deny_access, 'context', invalid_share,
                          invalid_access_type)

    def test_create_share(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "quota_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_add", mock.Mock())

        result = self._driver.create_share('context', share)

        self.assertEqual(self._driver.hnas_evs_ip + ":/shares/" + share['id'],
                         result)
        self.assertTrue(self.mock_log.debug.called)
        ssh.HNASSSHBackend.vvol_create.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.quota_add.assert_called_once_with(share['id'],
                                                             share['size'])
        ssh.HNASSSHBackend.nfs_export_add.assert_called_once_with(share['id'])

    def test_create_share_export_error(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "quota_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_add", mock.Mock(
            side_effect=exception.HNASBackendException('msg')))
        self.mock_object(ssh.HNASSSHBackend, "vvol_delete", mock.Mock())

        self.assertRaises(exception.HNASBackendException,
                          self._driver.create_share, 'context', share)
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.exception.called)
        ssh.HNASSSHBackend.vvol_create.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.quota_add.assert_called_once_with(share['id'],
                                                             share['size'])
        ssh.HNASSSHBackend.nfs_export_add.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.vvol_delete.assert_called_once_with(share['id'])

    def test_create_share_invalid_share_protocol(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_create_share",
                         mock.Mock(return_value="path"))

        self.assertRaises(exception.ShareBackendException,
                          self._driver.create_share, 'context', invalid_share)

    def test_delete_share(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_del", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_delete", mock.Mock())

        self._driver.delete_share('context', share)

        self.assertTrue(self.mock_log.debug.called)
        ssh.HNASSSHBackend.nfs_export_del.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.vvol_delete.assert_called_once_with(share['id'])

    def test_create_snapshot(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(ssh.HNASSSHBackend, "get_host_list", mock.Mock(
            return_value=['172.24.44.200(rw)']))
        self.mock_object(ssh.HNASSSHBackend, "update_access_rule", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "tree_clone", mock.Mock())

        self._driver.create_snapshot('context', snapshot)

        ssh.HNASSSHBackend.get_host_list.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.update_access_rule.assert_any_call(
            share['id'], ['172.24.44.200(ro)'])
        ssh.HNASSSHBackend.update_access_rule.assert_any_call(
            share['id'], ['172.24.44.200(rw)'])
        ssh.HNASSSHBackend.tree_clone.assert_called_once_with(
            '/shares/' + share['id'], '/snapshots/' + share['id'] + '/' +
                                      snapshot['id'])

    def test_create_snapshot_first_snapshot(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(ssh.HNASSSHBackend, "get_host_list", mock.Mock(
            return_value=['172.24.44.200(rw)']))
        self.mock_object(ssh.HNASSSHBackend, "update_access_rule", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "tree_clone", mock.Mock(
            side_effect=exception.HNASNothingToCloneException('msg')))
        self.mock_object(ssh.HNASSSHBackend, "create_directory", mock.Mock())

        self._driver.create_snapshot('context', snapshot)

        self.assertTrue(self.mock_log.warning.called)
        ssh.HNASSSHBackend.get_host_list.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.update_access_rule.assert_any_call(
            share['id'], ['172.24.44.200(ro)'])
        ssh.HNASSSHBackend.update_access_rule.assert_any_call(
            share['id'], ['172.24.44.200(rw)'])
        ssh.HNASSSHBackend.create_directory.assert_called_once_with(
            '/snapshots/' + share['id'] + '/' + snapshot['id'])

    def test_delete_snapshot(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(ssh.HNASSSHBackend, "tree_delete", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "delete_directory", mock.Mock())

        self._driver.delete_snapshot('context', snapshot)

        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.info.called)
        ssh.HNASSSHBackend.tree_delete.assert_called_once_with(
            '/snapshots/' + share['id'] + '/' + snapshot['id'])
        ssh.HNASSSHBackend.delete_directory.assert_called_once_with(
            '/snapshots/' + share['id'])

    def test_ensure_share(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "check_vvol", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "check_quota", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "check_export", mock.Mock())

        result = self._driver.ensure_share('context', share)

        self.assertEqual(['172.24.44.10:/shares/' + share['id']], result)
        ssh.HNASSSHBackend.check_vvol.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.check_quota.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.check_export.assert_called_once_with(share['id'])

    def test_extend_share(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_stats", mock.Mock(
            return_value=(500, 200)))
        self.mock_object(ssh.HNASSSHBackend, "modify_quota", mock.Mock())

        self._driver.extend_share(share, 150)

        ssh.HNASSSHBackend.get_stats.assert_called_once_with()
        ssh.HNASSSHBackend.modify_quota.assert_called_once_with(share['id'],
                                                                150)

    def test_extend_share_with_no_available_space_in_fs(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_stats", mock.Mock(
            return_value=(500, 200)))
        self.mock_object(ssh.HNASSSHBackend, "modify_quota", mock.Mock())

        self.assertRaises(exception.HNASBackendException,
                          self._driver.extend_share, share, 1000)
        ssh.HNASSSHBackend.get_stats.assert_called_once_with()

    def test_manage_existing(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_share_quota", mock.Mock(
            return_value=1))

        self._driver.manage_existing(share, 'option')

        ssh.HNASSSHBackend.get_share_quota.assert_called_once_with(share['id'])

    def test_manage_existing_no_quota(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_get_hnas_share_id",
                         mock.Mock(return_value=share['id']))
        self.mock_object(hds_hnas.HDSHNASDriver, "_ensure_share", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "get_share_quota", mock.Mock(
            return_value=None))

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing, share, 'option')
        ssh.HNASSSHBackend.get_share_quota.assert_called_once_with(share['id'])

    def test_manage_existing_wrong_share_id(self):
        self.mock_object(self.fake_private_storage, 'get',
                         mock.Mock(return_value='Wrong_share_id'))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.manage_existing, share, 'option')

    def test_manage_existing_wrong_path_format(self):
        share['export_locations'] = [{'path': ':/'}]

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing, share,
                          'option')

    def test_manage_existing_wrong_evs_ip(self):
        share['export_locations'] = [{'path': '172.24.44.189:/shares/'
                                     'aa4a7710-f326-41fb-ad18-'}]

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing, share,
                          'option')

    def test_manage_existing_invalid_host(self):
        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing, share_invalid_host,
                          'option')

    def test_unmanage(self):
        self._driver.unmanage(share)

        self.assertTrue(self.fake_private_storage.delete.called)
        self.assertTrue(self.mock_log.info.called)

    def test_get_network_allocations_number(self):
        result = self._driver.get_network_allocations_number()

        self.assertEqual(0, result)

    def test_create_share_from_snapshot(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "quota_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "tree_clone", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_add", mock.Mock())

        result = self._driver.create_share_from_snapshot('context',
                                                         share, snapshot)

        self.assertEqual('172.24.44.10:/shares/' + share['id'], result)
        ssh.HNASSSHBackend.vvol_create.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.quota_add.assert_called_once_with(share['id'],
                                                             share['size'])
        ssh.HNASSSHBackend.tree_clone.assert_called_once_with(
            '/snapshots/' + snapshot['share_id'] + '/' + snapshot['id'],
            '/shares/' + share['id'])
        ssh.HNASSSHBackend.nfs_export_add.assert_called_once_with(share['id'])

    def test_create_share_from_snapshot_empty_snapshot(self):
        self.mock_object(hds_hnas.HDSHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "quota_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "tree_clone", mock.Mock(
            side_effect=exception.HNASNothingToCloneException('msg')))
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_add", mock.Mock())

        result = self._driver.create_share_from_snapshot('context', share,
                                                         snapshot)

        self.assertEqual('172.24.44.10:/shares/' + share['id'], result)
        self.assertTrue(self.mock_log.warning.called)
        ssh.HNASSSHBackend.vvol_create.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.quota_add.assert_called_once_with(share['id'],
                                                             share['size'])
        ssh.HNASSSHBackend.tree_clone.assert_called_once_with(
            '/snapshots/' + snapshot['share_id'] + '/' + snapshot['id'],
            '/shares/' + share['id'])
        ssh.HNASSSHBackend.nfs_export_add.assert_called_once_with(share['id'])

    def test__check_fs_mounted(self):
        self.mock_object(ssh.HNASSSHBackend, 'check_fs_mounted', mock.Mock(
            return_value=True))

        self._driver._check_fs_mounted()

        ssh.HNASSSHBackend.check_fs_mounted.assert_called_once_with()

    def test__check_fs_mounted_not_mounted(self):
        self.mock_object(ssh.HNASSSHBackend, 'check_fs_mounted', mock.Mock(
            return_value=False))
        self.mock_object(ssh.HNASSSHBackend, 'mount', mock.Mock())

        self._driver._check_fs_mounted()

        ssh.HNASSSHBackend.check_fs_mounted.assert_called_once_with()
        ssh.HNASSSHBackend.mount.assert_called_once_with()
        self.assertTrue(self.mock_log.debug.called)

    def test__update_share_stats(self):
        fake_data = {
            'share_backend_name': self._driver.backend_name,
            'driver_handles_share_servers':
                self._driver.driver_handles_share_servers,
            'vendor_name': 'HDS',
            'driver_version': '1.0',
            'storage_protocol': 'NFS',
            'total_capacity_gb': 1000,
            'free_capacity_gb': 200,
            'reserved_percentage': hds_hnas.CONF.reserved_share_percentage,
            'qos': False,
        }

        self.mock_object(ssh.HNASSSHBackend, 'get_stats', mock.Mock(
            return_value=(1000, 200)))
        self.mock_object(manila.share.driver.ShareDriver,
                         '_update_share_stats', mock.Mock())

        self._driver._update_share_stats()

        self.assertTrue(self._driver.hnas.get_stats.called)
        (manila.share.driver.ShareDriver._update_share_stats.
         assert_called_once_with(fake_data))
        self.assertTrue(self.mock_log.info.called)
