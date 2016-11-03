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
from manila.share.drivers.hitachi.hnas import driver
from manila.share.drivers.hitachi.hnas import ssh
from manila import test

CONF = cfg.CONF

share_nfs = {
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

share_cifs = {
    'id': 'f5cadaf2-afbe-4cc4-9021-85491b6b76f7',
    'name': 'f5cadaf2-afbe-4cc4-9021-85491b6b76f7',
    'size': 50,
    'host': 'hnas',
    'share_proto': 'CIFS',
    'share_type_id': 1,
    'share_network_id': 'bb329e24-3bdb-491d-acfd-dfe70c09b98d',
    'share_server_id': 'cc345a53-491d-acfd-3bdb-dfe70c09b98d',
    'export_locations': [{'path': '\\\\172.24.44.10\\'
                                  'f5cadaf2-afbe-4cc4-9021-85491b6b76f7'}],
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

access_nfs_rw = {
    'id': 'acdc7172b-fe07-46c4-b78f-df3e0324ccd0',
    'access_type': 'ip',
    'access_to': '172.24.44.200',
    'access_level': 'rw',
    'state': 'active',
}

access_cifs_rw = {
    'id': '43167594-40e9-b899-1f4f-b9c2176b7564',
    'access_type': 'user',
    'access_to': 'fake_user',
    'access_level': 'rw',
    'state': 'active',
}

access_cifs_ro = {
    'id': '32407088-1f4f-40e9-b899-b9a4176b574d',
    'access_type': 'user',
    'access_to': 'fake_user',
    'access_level': 'ro',
    'state': 'active',
}

snapshot_nfs = {
    'id': 'abba6d9b-f29c-4bf7-aac1-618cda7aaf0f',
    'share_id': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'share': share_nfs,
}

snapshot_cifs = {
    'id': '91bc6e1b-1ba5-f29c-abc1-da7618cabf0a',
    'share_id': 'f5cadaf2-afbe-4cc4-9021-85491b6b76f7',
    'share': share_cifs,
}

invalid_share = {
    'id': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'name': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'size': 100,
    'host': 'hnas',
    'share_proto': 'HDFS',
}

invalid_snapshot = {
    'id': '24dcdcb5-a582-4bcc-b462-641da143afee',
    'share_id': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'share': invalid_share,
}

invalid_access_type = {
    'id': 'acdc7172b-fe07-46c4-b78f-df3e0324ccd0',
    'access_type': 'cert',
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

invalid_protocol_msg = ("Share backend error: Only NFS or CIFS protocol are "
                        "currently supported. Share provided %(id)s with "
                        "protocol %(proto)s." %
                        {'id': invalid_share['id'],
                         'proto': invalid_share['share_proto']})


@ddt.ddt
class HitachiHNASTestCase(test.TestCase):
    def setUp(self):
        super(HitachiHNASTestCase, self).setUp()
        CONF.set_default('driver_handles_share_servers', False)
        CONF.hitachi_hnas_evs_id = '2'
        CONF.hitachi_hnas_evs_ip = '172.24.44.10'
        CONF.hitachi_hnas_admin_network_ip = '10.20.30.40'
        CONF.hitachi_hnas_ip = '172.24.44.1'
        CONF.hitachi_hnas_ip_port = 'hitachi_hnas_ip_port'
        CONF.hitachi_hnas_user = 'hitachi_hnas_user'
        CONF.hitachi_hnas_password = 'hitachi_hnas_password'
        CONF.hitachi_hnas_file_system_name = 'file_system'
        CONF.hitachi_hnas_ssh_private_key = 'private_key'
        CONF.hitachi_hnas_cluster_admin_ip0 = None
        CONF.hitachi_hnas_stalled_job_timeout = 10
        CONF.hitachi_hnas_driver_helper = ('manila.share.drivers.hitachi.hnas.'
                                           'ssh.HNASSSHBackend')
        self.fake_conf = manila.share.configuration.Configuration(None)

        self.fake_private_storage = mock.Mock()
        self.mock_object(self.fake_private_storage, 'get',
                         mock.Mock(return_value=None))
        self.mock_object(self.fake_private_storage, 'delete',
                         mock.Mock(return_value=None))

        self._driver = driver.HitachiHNASDriver(
            private_storage=self.fake_private_storage,
            configuration=self.fake_conf)
        self._driver.backend_name = "hnas"
        self.mock_log = self.mock_object(driver, 'LOG')

        # mocking common backend calls
        self.mock_object(ssh.HNASSSHBackend, "check_fs_mounted", mock.Mock(
            return_value=True))
        self.mock_object(ssh.HNASSSHBackend, "check_vvol", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "check_quota", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "check_cifs", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "check_export", mock.Mock())

    @ddt.data('hitachi_hnas_driver_helper', 'hitachi_hnas_evs_id',
              'hitachi_hnas_evs_ip', 'hitachi_hnas_ip', 'hitachi_hnas_user')
    def test_init_invalid_conf_parameters(self, attr_name):
        self.mock_object(manila.share.driver.ShareDriver, '__init__')
        setattr(CONF, attr_name, None)

        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.__init__)

    def test_init_invalid_credentials(self):
        self.mock_object(manila.share.driver.ShareDriver,
                         '__init__')
        CONF.hitachi_hnas_password = None
        CONF.hitachi_hnas_ssh_private_key = None

        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.__init__)

    def test_update_access_nfs(self):
        access1 = {
            'access_type': 'ip',
            'access_to': '172.24.10.10',
            'access_level': 'rw'
        }
        access2 = {
            'access_type': 'ip',
            'access_to': '188.100.20.10',
            'access_level': 'ro'
        }
        access_list = [access1, access2]

        self.mock_object(ssh.HNASSSHBackend, "update_nfs_access_rule",
                         mock.Mock())
        self._driver.update_access('context', share_nfs, access_list, [], [])

        ssh.HNASSSHBackend.update_nfs_access_rule.assert_called_once_with(
            share_nfs['id'], [access1['access_to'] + '('
                              + access1['access_level'] + ',norootsquash)',
                              access2['access_to'] + '('
                              + access2['access_level'] + ')'])
        self.assertTrue(self.mock_log.debug.called)

    def test_update_access_ip_exception(self):
        access1 = {
            'access_type': 'ip',
            'access_to': '188.100.20.10',
            'access_level': 'ro'
        }
        access2 = {
            'access_type': 'something',
            'access_to': '172.24.10.10',
            'access_level': 'rw'
        }
        access_list = [access1, access2]

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.update_access, 'context', share_nfs,
                          access_list, [], [])

    def test_update_access_not_found_exception(self):
        access1 = {
            'access_type': 'ip',
            'access_to': '188.100.20.10',
            'access_level': 'ro'
        }
        access2 = {
            'access_type': 'something',
            'access_to': '172.24.10.10',
            'access_level': 'rw'
        }
        access_list = [access1, access2]

        self.mock_object(self._driver, '_ensure_share', mock.Mock(
            side_effect=exception.HNASItemNotFoundException(msg='fake')))

        self.assertRaises(exception.ShareResourceNotFound,
                          self._driver.update_access, 'context', share_nfs,
                          access_list, add_rules=[], delete_rules=[])

    @ddt.data([access_cifs_rw, 'acr'], [access_cifs_ro, 'ar'])
    @ddt.unpack
    def test_allow_access_cifs(self, access_cifs, permission):
        access_list_allow = [access_cifs]

        self.mock_object(ssh.HNASSSHBackend, 'cifs_allow_access', mock.Mock())

        self._driver.update_access('context', share_cifs, [],
                                   access_list_allow, [])

        ssh.HNASSSHBackend.cifs_allow_access.assert_called_once_with(
            share_cifs['id'], 'fake_user', permission)
        self.assertTrue(self.mock_log.debug.called)

    def test_allow_access_cifs_invalid_type(self):
        access_cifs_type_ip = {
            'id': '43167594-40e9-b899-1f4f-b9c2176b7564',
            'access_type': 'ip',
            'access_to': 'fake_user',
            'access_level': 'rw',
            'state': 'active',
        }
        access_list_allow = [access_cifs_type_ip]

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.update_access, 'context', share_cifs,
                          [], access_list_allow, [])

    def test_deny_access_cifs(self):
        access_list_deny = [access_cifs_rw]

        self.mock_object(ssh.HNASSSHBackend, 'cifs_deny_access', mock.Mock())

        self._driver.update_access('context', share_cifs, [], [],
                                   access_list_deny)

        ssh.HNASSSHBackend.cifs_deny_access.assert_called_once_with(
            share_cifs['id'], 'fake_user')
        self.assertTrue(self.mock_log.debug.called)

    def test_deny_access_cifs_unsupported_type(self):
        access_cifs_type_ip = {
            'id': '43167594-40e9-b899-1f4f-b9c2176b7564',
            'access_type': 'ip',
            'access_to': 'fake_user',
            'access_level': 'rw',
            'state': 'active',
        }
        access_list_deny = [access_cifs_type_ip]

        self.mock_object(ssh.HNASSSHBackend, 'cifs_deny_access', mock.Mock())

        self._driver.update_access('context', share_cifs, [], [],
                                   access_list_deny)
        self.assertTrue(self.mock_log.warning.called)

    def test_update_access_invalid_share_protocol(self):
        self.mock_object(self._driver, '_ensure_share', mock.Mock())
        ex = self.assertRaises(exception.ShareBackendException,
                               self._driver.update_access, 'context',
                               invalid_share, [], [], [])
        self.assertEqual(invalid_protocol_msg, ex.msg)

    def test_update_access_cifs_recovery_mode(self):
        access_list = [access_cifs_rw, access_cifs_ro]
        permission_list = [('fake_user1', 'acr'), ('fake_user2', 'ar')]

        self.mock_object(ssh.HNASSSHBackend, 'list_cifs_permissions',
                         mock.Mock(return_value=permission_list))
        self.mock_object(ssh.HNASSSHBackend, 'cifs_deny_access', mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, 'cifs_allow_access', mock.Mock())

        self._driver.update_access('context', share_cifs, access_list, [], [])

        ssh.HNASSSHBackend.list_cifs_permissions.assert_called_once_with(
            share_cifs['id'])
        self.assertTrue(self.mock_log.debug.called)

    def _get_export(self, share, ip, is_admin_only):
        if share['share_proto'].lower() == 'nfs':
            export = ':'.join((ip, '/shares/' + share['id']))
        else:
            export = r'\\%s\%s' % (ip, share['id'])

        return {
            "path": export,
            "is_admin_only": is_admin_only,
            "metadata": {},
        }

    @ddt.data(share_nfs, share_cifs)
    def test_create_share(self, share):
        self.mock_object(driver.HitachiHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "quota_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_add", mock.Mock(
            return_value='/shares/' + share['id']))
        self.mock_object(ssh.HNASSSHBackend, "cifs_share_add", mock.Mock())

        result = self._driver.create_share('context', share)

        self.assertTrue(self.mock_log.debug.called)
        ssh.HNASSSHBackend.vvol_create.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.quota_add.assert_called_once_with(share['id'],
                                                             share['size'])
        expected = [
            self._get_export(
                share, self._driver.hnas_evs_ip, False),
            self._get_export(
                share, self._driver.hnas_admin_network_ip, True)]

        if share['share_proto'].lower() == 'nfs':
            ssh.HNASSSHBackend.nfs_export_add.assert_called_once_with(
                share_nfs['id'])
            self.assertFalse(ssh.HNASSSHBackend.cifs_share_add.called)
        else:
            ssh.HNASSSHBackend.cifs_share_add.assert_called_once_with(
                share_cifs['id'])
            self.assertFalse(ssh.HNASSSHBackend.nfs_export_add.called)
        self.assertEqual(expected, result)

    def test_create_share_export_error(self):
        self.mock_object(driver.HitachiHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "quota_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_add", mock.Mock(
            side_effect=exception.HNASBackendException('msg')))
        self.mock_object(ssh.HNASSSHBackend, "vvol_delete", mock.Mock())

        self.assertRaises(exception.HNASBackendException,
                          self._driver.create_share, 'context', share_nfs)
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.exception.called)
        ssh.HNASSSHBackend.vvol_create.assert_called_once_with(share_nfs['id'])
        ssh.HNASSSHBackend.quota_add.assert_called_once_with(share_nfs['id'],
                                                             share_nfs['size'])
        ssh.HNASSSHBackend.nfs_export_add.assert_called_once_with(
            share_nfs['id'])
        ssh.HNASSSHBackend.vvol_delete.assert_called_once_with(share_nfs['id'])

    def test_create_share_invalid_share_protocol(self):
        self.mock_object(driver.HitachiHNASDriver, "_create_share",
                         mock.Mock(return_value="path"))

        ex = self.assertRaises(exception.ShareBackendException,
                               self._driver.create_share, 'context',
                               invalid_share)
        self.assertEqual(invalid_protocol_msg, ex.msg)

    @ddt.data(share_nfs, share_cifs)
    def test_delete_share(self, share):
        self.mock_object(driver.HitachiHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_del", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "cifs_share_del", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_delete", mock.Mock())

        self._driver.delete_share('context', share)

        self.assertTrue(self.mock_log.debug.called)
        ssh.HNASSSHBackend.vvol_delete.assert_called_once_with(share['id'])

        if share['share_proto'].lower() == 'nfs':
            ssh.HNASSSHBackend.nfs_export_del.assert_called_once_with(
                share['id'])
            self.assertFalse(ssh.HNASSSHBackend.cifs_share_del.called)
        else:
            ssh.HNASSSHBackend.cifs_share_del.assert_called_once_with(
                share['id'])
            self.assertFalse(ssh.HNASSSHBackend.nfs_export_del.called)

    @ddt.data(snapshot_nfs, snapshot_cifs)
    def test_create_snapshot(self, snapshot):
        hnas_id = snapshot['share_id']
        self.mock_object(ssh.HNASSSHBackend, "get_nfs_host_list", mock.Mock(
            return_value=['172.24.44.200(rw)']))
        self.mock_object(ssh.HNASSSHBackend, "update_nfs_access_rule",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "is_cifs_in_use", mock.Mock(
            return_value=False))
        self.mock_object(ssh.HNASSSHBackend, "tree_clone", mock.Mock())

        self._driver.create_snapshot('context', snapshot)

        ssh.HNASSSHBackend.tree_clone.assert_called_once_with(
            '/shares/' + hnas_id, '/snapshots/' + hnas_id + '/' +
            snapshot['id'])

        if snapshot['share']['share_proto'].lower() == 'nfs':
            ssh.HNASSSHBackend.get_nfs_host_list.assert_called_once_with(
                hnas_id)
            ssh.HNASSSHBackend.update_nfs_access_rule.assert_any_call(
                hnas_id, ['172.24.44.200(ro)'])
            ssh.HNASSSHBackend.update_nfs_access_rule.assert_any_call(
                hnas_id, ['172.24.44.200(rw)'])
        else:
            ssh.HNASSSHBackend.is_cifs_in_use.assert_called_once_with(
                hnas_id)

    def test_create_snapshot_invalid_protocol(self):
        self.mock_object(self._driver, '_ensure_share', mock.Mock())
        ex = self.assertRaises(exception.ShareBackendException,
                               self._driver.create_snapshot, 'context',
                               invalid_snapshot)
        self.assertEqual(invalid_protocol_msg, ex.msg)

    def test_create_snapshot_cifs_exception(self):
        cifs_excep_msg = ("Share backend error: CIFS snapshot when share is "
                          "mounted is disabled. Set "
                          "hitachi_hnas_allow_cifs_snapshot_while_mounted to "
                          "True or unmount the share to take a snapshot.")

        self.mock_object(ssh.HNASSSHBackend, "is_cifs_in_use", mock.Mock(
            return_value=True))

        ex = self.assertRaises(exception.ShareBackendException,
                               self._driver.create_snapshot, 'context',
                               snapshot_cifs)
        self.assertEqual(cifs_excep_msg, ex.msg)

    def test_create_snapshot_first_snapshot(self):
        hnas_id = snapshot_nfs['share_id']
        self.mock_object(ssh.HNASSSHBackend, "get_nfs_host_list", mock.Mock(
            return_value=['172.24.44.200(rw)']))
        self.mock_object(ssh.HNASSSHBackend, "update_nfs_access_rule",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "tree_clone", mock.Mock(
            side_effect=exception.HNASNothingToCloneException('msg')))
        self.mock_object(ssh.HNASSSHBackend, "create_directory", mock.Mock())

        self._driver.create_snapshot('context', snapshot_nfs)

        self.assertTrue(self.mock_log.warning.called)
        ssh.HNASSSHBackend.get_nfs_host_list.assert_called_once_with(hnas_id)
        ssh.HNASSSHBackend.update_nfs_access_rule.assert_any_call(
            hnas_id, ['172.24.44.200(ro)'])
        ssh.HNASSSHBackend.update_nfs_access_rule.assert_any_call(
            hnas_id, ['172.24.44.200(rw)'])
        ssh.HNASSSHBackend.create_directory.assert_called_once_with(
            '/snapshots/' + hnas_id + '/' + snapshot_nfs['id'])

    def test_delete_snapshot(self):
        hnas_id = snapshot_nfs['share_id']
        self.mock_object(driver.HitachiHNASDriver, "_check_fs_mounted")
        self.mock_object(ssh.HNASSSHBackend, "tree_delete", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "delete_directory", mock.Mock())

        self._driver.delete_snapshot('context', snapshot_nfs)

        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.info.called)
        driver.HitachiHNASDriver._check_fs_mounted.assert_called_once_with()
        ssh.HNASSSHBackend.tree_delete.assert_called_once_with(
            '/snapshots/' + hnas_id + '/' + snapshot_nfs['id'])
        ssh.HNASSSHBackend.delete_directory.assert_called_once_with(
            '/snapshots/' + hnas_id)

    @ddt.data(share_nfs, share_cifs)
    def test_ensure_share(self, share):
        result = self._driver.ensure_share('context', share)

        ssh.HNASSSHBackend.check_vvol.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.check_quota.assert_called_once_with(share['id'])

        expected = [
            self._get_export(
                share, self._driver.hnas_evs_ip, False),
            self._get_export(
                share, self._driver.hnas_admin_network_ip, True)]

        if share['share_proto'].lower() == 'nfs':
            ssh.HNASSSHBackend.check_export.assert_called_once_with(
                share['id'])
            self.assertFalse(ssh.HNASSSHBackend.check_cifs.called)
        else:
            ssh.HNASSSHBackend.check_cifs.assert_called_once_with(share['id'])
            self.assertFalse(ssh.HNASSSHBackend.check_export.called)
        self.assertEqual(expected, result)

    def test_ensure_share_invalid_protocol(self):
        ex = self.assertRaises(exception.ShareBackendException,
                               self._driver.ensure_share, 'context',
                               invalid_share)

        self.assertEqual(invalid_protocol_msg, ex.msg)

    def test_shrink_share(self):
        self.mock_object(ssh.HNASSSHBackend, "get_share_usage", mock.Mock(
            return_value=10))
        self.mock_object(ssh.HNASSSHBackend, "modify_quota", mock.Mock())

        self._driver.shrink_share(share_nfs, 11)

        ssh.HNASSSHBackend.get_share_usage.assert_called_once_with(
            share_nfs['id'])
        ssh.HNASSSHBackend.modify_quota.assert_called_once_with(
            share_nfs['id'], 11)

    def test_shrink_share_new_size_lower_than_usage(self):
        self.mock_object(ssh.HNASSSHBackend, "get_share_usage", mock.Mock(
            return_value=10))

        self.assertRaises(exception.ShareShrinkingPossibleDataLoss,
                          self._driver.shrink_share, share_nfs, 9)
        ssh.HNASSSHBackend.get_share_usage.assert_called_once_with(
            share_nfs['id'])

    def test_extend_share(self):
        self.mock_object(ssh.HNASSSHBackend, "get_stats", mock.Mock(
            return_value=(500, 200, True)))
        self.mock_object(ssh.HNASSSHBackend, "modify_quota", mock.Mock())

        self._driver.extend_share(share_nfs, 150)

        ssh.HNASSSHBackend.get_stats.assert_called_once_with()
        ssh.HNASSSHBackend.modify_quota.assert_called_once_with(
            share_nfs['id'], 150)

    def test_extend_share_with_no_available_space_in_fs(self):
        self.mock_object(ssh.HNASSSHBackend, "get_stats", mock.Mock(
            return_value=(500, 200, False)))
        self.mock_object(ssh.HNASSSHBackend, "modify_quota", mock.Mock())

        self.assertRaises(exception.HNASBackendException,
                          self._driver.extend_share, share_nfs, 1000)
        ssh.HNASSSHBackend.get_stats.assert_called_once_with()

    @ddt.data(share_nfs, share_cifs)
    def test_manage_existing(self, share):

        expected_exports = [
            self._get_export(
                share, self._driver.hnas_evs_ip, False),
            self._get_export(
                share, self._driver.hnas_admin_network_ip, True)]

        expected_out = {'size': share['size'],
                        'export_locations': expected_exports}

        self.mock_object(ssh.HNASSSHBackend, "get_share_quota", mock.Mock(
            return_value=share['size']))

        out = self._driver.manage_existing(share, 'option')

        self.assertEqual(expected_out, out)
        ssh.HNASSSHBackend.get_share_quota.assert_called_once_with(
            share['id'])

    def test_manage_existing_no_quota(self):
        self.mock_object(ssh.HNASSSHBackend, "get_share_quota", mock.Mock(
            return_value=None))

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing, share_nfs, 'option')
        ssh.HNASSSHBackend.get_share_quota.assert_called_once_with(
            share_nfs['id'])

    def test_manage_existing_wrong_share_id(self):
        self.mock_object(self.fake_private_storage, 'get',
                         mock.Mock(return_value='Wrong_share_id'))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.manage_existing, share_nfs, 'option')

    @ddt.data(':/', '1.1.1.1:/share_id', '1.1.1.1:/shares',
              '1.1.1.1:shares/share_id', ':/share_id')
    def test_manage_existing_wrong_path_format(self, wrong_location):
        expected_exception = ("Share backend error: Incorrect path. It "
                              "should have the following format: "
                              "IP:/shares/share_id.")
        share_copy = share_nfs.copy()
        share_copy['export_locations'] = [{'path': wrong_location}]

        ex = self.assertRaises(exception.ShareBackendException,
                               self._driver.manage_existing, share_copy,
                               'option')
        self.assertEqual(expected_exception, ex.msg)

    def test_manage_existing_wrong_evs_ip(self):
        share_nfs['export_locations'] = [{'path': '172.24.44.189:/shares/'
                                                  'aa4a7710-f326-41fb-ad18-'}]

        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing, share_nfs,
                          'option')

    def test_manage_existing_invalid_host(self):
        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing, share_invalid_host,
                          'option')

    def test_manage_existing_invalid_protocol(self):
        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing, invalid_share,
                          'option')

    def test_unmanage(self):
        self._driver.unmanage(share_nfs)

        self.assertTrue(self.fake_private_storage.delete.called)
        self.assertTrue(self.mock_log.info.called)

    def test_get_network_allocations_number(self):
        result = self._driver.get_network_allocations_number()

        self.assertEqual(0, result)

    @ddt.data([share_nfs, snapshot_nfs], [share_cifs, snapshot_cifs])
    @ddt.unpack
    def test_create_share_from_snapshot(self, share, snapshot):
        self.mock_object(driver.HitachiHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "quota_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "tree_clone", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "cifs_share_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_add", mock.Mock())

        result = self._driver.create_share_from_snapshot('context',
                                                         share,
                                                         snapshot)

        ssh.HNASSSHBackend.vvol_create.assert_called_once_with(share['id'])
        ssh.HNASSSHBackend.quota_add.assert_called_once_with(share['id'],
                                                             share['size'])
        ssh.HNASSSHBackend.tree_clone.assert_called_once_with(
            '/snapshots/' + share['id'] + '/' + snapshot['id'],
            '/shares/' + share['id'])

        expected = [
            self._get_export(
                share, self._driver.hnas_evs_ip, False),
            self._get_export(
                share, self._driver.hnas_admin_network_ip, True)]

        if share['share_proto'].lower() == 'nfs':
            ssh.HNASSSHBackend.nfs_export_add.assert_called_once_with(
                share['id'])
            self.assertFalse(ssh.HNASSSHBackend.cifs_share_add.called)
        else:
            ssh.HNASSSHBackend.cifs_share_add.assert_called_once_with(
                share['id'])
            self.assertFalse(ssh.HNASSSHBackend.nfs_export_add.called)

        self.assertEqual(expected, result)

    def test_create_share_from_snapshot_empty_snapshot(self):
        self.mock_object(driver.HitachiHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "quota_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "tree_clone", mock.Mock(
            side_effect=exception.HNASNothingToCloneException('msg')))
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_add", mock.Mock())

        result = self._driver.create_share_from_snapshot('context', share_nfs,
                                                         snapshot_nfs)
        expected = [
            self._get_export(
                share_nfs, self._driver.hnas_evs_ip, False),
            self._get_export(
                share_nfs, self._driver.hnas_admin_network_ip, True)]

        self.assertEqual(expected, result)
        self.assertTrue(self.mock_log.warning.called)
        ssh.HNASSSHBackend.vvol_create.assert_called_once_with(share_nfs['id'])
        ssh.HNASSSHBackend.quota_add.assert_called_once_with(share_nfs['id'],
                                                             share_nfs['size'])
        ssh.HNASSSHBackend.tree_clone.assert_called_once_with(
            '/snapshots/' + share_nfs['id'] + '/' + snapshot_nfs['id'],
            '/shares/' + share_nfs['id'])
        ssh.HNASSSHBackend.nfs_export_add.assert_called_once_with(
            share_nfs['id'])

    def test_create_share_from_snapshot_invalid_protocol(self):
        self.mock_object(driver.HitachiHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "quota_add", mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "tree_clone", mock.Mock())

        ex = self.assertRaises(exception.ShareBackendException,
                               self._driver.create_share_from_snapshot,
                               'context', invalid_share, snapshot_nfs)
        self.assertEqual(invalid_protocol_msg, ex.msg)

    def test_create_share_from_snapshot_cleanup(self):
        dest_path = '/snapshots/' + share_nfs['id'] + '/' + snapshot_nfs['id']
        src_path = '/shares/' + share_nfs['id']

        self.mock_object(driver.HitachiHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(ssh.HNASSSHBackend, "vvol_create")
        self.mock_object(ssh.HNASSSHBackend, "quota_add")
        self.mock_object(ssh.HNASSSHBackend, "tree_clone")
        self.mock_object(ssh.HNASSSHBackend, "vvol_delete")
        self.mock_object(ssh.HNASSSHBackend, "nfs_export_add", mock.Mock(
            side_effect=exception.HNASBackendException(
                msg='Error adding nfs export.')))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.create_share_from_snapshot,
                          'context', share_nfs, snapshot_nfs)

        ssh.HNASSSHBackend.vvol_create.assert_called_once_with(
            share_nfs['id'])
        ssh.HNASSSHBackend.quota_add.assert_called_once_with(
            share_nfs['id'], share_nfs['size'])
        ssh.HNASSSHBackend.tree_clone.assert_called_once_with(
            dest_path, src_path)
        ssh.HNASSSHBackend.nfs_export_add.assert_called_once_with(
            share_nfs['id'])
        ssh.HNASSSHBackend.vvol_delete.assert_called_once_with(
            share_nfs['id'])

    def test__check_fs_mounted(self):
        self._driver._check_fs_mounted()

        ssh.HNASSSHBackend.check_fs_mounted.assert_called_once_with()

    def test__check_fs_mounted_not_mounted(self):
        self.mock_object(ssh.HNASSSHBackend, 'check_fs_mounted', mock.Mock(
            return_value=False))

        self.assertRaises(exception.HNASBackendException,
                          self._driver._check_fs_mounted)

        ssh.HNASSSHBackend.check_fs_mounted.assert_called_once_with()

    def test__update_share_stats(self):
        fake_data = {
            'share_backend_name': self._driver.backend_name,
            'driver_handles_share_servers':
                self._driver.driver_handles_share_servers,
            'vendor_name': 'Hitachi',
            'driver_version': '3.0.0',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 1000,
            'free_capacity_gb': 200,
            'reserved_percentage': driver.CONF.reserved_share_percentage,
            'qos': False,
            'thin_provisioning': True,
            'dedupe': True,
        }

        self.mock_object(ssh.HNASSSHBackend, 'get_stats', mock.Mock(
            return_value=(1000, 200, True)))
        self.mock_object(driver.HitachiHNASDriver, "_check_fs_mounted",
                         mock.Mock())
        self.mock_object(manila.share.driver.ShareDriver,
                         '_update_share_stats', mock.Mock())

        self._driver._update_share_stats()

        self.assertTrue(self._driver.hnas.get_stats.called)
        (manila.share.driver.ShareDriver._update_share_stats.
         assert_called_once_with(fake_data))
        self.assertTrue(self.mock_log.info.called)
