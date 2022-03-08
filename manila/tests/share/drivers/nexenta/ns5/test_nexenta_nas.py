# Copyright 2019 Nexenta by DDN, Inc.
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

from unittest import mock

import ddt
from oslo_utils import units

from manila import context
from manila.share.drivers.nexenta.ns5 import jsonrpc
from manila.share.drivers.nexenta.ns5 import nexenta_nas
from manila import test

RPC_PATH = 'manila.share.drivers.nexenta.ns5.jsonrpc'
DRV_PATH = 'manila.share.drivers.nexenta.ns5.nexenta_nas.NexentaNasDriver'
DRIVER_VERSION = '1.1'
SHARE = {'share_id': 'uuid', 'size': 1, 'share_proto': 'NFS'}
SHARE_PATH = 'pool1/nfs_share/share-uuid'
SHARE2 = {'share_id': 'uuid2', 'size': 2, 'share_proto': 'NFS'}
SHARE2_PATH = 'pool1/nfs_share/share-uuid2'
SNAPSHOT = {
    'snapshot_id': 'snap_id',
    'share': SHARE,
    'snapshot_path': '%s@%s' % (SHARE_PATH, 'snapshot-snap_id')}


@ddt.ddt
class TestNexentaNasDriver(test.TestCase):

    def setUp(self):
        def _safe_get(opt):
            return getattr(self.cfg, opt)
        self.cfg = mock.Mock()
        self.mock_object(
            self.cfg, 'safe_get', mock.Mock(side_effect=_safe_get))
        super(TestNexentaNasDriver, self).setUp()
        self.cfg.nexenta_nas_host = '1.1.1.1'
        self.cfg.nexenta_rest_addresses = ['2.2.2.2']
        self.ctx = context.get_admin_context()
        self.cfg.nexenta_rest_port = 8080
        self.cfg.nexenta_rest_protocol = 'auto'
        self.cfg.nexenta_pool = 'pool1'
        self.cfg.nexenta_dataset_record_size = 131072
        self.cfg.reserved_share_percentage = 0
        self.cfg.reserved_share_from_snapshot_percentage = 0
        self.cfg.reserved_share_extend_percentage = 0
        self.cfg.nexenta_folder = 'nfs_share'
        self.cfg.nexenta_user = 'user'
        self.cfg.share_backend_name = 'NexentaStor5'
        self.cfg.nexenta_password = 'password'
        self.cfg.nexenta_thin_provisioning = False
        self.cfg.nexenta_mount_point_base = 'mnt'
        self.cfg.nexenta_rest_retry_count = 3
        self.cfg.nexenta_share_name_prefix = 'share-'
        self.cfg.max_over_subscription_ratio = 20.0
        self.cfg.enabled_share_protocols = 'NFS'
        self.cfg.nexenta_mount_point_base = '$state_path/mnt'
        self.cfg.nexenta_dataset_compression = 'on'
        self.cfg.network_config_group = 'DEFAULT'
        self.cfg.admin_network_config_group = (
            'fake_admin_network_config_group')
        self.cfg.driver_handles_share_servers = False
        self.cfg.safe_get = self.fake_safe_get
        self.nef_mock = mock.Mock()
        self.mock_object(jsonrpc, 'NefRequest')
        self.drv = nexenta_nas.NexentaNasDriver(configuration=self.cfg)
        self.drv.do_setup(self.ctx)

    def fake_safe_get(self, key):
        try:
            value = getattr(self.cfg, key)
        except AttributeError:
            value = None
        return value

    def test_backend_name(self):
        self.assertEqual('NexentaStor5', self.drv.share_backend_name)

    @mock.patch('%s._get_provisioned_capacity' % DRV_PATH)
    @mock.patch('manila.share.drivers.nexenta.ns5.'
                'jsonrpc.NefServices.get')
    @mock.patch('manila.share.drivers.nexenta.ns5.'
                'jsonrpc.NefFilesystems.set')
    @mock.patch('manila.share.drivers.nexenta.ns5.'
                'jsonrpc.NefFilesystems.get')
    def test_check_for_setup_error(self, get_filesystem, set_filesystem,
                                   get_service, prov_capacity):
        prov_capacity.return_value = 1
        get_filesystem.return_value = {
            'mountPoint': '/path/to/volume',
            'nonBlockingMandatoryMode': False,
            'smartCompression': False,
            'isMounted': True
        }
        get_service.return_value = {
            'state': 'online'
        }
        self.assertIsNone(self.drv.check_for_setup_error())
        get_filesystem.assert_called_with(self.drv.root_path)
        set_filesystem.assert_not_called()
        get_service.assert_called_with('nfs')
        get_filesystem.return_value = {
            'mountPoint': '/path/to/volume',
            'nonBlockingMandatoryMode': True,
            'smartCompression': True,
            'isMounted': True
        }
        set_filesystem.return_value = {}
        payload = {
            'nonBlockingMandatoryMode': False,
            'smartCompression': False
        }
        self.assertIsNone(self.drv.check_for_setup_error())
        get_filesystem.assert_called_with(self.drv.root_path)
        set_filesystem.assert_called_with(self.drv.root_path, payload)
        get_service.assert_called_with('nfs')
        get_filesystem.return_value = {
            'mountPoint': '/path/to/volume',
            'nonBlockingMandatoryMode': False,
            'smartCompression': True,
            'isMounted': True
        }
        payload = {
            'smartCompression': False
        }
        set_filesystem.return_value = {}
        self.assertIsNone(self.drv.check_for_setup_error())
        get_filesystem.assert_called_with(self.drv.root_path)
        set_filesystem.assert_called_with(self.drv.root_path, payload)
        get_service.assert_called_with('nfs')
        get_filesystem.return_value = {
            'mountPoint': '/path/to/volume',
            'nonBlockingMandatoryMode': True,
            'smartCompression': False,
            'isMounted': True
        }
        payload = {
            'nonBlockingMandatoryMode': False
        }
        set_filesystem.return_value = {}
        self.assertIsNone(self.drv.check_for_setup_error())
        get_filesystem.assert_called_with(self.drv.root_path)
        set_filesystem.assert_called_with(self.drv.root_path, payload)
        get_service.assert_called_with('nfs')
        get_filesystem.return_value = {
            'mountPoint': 'none',
            'nonBlockingMandatoryMode': False,
            'smartCompression': False,
            'isMounted': False
        }
        self.assertRaises(jsonrpc.NefException,
                          self.drv.check_for_setup_error)
        get_filesystem.return_value = {
            'mountPoint': '/path/to/volume',
            'nonBlockingMandatoryMode': False,
            'smartCompression': False,
            'isMounted': False
        }
        self.assertRaises(jsonrpc.NefException,
                          self.drv.check_for_setup_error)
        get_service.return_value = {
            'state': 'online'
        }
        self.assertRaises(jsonrpc.NefException,
                          self.drv.check_for_setup_error)

    @mock.patch('%s.NefFilesystems.get' % RPC_PATH)
    def test__get_provisioned_capacity(self, fs_get):
        fs_get.return_value = {
            'path': 'pool1/nfs_share/123',
            'referencedQuotaSize': 1 * units.Gi
        }

        self.drv._get_provisioned_capacity()

        self.assertEqual(1 * units.Gi, self.drv.provisioned_capacity)

    @mock.patch('%s._mount_filesystem' % DRV_PATH)
    @mock.patch('%s.NefFilesystems.create' % RPC_PATH)
    @mock.patch('%s.NefFilesystems.delete' % RPC_PATH)
    def test_create_share(self, delete_fs, create_fs, mount_fs):
        mount_path = '%s:/%s' % (self.cfg.nexenta_nas_host, SHARE_PATH)
        mount_fs.return_value = mount_path
        size = int(1 * units.Gi * 1.1)
        self.assertEqual(
            [{
                'path': mount_path,
                'id': 'share-uuid'
            }],
            self.drv.create_share(self.ctx, SHARE))

        payload = {
            'recordSize': 131072,
            'compressionMode': self.cfg.nexenta_dataset_compression,
            'path': SHARE_PATH,
            'referencedQuotaSize': size,
            'nonBlockingMandatoryMode': False,
            'referencedReservationSize': size
        }
        self.drv.nef.filesystems.create.assert_called_with(payload)

        mount_fs.side_effect = jsonrpc.NefException('some error')
        self.assertRaises(jsonrpc.NefException,
                          self.drv.create_share, self.ctx, SHARE)
        delete_payload = {'force': True}
        self.drv.nef.filesystems.delete.assert_called_with(
            SHARE_PATH, delete_payload)

    @mock.patch('%s.NefFilesystems.promote' % RPC_PATH)
    @mock.patch('%s.NefSnapshots.get' % RPC_PATH)
    @mock.patch('%s.NefSnapshots.list' % RPC_PATH)
    @mock.patch('%s.NefFilesystems.delete' % RPC_PATH)
    def test_delete_share(self, fs_delete, snap_list, snap_get, fs_promote):
        delete_payload = {'force': True, 'snapshots': True}
        snapshots_payload = {'parent': SHARE_PATH, 'fields': 'path'}
        clones_payload = {'fields': 'clones,creationTxg'}
        clone_path = '%s:/%s' % (self.cfg.nexenta_nas_host, 'path_to_fs')
        fs_delete.side_effect = [
            jsonrpc.NefException({
                'message': 'some_error',
                'code': 'EEXIST'}),
            None]
        snap_list.return_value = [{'path': '%s@snap1' % SHARE_PATH}]
        snap_get.return_value = {'clones': [clone_path], 'creationTxg': 1}
        self.assertIsNone(self.drv.delete_share(self.ctx, SHARE))
        fs_delete.assert_called_with(SHARE_PATH, delete_payload)
        fs_promote.assert_called_with(clone_path)
        snap_get.assert_called_with('%s@snap1' % SHARE_PATH, clones_payload)
        snap_list.assert_called_with(snapshots_payload)

    @mock.patch('%s.NefFilesystems.mount' % RPC_PATH)
    @mock.patch('%s.NefFilesystems.get' % RPC_PATH)
    def test_mount_filesystem(self, fs_get, fs_mount):
        mount_path = '%s:/%s' % (self.cfg.nexenta_nas_host, SHARE_PATH)
        fs_get.return_value = {
            'mountPoint': '/%s' % SHARE_PATH, 'isMounted': False}
        self.assertEqual(mount_path, self.drv._mount_filesystem(SHARE))
        self.drv.nef.filesystems.mount.assert_called_with(SHARE_PATH)

    @mock.patch('%s.NefHpr.activate' % RPC_PATH)
    @mock.patch('%s.NefFilesystems.mount' % RPC_PATH)
    @mock.patch('%s.NefFilesystems.get' % RPC_PATH)
    def test_mount_filesystem_with_activate(
            self, fs_get, fs_mount, hpr_activate):
        mount_path = '%s:/%s' % (self.cfg.nexenta_nas_host, SHARE_PATH)
        fs_get.side_effect = [
            {'mountPoint': 'none', 'isMounted': False},
            {'mountPoint': '/%s' % SHARE_PATH, 'isMounted': False}]
        self.assertEqual(mount_path, self.drv._mount_filesystem(SHARE))
        payload = {'datasetName': SHARE_PATH}
        self.drv.nef.hpr.activate.assert_called_once_with(payload)

    @mock.patch('%s.NefFilesystems.mount' % RPC_PATH)
    @mock.patch('%s.NefFilesystems.unmount' % RPC_PATH)
    def test_remount_filesystem(self, fs_unmount, fs_mount):
        self.drv._remount_filesystem(SHARE_PATH)
        fs_unmount.assert_called_once_with(SHARE_PATH)
        fs_mount.assert_called_once_with(SHARE_PATH)

    def parse_fqdn(self, fqdn):
        address_mask = fqdn.strip().split('/', 1)
        address = address_mask[0]
        ls = {"allow": True, "etype": "fqdn", "entity": address}
        if len(address_mask) == 2:
            ls['mask'] = address_mask[1]
            ls['etype'] = 'network'
        return ls

    @ddt.data({'key': 'value'}, {})
    @mock.patch('%s.NefNfs.list' % RPC_PATH)
    @mock.patch('%s.NefNfs.set' % RPC_PATH)
    @mock.patch('%s.NefFilesystems.acl' % RPC_PATH)
    def test_update_nfs_access(self, acl, nfs_set, nfs_list, list_data):
        security_contexts = {'securityModes': ['sys']}
        nfs_list.return_value = list_data
        rw_list = ['1.1.1.1/24', '2.2.2.2']
        ro_list = ['3.3.3.3', '4.4.4.4/30']
        security_contexts['readWriteList'] = []
        security_contexts['readOnlyList'] = []
        for fqdn in rw_list:
            ls = self.parse_fqdn(fqdn)
            if ls.get('mask'):
                ls['mask'] = int(ls['mask'])
            security_contexts['readWriteList'].append(ls)
        for fqdn in ro_list:
            ls = self.parse_fqdn(fqdn)
            if ls.get('mask'):
                ls['mask'] = int(ls['mask'])
            security_contexts['readOnlyList'].append(ls)

        self.assertIsNone(self.drv._update_nfs_access(SHARE, rw_list, ro_list))
        payload = {
            'flags': ['file_inherit', 'dir_inherit'],
            'permissions': ['full_set'],
            'principal': 'everyone@',
            'type': 'allow'
        }
        self.drv.nef.filesystems.acl.assert_called_with(SHARE_PATH, payload)
        payload = {'securityContexts': [security_contexts]}
        if list_data:
            self.drv.nef.nfs.set.assert_called_with(SHARE_PATH, payload)
        else:
            payload['filesystem'] = SHARE_PATH
            self.drv.nef.nfs.create.assert_called_with(payload)

    def test_update_nfs_access_bad_mask(self):
        security_contexts = {'securityModes': ['sys']}
        rw_list = ['1.1.1.1/24', '2.2.2.2/1a']
        ro_list = ['3.3.3.3', '4.4.4.4/30']
        security_contexts['readWriteList'] = []
        security_contexts['readOnlyList'] = []
        for fqdn in rw_list:
            security_contexts['readWriteList'].append(self.parse_fqdn(fqdn))
        for fqdn in ro_list:
            security_contexts['readOnlyList'].append(self.parse_fqdn(fqdn))

        self.assertRaises(ValueError, self.drv._update_nfs_access,
                          SHARE, rw_list, ro_list)

    @mock.patch('%s._update_nfs_access' % DRV_PATH)
    def test_update_access__ip_rw(self, update_nfs_access):
        access = {
            'access_type': 'ip',
            'access_to': '1.1.1.1',
            'access_level': 'rw',
            'access_id': 'fake_id'
        }

        self.assertEqual(
            {'fake_id': {'state': 'active'}},
            self.drv.update_access(
                self.ctx, SHARE, [access], None, None))
        self.drv._update_nfs_access.assert_called_with(SHARE, ['1.1.1.1'], [])

    @mock.patch('%s._update_nfs_access' % DRV_PATH)
    def test_update_access__ip_ro(self, update_nfs_access):
        access = {
            'access_type': 'ip',
            'access_to': '1.1.1.1',
            'access_level': 'ro',
            'access_id': 'fake_id'
        }

        expected = {'fake_id': {'state': 'active'}}
        self.assertEqual(
            expected, self.drv.update_access(
                self.ctx, SHARE, [access], None, None))
        self.drv._update_nfs_access.assert_called_with(SHARE, [], ['1.1.1.1'])

    @ddt.data('rw', 'ro')
    def test_update_access__not_ip(self, access_level):
        access = {
            'access_type': 'username',
            'access_to': 'some_user',
            'access_level': access_level,
            'access_id': 'fake_id'
        }
        expected = {'fake_id': {'state': 'error'}}
        self.assertEqual(expected, self.drv.update_access(
            self.ctx, SHARE, [access], None, None))

    @mock.patch('%s._get_capacity_info' % DRV_PATH)
    @mock.patch('manila.share.driver.ShareDriver._update_share_stats')
    def test_update_share_stats(self, super_stats, info):
        info.return_value = (100, 90, 10)
        stats = {
            'vendor_name': 'Nexenta',
            'storage_protocol': 'NFS',
            'nfs_mount_point_base': self.cfg.nexenta_mount_point_base,
            'create_share_from_snapshot_support': True,
            'revert_to_snapshot_support': True,
            'snapshot_support': True,
            'driver_version': DRIVER_VERSION,
            'share_backend_name': self.cfg.share_backend_name,
            'pools': [{
                'compression': True,
                'pool_name': 'pool1',
                'total_capacity_gb': 100,
                'free_capacity_gb': 90,
                'provisioned_capacity_gb': 0,
                'max_over_subscription_ratio': 20.0,
                'reserved_percentage': (
                    self.cfg.reserved_share_percentage),
                'reserved_snapshot_percentage': (
                    self.cfg.reserved_share_from_snapshot_percentage),
                'reserved_share_extend_percentage': (
                    self.cfg.reserved_share_extend_percentage),
                'thin_provisioning': self.cfg.nexenta_thin_provisioning,
            }],
        }

        self.drv._update_share_stats()

        self.assertEqual(stats, self.drv._stats)

    def test_get_capacity_info(self):
        self.drv.nef.get.return_value = {
            'bytesAvailable': 9 * units.Gi, 'bytesUsed': 1 * units.Gi}

        self.assertEqual((10, 9, 1), self.drv._get_capacity_info())

    @mock.patch('%s._set_reservation' % DRV_PATH)
    @mock.patch('%s._set_quota' % DRV_PATH)
    @mock.patch('%s.NefFilesystems.rename' % RPC_PATH)
    @mock.patch('%s.NefFilesystems.get' % RPC_PATH)
    def test_manage_existing(self, fs_get, fs_rename, set_res, set_quota):
        fs_get.return_value = {'referencedQuotaSize': 1073741824}
        old_path = '%s:/%s' % (self.cfg.nexenta_nas_host, 'path_to_fs')
        new_path = '%s:/%s' % (self.cfg.nexenta_nas_host, SHARE_PATH)
        SHARE['export_locations'] = [{'path': old_path}]
        expected = {'size': 2, 'export_locations': [{
            'path': new_path
        }]}
        self.assertEqual(expected, self.drv.manage_existing(SHARE, None))
        fs_rename.assert_called_with('path_to_fs', {'newPath': SHARE_PATH})
        set_res.assert_called_with(SHARE, 2)
        set_quota.assert_called_with(SHARE, 2)

    @mock.patch('%s.NefSnapshots.create' % RPC_PATH)
    def test_create_snapshot(self, snap_create):
        self.assertIsNone(self.drv.create_snapshot(self.ctx, SNAPSHOT))
        snap_create.assert_called_once_with({
            'path': SNAPSHOT['snapshot_path']})

    @mock.patch('%s.NefSnapshots.delete' % RPC_PATH)
    def test_delete_snapshot(self, snap_delete):
        self.assertIsNone(self.drv.delete_snapshot(self.ctx, SNAPSHOT))
        payload = {'defer': True}
        snap_delete.assert_called_once_with(
            SNAPSHOT['snapshot_path'], payload)

    @mock.patch('%s._mount_filesystem' % DRV_PATH)
    @mock.patch('%s._remount_filesystem' % DRV_PATH)
    @mock.patch('%s.NefFilesystems.delete' % RPC_PATH)
    @mock.patch('%s.NefSnapshots.clone' % RPC_PATH)
    def test_create_share_from_snapshot(
            self, snap_clone, fs_delete, remount_fs, mount_fs):
        mount_fs.return_value = 'mount_path'
        location = {
            'path': 'mount_path',
            'id': 'share-uuid2'
        }
        self.assertEqual([location], self.drv.create_share_from_snapshot(
            self.ctx, SHARE2, SNAPSHOT))

        size = int(SHARE2['size'] * units.Gi * 1.1)
        payload = {
            'targetPath': SHARE2_PATH,
            'referencedQuotaSize': size,
            'recordSize': self.cfg.nexenta_dataset_record_size,
            'compressionMode': self.cfg.nexenta_dataset_compression,
            'nonBlockingMandatoryMode': False,
            'referencedReservationSize': size
        }
        snap_clone.assert_called_once_with(SNAPSHOT['snapshot_path'], payload)

    @mock.patch('%s._mount_filesystem' % DRV_PATH)
    @mock.patch('%s._remount_filesystem' % DRV_PATH)
    @mock.patch('%s.NefFilesystems.delete' % RPC_PATH)
    @mock.patch('%s.NefSnapshots.clone' % RPC_PATH)
    def test_create_share_from_snapshot_error(
            self, snap_clone, fs_delete, remount_fs, mount_fs):
        fs_delete.side_effect = jsonrpc.NefException('delete error')
        mount_fs.side_effect = jsonrpc.NefException('create error')
        self.assertRaises(
            jsonrpc.NefException,
            self.drv.create_share_from_snapshot, self.ctx, SHARE2, SNAPSHOT)

        size = int(SHARE2['size'] * units.Gi * 1.1)
        payload = {
            'targetPath': SHARE2_PATH,
            'referencedQuotaSize': size,
            'recordSize': self.cfg.nexenta_dataset_record_size,
            'compressionMode': self.cfg.nexenta_dataset_compression,
            'nonBlockingMandatoryMode': False,
            'referencedReservationSize': size
        }
        snap_clone.assert_called_once_with(SNAPSHOT['snapshot_path'], payload)
        payload = {'force': True}
        fs_delete.assert_called_once_with(SHARE2_PATH, payload)

    @mock.patch('%s.NefFilesystems.rollback' % RPC_PATH)
    def test_revert_to_snapshot(self, fs_rollback):
        self.assertIsNone(self.drv.revert_to_snapshot(
            self.ctx, SNAPSHOT, [], []))
        payload = {'snapshot': 'snapshot-snap_id'}
        fs_rollback.assert_called_once_with(
            SHARE_PATH, payload)

    @mock.patch('%s._set_reservation' % DRV_PATH)
    @mock.patch('%s._set_quota' % DRV_PATH)
    def test_extend_share(self, set_quota, set_reservation):
        self.assertIsNone(self.drv.extend_share(
            SHARE, 2))
        set_quota.assert_called_once_with(
            SHARE, 2)
        set_reservation.assert_called_once_with(
            SHARE, 2)

    @mock.patch('%s.NefFilesystems.get' % RPC_PATH)
    @mock.patch('%s._set_reservation' % DRV_PATH)
    @mock.patch('%s._set_quota' % DRV_PATH)
    def test_shrink_share(self, set_quota, set_reservation, fs_get):
        fs_get.return_value = {
            'bytesUsedBySelf': 0.5 * units.Gi
        }
        self.assertIsNone(self.drv.shrink_share(
            SHARE2, 1))
        set_quota.assert_called_once_with(
            SHARE2, 1)
        set_reservation.assert_called_once_with(
            SHARE2, 1)

    @mock.patch('%s.NefFilesystems.set' % RPC_PATH)
    def test_set_quota(self, fs_set):
        quota = int(2 * units.Gi * 1.1)
        payload = {'referencedQuotaSize': quota}
        self.assertIsNone(self.drv._set_quota(
            SHARE, 2))
        fs_set.assert_called_once_with(SHARE_PATH, payload)

    @mock.patch('%s.NefFilesystems.set' % RPC_PATH)
    def test_set_reservation(self, fs_set):
        reservation = int(2 * units.Gi * 1.1)
        payload = {'referencedReservationSize': reservation}
        self.assertIsNone(self.drv._set_reservation(
            SHARE, 2))
        fs_set.assert_called_once_with(SHARE_PATH, payload)
