# Copyright 2026 Weka.IO Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Unit tests for manila.share.drivers.weka.driver."""

import json
import os
import shutil
import tempfile
import threading
from unittest import mock

from manila.common import constants
from oslo_concurrency import processutils
from oslo_config import cfg

from manila import exception
from manila.share.drivers.weka import driver as weka_driver
from manila.share.drivers.weka import exceptions as weka_exc
from manila.share.drivers.weka import posix as weka_posix
from manila import test
from manila.tests.share.drivers.weka import fakes

CONF = cfg.CONF


def _make_config(**kwargs):
    """Return a mock configuration object."""
    defaults = {
        'weka_api_server': 'weka-test.example.com',
        'weka_api_port': 14000,
        'weka_username': 'admin',
        'weka_password': 'secret',
        'weka_organization': 'Root',
        'weka_ssl_verify': False,
        'weka_filesystem_group': 'default',
        'weka_mount_point_base': '/mnt/weka',
        'weka_num_cores': 1,
        'weka_net_device': None,
        'weka_api_timeout': 30,
        'weka_max_api_retries': 3,
        'weka_share_name_prefix': 'manila_',
        'weka_nfs_server': None,
        'share_backend_name': 'weka',
        'weka_org_admin_secret': 'test-secret',
        'weka_org_prefix': 'manila-',
        'weka_org_user': 'manila',
        'weka_auth_token_dir': '/var/lib/manila/weka-tokens',
        'weka_api_pool_connections': 4,
        'weka_api_pool_maxsize': 10,
        'reserved_share_percentage': 0,
        'reserved_share_from_snapshot_percentage': 0,
        'reserved_share_extend_percentage': 0,
        'max_over_subscription_ratio': 20.0,
    }
    defaults.update(kwargs)

    config = mock.Mock()
    config.safe_get = lambda key: defaults.get(key)
    return config


def _wire_org(drv, org_client=None):
    """Wire mandatory WEKAFS per-tenant isolation attrs on a driver.

    Every WEKAFS share routes through the org-scoped client. By default
    that client IS drv._client so existing assertions keep working. Pass
    a distinct mock to verify org-vs-admin routing. Returns org client.
    """
    drv._org_prefix = 'manila-'
    drv._org_user = 'manila'
    drv._org_admin_secret = 'test-secret'
    drv._auth_token_dir = '/tmp/weka-tok-test'
    drv._org_clients = {}
    drv._org_lock = threading.Lock()
    drv._client.get_organization_by_name.return_value = (
        fakes.fake_organization())
    drv._client.auth_token_payload.return_value = {
        'access_token': 'acc', 'refresh_token': 'ref',
        'token_type': 'Bearer'}
    drv._client.for_org.return_value = org_client or drv._client
    return drv._client.for_org.return_value


class TestWekaShareDriverSetup(test.TestCase):

    def _make_driver(self, **cfg_kwargs):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config(**cfg_kwargs)
        drv._client = None
        drv._fs_group_uid = None
        return drv

    @mock.patch('manila.share.drivers.weka.client.WekaApiClient')
    def test_do_setup_creates_client_and_logs(self, mock_client_cls):
        drv = self._make_driver()
        mock_client = mock.Mock()
        mock_client.get_cluster_status.return_value = (
            fakes.fake_cluster_status())
        mock_client.get_filesystem_group_by_name.return_value = (
            fakes.fake_filesystem_group())
        mock_client_cls.return_value = mock_client

        drv.do_setup(context=None)

        mock_client.login.assert_called_once()
        self.assertIsNotNone(drv._client)

    @mock.patch('manila.share.drivers.weka.client.WekaApiClient')
    def test_do_setup_creates_fs_group_if_missing(self, mock_client_cls):
        drv = self._make_driver()
        mock_client = mock.Mock()
        mock_client.get_cluster_status.return_value = (
            fakes.fake_cluster_status())
        mock_client.get_filesystem_group_by_name.return_value = None
        mock_client.create_filesystem_group.return_value = (
            fakes.fake_filesystem_group())
        mock_client_cls.return_value = mock_client

        drv.do_setup(context=None)

        mock_client.create_filesystem_group.assert_called_once_with('default')

    @mock.patch('manila.share.drivers.weka.client.WekaApiClient')
    def test_do_setup_isolation_requires_secret(self, mock_client_cls):
        drv = self._make_driver(weka_org_admin_secret=None)
        mock_client = mock.Mock()
        mock_client.get_cluster_status.return_value = (
            fakes.fake_cluster_status())
        mock_client_cls.return_value = mock_client
        self.assertRaises(
            weka_exc.WekaConfigurationError, drv.do_setup, None)

    @mock.patch('manila.share.drivers.weka.client.WekaApiClient')
    def test_do_setup_rejects_org_prefix_with_separator(
            self, mock_client_cls):
        drv = self._make_driver(weka_org_prefix='../evil-')
        mock_client = mock.Mock()
        mock_client.get_cluster_status.return_value = (
            fakes.fake_cluster_status())
        mock_client_cls.return_value = mock_client
        self.assertRaises(
            weka_exc.WekaConfigurationError, drv.do_setup, None)

    def test_check_for_setup_error_missing_required(self):
        drv = self._make_driver(weka_api_server=None)
        self.assertRaises(
            exception.InvalidInput, drv.check_for_setup_error)

    @mock.patch('builtins.open',
                mock.mock_open(read_data='nodev wekafs\n'))
    def test_check_for_setup_error_wekafs_loaded(self):
        drv = self._make_driver()
        drv._client = mock.Mock()
        drv._client.get_cluster_status.return_value = {}
        # Should not raise
        drv.check_for_setup_error()

    def test_check_for_setup_error_auth_failure(self):
        drv = self._make_driver()
        drv._client = mock.Mock()
        drv._client.get_cluster_status.side_effect = (
            weka_exc.WekaAuthError(reason='bad creds'))
        with mock.patch('builtins.open',
                        mock.mock_open(read_data='nodev wekafs\n')):
            self.assertRaises(
                exception.ManilaException, drv.check_for_setup_error)


class TestWekaShareDriverCreateShare(test.TestCase):

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_create_share_wekafs(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None
        drv._client.create_filesystem.return_value = fakes.fake_filesystem()

        share = fakes.fake_share(proto='WEKAFS')
        result = drv.create_share(context=None, share=share)

        drv._client.create_filesystem.assert_called_once()
        self.assertEqual(1, len(result))
        path = result[0]['path']
        self.assertIn(fakes.FAKE_FS_NAME, path)

    def test_create_share_nfs(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None
        drv._client.create_filesystem.return_value = fakes.fake_filesystem()

        share = fakes.fake_share(proto='NFS')
        result = drv.create_share(context=None, share=share)

        self.assertEqual(1, len(result))
        self.assertIn(':/', result[0]['path'])

    def test_create_share_unsupported_protocol(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='CEPHFS')
        self.assertRaises(
            exception.InvalidShare,
            drv.create_share, None, share)

    def test_create_share_idempotent_when_fs_exists(self):
        drv = self._make_driver()
        existing_fs = fakes.fake_filesystem()
        drv._client.get_filesystem_by_name.return_value = existing_fs

        share = fakes.fake_share(proto='WEKAFS')
        result = drv.create_share(context=None, share=share)

        drv._client.create_filesystem.assert_not_called()
        self.assertEqual(1, len(result))

    def test_create_share_stores_fs_uid_in_metadata(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None
        drv._client.create_filesystem.return_value = fakes.fake_filesystem()

        share = fakes.fake_share(proto='WEKAFS')
        result = drv.create_share(context=None, share=share)

        meta = result[0].get('metadata', {})
        self.assertEqual(fakes.FAKE_FS_UID, meta.get('weka_fs_uid'))

    def test_create_share_raises_share_backend_on_capacity(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None
        drv._client.create_filesystem.side_effect = (
            weka_exc.WekaCapacityError(reason='no space')
        )
        share = fakes.fake_share(proto='WEKAFS')
        self.assertRaises(
            exception.ShareBackendException,
            drv.create_share, None, share)


_PATCH_NFS_MOUNT = (
    'manila.share.drivers.weka.driver.weka_privsep.nfs_mount')
_PATCH_UMOUNT = (
    'manila.share.drivers.weka.driver.weka_privsep.umount')
_PATCH_RSYNC = (
    'manila.share.drivers.weka.driver.weka_privsep.rsync')
_PATCH_MAKEDIRS = 'manila.share.drivers.weka.driver.os.makedirs'
_PATCH_MKDTEMP = 'manila.share.drivers.weka.driver.tempfile.mkdtemp'
_PATCH_RMDIR = 'manila.share.drivers.weka.driver.os.rmdir'
_PATCH_SOCKET = 'manila.share.drivers.weka.driver.socket.socket'
_PATCH_SLEEP = 'manila.utils.time.sleep'
_PATCH_THREAD = 'manila.share.drivers.weka.driver.threading.Thread'


class TestWekaShareDriverCreateFromSnapshot(test.TestCase):
    """Tests for the async create_share_from_snapshot path."""

    NFS_SERVER = 'nfs.example.com'
    TMP_CG_NAME = 'manila-snap-' + fakes.FAKE_NEW_SHARE_ID[:8]

    def _make_driver(self, nfs_server=NFS_SERVER):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config(weka_nfs_server=nfs_server)
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        drv._async_copies = {}
        drv._async_copies_lock = threading.Lock()
        drv._nfs_server = nfs_server
        _wire_org(drv)
        return drv

    def _make_iso_driver(self):
        """Isolation-enabled driver; returns (drv, org_client mock)."""
        drv = self._make_driver()
        org_client = _wire_org(drv, mock.Mock())
        return drv, org_client

    def _setup_happy_path_client(self, drv):
        """Configure client mocks for a fully successful operation."""
        snap = fakes.fake_snapshot()
        src_fs = fakes.fake_filesystem()
        new_fs = fakes.fake_new_filesystem()
        cg = fakes.fake_client_group()
        perm_src = fakes.fake_nfs_permission(
            uid='perm-src', fs_name=fakes.FAKE_FS_NAME,
            cg_name=self.TMP_CG_NAME)
        perm_dst = fakes.fake_nfs_permission(
            uid='perm-dst', fs_name=fakes.FAKE_NEW_FS_NAME,
            cg_name=self.TMP_CG_NAME)

        drv._client.get_snapshot_by_name.return_value = snap
        drv._client.get_filesystem.return_value = src_fs
        drv._client.get_filesystem_by_name.return_value = None
        drv._client.create_filesystem.return_value = new_fs
        drv._client.create_client_group.return_value = cg
        drv._client.add_client_group_rule.return_value = {
            'uid': fakes.FAKE_CG_RULE_UID}
        drv._client.list_nfs_permissions.return_value = [perm_src, perm_dst]
        return snap, new_fs, cg

    def _new_share(self, proto='WEKAFS'):
        return fakes.fake_share(
            share_id=fakes.FAKE_NEW_SHARE_ID, proto=proto)

    def test_snapshot_not_found_raises(self):
        drv = self._make_driver()
        drv._client.get_snapshot_by_name.return_value = None

        self.assertRaises(
            exception.ShareSnapshotNotFound,
            drv.create_share_from_snapshot,
            None, self._new_share(), fakes.fake_snapshot_model())
        drv._client.create_filesystem.assert_not_called()

    def test_no_nfs_server_raises_before_fs_create(self):
        drv = self._make_driver(nfs_server=None)
        drv._client.get_snapshot_by_name.return_value = fakes.fake_snapshot()
        drv._client.get_filesystem.return_value = fakes.fake_filesystem()
        self.assertRaises(
            exception.ShareBackendException,
            drv.create_share_from_snapshot,
            None, self._new_share(proto='NFS'),
            fakes.fake_snapshot_model())
        drv._client.create_filesystem.assert_not_called()

    @mock.patch(_PATCH_THREAD)
    def test_create_from_snapshot_returns_creating_status(
            self, mock_thread):
        drv = self._make_driver()
        snap, new_fs, _ = self._setup_happy_path_client(drv)

        result = drv.create_share_from_snapshot(
            None, self._new_share(), fakes.fake_snapshot_model())

        self.assertIsInstance(result, dict)
        self.assertEqual(
            constants.STATUS_CREATING_FROM_SNAPSHOT,
            result['status'])
        self.assertIn('export_locations', result)
        self.assertGreater(len(result['export_locations']), 0)
        mock_thread.assert_called_once()

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_happy_path_nfs_copy(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        self._setup_happy_path_client(drv)
        mock_socket.return_value.getsockname.return_value = (
            '192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        snap = fakes.fake_snapshot()

        drv._copy_snapshot_nfs(
            self._new_share(), fakes.fake_snapshot_model(),
            snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

        drv._client.create_client_group.assert_called_once()
        drv._client.add_client_group_rule.assert_called_once()
        self.assertEqual(
            2, drv._client.create_nfs_permission.call_count)
        self.assertEqual(2, mock_nfs_mount.call_count)
        mock_rsync.assert_called_once()
        self.assertEqual(2, mock_umount.call_count)
        drv._client.delete_nfs_permission.assert_called()
        drv._client.delete_client_group.assert_called_once_with(
            fakes.FAKE_CG_UID)

    @mock.patch(_PATCH_RSYNC)
    def test_happy_path_wekafs_copy(self, mock_rsync):
        """_copy_snapshot_wekafs: rsync called; both mounts use bare fs name.

        The Manila host is a joined Weka client.  Passing backends would
        trigger a second cluster attachment and fail (regression fc3cdad).
        Both WekaMount calls must receive backends=None.
        """
        drv = self._make_driver()
        snap = fakes.fake_snapshot()

        with mock.patch(
                'manila.share.drivers.weka.driver.tempfile.mkdtemp',
                side_effect=['/tmp/weka_src', '/tmp/weka_dst']):
            with mock.patch(
                    'manila.share.drivers.weka.driver.weka_posix.'
                    'WekaMount') as mock_mount:
                drv._copy_snapshot_wekafs(
                    self._new_share(),
                    fakes.fake_snapshot_model(),
                    snap,
                    fakes.FAKE_FS_NAME,
                    fakes.FAKE_NEW_FS_NAME)

        self.assertEqual(2, mock_mount.call_count)
        for call in mock_mount.call_args_list:
            self.assertIsNone(call.kwargs.get('backends'),
                              "backends must be None for bare-fs mount")
        mock_rsync.assert_called_once()

    @mock.patch(_PATCH_THREAD)
    def test_create_from_snapshot_isolation_uses_org_client(
            self, mock_thread):
        drv, org_client = self._make_iso_driver()
        org_client.get_snapshot_by_name.return_value = fakes.fake_snapshot()
        org_client.get_filesystem.return_value = fakes.fake_filesystem()
        org_client.get_filesystem_by_name.return_value = None
        org_client.create_filesystem.return_value = (
            fakes.fake_new_filesystem())

        result = drv.create_share_from_snapshot(
            None, self._new_share(proto='WEKAFS'),
            fakes.fake_snapshot_model())

        self.assertEqual(
            constants.STATUS_CREATING_FROM_SNAPSHOT, result['status'])
        org_client.get_snapshot_by_name.assert_called_once()
        org_client.get_filesystem.assert_called_once()
        _, kwargs = org_client.create_filesystem.call_args
        self.assertTrue(kwargs.get('auth_required'))
        # The admin client is never used for the isolated fs creation.
        drv._client.create_filesystem.assert_not_called()
        mock_thread.assert_called_once()

    @mock.patch(_PATCH_RSYNC)
    def test_copy_snapshot_wekafs_isolation_passes_auth_token(
            self, mock_rsync):
        """_copy_snapshot_wekafs mounts with the org's auth_token_path."""
        drv, _ = self._make_iso_driver()
        with mock.patch.object(
                drv, '_org_token_file', return_value='/tmp/tok.json'):
            with mock.patch(
                    'manila.share.drivers.weka.driver.tempfile.mkdtemp',
                    side_effect=['/tmp/weka_src', '/tmp/weka_dst']):
                with mock.patch(
                        'manila.share.drivers.weka.driver.weka_posix.'
                        'WekaMount') as mock_mount:
                    drv._copy_snapshot_wekafs(
                        self._new_share(proto='WEKAFS'),
                        fakes.fake_snapshot_model(),
                        fakes.fake_snapshot(),
                        fakes.FAKE_FS_NAME,
                        fakes.FAKE_NEW_FS_NAME)

        self.assertEqual(2, mock_mount.call_count)
        for call in mock_mount.call_args_list:
            self.assertEqual(
                '/tmp/tok.json', call.kwargs.get('auth_token_path'))
            self.assertIsNone(call.kwargs.get('backends'),
                              "backends must be None for bare-fs mount")
        mock_rsync.assert_called_once()

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_happy_path_nfs_protocol_returns_nfs_path(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        self._setup_happy_path_client(drv)
        mock_socket.return_value.getsockname.return_value = (
            '192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']

        with mock.patch(_PATCH_THREAD):
            result = drv.create_share_from_snapshot(
                None, self._new_share(proto='NFS'),
                fakes.fake_snapshot_model())

        self.assertIsInstance(result, dict)
        self.assertEqual(
            constants.STATUS_CREATING_FROM_SNAPSHOT,
            result['status'])
        self.assertIn(':/', result['export_locations'][0]['path'])

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_src_mount_fails_reraises_and_cleans_up(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        self._setup_happy_path_client(drv)
        mock_socket.return_value.getsockname.return_value = (
            '192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        mock_nfs_mount.side_effect = processutils.ProcessExecutionError(
            'mount src failed')
        snap = fakes.fake_snapshot()

        self.assertRaises(
            processutils.ProcessExecutionError,
            drv._copy_snapshot_nfs,
            self._new_share(), fakes.fake_snapshot_model(),
            snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

        mock_umount.assert_not_called()
        drv._client.delete_nfs_permission.assert_called()
        drv._client.delete_client_group.assert_called_once()

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_dst_mount_fails_reraises_and_cleans_up(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        self._setup_happy_path_client(drv)
        mock_socket.return_value.getsockname.return_value = (
            '192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        # First mount succeeds; every dst attempt (retries included)
        # fails.
        mock_nfs_mount.side_effect = (
            [None]
            + [processutils.ProcessExecutionError('mount dst failed')] * 6
        )
        snap = fakes.fake_snapshot()

        self.assertRaises(
            processutils.ProcessExecutionError,
            drv._copy_snapshot_nfs,
            self._new_share(), fakes.fake_snapshot_model(),
            snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

        self.assertEqual(1, mock_umount.call_count)
        drv._client.delete_nfs_permission.assert_called()
        drv._client.delete_client_group.assert_called_once()

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_rsync_fails_reraises_and_cleans_up(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        self._setup_happy_path_client(drv)
        mock_socket.return_value.getsockname.return_value = (
            '192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        mock_rsync.side_effect = processutils.ProcessExecutionError(
            'rsync failed')
        snap = fakes.fake_snapshot()

        self.assertRaises(
            processutils.ProcessExecutionError,
            drv._copy_snapshot_nfs,
            self._new_share(), fakes.fake_snapshot_model(),
            snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

        self.assertEqual(2, mock_umount.call_count)
        drv._client.delete_nfs_permission.assert_called()
        drv._client.delete_client_group.assert_called_once()

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_umount_failure_does_not_mask_rsync_exception(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        """A umount error in the finally block must not hide the original.

        The rsync error is what the caller should see.
        """
        drv = self._make_driver()
        self._setup_happy_path_client(drv)
        mock_socket.return_value.getsockname.return_value = (
            '192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        rsync_err = processutils.ProcessExecutionError('rsync failed')
        umount_err = processutils.ProcessExecutionError('umount failed')
        mock_rsync.side_effect = rsync_err
        mock_umount.side_effect = umount_err
        snap = fakes.fake_snapshot()

        with self.assertRaises(processutils.ProcessExecutionError) as cm:
            drv._copy_snapshot_nfs(
                self._new_share(), fakes.fake_snapshot_model(),
                snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

        self.assertIs(rsync_err, cm.exception)

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_permission_delete_failure_does_not_raise_on_success(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        """A permission cleanup failure must not propagate on success."""
        drv = self._make_driver()
        self._setup_happy_path_client(drv)
        mock_socket.return_value.getsockname.return_value = (
            '192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        drv._client.delete_nfs_permission.side_effect = Exception(
            'API error during cleanup')
        snap = fakes.fake_snapshot()

        # Should not raise — copy succeeded
        drv._copy_snapshot_nfs(
            self._new_share(), fakes.fake_snapshot_model(),
            snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)


class TestWekaShareDriverDeleteShare(test.TestCase):

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_delete_share(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.list_nfs_permissions.return_value = []

        with mock.patch.object(weka_posix.WekaMount, 'is_mounted',
                               return_value=False):
            drv.delete_share(context=None, share=fakes.fake_share())

        drv._client.delete_filesystem.assert_called_once_with(
            fakes.FAKE_FS_UID)

    def test_delete_share_idempotent_when_not_found(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None

        # Should not raise
        drv.delete_share(context=None, share=fakes.fake_share())
        drv._client.delete_filesystem.assert_not_called()

    def test_delete_share_leaves_access_cleanup_to_the_manager(self):
        """The manager calls update_access before delete_share."""
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.list_nfs_permissions.return_value = [
            fakes.fake_nfs_permission()]

        with mock.patch.object(weka_posix.WekaMount, 'is_mounted',
                               return_value=False):
            drv.delete_share(context=None, share=fakes.fake_share())

        drv._client.delete_nfs_permission.assert_not_called()
        drv._client.delete_filesystem.assert_called_once()


class TestWekaShareDriverExtendShrink(test.TestCase):

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_extend_share(self):
        drv = self._make_driver()
        share = fakes.fake_share(size=10)
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())

        drv.extend_share(share, new_size=20)

        drv._client.update_filesystem.assert_called_once_with(
            fakes.FAKE_FS_UID,
            total_capacity=20 * 1024 ** 3,
        )

    def test_shrink_share_success(self):
        drv = self._make_driver()
        share = fakes.fake_share(size=10)
        # used = 1 GiB, shrinking to 5 GiB — OK
        fs = fakes.fake_filesystem(
            total_capacity=10 * 1024 ** 3,
            used_size_bytes=1 * 1024 ** 3,
        )
        drv._client.get_filesystem_by_name.return_value = fs
        drv._client.get_filesystem.return_value = fs

        drv.shrink_share(share, new_size=5)

        drv._client.update_filesystem.assert_called_once_with(
            fakes.FAKE_FS_UID,
            total_capacity=5 * 1024 ** 3,
        )

    def test_shrink_share_raises_when_used_gt_new_size(self):
        drv = self._make_driver()
        share = fakes.fake_share(size=10)
        # used = 8 GiB, trying to shrink to 5 GiB
        fs = fakes.fake_filesystem(
            total_capacity=10 * 1024 ** 3,
            used_size_bytes=8 * 1024 ** 3,
        )
        drv._client.get_filesystem_by_name.return_value = fs
        drv._client.get_filesystem.return_value = fs

        self.assertRaises(
            exception.ShareShrinkingPossibleDataLoss,
            drv.shrink_share, share, new_size=5,
        )


class TestWekaShareDriverSnapshots(test.TestCase):

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_create_snapshot(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        snap_model = fakes.fake_snapshot_model()

        drv.create_snapshot(context=None, snapshot=snap_model)

        drv._client.create_snapshot.assert_called_once()

    def test_delete_snapshot(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        snap = fakes.fake_snapshot()
        drv._client.get_snapshot_by_name.return_value = snap
        snap_model = fakes.fake_snapshot_model()

        drv.delete_snapshot(context=None, snapshot=snap_model)

        drv._client.delete_snapshot.assert_called_once_with(
            fakes.FAKE_SNAP_UID)

    def test_delete_snapshot_idempotent_when_not_found(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.get_snapshot_by_name.return_value = None
        snap_model = fakes.fake_snapshot_model()

        # Should not raise
        drv.delete_snapshot(context=None, snapshot=snap_model)
        drv._client.delete_snapshot.assert_not_called()

    def test_delete_snapshot_idempotent_when_share_not_found(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None
        # Share with no export metadata: _get_fs_uid_for_share falls back
        # to get_filesystem_by_name (returns None -> ShareNotFound).
        share_no_meta = fakes.fake_share(export_locations=[])
        snap_model = fakes.fake_snapshot_model()
        snap_model['share'] = share_no_meta

        # Should not raise
        drv.delete_snapshot(context=None, snapshot=snap_model)
        drv._client.delete_snapshot.assert_not_called()

    def test_revert_to_snapshot(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        snap = fakes.fake_snapshot()
        drv._client.get_snapshot_by_name.return_value = snap
        snap_model = fakes.fake_snapshot_model()

        drv.revert_to_snapshot(
            context=None, snapshot=snap_model,
            share_access_rules=[], snapshot_access_rules=[])

        drv._client.restore_snapshot.assert_called_once_with(
            fakes.FAKE_SNAP_UID, fakes.FAKE_FS_UID)

    def test_revert_to_snapshot_raises_when_not_found(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.get_snapshot_by_name.return_value = None
        snap_model = fakes.fake_snapshot_model()

        self.assertRaises(
            exception.ShareSnapshotNotFound,
            drv.revert_to_snapshot,
            None, snap_model, [], [],
        )


class TestWekaShareDriverUpdateAccess(test.TestCase):

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_update_access_nfs_add_ip_rule(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        # No pre-existing client groups or permissions — new rule path.
        drv._client.list_client_groups.return_value = []
        drv._client.list_nfs_permissions.return_value = []
        drv._client.create_client_group.return_value = (
            fakes.fake_client_group())
        drv._client.add_client_group_rule.return_value = {}
        drv._client.create_nfs_permission.return_value = (
            fakes.fake_nfs_permission())

        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(access_type='ip',
                                      access_to='192.0.2.0/24')
        result = drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[rule], delete_rules=[],
            update_rules=[],
        )

        drv._client.create_client_group.assert_called_once()
        drv._client.create_nfs_permission.assert_called_once()
        self.assertEqual('active', result[rule['access_id']]['state'])

    def test_update_access_nfs_full_sync(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.list_client_groups.return_value = []
        drv._client.list_nfs_permissions.return_value = []
        drv._client.create_client_group.return_value = (
            fakes.fake_client_group())
        drv._client.add_client_group_rule.return_value = {}
        drv._client.create_nfs_permission.return_value = (
            fakes.fake_nfs_permission())

        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(access_type='ip',
                                      access_to='198.51.100.0/24')
        # Full sync: access_rules populated, add/delete/update empty
        drv.update_access(
            context=None, share=share,
            access_rules=[rule], add_rules=[], delete_rules=[],
            update_rules=[],
        )

        drv._client.create_nfs_permission.assert_called_once()

    def test_update_access_nfs_full_sync_prunes_stale_rules(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        fs_name = drv._share_name(share['id'])
        kept = fakes.fake_access_rule(access_type='ip',
                                      access_to='198.51.100.0/24')
        kept_cg = 'manila-{}-{}'.format(
            share['id'][:8], kept['access_id'][:8])

        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.list_client_groups.return_value = [
            fakes.fake_client_group(uid='cg-stale', name='manila-share-uu-'
                                                         'deadbeef'),
        ]
        drv._client.get_client_group.return_value = (
            fakes.fake_client_group_detail())
        drv._client.create_client_group.return_value = (
            fakes.fake_client_group(name=kept_cg))
        drv._client.create_nfs_permission.return_value = (
            fakes.fake_nfs_permission())
        drv._client.list_nfs_permissions.return_value = [
            # Another share's filesystem — never touched.
            fakes.fake_nfs_permission(
                uid='perm-other-fs', fs_name='manila_other',
                cg_name='manila-share-uu-deadbeef'),
            # Not a manila-managed group on this filesystem — left alone.
            fakes.fake_nfs_permission(
                uid='perm-foreign', fs_name=fs_name, cg_name='ops-group'),
            # Still backed by a rule in access_rules — kept.
            fakes.fake_nfs_permission(
                uid='perm-kept', fs_name=fs_name, cg_name=kept_cg),
            # Stale: no rule in access_rules maps to it — pruned.
            fakes.fake_nfs_permission(
                uid='perm-stale', fs_name=fs_name,
                cg_name='manila-share-uu-deadbeef'),
        ]

        drv.update_access(
            context=None, share=share,
            access_rules=[kept], add_rules=[], delete_rules=[],
            update_rules=[],
        )

        drv._client.delete_nfs_permission.assert_called_once_with(
            'perm-stale')
        drv._client.delete_client_group.assert_called_once_with('cg-stale')

    def test_update_access_nfs_full_sync_prunes_all_when_no_rules(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        fs_name = drv._share_name(share['id'])
        drv._client.list_nfs_permissions.return_value = [
            fakes.fake_nfs_permission(
                uid='perm-stale', fs_name=fs_name,
                cg_name='manila-share-uu-deadbeef'),
        ]
        drv._client.list_client_groups.return_value = [
            fakes.fake_client_group(
                uid='cg-stale', name='manila-share-uu-deadbeef'),
        ]

        drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[], delete_rules=[], update_rules=[],
        )

        drv._client.delete_nfs_permission.assert_called_once_with(
            'perm-stale')
        drv._client.delete_client_group.assert_called_once_with('cg-stale')

    def test_update_access_nfs_prune_permission_failure_is_tolerated(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        fs_name = drv._share_name(share['id'])
        drv._client.list_nfs_permissions.return_value = [
            fakes.fake_nfs_permission(
                uid='perm-stale', fs_name=fs_name,
                cg_name='manila-share-uu-deadbeef'),
        ]
        drv._client.delete_nfs_permission.side_effect = (
            weka_exc.WekaApiError('boom'))

        drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[], delete_rules=[], update_rules=[],
        )

        # The client group is not reaped when its permission survived.
        drv._client.delete_client_group.assert_not_called()

    def test_update_access_nfs_prune_client_group_failure_is_tolerated(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        fs_name = drv._share_name(share['id'])
        drv._client.list_nfs_permissions.return_value = [
            fakes.fake_nfs_permission(
                uid='perm-stale', fs_name=fs_name,
                cg_name='manila-share-uu-deadbeef'),
        ]
        drv._client.list_client_groups.side_effect = (
            weka_exc.WekaApiError('boom'))

        drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[], delete_rules=[], update_rules=[],
        )

        drv._client.delete_nfs_permission.assert_called_once_with(
            'perm-stale')

    def test_update_access_nfs_invalid_type_sets_error(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())

        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(access_type='user',
                                      access_to='bob')
        rule_id = rule['access_id']
        result = drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[rule], delete_rules=[],
            update_rules=[],
        )

        self.assertIn(rule_id, result)
        self.assertEqual('error', result[rule_id]['state'])

    def test_update_access_wekafs_ip_rule_creates_policy(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.get_security_policy_by_name.return_value = None
        drv._client.create_security_policy.return_value = (
            fakes.fake_security_policy())
        drv._client.attach_fs_security_policies.return_value = {}

        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule(access_type='ip',
                                      access_to='10.0.0.1')
        result = drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[rule], delete_rules=[],
            update_rules=[],
        )
        entry = result[rule['access_id']]
        self.assertEqual('active', entry['state'])
        self.assertEqual(
            drv._org_mount_password(share['project_id']),
            entry['access_key'])
        # A per-share rw Allow policy was created and attached.
        args, kwargs = drv._client.create_security_policy.call_args
        self.assertEqual('manila-share-uu-rw', args[0])
        self.assertEqual(['10.0.0.1'], kwargs['ips'])
        self.assertFalse(kwargs['read_only'])
        drv._client.attach_fs_security_policies.assert_called_once_with(
            fakes.FAKE_FS_UID, [fakes.FAKE_POLICY_UID])
        # No NFS resources touched.
        drv._client.create_client_group.assert_not_called()

    def test_update_access_wekafs_ro_ip_rule_is_read_only_policy(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.get_security_policy_by_name.return_value = None
        drv._client.create_security_policy.return_value = (
            fakes.fake_security_policy(read_only=True))
        drv._client.attach_fs_security_policies.return_value = {}

        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='10.0.0.5', access_level='ro')
        drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[rule], delete_rules=[],
            update_rules=[])

        args, kwargs = drv._client.create_security_policy.call_args
        self.assertEqual('manila-share-uu-ro', args[0])
        self.assertTrue(kwargs['read_only'])

    def test_update_access_wekafs_user_rule_grants_credential_no_policy(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule(access_type='user',
                                      access_to='bob')
        result = drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[rule], delete_rules=[],
            update_rules=[],
        )
        entry = result[rule['access_id']]
        self.assertEqual('active', entry['state'])
        self.assertEqual(
            drv._org_mount_password(share['project_id']),
            entry['access_key'])
        # No IP policy for a non-ip rule.
        drv._client.create_security_policy.assert_not_called()

    def test_update_access_wekafs_full_sync_prunes_stale_policy_ip(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        policies = {
            'manila-share-uu-rw': fakes.fake_security_policy(
                name='manila-share-uu-rw', ips=['10.0.0.1', '10.0.0.9']),
            'manila-share-uu-ro': None,
        }
        drv._client.get_security_policy_by_name.side_effect = (
            lambda name: policies.get(name))
        drv._client.attach_fs_security_policies.return_value = {}

        rules = [
            fakes.fake_access_rule(access_type='ip', access_to='10.0.0.1'),
            # Non-ip and IPv6 rules never map to a policy IP.
            fakes.fake_access_rule(access_type='user', access_to='bob'),
            fakes.fake_access_rule(access_type='ip', access_to='2001:db8::1'),
        ]
        drv.update_access(
            context=None, share=share,
            access_rules=rules, add_rules=[], delete_rules=[],
            update_rules=[],
        )

        # 10.0.0.1 is still granted; only the orphaned 10.0.0.9 is removed.
        drv._client.update_security_policy.assert_called_once_with(
            fakes.FAKE_POLICY_UID, remove_ips=['10.0.0.9'])
        drv._client.delete_security_policy.assert_not_called()

    def test_update_access_wekafs_full_sync_no_rules_deletes_policy(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        policies = {
            'manila-share-uu-rw': None,
            'manila-share-uu-ro': fakes.fake_security_policy(
                name='manila-share-uu-ro', ips=['10.0.0.7'],
                read_only=True),
        }
        drv._client.get_security_policy_by_name.side_effect = (
            lambda name: policies.get(name))

        drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[], delete_rules=[], update_rules=[],
        )

        drv._client.update_security_policy.assert_called_once_with(
            fakes.FAKE_POLICY_UID, remove_ips=['10.0.0.7'])
        drv._client.detach_fs_security_policies.assert_called_once_with(
            fakes.FAKE_FS_UID, [fakes.FAKE_POLICY_UID])
        drv._client.delete_security_policy.assert_called_once_with(
            fakes.FAKE_POLICY_UID)

    def test_update_access_wekafs_full_sync_nothing_stale_is_noop(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.get_security_policy_by_name.return_value = None

        drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[], delete_rules=[], update_rules=[],
        )

        drv._client.update_security_policy.assert_not_called()
        drv._client.delete_security_policy.assert_not_called()

    def test_update_access_wekafs_prune_reads_ips_key(self):
        """Policy addresses are read from 'ips', the key the API returns.

        Regression: the driver read 'ip', which is only a *write* key.
        On a live cluster that yields None, so prune iterated nothing and
        the WEKAFS half of full-sync reconciliation silently did nothing.
        """
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        # Raw API shape: addresses under 'ips', with no 'ip' key at all.
        pol = {
            'uid': fakes.FAKE_POLICY_UID,
            'name': 'manila-share-uu-rw',
            'action': 'Allow',
            'read_only': False,
            'ips': ['10.0.0.1', '10.0.0.9'],
        }
        policies = {'manila-share-uu-rw': pol, 'manila-share-uu-ro': None}
        drv._client.get_security_policy_by_name.side_effect = (
            lambda name: policies.get(name))
        drv._client.attach_fs_security_policies.return_value = {}

        rule = fakes.fake_access_rule(access_type='ip', access_to='10.0.0.1')
        drv.update_access(
            context=None, share=share,
            access_rules=[rule], add_rules=[], delete_rules=[],
            update_rules=[])

        drv._client.update_security_policy.assert_called_once_with(
            fakes.FAKE_POLICY_UID, remove_ips=['10.0.0.9'])

    def test_update_access_wekafs_prune_keeps_policy_with_other_ips(self):
        """Removing one address of several must not delete the policy."""
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        policies = {
            'manila-share-uu-rw': fakes.fake_security_policy(
                name='manila-share-uu-rw',
                ips=['10.0.0.1', '10.0.0.2', '10.0.0.9']),
            'manila-share-uu-ro': None,
        }
        drv._client.get_security_policy_by_name.side_effect = (
            lambda name: policies.get(name))
        drv._client.attach_fs_security_policies.return_value = {}

        rules = [
            fakes.fake_access_rule(access_type='ip', access_to='10.0.0.1'),
            fakes.fake_access_rule(access_type='ip', access_to='10.0.0.2'),
        ]
        drv.update_access(
            context=None, share=share,
            access_rules=rules, add_rules=[], delete_rules=[],
            update_rules=[])

        drv._client.update_security_policy.assert_called_once_with(
            fakes.FAKE_POLICY_UID, remove_ips=['10.0.0.9'])
        # Two addresses still backed by rules -> the policy stays put.
        drv._client.delete_security_policy.assert_not_called()
        drv._client.detach_fs_security_policies.assert_not_called()

    def test_update_access_wekafs_prune_failure_is_tolerated(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        policies = {
            'manila-share-uu-rw': fakes.fake_security_policy(
                name='manila-share-uu-rw', ips=['10.0.0.9']),
            'manila-share-uu-ro': None,
        }
        drv._client.get_security_policy_by_name.side_effect = (
            lambda name: policies.get(name))
        drv._client.update_security_policy.side_effect = (
            weka_exc.WekaApiError('boom'))

        drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[], delete_rules=[], update_rules=[],
        )

        drv._client.delete_security_policy.assert_not_called()

    def test_update_access_wekafs_ipv6_ip_rule_ignored(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='2001:db8::1')
        result = drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[rule], delete_rules=[],
            update_rules=[])
        self.assertNotIn(rule['access_id'], result)
        drv._client.create_security_policy.assert_not_called()

    def test_update_access_wekafs_delete_ipv6_rule_is_noop(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='2001:db8::1')
        # Must not raise; IPv6 was never applied so no policy to remove.
        result = drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[], delete_rules=[rule],
            update_rules=[])
        self.assertEqual({}, result)
        drv._client.get_security_policy_by_name.assert_not_called()

    def test_update_access_nfs_ipv6_rule_ignored_batch_unaffected(self):
        """A bad rule in a batch must not fail the valid rules with it."""
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.list_client_groups.return_value = []
        drv._client.list_nfs_permissions.return_value = []
        drv._client.create_client_group.return_value = (
            fakes.fake_client_group())
        drv._client.add_client_group_rule.return_value = {}
        drv._client.create_nfs_permission.return_value = (
            fakes.fake_nfs_permission())
        share = fakes.fake_share(proto='NFS')
        bad = fakes.fake_access_rule(
            rule_id='r-ipv6', access_type='ip', access_to='2001:db8::1')
        good = [
            fakes.fake_access_rule(
                rule_id='r-%d' % i, access_type='ip',
                access_to='203.0.113.%d' % i)
            for i in range(1, 6)
        ]

        result = drv.update_access(
            None, share, [], [bad] + good, [], [])

        self.assertNotIn('r-ipv6', result)
        for rule in good:
            self.assertEqual(
                'active', result[rule['access_id']]['state'])

    def test_driver_declares_no_ipv6_support(self):
        """ipv6_implemented=False keeps IPv6 rules away from the driver."""
        drv = self._make_driver()
        self.assertFalse(drv.ipv6_implemented)


class TestWekaShareDriverStats(test.TestCase):

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        # Provide a stub for _update_share_stats super call
        drv._stats = {}
        _wire_org(drv)
        return drv

    def test_update_share_stats_fields(self):
        drv = self._make_driver()
        cap = fakes.fake_capacity(
            total_bytes=100 * 1024 ** 3,
            used_bytes=30 * 1024 ** 3,
        )
        drv._client.get_capacity.return_value = cap

        captured = {}

        def _capture(stats):
            captured.update(stats)

        with mock.patch.object(
                weka_driver.driver.ShareDriver, '_update_share_stats',
                side_effect=_capture):
            drv._update_share_stats()

        self.assertEqual('WEKAFS_NFS', captured['storage_protocol'])
        self.assertIsInstance(captured['storage_protocol'], str)
        self.assertAlmostEqual(100.0, captured['total_capacity_gb'], places=0)
        self.assertAlmostEqual(70.0, captured['free_capacity_gb'], places=0)

    def test_update_share_stats_storage_protocol_is_underscore_joined(self):
        """storage_protocol must be an underscore-joined string.

        Manila's scheduler CapabilitiesFilter exact-matches the reported
        storage_protocol string against the share type's
        capability_storage_protocol extra-spec (both must be "WEKAFS_NFS").
        manila-tempest-plugin's ShareMultiBackendTest also calls
        storage_protocol.lower().split('_'), which requires a string — a
        Python list would raise AttributeError on .lower().
        """
        drv = self._make_driver()
        drv._client.get_capacity.return_value = fakes.fake_capacity()

        captured = {}

        def _capture(stats):
            captured.update(stats)

        with mock.patch.object(
                weka_driver.driver.ShareDriver, '_update_share_stats',
                side_effect=_capture):
            drv._update_share_stats()

        proto = captured['storage_protocol']
        self.assertIsInstance(proto, str,
                              "storage_protocol must be a string, not a list")
        self.assertEqual('WEKAFS_NFS', proto)

    def test_update_share_stats_handles_api_error(self):
        drv = self._make_driver()
        drv._client.get_capacity.side_effect = Exception("API down")

        with mock.patch.object(
                weka_driver.driver.ShareDriver, '_update_share_stats'):
            # Should not raise; falls back to zeros.
            drv._update_share_stats()

    def test_update_share_stats_reserved_percentage(self):
        """reserved_percentage is read from reserved_share_percentage."""
        drv = self._make_driver()
        drv.configuration = _make_config(reserved_share_percentage=5)
        drv._client.get_capacity.return_value = fakes.fake_capacity()

        captured = {}

        def _capture(stats):
            captured.update(stats)

        with mock.patch.object(
                weka_driver.driver.ShareDriver,
                '_update_share_stats',
                side_effect=_capture):
            drv._update_share_stats()

        self.assertEqual(5, captured['reserved_percentage'])


class TestWekaShareDriverManage(test.TestCase):

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_manage_existing_success(self):
        drv = self._make_driver()
        fs = fakes.fake_filesystem(total_capacity=20 * 1024 ** 3)
        drv._client.get_filesystem_by_name.return_value = fs

        share = fakes.fake_share(proto='NFS')
        result = drv.manage_existing(share, driver_options={})

        self.assertIn('size', result)
        self.assertEqual(20, result['size'])

    def test_manage_existing_wekafs_rejected(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        self.assertRaises(
            exception.ManageInvalidShare,
            drv.manage_existing, share, {},
        )
        # Rejected before any filesystem lookup.
        drv._client.get_filesystem_by_name.assert_not_called()

    def test_manage_existing_not_found(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None

        share = fakes.fake_share(proto='NFS')
        self.assertRaises(
            exception.ManageInvalidShare,
            drv.manage_existing, share, {},
        )

    def test_unmanage_does_not_delete(self):
        drv = self._make_driver()
        drv.unmanage(share=fakes.fake_share())
        drv._client.delete_filesystem.assert_not_called()

    def test_manage_existing_calls_remove_all_nfs_permissions(self):
        drv = self._make_driver()
        fs = fakes.fake_filesystem(total_capacity=20 * 1024 ** 3)
        drv._client.get_filesystem_by_name.return_value = fs

        share = fakes.fake_share(proto='NFS')
        with mock.patch.object(
                drv, '_remove_all_nfs_permissions') as mock_rm:
            drv.manage_existing(share, driver_options={})
        mock_rm.assert_called_once()


class TestWekaShareDriverMiscellaneous(test.TestCase):

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_get_network_allocations_number(self):
        drv = self._make_driver()
        self.assertEqual(0, drv.get_network_allocations_number())

    def test_share_name_uses_prefix(self):
        drv = self._make_driver()
        # Hyphens are stripped from the share UUID before appending.
        name = drv._share_name('my-uuid')
        self.assertEqual('manila_myuuid', name)

    def test_snapshot_name(self):
        drv = self._make_driver()
        # Driver uses 's_' prefix and strips hyphens from the snapshot UUID.
        name = drv._snapshot_name('snap-uuid')
        self.assertEqual('s_snapuuid', name)

    def test_mount_point(self):
        drv = self._make_driver()
        mp = drv._mount_point('manila_my-uuid')
        self.assertEqual('/mnt/weka/manila_my-uuid', mp)

    def test_ensure_share_re_mounts_if_not_mounted(self):
        drv = self._make_driver()
        fs = fakes.fake_filesystem()
        drv._client.get_filesystem_by_name.return_value = fs

        share = fakes.fake_share(proto='WEKAFS')

        with mock.patch.object(weka_posix.WekaMount, 'is_mounted',
                               return_value=False):
            with mock.patch.object(
                    weka_posix.WekaMount, 'mount') as mock_mnt:
                drv._ensure_share(context=None, share=share)
        mock_mnt.assert_called_once()

    def test_ensure_share_not_found_raises(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None
        share = fakes.fake_share()
        self.assertRaises(
            exception.ShareNotFound,
            drv._ensure_share, None, share,
        )

    def test_get_backend_info(self):
        drv = self._make_driver()
        result = drv.get_backend_info(context=None)
        self.assertEqual(
            'weka-test.example.com', result['weka_api_server'])
        self.assertEqual(
            '/mnt/weka', result['weka_mount_point_base'])


class TestWekaShareDriverNFSHelpers(test.TestCase):
    """Tests for NFS permission helpers and internal utility methods."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_remove_nfs_rule_removes_matching_permission(self):
        drv = self._make_driver()
        rule_id = 'abcdefgh-1234-5678-0000-111111111111'
        cg_name = 'manila-shareuui-abcdefgh'
        # cg_name embeds the first 8 chars of the rule access_id.
        perm = fakes.fake_nfs_permission(
            fs_name=fakes.FAKE_FS_NAME,
            cg_name=cg_name,
        )
        cg = fakes.fake_client_group(name=cg_name)
        drv._client.list_nfs_permissions.return_value = [perm]
        drv._client.list_client_groups.return_value = [cg]
        rule = fakes.fake_access_rule(rule_id=rule_id)

        drv._remove_nfs_rule(fakes.FAKE_FS_NAME, rule)

        drv._client.delete_nfs_permission.assert_called_once_with(
            fakes.FAKE_PERM_UID)
        drv._client.delete_client_group.assert_called_once_with(
            fakes.FAKE_CG_UID)

    def test_remove_nfs_rule_skips_different_filesystem(self):
        drv = self._make_driver()
        rule_id = 'abcdefgh-1234-5678-0000-111111111111'
        perm = fakes.fake_nfs_permission(
            fs_name='other-filesystem',
            cg_name='manila-shareuui-abcdefgh',
        )
        drv._client.list_nfs_permissions.return_value = [perm]
        drv._client.list_client_groups.return_value = []
        rule = fakes.fake_access_rule(rule_id=rule_id)

        drv._remove_nfs_rule(fakes.FAKE_FS_NAME, rule)

        drv._client.delete_nfs_permission.assert_not_called()

    def test_remove_nfs_rule_skips_non_matching_rule_id(self):
        drv = self._make_driver()
        rule_id = 'abcdefgh-1234-5678-0000-111111111111'
        # cg_name does NOT contain the first 8 chars of rule_id.
        perm = fakes.fake_nfs_permission(
            fs_name=fakes.FAKE_FS_NAME,
            cg_name='manila-shareuui-xxxxxxxx',
        )
        drv._client.list_nfs_permissions.return_value = [perm]
        drv._client.list_client_groups.return_value = []
        rule = fakes.fake_access_rule(rule_id=rule_id)

        drv._remove_nfs_rule(fakes.FAKE_FS_NAME, rule)

        drv._client.delete_nfs_permission.assert_not_called()

    def test_remove_nfs_rule_empty_permissions(self):
        drv = self._make_driver()
        drv._client.list_nfs_permissions.return_value = []
        drv._client.list_client_groups.return_value = []
        rule = fakes.fake_access_rule()

        # Should not raise, nothing to delete.
        drv._remove_nfs_rule(fakes.FAKE_FS_NAME, rule)
        drv._client.delete_nfs_permission.assert_not_called()

    def test_remove_all_nfs_permissions_deletes_matching(self):
        drv = self._make_driver()
        perm1 = fakes.fake_nfs_permission(
            uid='perm-uid-0001', fs_name=fakes.FAKE_FS_NAME,
            cg_name='manila-share111-rule1111')
        perm2 = fakes.fake_nfs_permission(
            uid='perm-uid-0002', fs_name=fakes.FAKE_FS_NAME,
            cg_name='manila-share222-rule2222')
        perm_other = fakes.fake_nfs_permission(
            uid='perm-uid-0003', fs_name='other-filesystem')
        drv._client.list_nfs_permissions.return_value = [
            perm1, perm2, perm_other]
        # No pre-existing client groups (simplifies the delete path).
        drv._client.list_client_groups.return_value = []

        drv._remove_all_nfs_permissions(fakes.FAKE_FS_NAME)

        self.assertEqual(2, drv._client.delete_nfs_permission.call_count)
        drv._client.delete_nfs_permission.assert_any_call('perm-uid-0001')
        drv._client.delete_nfs_permission.assert_any_call('perm-uid-0002')

    def test_remove_all_nfs_permissions_empty(self):
        drv = self._make_driver()
        drv._client.list_nfs_permissions.return_value = []
        drv._client.list_client_groups.return_value = []

        # Should not raise.
        drv._remove_all_nfs_permissions(fakes.FAKE_FS_NAME)
        drv._client.delete_nfs_permission.assert_not_called()

    def test_remove_all_nfs_permissions_silences_not_found(self):
        drv = self._make_driver()
        perm = fakes.fake_nfs_permission(fs_name=fakes.FAKE_FS_NAME)
        drv._client.list_nfs_permissions.return_value = [perm]
        drv._client.list_client_groups.return_value = []
        from manila.share.drivers.weka import exceptions as weka_exc
        drv._client.delete_nfs_permission.side_effect = (
            weka_exc.WekaNotFound(reason='already gone'))

        # WekaNotFound should be swallowed, not re-raised.
        drv._remove_all_nfs_permissions(fakes.FAKE_FS_NAME)

    def test_apply_nfs_rule_returns_active_state(self):
        drv = self._make_driver()
        drv._client.list_client_groups.return_value = []
        drv._client.list_nfs_permissions.return_value = []
        drv._client.create_client_group.return_value = (
            fakes.fake_client_group())

        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='10.1.1.1')
        result = drv._update_nfs_access(share, [rule], [], False)

        self.assertEqual('active', result[rule['access_id']]['state'])
        drv._client.create_client_group.assert_called_once()
        drv._client.create_nfs_permission.assert_called_once()

    def test_apply_nfs_rule_reuses_existing_client_group(self):
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='10.2.2.2')
        cg_name = 'manila-{}-{}'.format(
            share['id'][:8], rule['access_id'][:8])
        cg = fakes.fake_client_group(name=cg_name)

        drv = self._make_driver()
        # CG already exists; get_client_group returns no existing IP rules.
        drv._client.list_client_groups.return_value = [cg]
        drv._client.get_client_group.return_value = (
            fakes.fake_client_group_detail(
                uid=cg['uid'], name=cg_name, rules=[]))
        drv._client.list_nfs_permissions.return_value = []

        result = drv._update_nfs_access(share, [rule], [], False)

        drv._client.create_client_group.assert_not_called()
        drv._client.add_client_group_rule.assert_called_once()
        self.assertEqual('active', result[rule['access_id']]['state'])

    def test_apply_nfs_rule_idempotent_existing_ip(self):
        from manila.share.drivers.weka.driver import _cidr_to_weka_ip
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='10.3.3.3')
        cg_name = 'manila-{}-{}'.format(
            share['id'][:8], rule['access_id'][:8])
        cg = fakes.fake_client_group(name=cg_name)
        weka_ip = _cidr_to_weka_ip('10.3.3.3')

        drv = self._make_driver()
        drv._client.list_client_groups.return_value = [cg]
        # get_client_group returns the IP already present.
        drv._client.get_client_group.return_value = (
            fakes.fake_client_group_detail(
                uid=cg['uid'], name=cg_name,
                rules=[fakes.fake_client_group_ip_rule(weka_ip)]))
        drv._client.list_nfs_permissions.return_value = []

        drv._update_nfs_access(share, [rule], [], False)

        drv._client.add_client_group_rule.assert_not_called()

    def test_apply_nfs_rule_idempotent_existing_cidr(self):
        from manila.share.drivers.weka.driver import _cidr_to_weka_ip
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='10.0.0.0/8')
        cg_name = 'manila-{}-{}'.format(
            share['id'][:8], rule['access_id'][:8])
        cg = fakes.fake_client_group(name=cg_name)
        weka_ip = _cidr_to_weka_ip('10.0.0.0/8')

        drv = self._make_driver()
        drv._client.list_client_groups.return_value = [cg]
        drv._client.get_client_group.return_value = (
            fakes.fake_client_group_detail(
                uid=cg['uid'], name=cg_name,
                rules=[fakes.fake_client_group_ip_rule(weka_ip)]))
        drv._client.list_nfs_permissions.return_value = []

        drv._update_nfs_access(share, [rule], [], False)

        drv._client.add_client_group_rule.assert_not_called()

    def test_apply_nfs_rule_ignores_non_ip_group_rules(self):
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='10.5.5.5')
        cg_name = 'manila-{}-{}'.format(
            share['id'][:8], rule['access_id'][:8])
        cg = fakes.fake_client_group(name=cg_name)

        drv = self._make_driver()
        drv._client.list_client_groups.return_value = [cg]
        drv._client.get_client_group.return_value = (
            fakes.fake_client_group_detail(
                uid=cg['uid'], name=cg_name,
                rules=[{'id': 'r1', 'uid': 'u1', 'type': 'DNS',
                        'rule': 'host.example.com'}]))
        drv._client.list_nfs_permissions.return_value = []

        drv._update_nfs_access(share, [rule], [], False)

        drv._client.add_client_group_rule.assert_called_once_with(
            fakes.FAKE_CG_UID, 'IP', '10.5.5.5')

    def test_apply_nfs_rule_unparseable_group_rule_is_tolerated(self):
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='10.6.6.6')
        cg_name = 'manila-{}-{}'.format(
            share['id'][:8], rule['access_id'][:8])
        cg = fakes.fake_client_group(name=cg_name)

        drv = self._make_driver()
        drv._client.list_client_groups.return_value = [cg]
        drv._client.get_client_group.return_value = (
            fakes.fake_client_group_detail(
                uid=cg['uid'], name=cg_name,
                rules=[{'id': 'r1', 'uid': 'u1', 'type': 'IP',
                        'rule': 'not-an-address'}]))
        drv._client.list_nfs_permissions.return_value = []

        drv._update_nfs_access(share, [rule], [], False)

        drv._client.add_client_group_rule.assert_called_once_with(
            fakes.FAKE_CG_UID, 'IP', '10.6.6.6')

    def test_apply_nfs_rule_access_level_change(self):
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='10.4.4.4', access_level='rw')
        cg_name = 'manila-{}-{}'.format(
            share['id'][:8], rule['access_id'][:8])
        cg = fakes.fake_client_group(name=cg_name)
        from manila.share.drivers.weka.driver import _cidr_to_weka_ip
        weka_ip = _cidr_to_weka_ip('10.4.4.4')

        # Existing permission is RO; rule requests RW.
        perm = fakes.fake_nfs_permission(
            fs_name=fakes.FAKE_FS_NAME,
            cg_name=cg_name,
            permission_type='RO')

        drv = self._make_driver()
        drv._client.list_client_groups.return_value = [cg]
        drv._client.get_client_group.return_value = (
            fakes.fake_client_group_detail(
                uid=cg['uid'], name=cg_name,
                rules=[fakes.fake_client_group_ip_rule(weka_ip)]))
        drv._client.list_nfs_permissions.return_value = [perm]

        drv._update_nfs_access(share, [rule], [], False)

        drv._client.delete_nfs_permission.assert_called_once_with(
            fakes.FAKE_PERM_UID)
        drv._client.create_nfs_permission.assert_called_once()
        _, kwargs = drv._client.create_nfs_permission.call_args
        self.assertEqual('RW', kwargs.get('access_type'))

    def test_update_rules_path_applied_not_ignored(self):
        drv = self._make_driver()
        drv._client.list_client_groups.return_value = []
        drv._client.list_nfs_permissions.return_value = []
        drv._client.create_client_group.return_value = (
            fakes.fake_client_group())

        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='10.5.5.5', access_level='rw')
        result = drv.update_access(
            context=None, share=share,
            access_rules=[],
            add_rules=[],
            delete_rules=[],
            update_rules=[rule],
        )

        self.assertEqual('active', result[rule['access_id']]['state'])
        drv._client.create_client_group.assert_called_once()

    def test_remove_nfs_rule_leak_fix_deletes_client_group(self):
        rule_id = 'abcdefgh-1234-5678-0000-222222222222'
        cg_name = 'manila-shareuui-abcdefgh'
        cg = fakes.fake_client_group(
            uid='cg-uid-leak', name=cg_name)
        perm = fakes.fake_nfs_permission(
            uid='perm-uid-leak',
            fs_name=fakes.FAKE_FS_NAME,
            cg_name=cg_name)

        drv = self._make_driver()
        drv._client.list_nfs_permissions.return_value = [perm]
        drv._client.list_client_groups.return_value = [cg]
        rule = fakes.fake_access_rule(rule_id=rule_id)

        drv._remove_nfs_rule(fakes.FAKE_FS_NAME, rule)

        drv._client.delete_nfs_permission.assert_called_once_with(
            'perm-uid-leak')
        drv._client.delete_client_group.assert_called_once_with(
            'cg-uid-leak')

    def test_remove_all_nfs_permissions_leak_fix_deletes_client_groups(self):
        cg1_name = 'manila-share111-rule1111'
        cg2_name = 'manila-share222-rule2222'
        perm1 = fakes.fake_nfs_permission(
            uid='perm-uid-1', fs_name=fakes.FAKE_FS_NAME,
            cg_name=cg1_name)
        perm2 = fakes.fake_nfs_permission(
            uid='perm-uid-2', fs_name=fakes.FAKE_FS_NAME,
            cg_name=cg2_name)
        cg1 = fakes.fake_client_group(uid='cg-uid-1', name=cg1_name)
        cg2 = fakes.fake_client_group(uid='cg-uid-2', name=cg2_name)

        drv = self._make_driver()
        drv._client.list_nfs_permissions.return_value = [perm1, perm2]
        drv._client.list_client_groups.return_value = [cg1, cg2]

        drv._remove_all_nfs_permissions(fakes.FAKE_FS_NAME)

        self.assertEqual(2, drv._client.delete_nfs_permission.call_count)
        self.assertEqual(2, drv._client.delete_client_group.call_count)
        drv._client.delete_client_group.assert_any_call('cg-uid-1')
        drv._client.delete_client_group.assert_any_call('cg-uid-2')

    def test_apply_nfs_rule_tolerates_existing_ip_rule(self):
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='2.2.2.2', access_level='rw')
        cg_name = 'manila-{}-{}'.format(
            share['id'][:8], rule['access_id'][:8])
        cg = fakes.fake_client_group(name=cg_name)
        # Existing permission is RO; rule requests RW — reconcile must run.
        perm = fakes.fake_nfs_permission(
            fs_name=fakes.FAKE_FS_NAME,
            cg_name=cg_name,
            permission_type='RO')

        drv = self._make_driver()
        drv._client.list_client_groups.return_value = [cg]
        # existing_ips set is empty (normalized form not matched locally).
        drv._client.get_client_group.return_value = (
            fakes.fake_client_group_detail(
                uid=cg['uid'], name=cg_name, rules=[]))
        drv._client.list_nfs_permissions.return_value = [perm]
        # Weka returns 400 "Rule already exists" on the add call.
        drv._client.add_client_group_rule.side_effect = (
            weka_exc.WekaApiError(
                status_code=400,
                reason='/nfs/clientGroups/x/rules: Rule already exists'))

        # Must not raise; result for this rule must be 'active'.
        result = drv._update_nfs_access(share, [rule], [], False)

        self.assertEqual('active', result[rule['access_id']]['state'])
        # Permission reconcile (ro->rw) must have run despite the add error.
        drv._client.delete_nfs_permission.assert_called_once_with(
            fakes.FAKE_PERM_UID)
        drv._client.create_nfs_permission.assert_called_once()
        _, kwargs = drv._client.create_nfs_permission.call_args
        self.assertEqual('RW', kwargs.get('access_type'))

    def test_apply_nfs_rule_reraises_other_add_errors(self):
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='3.3.3.3')
        cg_name = 'manila-{}-{}'.format(
            share['id'][:8], rule['access_id'][:8])
        cg = fakes.fake_client_group(name=cg_name)

        drv = self._make_driver()
        drv._client.list_client_groups.return_value = [cg]
        drv._client.get_client_group.return_value = (
            fakes.fake_client_group_detail(
                uid=cg['uid'], name=cg_name, rules=[]))
        drv._client.list_nfs_permissions.return_value = []
        drv._client.add_client_group_rule.side_effect = (
            weka_exc.WekaApiError(
                status_code=400,
                reason='bad request: invalid something'))

        result = drv._update_nfs_access(share, [rule], [], False)

        self.assertEqual('error', result[rule['access_id']]['state'])

    def test_get_backends_returns_api_server(self):
        drv = self._make_driver()
        self.assertEqual('weka-test.example.com', drv._get_backends())

    def test_get_backends_empty_when_not_configured(self):
        drv = self._make_driver()
        drv.configuration = _make_config(weka_api_server=None)
        self.assertEqual('', drv._get_backends())

    def test_build_export_locations_nfs_uses_api_server_by_default(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        result = drv._build_export_locations(
            share, fakes.FAKE_FS_NAME, fakes.FAKE_FS_UID, 'NFS')
        self.assertEqual(
            'weka-test.example.com:/{}'.format(fakes.FAKE_FS_NAME),
            result[0]['path'],
        )

    def test_build_export_locations_nfs_uses_nfs_server_when_set(self):
        drv = self._make_driver()
        drv.configuration = _make_config(
            weka_nfs_server='nfs-lb.example.com')
        share = fakes.fake_share(proto='NFS')
        result = drv._build_export_locations(
            share, fakes.FAKE_FS_NAME, fakes.FAKE_FS_UID, 'NFS')
        self.assertEqual(
            'nfs-lb.example.com:/{}'.format(fakes.FAKE_FS_NAME),
            result[0]['path'],
        )

    def test_build_export_locations_wekafs_uses_api_server(self):
        drv = self._make_driver()
        drv.configuration = _make_config(
            weka_nfs_server='nfs-lb.example.com')
        share = fakes.fake_share(proto='WEKAFS')
        result = drv._build_export_locations(
            share, fakes.FAKE_FS_NAME, fakes.FAKE_FS_UID, 'WEKAFS')
        # WEKAFS path must use API server, not the NFS server
        self.assertIn('weka-test.example.com', result[0]['path'])
        self.assertNotIn('nfs-lb.example.com', result[0]['path'])

    def test_get_fs_uid_from_export_metadata(self):
        drv = self._make_driver()
        share = fakes.fake_share()  # has weka_fs_uid in export metadata

        uid = drv._get_fs_uid_for_share(share)

        self.assertEqual(fakes.FAKE_FS_UID, uid)
        drv._client.get_filesystem_by_name.assert_not_called()

    def test_get_fs_uid_falls_back_to_api(self):
        drv = self._make_driver()
        # Share with no export_locations — must fall back to API lookup.
        share = fakes.fake_share(export_locations=[])
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())

        uid = drv._get_fs_uid_for_share(share)

        self.assertEqual(fakes.FAKE_FS_UID, uid)
        drv._client.get_filesystem_by_name.assert_called_once()

    def test_get_fs_uid_raises_when_not_found(self):
        drv = self._make_driver()
        share = fakes.fake_share(export_locations=[])
        drv._client.get_filesystem_by_name.return_value = None

        from manila import exception
        self.assertRaises(
            exception.ShareNotFound,
            drv._get_fs_uid_for_share, share,
        )


class TestCidrToWekaIp(test.TestCase):
    """Tests for the _cidr_to_weka_ip module-level helper."""

    def test_cidr_prefix_converted_to_dotted_mask(self):
        result = weka_driver._cidr_to_weka_ip('192.168.1.0/24')
        self.assertEqual('192.168.1.0/255.255.255.0', result)

    def test_single_ip_unchanged(self):
        result = weka_driver._cidr_to_weka_ip('10.0.0.5')
        self.assertEqual('10.0.0.5', result)

    def test_slash_zero_all_hosts(self):
        result = weka_driver._cidr_to_weka_ip('0.0.0.0/0')
        self.assertEqual('0.0.0.0/0.0.0.0', result)

    def test_slash_32_single_host(self):
        result = weka_driver._cidr_to_weka_ip('10.1.2.3/32')
        self.assertEqual('10.1.2.3/255.255.255.255', result)

    def test_host_bits_set_normalised(self):
        # strict=False — host bits are masked off.
        result = weka_driver._cidr_to_weka_ip('192.168.1.5/24')
        self.assertEqual('192.168.1.0/255.255.255.0', result)

    def test_invalid_input_raises_value_error(self):
        self.assertRaises(
            ValueError,
            weka_driver._cidr_to_weka_ip, 'not-an-ip/24')


class TestWekaShareDriverGetShareStatus(test.TestCase):
    """Tests for WekaShareDriver.get_share_status."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        drv._async_copies = {}
        drv._async_copies_lock = threading.Lock()
        _wire_org(drv)
        return drv

    def test_get_share_status_creating(self):
        drv = self._make_driver()
        share = fakes.fake_share()
        drv._async_copies[share['id']] = {
            'status': constants.STATUS_CREATING_FROM_SNAPSHOT,
            'fs_uid': fakes.FAKE_FS_UID,
            'fs_name': fakes.FAKE_FS_NAME,
        }

        result = drv.get_share_status(share)

        self.assertEqual(
            constants.STATUS_CREATING_FROM_SNAPSHOT,
            result['status'])

    def test_get_share_status_available(self):
        drv = self._make_driver()
        share = fakes.fake_share()
        drv._async_copies[share['id']] = {
            'status': constants.STATUS_AVAILABLE,
            'fs_uid': fakes.FAKE_FS_UID,
            'fs_name': fakes.FAKE_FS_NAME,
        }
        # No API call expected — fs_uid/fs_name come from the dict.

        result = drv.get_share_status(share)

        self.assertEqual(constants.STATUS_AVAILABLE, result['status'])
        self.assertIn('export_locations', result)
        drv._client.get_filesystem_by_name.assert_not_called()

    def test_get_share_status_error(self):
        drv = self._make_driver()
        share = fakes.fake_share()
        drv._async_copies[share['id']] = {
            'status': constants.STATUS_ERROR,
            'fs_uid': fakes.FAKE_FS_UID,
            'fs_name': fakes.FAKE_FS_NAME,
        }

        result = drv.get_share_status(share)

        self.assertEqual(constants.STATUS_ERROR, result['status'])

    def test_get_share_status_missing_key(self):
        drv = self._make_driver()
        share = fakes.fake_share()
        # _async_copies is empty — simulates process restart

        result = drv.get_share_status(share)

        self.assertEqual(constants.STATUS_ERROR, result['status'])


class TestWekaShareDriverEnsureShares(test.TestCase):
    """Tests for WekaShareDriver.ensure_shares."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_ensure_shares_happy_path(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        fs = fakes.fake_filesystem()
        # ensure_shares now calls list_filesystems() once.
        drv._client.list_filesystems.return_value = [fs]

        with mock.patch.object(weka_posix.WekaMount, 'is_mounted',
                               return_value=True):
            result = drv.ensure_shares(context=None, shares=[share])

        self.assertIn(share['id'], result)
        self.assertIn('export_locations', result[share['id']])
        drv._client.list_filesystems.assert_called_once()
        # No per-share get_filesystem_by_name call expected.
        drv._client.get_filesystem_by_name.assert_not_called()

    def test_ensure_shares_not_found_returns_error(self):
        drv = self._make_driver()
        share = fakes.fake_share()
        # Filesystem not found — org client returns None for WEKAFS share.
        drv._client.list_filesystems.return_value = []
        drv._client.get_filesystem_by_name.return_value = None

        result = drv.ensure_shares(context=None, shares=[share])

        self.assertIn(share['id'], result)
        self.assertEqual(
            constants.STATUS_ERROR,
            result[share['id']]['status'])

    def test_ensure_shares_missing_org_does_not_provision(self):
        drv = self._make_driver()
        share = fakes.fake_share()  # WEKAFS
        drv._client.list_filesystems.return_value = []
        drv._client.get_organization_by_name.return_value = None

        result = drv.ensure_shares(context=None, shares=[share])

        self.assertEqual(
            constants.STATUS_ERROR, result[share['id']]['status'])
        # No side effects: neither an org client nor org creation.
        drv._client.for_org.assert_not_called()
        drv._client.create_organization.assert_not_called()


class TestWekaShareDriverWekafsIsolation(test.TestCase):
    """Per-tenant WEKAFS organization isolation."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def _org_client(self, drv):
        """Wire drv._client.for_org to return a fresh mock org client."""
        org_client = mock.Mock()
        drv._client.for_org.return_value = org_client
        return org_client

    def test_create_share_creates_org_and_authed_fs(self):
        drv = self._make_driver()
        # Organization does not exist yet.
        drv._client.get_organization_by_name.return_value = None
        drv._client.create_organization.return_value = (
            fakes.fake_organization())
        org_client = self._org_client(drv)
        org_client.get_filesystem_by_name.return_value = None
        org_client.create_filesystem.return_value = fakes.fake_filesystem()

        share = fakes.fake_share(proto='WEKAFS')
        result = drv.create_share(context=None, share=share)

        # Org was created, and the FS went through the org client with
        # authentication required — never through the admin client.
        drv._client.create_organization.assert_called_once()
        org_client.create_filesystem.assert_called_once()
        _, kwargs = org_client.create_filesystem.call_args
        self.assertTrue(kwargs.get('auth_required'))
        drv._client.create_filesystem.assert_not_called()

        meta = result[0]['metadata']
        self.assertEqual('manila-projuuid5678', meta['weka_org_name'])
        # Tenants log in as the least-privilege mount user, not the admin.
        self.assertEqual('manila-mnt', meta['weka_org_user'])
        self.assertNotIn('weka_mount_password', meta)

    def test_create_share_reuses_existing_org(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = self._org_client(drv)
        org_client.get_filesystem_by_name.return_value = None
        org_client.create_filesystem.return_value = fakes.fake_filesystem()

        drv.create_share(context=None, share=fakes.fake_share(proto='WEKAFS'))

        # Existing org: no create_organization call.
        drv._client.create_organization.assert_not_called()

    def test_delete_share_retains_org(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = self._org_client(drv)
        org_client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())

        with mock.patch.object(weka_posix.WekaMount, 'is_mounted',
                               return_value=False):
            drv.delete_share(context=None,
                             share=fakes.fake_share(proto='WEKAFS'))

        org_client.delete_filesystem.assert_called_once()
        # Org and its user are intentionally kept.
        drv._client.delete_organization.assert_not_called()

    def test_nfs_share_ignores_isolation(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None
        drv._client.create_filesystem.return_value = fakes.fake_filesystem()

        result = drv.create_share(
            context=None, share=fakes.fake_share(proto='NFS'))

        # NFS uses the admin client, no org, no auth_required.
        drv._client.create_organization.assert_not_called()
        _, kwargs = drv._client.create_filesystem.call_args
        self.assertFalse(kwargs.get('auth_required'))
        self.assertNotIn('weka_org_name', result[0]['metadata'])

    def test_update_access_returns_mount_credential(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = self._org_client(drv)

        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule(access_type='user', access_to='weka')
        result = drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[rule], delete_rules=[],
            update_rules=[])

        entry = result[rule['access_id']]
        self.assertEqual('active', entry['state'])
        self.assertEqual(
            drv._org_mount_password(share['project_id']),
            entry['access_key'])
        # A Regular (mount-only) user was ensured in the org.
        args, _ = org_client.create_user.call_args
        self.assertEqual('Regular', args[1])

    def test_update_access_mount_user_already_exists_is_idempotent(self):
        # Second+ share in a project: the org mount user already exists,
        # and Weka rejects re-creation with a 400 "Username already in
        # use." update_access must tolerate it and still return the
        # mount credential (not error the access rule).
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = self._org_client(drv)
        org_client.create_user.side_effect = weka_exc.WekaApiError(
            status_code=400,
            reason='/users: Could not create user: Username already in use.')

        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule(access_type='user', access_to='weka')
        result = drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[rule], delete_rules=[],
            update_rules=[])

        entry = result[rule['access_id']]
        self.assertEqual('active', entry['state'])
        self.assertEqual(
            drv._org_mount_password(share['project_id']),
            entry['access_key'])

    def test_mount_password_differs_from_admin_password(self):
        drv = self._make_driver()
        pid = 'proj-x'
        self.assertNotEqual(
            drv._org_password(pid), drv._org_mount_password(pid))

    def test_org_password_deterministic_and_complex(self):
        drv = self._make_driver()
        p1 = drv._org_password('proj-a')
        p2 = drv._org_password('proj-a')
        p3 = drv._org_password('proj-b')
        self.assertEqual(p1, p2)
        self.assertNotEqual(p1, p3)
        self.assertGreaterEqual(len(p1), 8)
        self.assertTrue(any(c.isupper() for c in p1))
        self.assertTrue(any(c.islower() for c in p1))
        self.assertTrue(any(c.isdigit() for c in p1))
        self.assertTrue(any(not c.isalnum() for c in p1))

    def test_org_name_prefixed_and_bounded(self):
        drv = self._make_driver()
        self.assertEqual(
            'manila-projuuid5678', drv._org_name('proj-uuid-5678'))

    def test_org_token_file_written_0600(self):
        drv = self._make_driver()
        tmpdir = tempfile.mkdtemp(prefix='weka-tok-test-')
        drv._auth_token_dir = tmpdir
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = self._org_client(drv)
        org_client.auth_token_payload.return_value = {
            'access_token': 'acc', 'refresh_token': 'ref',
            'token_type': 'Bearer'}
        try:
            path = drv._org_token_file('proj-uuid-5678')
            self.assertTrue(path.endswith('manila-projuuid5678.json'))
            with open(path) as fh:
                self.assertEqual('acc', json.load(fh)['access_token'])
            self.assertEqual(0o600, os.stat(path).st_mode & 0o777)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_isolated_wekafs_without_project_id_raises(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS', project_id=None)
        # Would otherwise collapse into a shared "manila-" org.
        self.assertRaises(
            weka_exc.WekaOrgError, drv._client_for_share, share)

    def test_org_client_cached(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        self._org_client(drv)

        c1 = drv._org_client('proj-1')
        c2 = drv._org_client('proj-1')

        self.assertIs(c1, c2)
        # for_org (and thus login) only happens once per project.
        drv._client.for_org.assert_called_once()


class TestWekaShareDriverInit(test.TestCase):
    """Test normal __init__ construction path (lines 192-209)."""

    @mock.patch('manila.share.drivers.weka.client.WekaApiClient')
    def test_init_via_normal_constructor(self, mock_client_cls):
        # ShareDriver.__init__ requires config_opts kwarg; driver passes it.
        # We mock the parent's __init__ to avoid full Manila config machinery.
        with mock.patch(
                'manila.share.driver.ShareDriver.__init__') as mock_super:
            mock_super.return_value = None
            drv = weka_driver.WekaShareDriver(
                execute='fake_execute', configuration=mock.Mock())
        self.assertIsNone(drv._client)
        self.assertIsNone(drv._fs_group_uid)
        self.assertEqual({}, drv._async_copies)
        self.assertIsInstance(drv._async_copies_lock, type(threading.Lock()))
        self.assertIsNone(drv._nfs_server)
        self.assertEqual({}, drv._org_clients)
        self.assertIsInstance(drv._org_lock, type(threading.Lock()))


class TestWekaShareDriverSetupEdgeCases(test.TestCase):
    """Cover remaining branches in do_setup / check_for_setup_error."""

    def _make_driver(self, **cfg_kwargs):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config(**cfg_kwargs)
        drv._client = None
        drv._fs_group_uid = None
        return drv

    @mock.patch('manila.share.drivers.weka.client.WekaApiClient')
    def test_do_setup_ssl_verify_defaults_to_true_when_not_set(
            self, mock_client_cls):
        drv = self._make_driver(weka_ssl_verify=None)
        mock_client = mock.Mock()
        mock_client.get_cluster_status.return_value = (
            fakes.fake_cluster_status())
        mock_client.get_filesystem_group_by_name.return_value = (
            fakes.fake_filesystem_group())
        mock_client_cls.return_value = mock_client

        drv.do_setup(context=None)

        _, kwargs = mock_client_cls.call_args
        self.assertTrue(kwargs['ssl_verify'])

    @mock.patch('manila.share.drivers.weka.client.WekaApiClient')
    def test_do_setup_cluster_status_failure_warns_but_continues(
            self, mock_client_cls):
        drv = self._make_driver()
        mock_client = mock.Mock()
        mock_client.get_cluster_status.side_effect = Exception('conn refused')
        mock_client.get_filesystem_group_by_name.return_value = (
            fakes.fake_filesystem_group())
        mock_client_cls.return_value = mock_client

        # Must not raise; status error is only a warning.
        drv.do_setup(context=None)

    def test_check_for_setup_error_non_auth_exception_just_warns(self):
        drv = self._make_driver()
        drv._client = mock.Mock()
        drv._client.get_cluster_status.side_effect = Exception('timeout')
        with mock.patch('builtins.open',
                        mock.mock_open(read_data='nodev wekafs\n')):
            # Must not raise; any non-auth exception is just a warning.
            drv.check_for_setup_error()

    def test_check_for_setup_error_wekafs_not_loaded_warns(self):
        drv = self._make_driver()
        drv._client = mock.Mock()
        drv._client.get_cluster_status.return_value = {}
        with mock.patch('builtins.open',
                        mock.mock_open(read_data='nodev ext4\n')):
            # Missing wekafs is a warning, not an error.
            drv.check_for_setup_error()


class TestRunSnapshotCopyWorker(test.TestCase):
    """Test _run_snapshot_copy background worker (lines 493-517)."""

    NFS_SERVER = 'nfs.example.com'

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config(weka_nfs_server=self.NFS_SERVER)
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        drv._async_copies = {}
        drv._async_copies_lock = threading.Lock()
        drv._nfs_server = self.NFS_SERVER
        _wire_org(drv)
        return drv

    def test_run_snapshot_copy_nfs_sets_available_on_success(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        drv._async_copies[share['id']] = {
            'status': 'creating',
            'fs_uid': fakes.FAKE_FS_UID,
            'fs_name': fakes.FAKE_FS_NAME,
        }

        with mock.patch.object(drv, '_copy_snapshot_nfs') as mock_copy:
            mock_copy.return_value = None
            drv._run_snapshot_copy(
                share, fakes.fake_snapshot_model(),
                fakes.fake_snapshot(),
                fakes.FAKE_FS_NAME, fakes.FAKE_FS_NAME, 'NFS')

        self.assertEqual(
            'available',
            drv._async_copies[share['id']]['status'])

    def test_run_snapshot_copy_wekafs_sets_available_on_success(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        drv._async_copies[share['id']] = {
            'status': 'creating',
            'fs_uid': fakes.FAKE_FS_UID,
            'fs_name': fakes.FAKE_FS_NAME,
        }

        with mock.patch.object(drv, '_copy_snapshot_wekafs') as mock_copy:
            mock_copy.return_value = None
            drv._run_snapshot_copy(
                share, fakes.fake_snapshot_model(),
                fakes.fake_snapshot(),
                fakes.FAKE_FS_NAME, fakes.FAKE_FS_NAME, 'WEKAFS')

        self.assertEqual(
            'available',
            drv._async_copies[share['id']]['status'])

    def test_run_snapshot_copy_sets_error_on_exception(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        drv._async_copies[share['id']] = {
            'status': 'creating',
            'fs_uid': fakes.FAKE_FS_UID,
            'fs_name': fakes.FAKE_FS_NAME,
        }

        with mock.patch.object(drv, '_copy_snapshot_wekafs') as mock_copy:
            mock_copy.side_effect = Exception('copy failed')
            drv._run_snapshot_copy(
                share, fakes.fake_snapshot_model(),
                fakes.fake_snapshot(),
                fakes.FAKE_FS_NAME, fakes.FAKE_FS_NAME, 'WEKAFS')

        self.assertEqual(
            'error',
            drv._async_copies[share['id']]['status'])


class TestSnapshotCopyNfsEdgeCases(test.TestCase):
    """Additional _copy_snapshot_nfs coverage."""

    NFS_SERVER = 'nfs.example.com'
    TMP_CG_NAME = 'manila-snap-' + fakes.FAKE_NEW_SHARE_ID[:8]

    def _make_driver(self, nfs_server=NFS_SERVER):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config(weka_nfs_server=nfs_server)
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        drv._async_copies = {}
        drv._async_copies_lock = threading.Lock()
        drv._nfs_server = nfs_server
        _wire_org(drv)
        return drv

    def _new_share(self, proto='NFS'):
        return fakes.fake_share(
            share_id=fakes.FAKE_NEW_SHARE_ID, proto=proto)

    def _setup_happy_path_client(self, drv):
        snap = fakes.fake_snapshot()
        cg = fakes.fake_client_group()
        perm_src = fakes.fake_nfs_permission(
            uid='perm-src', fs_name=fakes.FAKE_FS_NAME,
            cg_name=self.TMP_CG_NAME)
        perm_dst = fakes.fake_nfs_permission(
            uid='perm-dst', fs_name=fakes.FAKE_NEW_FS_NAME,
            cg_name=self.TMP_CG_NAME)
        drv._client.create_client_group.return_value = cg
        drv._client.add_client_group_rule.return_value = {
            'uid': fakes.FAKE_CG_RULE_UID}
        drv._client.list_nfs_permissions.return_value = [perm_src, perm_dst]
        return snap, cg

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_umount_dst_failure_warns_and_continues(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        self._setup_happy_path_client(drv)
        mock_socket.return_value.getsockname.return_value = ('192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        # Succeed src mount, fail dst mount — triggers dst_mounted=False path.
        # Actually test dst unmount failure: succeed both mounts, fail rsync so
        # both unmounts run, and make dst umount fail.
        mock_rsync.side_effect = processutils.ProcessExecutionError(
            'rsync error')
        umount_calls = [Exception('umount dst failed'), None]
        mock_umount.side_effect = umount_calls
        snap = fakes.fake_snapshot()

        # rsync fails but umount dst also fails — warns; no double-raise.
        with self.assertRaises(processutils.ProcessExecutionError):
            drv._copy_snapshot_nfs(
                self._new_share(), fakes.fake_snapshot_model(),
                snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_list_nfs_permissions_failure_warns(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        cg = fakes.fake_client_group()
        drv._client.create_client_group.return_value = cg
        drv._client.add_client_group_rule.return_value = {
            'uid': fakes.FAKE_CG_RULE_UID}
        # list_nfs_permissions fails during cleanup
        drv._client.list_nfs_permissions.side_effect = Exception('api error')
        mock_socket.return_value.getsockname.return_value = ('192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        mock_rsync.side_effect = processutils.ProcessExecutionError(
            'rsync failed')
        snap = fakes.fake_snapshot()

        # Exception re-raised (from rsync), but cleanup warning also fires.
        with self.assertRaises(processutils.ProcessExecutionError):
            drv._copy_snapshot_nfs(
                self._new_share(), fakes.fake_snapshot_model(),
                snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_delete_client_group_failure_warns(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        self._setup_happy_path_client(drv)
        mock_socket.return_value.getsockname.return_value = ('192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        mock_rsync.side_effect = processutils.ProcessExecutionError(
            'rsync failed')
        drv._client.delete_client_group.side_effect = Exception('cg del fail')
        snap = fakes.fake_snapshot()

        # rsync exception re-raised; delete_client_group warning fires too.
        with self.assertRaises(processutils.ProcessExecutionError):
            drv._copy_snapshot_nfs(
                self._new_share(), fakes.fake_snapshot_model(),
                snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_rule_uid_none_skips_delete_rule(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        cg = fakes.fake_client_group()
        drv._client.create_client_group.return_value = cg
        # Return None for rule uid (no 'uid' key in response).
        drv._client.add_client_group_rule.return_value = {}
        drv._client.list_nfs_permissions.return_value = []
        mock_socket.return_value.getsockname.return_value = ('192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        snap = fakes.fake_snapshot()

        # Success path with rule_uid=None — delete_client_group_rule skipped.
        drv._copy_snapshot_nfs(
            self._new_share(), fakes.fake_snapshot_model(),
            snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

        drv._client.delete_client_group_rule.assert_not_called()
        drv._client.delete_client_group.assert_called_once()

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_socket_route_fallback_on_connect_exception(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        cg = fakes.fake_client_group()
        drv._client.create_client_group.return_value = cg
        drv._client.add_client_group_rule.return_value = {
            'uid': fakes.FAKE_CG_RULE_UID}
        drv._client.list_nfs_permissions.return_value = []
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        # s.connect raises — should fall back to gethostbyname
        mock_socket.return_value.connect.side_effect = OSError('no route')
        snap = fakes.fake_snapshot()

        _patch_ghbn = (
            'manila.share.drivers.weka.driver.socket.gethostbyname')
        with mock.patch(_patch_ghbn, return_value='127.0.0.1'):
            drv._copy_snapshot_nfs(
                self._new_share(), fakes.fake_snapshot_model(),
                snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

        drv._client.create_client_group.assert_called_once()


class TestGetShareStatusEdgeCases(test.TestCase):
    """Cover the 'else' branch of get_share_status (line 752)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        drv._async_copies = {}
        drv._async_copies_lock = threading.Lock()
        _wire_org(drv)
        return drv

    def test_get_share_status_unknown_state_returns_state(self):
        drv = self._make_driver()
        share = fakes.fake_share()
        drv._async_copies[share['id']] = {
            'status': 'some_other_state',
            'fs_uid': fakes.FAKE_FS_UID,
            'fs_name': fakes.FAKE_FS_NAME,
        }

        result = drv.get_share_status(share)

        self.assertEqual('some_other_state', result['status'])


class TestDeleteShareEdgeCases(test.TestCase):
    """Cover unmount-failure and WekaNotFound branches in delete_share."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_delete_share_stops_when_unmount_fails(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.list_nfs_permissions.return_value = []

        with mock.patch.object(weka_posix.WekaMount, 'is_mounted',
                               return_value=True):
            with mock.patch.object(
                    weka_posix.WekaMount, 'unmount',
                    side_effect=weka_exc.WekaUnmountError(reason='stuck')):
                self.assertRaises(
                    weka_exc.WekaUnmountError, drv.delete_share,
                    None, fakes.fake_share())

        drv._client.delete_filesystem.assert_not_called()

    def test_delete_share_weka_not_found_swallowed(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        drv._client.list_nfs_permissions.return_value = []
        drv._client.delete_filesystem.side_effect = (
            weka_exc.WekaNotFound(reason='already gone'))

        with mock.patch.object(weka_posix.WekaMount, 'is_mounted',
                               return_value=False):
            # Must not raise.
            drv.delete_share(context=None, share=fakes.fake_share())


class TestEnsureSharesEdgeCases(test.TestCase):
    """Cover remaining branches in ensure_shares / _ensure_share."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_ensure_shares_propagates_list_failure(self):
        drv = self._make_driver()
        drv._client.list_filesystems.side_effect = weka_exc.WekaApiError(
            status_code=500, reason='api down')

        self.assertRaises(
            weka_exc.WekaApiError, drv.ensure_shares,
            None, [fakes.fake_share(proto='WEKAFS')])

    def test_ensure_share_nfs_falls_back_to_api_when_no_fs_by_name(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        fs = fakes.fake_filesystem()
        drv._client.get_filesystem_by_name.return_value = fs

        with mock.patch.object(weka_posix.WekaMount, 'is_mounted',
                               return_value=True):
            locations = drv._ensure_share(context=None, share=share,
                                          fs_by_name=None)

        self.assertGreater(len(locations), 0)
        drv._client.get_filesystem_by_name.assert_called()


class TestUpdateAccessEdgeCases(test.TestCase):
    """Cover remaining branches in update_access helpers."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_update_access_non_nfs_protocol_uses_wekafs_path(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule()

        with mock.patch.object(drv, '_update_wekafs_access') as mock_wekafs:
            mock_wekafs.return_value = {}
            result = drv.update_access(
                context=None, share=share,
                access_rules=[], add_rules=[rule], delete_rules=[],
                update_rules=[])

        mock_wekafs.assert_called_once()
        self.assertEqual({}, result)

    def test_update_nfs_access_delete_rule_exception_warns(self):
        drv = self._make_driver()
        rule = fakes.fake_access_rule()
        drv._client.list_nfs_permissions.return_value = []
        drv._client.list_client_groups.side_effect = Exception('api fail')

        share = fakes.fake_share(proto='NFS')
        # Must not raise — exception is only a warning.
        result = drv._update_nfs_access(share, [], [rule], False)

        self.assertEqual({}, result)

    def test_update_wekafs_access_user_already_exists_is_idempotent(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = mock.Mock()
        drv._client.for_org.return_value = org_client
        org_client.create_user.side_effect = weka_exc.WekaApiError(
            status_code=409,
            reason='User already exists')

        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule(access_type='user', access_to='weka')
        # Must not raise.
        result = drv.update_access(
            context=None, share=share,
            access_rules=[], add_rules=[rule], delete_rules=[],
            update_rules=[])

        self.assertEqual('active', result[rule['access_id']]['state'])

    def test_update_wekafs_access_create_user_other_error_reraises(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = mock.Mock()
        drv._client.for_org.return_value = org_client
        org_client.create_user.side_effect = weka_exc.WekaApiError(
            status_code=500,
            reason='internal server error')

        share = fakes.fake_share(proto='WEKAFS')
        rule = fakes.fake_access_rule(access_type='user', access_to='weka')
        self.assertRaises(
            weka_exc.WekaApiError,
            drv.update_access,
            None, share, [], [rule], [], [])


class TestDeleteClientGroupByName(test.TestCase):
    """Cover _delete_client_group_by_name (lines 1116-1117)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_delete_client_group_by_name_not_found_is_silent(self):
        drv = self._make_driver()
        cg = fakes.fake_client_group()
        drv._client.list_client_groups.return_value = [cg]
        drv._client.delete_client_group.side_effect = (
            weka_exc.WekaNotFound(reason='already gone'))

        # Must not raise.
        drv._delete_client_group_by_name(cg['name'])


class TestDeleteSnapshotEdgeCases(test.TestCase):
    """Cover WekaNotFound branch in delete_snapshot (lines 1262-1263)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_delete_snapshot_weka_not_found_swallowed(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        snap = fakes.fake_snapshot()
        drv._client.get_snapshot_by_name.return_value = snap
        drv._client.delete_snapshot.side_effect = (
            weka_exc.WekaNotFound(reason='already gone'))
        snap_model = fakes.fake_snapshot_model()

        # Must not raise.
        drv.delete_snapshot(context=None, snapshot=snap_model)


class TestManageExistingEdgeCases(test.TestCase):
    """Cover empty export_locations branch in manage_existing (line 1386)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_manage_existing_no_export_locations_raises(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS', export_locations=[])

        self.assertRaises(
            exception.ManageInvalidShare,
            drv.manage_existing, share, {},
        )
        drv._client.get_filesystem_by_name.assert_not_called()


class TestShareNameFromShare(test.TestCase):
    """Cover _share_name_from_share (line 1461)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_share_name_from_share_delegates_to_share_name(self):
        drv = self._make_driver()
        share = fakes.fake_share()
        result = drv._share_name_from_share(share)
        self.assertEqual(drv._share_name(share['id']), result)


class TestDerivePasswordEdgeCases(test.TestCase):
    """Cover _derive_password no-secret guard (line 1515)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_derive_password_raises_when_secret_is_none(self):
        drv = self._make_driver()
        drv._org_admin_secret = None

        self.assertRaises(
            weka_exc.WekaConfigurationError,
            drv._derive_password, 'proj-x')


class TestEnsureOrgEdgeCases(test.TestCase):
    """Cover _ensure_org already-exists branch (lines 1561-1563)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_ensure_org_create_conflict_is_idempotent(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = None
        drv._client.create_organization.side_effect = weka_exc.WekaApiError(
            status_code=409, reason='Organization already exists')

        # Must not raise; returns tuple.
        org_name, username, password = drv._ensure_org('proj-conflict')
        self.assertIn('proj', org_name)

    def test_ensure_org_create_other_error_raises_weka_org_error(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = None
        drv._client.create_organization.side_effect = weka_exc.WekaApiError(
            status_code=500, reason='internal error')

        self.assertRaises(
            weka_exc.WekaOrgError,
            drv._ensure_org, 'proj-error')


class TestOrgTokenFileEdgeCases(test.TestCase):
    """Cover OSError cleanup in _org_token_file (lines 1626-1651)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_org_token_file_oschmod_failure_is_ignored(self):
        drv = self._make_driver()
        tmpdir = tempfile.mkdtemp(prefix='weka-tok-test-')
        drv._auth_token_dir = tmpdir
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = mock.Mock()
        drv._client.for_org.return_value = org_client
        org_client.auth_token_payload.return_value = {
            'access_token': 'acc', 'refresh_token': 'ref',
            'token_type': 'Bearer'}
        try:
            with mock.patch('manila.share.drivers.weka.driver.os.chmod',
                            side_effect=OSError('permission denied')):
                path = drv._org_token_file('proj-uuid-5678')
            # File was still written despite chmod failure.
            self.assertTrue(os.path.exists(path))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_org_token_file_write_failure_cleans_up_tmp_and_raises(self):
        drv = self._make_driver()
        tmpdir = tempfile.mkdtemp(prefix='weka-tok-test-')
        drv._auth_token_dir = tmpdir
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = mock.Mock()
        drv._client.for_org.return_value = org_client
        # json.dump raises — simulates write failure.
        org_client.auth_token_payload.side_effect = OSError('write failed')
        try:
            self.assertRaises(
                weka_exc.WekaMountError,
                drv._org_token_file, 'proj-uuid-5678')
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_org_token_file_makedirs_oserror_raises_weka_mount_error(self):
        drv = self._make_driver()
        drv._auth_token_dir = '/tmp/weka-tok-test'
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = mock.Mock()
        drv._client.for_org.return_value = org_client
        org_client.auth_token_payload.return_value = {
            'access_token': 'acc', 'refresh_token': 'ref',
            'token_type': 'Bearer'}

        with mock.patch('manila.share.drivers.weka.driver.os.makedirs',
                        side_effect=OSError('permission denied')):
            self.assertRaises(
                weka_exc.WekaMountError,
                drv._org_token_file, 'proj-uuid-5678')


class TestGetFsUidForShareEdgeCases(test.TestCase):
    """Cover ORM-like metadata and managed-fs fallback (lines 1677-1711)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_get_fs_uid_from_orm_metadata_object(self):
        drv = self._make_driver()

        class FakeMeta:
            """Fake ORM metadata object with items() iterator."""

            def items(self):
                return [('weka_fs_uid', fakes.FAKE_FS_UID)]

        share = {
            'id': fakes.FAKE_SHARE_ID,
            'share_proto': 'WEKAFS',
            'project_id': fakes.FAKE_PROJECT_ID,
            'export_locations': [
                {'path': 'weka-host/fs', 'is_admin_only': False,
                 'metadata': FakeMeta()},
            ],
        }

        uid = drv._get_fs_uid_for_share(share)

        self.assertEqual(fakes.FAKE_FS_UID, uid)
        drv._client.get_filesystem_by_name.assert_not_called()

    def test_get_fs_uid_managed_share_custom_fs_name(self):
        drv = self._make_driver()
        # Managed share: filesystem name not manila_* but 'my-existing-fs'.
        custom_name = 'my-existing-fs'
        custom_fs = fakes.fake_filesystem(name=custom_name)
        # Standard manila name lookup misses, custom name hits.
        drv._client.get_filesystem_by_name.side_effect = (
            lambda n: custom_fs if n == custom_name else None)

        share = {
            'id': fakes.FAKE_SHARE_ID,
            'share_proto': 'NFS',
            'project_id': fakes.FAKE_PROJECT_ID,
            'export_locations': [
                {'path': 'nfs.host:/my-existing-fs',
                 'is_admin_only': False,
                 'metadata': {}},
            ],
        }

        uid = drv._get_fs_uid_for_share(share)

        self.assertEqual(fakes.FAKE_FS_UID, uid)

    def test_get_fs_uid_nfs_colon_path_stripped(self):
        drv = self._make_driver()
        custom_fs = fakes.fake_filesystem(name='the-fs')
        drv._client.get_filesystem_by_name.side_effect = (
            lambda n: custom_fs if n == 'the-fs' else None)

        share = {
            'id': fakes.FAKE_SHARE_ID,
            'share_proto': 'NFS',
            'project_id': fakes.FAKE_PROJECT_ID,
            'export_locations': [
                {'path': 'nfs.host:/the-fs',
                 'is_admin_only': False,
                 'metadata': {}},
            ],
        }

        uid = drv._get_fs_uid_for_share(share)

        self.assertEqual(fakes.FAKE_FS_UID, uid)


class TestCreateFilesystemIdempotentEdgeCases(test.TestCase):
    """Cover WekaConflict race and re-raise (lines 1757-1760)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_create_filesystem_conflict_race_returns_existing(self):
        drv = self._make_driver()
        fs = fakes.fake_filesystem()
        drv._client.get_filesystem_by_name.side_effect = [None, fs]
        drv._client.create_filesystem.side_effect = (
            weka_exc.WekaConflict(reason='already exists'))

        result = drv._create_filesystem_idempotent(
            fakes.FAKE_FS_NAME, 'default', 10 * 1024 ** 3)

        self.assertEqual(fs['uid'], result['uid'])

    def test_create_filesystem_conflict_race_reraises_if_still_missing(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None
        drv._client.create_filesystem.side_effect = (
            weka_exc.WekaConflict(reason='already exists'))

        self.assertRaises(
            weka_exc.WekaConflict,
            drv._create_filesystem_idempotent,
            fakes.FAKE_FS_NAME, 'default', 10 * 1024 ** 3)


class TestIsAlreadyExistsError(test.TestCase):
    """Cover _is_already_exists_error."""

    def test_weka_conflict_returns_true(self):
        exc = weka_exc.WekaConflict(reason='conflict')
        self.assertTrue(weka_driver._is_already_exists_error(exc))

    def test_non_api_error_returns_false(self):
        exc = Exception('Rule already exists in group')
        self.assertFalse(weka_driver._is_already_exists_error(exc))

    def test_already_exist_string_400_returns_true(self):
        exc = weka_exc.WekaApiError(
            status_code=400, reason='Rule already exists in group')
        self.assertTrue(weka_driver._is_already_exists_error(exc))

    def test_already_in_use_string_400_returns_true(self):
        exc = weka_exc.WekaApiError(
            status_code=400,
            reason='Could not create user: Username already in use.')
        self.assertTrue(weka_driver._is_already_exists_error(exc))

    def test_matching_phrase_wrong_status_returns_false(self):
        exc = weka_exc.WekaApiError(
            status_code=500, reason='backend already exists failure')
        self.assertFalse(weka_driver._is_already_exists_error(exc))

    def test_other_error_returns_false(self):
        exc = weka_exc.WekaApiError(
            status_code=400, reason='permission denied')
        self.assertFalse(weka_driver._is_already_exists_error(exc))


class TestCheckForSetupErrorIOError(test.TestCase):
    """Cover IOError branch when /proc/filesystems can't be read (322-323)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        return drv

    def test_ioerror_reading_proc_fs_silenced_warns_about_wekafs(self):
        drv = self._make_driver()
        drv._client.get_cluster_status.return_value = {}
        with mock.patch('builtins.open',
                        side_effect=IOError('permission denied')):
            # Must not raise; missing /proc/filesystems is a warning.
            drv.check_for_setup_error()


class TestCopySnapshotNfsNfsServerGuard(test.TestCase):
    """Cover defensive guard line 545 in _copy_snapshot_nfs."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config(weka_nfs_server=None)
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        drv._async_copies = {}
        drv._async_copies_lock = threading.Lock()
        drv._nfs_server = None
        _wire_org(drv)
        return drv

    def test_copy_snapshot_nfs_raises_when_no_nfs_server(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS',
                                 share_id=fakes.FAKE_NEW_SHARE_ID)
        self.assertRaises(
            exception.ManilaException,
            drv._copy_snapshot_nfs,
            share, fakes.fake_snapshot_model(),
            fakes.fake_snapshot(),
            fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)


class TestCopySnapshotNfsCleanupBranches(test.TestCase):
    """Cover exception-swallowed branches in _copy_snapshot_nfs cleanup."""

    NFS_SERVER = 'nfs.example.com'

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config(weka_nfs_server=self.NFS_SERVER)
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        drv._async_copies = {}
        drv._async_copies_lock = threading.Lock()
        drv._nfs_server = self.NFS_SERVER
        _wire_org(drv)
        return drv

    def _new_share(self):
        return fakes.fake_share(
            share_id=fakes.FAKE_NEW_SHARE_ID, proto='NFS')

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_rmdir_exception_swallowed_on_success(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        cg = fakes.fake_client_group()
        drv._client.create_client_group.return_value = cg
        drv._client.add_client_group_rule.return_value = {
            'uid': fakes.FAKE_CG_RULE_UID}
        drv._client.list_nfs_permissions.return_value = []
        mock_socket.return_value.getsockname.return_value = ('192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        # rmdir raises — must be swallowed.
        mock_rmdir.side_effect = OSError('busy')
        snap = fakes.fake_snapshot()

        # Must not raise.
        drv._copy_snapshot_nfs(
            self._new_share(), fakes.fake_snapshot_model(),
            snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

    @mock.patch(_PATCH_SLEEP)
    @mock.patch(_PATCH_SOCKET)
    @mock.patch(_PATCH_RMDIR)
    @mock.patch(_PATCH_MKDTEMP)
    @mock.patch(_PATCH_RSYNC)
    @mock.patch(_PATCH_UMOUNT)
    @mock.patch(_PATCH_NFS_MOUNT)
    def test_delete_cg_rule_exception_swallowed(
            self, mock_nfs_mount, mock_umount, mock_rsync,
            mock_mkdtemp, mock_rmdir, mock_socket, mock_sleep):
        drv = self._make_driver()
        cg = fakes.fake_client_group()
        drv._client.create_client_group.return_value = cg
        drv._client.add_client_group_rule.return_value = {
            'uid': fakes.FAKE_CG_RULE_UID}
        drv._client.list_nfs_permissions.return_value = []
        # Make delete_client_group_rule raise — must be swallowed.
        drv._client.delete_client_group_rule.side_effect = Exception(
            'delete rule error')
        mock_socket.return_value.getsockname.return_value = ('192.0.2.1', 0)
        mock_mkdtemp.side_effect = ['/tmp/snap_src', '/tmp/snap_dst']
        snap = fakes.fake_snapshot()

        # Must not raise.
        drv._copy_snapshot_nfs(
            self._new_share(), fakes.fake_snapshot_model(),
            snap, fakes.FAKE_FS_NAME, fakes.FAKE_NEW_FS_NAME)

        drv._client.delete_client_group_rule.assert_called_once()


class TestUpdateNfsAccessDeleteRuleWarning(test.TestCase):
    """Cover delete_rules exception warning (lines 1016-1017)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_delete_rule_exception_is_a_warning_not_an_error(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule()
        # _remove_nfs_rule itself calls list_nfs_permissions; make it raise.
        drv._client.list_nfs_permissions.side_effect = Exception('api fail')

        # Must not raise.
        result = drv._update_nfs_access(share, [], [rule], False)
        self.assertEqual({}, result)


class TestApplyNfsRuleInvalidIp(test.TestCase):
    """Cover _apply_nfs_rule ValueError branch (lines 1041-1042)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_apply_nfs_rule_invalid_ip_raises_invalid_share_access(self):
        drv = self._make_driver()
        share = fakes.fake_share(proto='NFS')
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='not-an-ip/24')
        drv._client.list_client_groups.return_value = []

        self.assertRaises(
            exception.InvalidShareAccess,
            drv._apply_nfs_rule, share,
            fakes.FAKE_FS_NAME, rule)


class TestOrgTokenFileUnlinkFailure(test.TestCase):
    """Cover os.unlink OSError in _org_token_file (lines 1646-1647)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_org_token_file_unlink_oserror_swallowed_reraises_write_error(
            self):
        drv = self._make_driver()
        tmpdir = tempfile.mkdtemp(prefix='weka-tok-test-')
        drv._auth_token_dir = tmpdir
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org_client = mock.Mock()
        drv._client.for_org.return_value = org_client
        org_client.auth_token_payload.return_value = {
            'access_token': 'acc', 'refresh_token': 'ref',
            'token_type': 'Bearer'}
        try:
            real_fdopen = os.fdopen

            def fake_fdopen(fd, mode):
                """Return a file that raises OSError on write."""
                class _BadFile:
                    def __enter__(self):
                        return self

                    def __exit__(self, *a):
                        return False

                    def write(self, data):
                        raise OSError('disk full')

                real_fdopen(fd, mode).close()
                return _BadFile()

            with mock.patch('manila.share.drivers.weka.driver.os.fdopen',
                            side_effect=fake_fdopen):
                with mock.patch(
                        'manila.share.drivers.weka.driver.os.unlink',
                        side_effect=OSError('unlink failed')):
                    self.assertRaises(
                        weka_exc.WekaMountError,
                        drv._org_token_file, 'proj-uuid-5678')
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestGetFsUidOrmAndPathEdgeCases(test.TestCase):
    """Cover ORM loc TypeError and no-slash colon path (1683-1684, 1707)."""

    def _make_driver(self):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config()
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        _wire_org(drv)
        return drv

    def test_get_fs_uid_orm_meta_attribute_error_skipped(self):
        drv = self._make_driver()

        class BadMeta:
            """Metadata object whose .items() raises AttributeError."""

            def get(self, key, default=None):
                return None

            def items(self):
                raise AttributeError('no items')

        # Standard name lookup hits.
        drv._client.get_filesystem_by_name.return_value = (
            fakes.fake_filesystem())
        share = {
            'id': fakes.FAKE_SHARE_ID,
            'share_proto': 'NFS',
            'project_id': fakes.FAKE_PROJECT_ID,
            'export_locations': [
                {'path': 'host/fs', 'is_admin_only': False,
                 'metadata': BadMeta()},
            ],
        }

        uid = drv._get_fs_uid_for_share(share)
        self.assertEqual(fakes.FAKE_FS_UID, uid)

    def test_get_fs_uid_path_no_slash_with_colon_stripped(self):
        drv = self._make_driver()
        custom_fs = fakes.fake_filesystem(name='the-fs')
        # First call: standard name miss; second call: custom name hit.
        drv._client.get_filesystem_by_name.side_effect = (
            lambda n: custom_fs if n == 'the-fs' else None)

        # path has no slash so candidate = full path; has colon → strip.
        share = {
            'id': fakes.FAKE_SHARE_ID,
            'share_proto': 'NFS',
            'project_id': fakes.FAKE_PROJECT_ID,
            'export_locations': [
                {'path': 'nfs.host:the-fs',
                 'is_admin_only': False,
                 'metadata': {}},
            ],
        }

        uid = drv._get_fs_uid_for_share(share)
        self.assertEqual(fakes.FAKE_FS_UID, uid)

    def test_get_fs_uid_orm_loc_attribute_error_on_path(self):
        drv = self._make_driver()
        drv._client.get_filesystem_by_name.return_value = None

        class BadLoc:
            """ORM-like loc whose .path property raises TypeError."""

            @property
            def path(self):
                raise TypeError('descriptor error')

        share = {
            'id': fakes.FAKE_SHARE_ID,
            'share_proto': 'NFS',
            'project_id': fakes.FAKE_PROJECT_ID,
            'export_locations': [BadLoc()],
        }

        self.assertRaises(
            exception.ShareNotFound,
            drv._get_fs_uid_for_share, share)


_SPEC_PATCH = (
    'manila.share.drivers.weka.driver.share_types.'
    'get_share_type_extra_specs')


class TestWekaShareDriverSecurityPolicies(test.TestCase):
    """WEKAFS per-share access via security policies (Model A + Model B)."""

    def _make_driver(self, **cfg):
        drv = weka_driver.WekaShareDriver.__new__(weka_driver.WekaShareDriver)
        drv.configuration = _make_config(**cfg)
        drv._client = mock.Mock()
        drv._fs_group_uid = fakes.FAKE_GROUP_UID
        drv._policy_groups = {}
        _wire_org(drv)
        return drv

    def _org_client(self, drv):
        org_client = mock.Mock()
        drv._client.for_org.return_value = org_client
        return org_client

    def _ip_rule(self, ip='10.0.0.1', level='rw'):
        return fakes.fake_access_rule(
            access_type='ip', access_to=ip, access_level=level)

    def test_apply_ip_rule_adds_to_existing_policy(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        existing = fakes.fake_security_policy(
            name='manila-share-uu-rw', ips=['10.0.0.9'])
        org.get_security_policy_by_name.side_effect = (
            lambda name: existing if name.endswith('-rw') else None)

        share = fakes.fake_share(proto='WEKAFS')
        drv.update_access(None, share, [], [self._ip_rule()], [], [])

        _, kwargs = org.update_security_policy.call_args
        self.assertEqual(['10.0.0.1'], kwargs['add_ips'])
        org.attach_fs_security_policies.assert_called_with(
            fakes.FAKE_FS_UID, [fakes.FAKE_POLICY_UID])
        org.create_security_policy.assert_not_called()

    def test_apply_ip_rule_already_present_no_update(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        existing = fakes.fake_security_policy(
            name='manila-share-uu-rw', ips=['10.0.0.1'])
        org.get_security_policy_by_name.side_effect = (
            lambda name: existing if name.endswith('-rw') else None)

        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [],
            [self._ip_rule()], [], [])

        org.update_security_policy.assert_not_called()
        org.attach_fs_security_policies.assert_called_once()

    def test_apply_ip_rule_level_change_removes_from_other(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.create_security_policy.return_value = fakes.fake_security_policy()
        ro_pol = fakes.fake_security_policy(
            name='manila-share-uu-ro', ips=['10.0.0.1'], uid='pol-ro')

        def by_name(name):
            return None if name.endswith('-rw') else ro_pol
        org.get_security_policy_by_name.side_effect = by_name

        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [],
            [self._ip_rule(level='rw')], [], [])

        # New rw policy created; the ip removed from the ro policy, which
        # then becomes empty and is detached + deleted.
        org.create_security_policy.assert_called_once()
        org.delete_security_policy.assert_called_once_with('pol-ro')

    def test_apply_ip_rule_fs_missing_skips_attach(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = None
        org.get_security_policy_by_name.return_value = None
        org.create_security_policy.return_value = fakes.fake_security_policy()

        result = drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [],
            [self._ip_rule()], [], [])

        self.assertEqual(
            'active', result[list(result)[0]]['state'])
        org.create_security_policy.assert_called_once()
        org.attach_fs_security_policies.assert_not_called()

    def test_apply_ip_rule_error_sets_error_state(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.get_security_policy_by_name.return_value = None
        org.create_security_policy.side_effect = weka_exc.WekaApiError(
            status_code=500, reason='boom')

        rule = self._ip_rule()
        result = drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [rule], [], [])
        self.assertEqual('error', result[rule['access_id']]['state'])

    def test_apply_ip_rule_add_ip_conflict_tolerated(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        existing = fakes.fake_security_policy(
            name='manila-share-uu-rw', ips=['10.0.0.9'])
        org.get_security_policy_by_name.side_effect = (
            lambda name: existing if name.endswith('-rw') else None)
        org.update_security_policy.side_effect = weka_exc.WekaConflict(
            reason='already exists')

        rule = self._ip_rule()
        result = drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [rule], [], [])
        self.assertEqual('active', result[rule['access_id']]['state'])

    def test_apply_ip_rule_attach_conflict_tolerated(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.get_security_policy_by_name.return_value = None
        org.create_security_policy.return_value = fakes.fake_security_policy()
        org.attach_fs_security_policies.side_effect = weka_exc.WekaConflict(
            reason='already attached')

        rule = self._ip_rule()
        result = drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [rule], [], [])
        self.assertEqual('active', result[rule['access_id']]['state'])

    def test_apply_ip_rule_attach_other_error_sets_error(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.get_security_policy_by_name.return_value = None
        org.create_security_policy.return_value = fakes.fake_security_policy()
        org.attach_fs_security_policies.side_effect = weka_exc.WekaApiError(
            status_code=500, reason='nope')

        rule = self._ip_rule()
        result = drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [rule], [], [])
        self.assertEqual('error', result[rule['access_id']]['state'])

    def test_delete_ip_rule_empties_and_deletes_policies(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        rw = fakes.fake_security_policy(
            name='manila-share-uu-rw', ips=['10.0.0.1'], uid='pol-rw')
        ro = fakes.fake_security_policy(
            name='manila-share-uu-ro', ips=['10.0.0.1'], uid='pol-ro')
        org.get_security_policy_by_name.side_effect = (
            lambda name: rw if name.endswith('-rw') else ro)

        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [],
            [self._ip_rule()])

        self.assertEqual(2, org.delete_security_policy.call_count)
        self.assertEqual(2, org.detach_fs_security_policies.call_count)

    def test_delete_ip_rule_keeps_nonempty_policy(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        rw = fakes.fake_security_policy(
            name='manila-share-uu-rw', ips=['10.0.0.1', '10.0.0.2'])
        org.get_security_policy_by_name.side_effect = (
            lambda name: rw if name.endswith('-rw') else None)

        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [],
            [self._ip_rule()])

        org.update_security_policy.assert_called_once()
        org.delete_security_policy.assert_not_called()

    def test_delete_ip_rule_ip_absent_noop(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        rw = fakes.fake_security_policy(
            name='manila-share-uu-rw', ips=['10.0.0.2'])
        org.get_security_policy_by_name.side_effect = (
            lambda name: rw if name.endswith('-rw') else None)

        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [],
            [self._ip_rule()])

        org.update_security_policy.assert_not_called()
        org.delete_security_policy.assert_not_called()

    def test_delete_non_ip_rule_is_noop(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        rule = fakes.fake_access_rule(access_type='user', access_to='bob')
        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [], [rule])
        org.get_security_policy_by_name.assert_not_called()

    def test_delete_ipv6_ip_rule_is_noop(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        rule = fakes.fake_access_rule(
            access_type='ip', access_to='2001:db8::1')
        # Must not raise.
        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [], [rule])
        org.get_security_policy_by_name.assert_not_called()
        org.delete_security_policy.assert_not_called()

    def test_update_access_group_share_is_noop_active(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        share = fakes.fake_share(proto='WEKAFS', share_type_id='st-1')
        rule = self._ip_rule()
        with mock.patch(_SPEC_PATCH,
                        return_value={'weka:security_policy_group': 'team-a'}):
            result = drv.update_access(None, share, [], [rule], [], [])
        entry = result[rule['access_id']]
        self.assertEqual('active', entry['state'])
        self.assertEqual(
            drv._org_mount_password(share['project_id']),
            entry['access_key'])
        org.create_security_policy.assert_not_called()
        org.get_filesystem_by_name.assert_not_called()

    def test_create_share_attaches_group_policies(self):
        drv = self._make_driver()
        drv._policy_groups = {
            'team-a': {'rw': ['10.0.1.0/24'], 'ro': ['10.0.9.0/24']}}
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = None
        org.create_filesystem.return_value = fakes.fake_filesystem()
        org.get_security_policy_by_name.return_value = None
        org.create_security_policy.return_value = fakes.fake_security_policy()

        share = fakes.fake_share(proto='WEKAFS', share_type_id='st-1')
        with mock.patch(_SPEC_PATCH,
                        return_value={'weka:security_policy_group': 'team-a'}):
            drv.create_share(None, share)

        self.assertEqual(2, org.create_security_policy.call_count)
        self.assertEqual(2, org.attach_fs_security_policies.call_count)
        names = [c.args[0] for c in org.create_security_policy.call_args_list]
        self.assertIn('manila-grp-team-a-rw', names)
        self.assertIn('manila-grp-team-a-ro', names)

    def test_create_share_group_reuses_existing_policy(self):
        drv = self._make_driver()
        drv._policy_groups = {'team-a': {'rw': ['10.0.1.0/24']}}
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = None
        org.create_filesystem.return_value = fakes.fake_filesystem()
        org.get_security_policy_by_name.return_value = (
            fakes.fake_security_policy(name='manila-grp-team-a-rw'))

        share = fakes.fake_share(proto='WEKAFS', share_type_id='st-1')
        with mock.patch(_SPEC_PATCH,
                        return_value={'weka:security_policy_group': 'team-a'}):
            drv.create_share(None, share)

        org.create_security_policy.assert_not_called()
        org.attach_fs_security_policies.assert_called_once()

    def test_create_share_unknown_group_no_attach(self):
        drv = self._make_driver()
        drv._policy_groups = {}  # team-a not defined
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = None
        org.create_filesystem.return_value = fakes.fake_filesystem()

        share = fakes.fake_share(proto='WEKAFS', share_type_id='st-1')
        with mock.patch(_SPEC_PATCH,
                        return_value={'weka:security_policy_group': 'team-a'}):
            drv.create_share(None, share)

        org.create_security_policy.assert_not_called()
        org.attach_fs_security_policies.assert_not_called()

    def test_parse_policy_groups_valid(self):
        g = weka_driver.WekaShareDriver._parse_policy_groups(
            'team-a:rw:10.0.1.0/24,10.0.2.0/24; team-a:ro:10.0.9.0/24; '
            'team-b:rw:10.1.0.0/16')
        self.assertEqual(
            {'rw': ['10.0.1.0/24', '10.0.2.0/24'], 'ro': ['10.0.9.0/24']},
            g['team-a'])
        self.assertEqual({'rw': ['10.1.0.0/16']}, g['team-b'])

    def test_parse_policy_groups_skips_malformed_and_empty(self):
        g = weka_driver.WekaShareDriver._parse_policy_groups(
            ' ; bad-entry ; team-a:rw:10.0.0.0/24')
        self.assertEqual({'team-a': {'rw': ['10.0.0.0/24']}}, g)

    def test_parse_policy_groups_skips_bad_level_and_empty_group(self):
        g = weka_driver.WekaShareDriver._parse_policy_groups(
            'team-a:xx:10.0.0.0/24; :rw:10.0.0.0/24')
        self.assertEqual({}, g)

    def test_parse_policy_groups_none_and_blank(self):
        self.assertEqual(
            {}, weka_driver.WekaShareDriver._parse_policy_groups(None))
        self.assertEqual(
            {}, weka_driver.WekaShareDriver._parse_policy_groups(''))

    def test_share_policy_group_no_type_id(self):
        drv = self._make_driver()
        self.assertIsNone(
            drv._share_policy_group({'id': 's', 'share_type_id': None}))

    def test_share_policy_group_specs_exception(self):
        drv = self._make_driver()
        with mock.patch(_SPEC_PATCH, side_effect=Exception('boom')):
            self.assertIsNone(
                drv._share_policy_group({'id': 's', 'share_type_id': 't'}))

    def test_share_policy_group_present_and_absent(self):
        drv = self._make_driver()
        with mock.patch(_SPEC_PATCH,
                        return_value={'weka:security_policy_group': 'team-a'}):
            self.assertEqual(
                'team-a',
                drv._share_policy_group({'id': 's', 'share_type_id': 't'}))
        with mock.patch(_SPEC_PATCH, return_value={}):
            self.assertIsNone(
                drv._share_policy_group({'id': 's', 'share_type_id': 't'}))

    def _delete_share(self, drv):
        with mock.patch.object(weka_posix.WekaMount, 'is_mounted',
                               return_value=False):
            drv.delete_share(None, fakes.fake_share(proto='WEKAFS'))

    def test_delete_share_cleans_up_per_share_policies(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.list_nfs_permissions.return_value = []
        org.get_security_policy_by_name.return_value = (
            fakes.fake_security_policy())

        self._delete_share(drv)

        self.assertEqual(2, org.detach_fs_security_policies.call_count)
        self.assertEqual(2, org.delete_security_policy.call_count)

    def test_delete_share_policy_absent_skips(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.list_nfs_permissions.return_value = []
        org.get_security_policy_by_name.return_value = None

        self._delete_share(drv)

        org.delete_security_policy.assert_not_called()

    def test_delete_share_policy_delete_notfound_tolerated(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.list_nfs_permissions.return_value = []
        org.get_security_policy_by_name.return_value = (
            fakes.fake_security_policy())
        org.delete_security_policy.side_effect = weka_exc.WekaNotFound(
            reason='gone')

        self._delete_share(drv)  # must not raise
        org.delete_filesystem.assert_called_once()

    def test_delete_share_policy_delete_other_error_warns(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.list_nfs_permissions.return_value = []
        org.get_security_policy_by_name.return_value = (
            fakes.fake_security_policy())
        org.delete_security_policy.side_effect = weka_exc.WekaApiError(
            status_code=500, reason='boom')

        self._delete_share(drv)  # warning only, no raise
        org.delete_filesystem.assert_called_once()

    def test_delete_share_policy_get_raises_continues(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.list_nfs_permissions.return_value = []
        org.get_security_policy_by_name.side_effect = Exception('boom')

        self._delete_share(drv)  # must not raise
        org.delete_security_policy.assert_not_called()

    def test_delete_share_cleanup_error_is_warned(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.list_nfs_permissions.return_value = []

        with mock.patch.object(drv, '_cleanup_wekafs_policies',
                               side_effect=Exception('boom')):
            self._delete_share(drv)  # outer try/except swallows it

        org.delete_filesystem.assert_called_once()

    def test_apply_ip_rule_add_ip_other_error_sets_error(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        existing = fakes.fake_security_policy(
            name='manila-share-uu-rw', ips=['10.0.0.9'])
        org.get_security_policy_by_name.side_effect = (
            lambda name: existing if name.endswith('-rw') else None)
        org.update_security_policy.side_effect = weka_exc.WekaApiError(
            status_code=500, reason='boom')

        rule = self._ip_rule()
        result = drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [rule], [], [])
        self.assertEqual('error', result[rule['access_id']]['state'])

    def test_delete_ip_rule_remove_raises_is_warned(self):
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.get_security_policy_by_name.side_effect = Exception('boom')

        # Must not raise; the delete loop logs a warning and continues.
        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [],
            [self._ip_rule()])

    def _delete_single_policy_org(self, drv, **policy_kwargs):
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        rw = fakes.fake_security_policy(
            name='manila-share-uu-rw', ips=['10.0.0.1'], **policy_kwargs)
        org.get_security_policy_by_name.side_effect = (
            lambda name: rw if name.endswith('-rw') else None)
        return org

    def test_delete_ip_rule_remove_notfound_tolerated(self):
        drv = self._make_driver()
        org = self._delete_single_policy_org(drv)
        org.update_security_policy.side_effect = weka_exc.WekaNotFound(
            reason='gone')

        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [],
            [self._ip_rule()])

        # IP still computed as removed -> policy empty -> deleted.
        org.delete_security_policy.assert_called_once()

    def test_delete_ip_rule_detach_error_tolerated(self):
        drv = self._make_driver()
        org = self._delete_single_policy_org(drv)
        org.detach_fs_security_policies.side_effect = weka_exc.WekaApiError(
            status_code=500, reason='boom')

        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [],
            [self._ip_rule()])

        org.delete_security_policy.assert_called_once()

    def test_delete_ip_rule_delete_notfound_tolerated(self):
        drv = self._make_driver()
        org = self._delete_single_policy_org(drv)
        org.delete_security_policy.side_effect = weka_exc.WekaNotFound(
            reason='gone')

        # Must not raise.
        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [],
            [self._ip_rule()])

    def _group_create_share(self, drv):
        drv._policy_groups = {'team-a': {'rw': ['10.0.1.0/24']}}
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = None
        org.create_filesystem.return_value = fakes.fake_filesystem()
        org.get_security_policy_by_name.return_value = None
        org.create_security_policy.return_value = fakes.fake_security_policy()
        return org

    def test_create_share_group_attach_conflict_tolerated(self):
        drv = self._make_driver()
        org = self._group_create_share(drv)
        org.attach_fs_security_policies.side_effect = weka_exc.WekaConflict(
            reason='already attached')

        share = fakes.fake_share(proto='WEKAFS', share_type_id='st-1')
        with mock.patch(_SPEC_PATCH,
                        return_value={'weka:security_policy_group': 'team-a'}):
            drv.create_share(None, share)  # must not raise

        org.create_filesystem.assert_called_once()

    def test_create_share_group_attach_other_error_propagates(self):
        drv = self._make_driver()
        org = self._group_create_share(drv)
        org.attach_fs_security_policies.side_effect = weka_exc.WekaApiError(
            status_code=500, reason='boom')

        share = fakes.fake_share(proto='WEKAFS', share_type_id='st-1')
        with mock.patch(_SPEC_PATCH,
                        return_value={'weka:security_policy_group': 'team-a'}):
            self.assertRaises(
                weka_exc.WekaApiError, drv.create_share, None, share)

    def test_delete_share_policy_detach_error_tolerated(self):
        drv = self._make_driver()
        drv._client.get_organization_by_name.return_value = (
            fakes.fake_organization())
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.list_nfs_permissions.return_value = []
        org.get_security_policy_by_name.return_value = (
            fakes.fake_security_policy())
        org.detach_fs_security_policies.side_effect = Exception('boom')

        self._delete_share(drv)  # detach error tolerated, delete proceeds
        self.assertEqual(2, org.delete_security_policy.call_count)

    def test_policy_ip_normalization(self):
        self.assertEqual(
            '10.0.1.0/24', weka_driver._policy_ip('10.0.1.0/24'))
        self.assertEqual('0.0.0.0/0', weka_driver._policy_ip('0.0.0.0/0'))
        self.assertEqual('192.0.2.1', weka_driver._policy_ip('192.0.2.1'))
        # host bits are stripped to the network form.
        self.assertEqual(
            '10.0.1.0/24', weka_driver._policy_ip('10.0.1.5/24'))
        # A malformed CIDR still raises; bare addresses are validated by
        # manila's API before they reach the driver.
        self.assertRaises(ValueError, weka_driver._policy_ip, 'notanip/24')

    def test_apply_cidr_ip_rule_uses_prefix_notation(self):
        # A CIDR rule must reach the security-policy API in prefix form
        # (10.0.1.0/24), NOT the NFS dotted-mask form (10.0.1.0/255...).
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.get_security_policy_by_name.return_value = None
        org.create_security_policy.return_value = (
            fakes.fake_security_policy())

        rule = self._ip_rule(ip='10.0.1.0/24')
        drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [rule], [], [])

        _, kwargs = org.create_security_policy.call_args
        self.assertEqual(['10.0.1.0/24'], kwargs['ips'])

    def test_is_already_attached_error(self):
        self.assertTrue(weka_driver._is_already_attached_error(
            weka_exc.WekaApiError(
                status_code=500,
                reason='.../securityPolicy/attach: Cannot add a security '
                       'policy that is already present in the list')))
        self.assertFalse(weka_driver._is_already_attached_error(
            weka_exc.WekaApiError(status_code=500, reason='other error')))
        self.assertFalse(
            weka_driver._is_already_attached_error(ValueError('x')))

    def test_apply_ip_rule_attach_already_present_tolerated(self):
        # A second IP at the same level reuses one policy, so the driver
        # re-attaches it; Weka returns a 500 "already present" which must
        # be tolerated (rule stays active).
        drv = self._make_driver()
        org = self._org_client(drv)
        org.get_filesystem_by_name.return_value = fakes.fake_filesystem()
        org.get_security_policy_by_name.return_value = None
        org.create_security_policy.return_value = (
            fakes.fake_security_policy())
        org.attach_fs_security_policies.side_effect = weka_exc.WekaApiError(
            status_code=500,
            reason='securityPolicy/attach: Cannot add a security policy '
                   'that is already present in the list')

        rule = self._ip_rule()
        result = drv.update_access(
            None, fakes.fake_share(proto='WEKAFS'), [], [rule], [], [])
        self.assertEqual('active', result[rule['access_id']]['state'])

    def test_group_attach_already_present_tolerated(self):
        drv = self._make_driver()
        org = self._group_create_share(drv)
        org.attach_fs_security_policies.side_effect = weka_exc.WekaApiError(
            status_code=500,
            reason='securityPolicy/attach: Cannot add a security policy '
                   'that is already present in the list')

        share = fakes.fake_share(proto='WEKAFS', share_type_id='st-1')
        with mock.patch(_SPEC_PATCH,
                        return_value={'weka:security_policy_group': 'team-a'}):
            drv.create_share(None, share)  # must not raise
        org.create_filesystem.assert_called_once()
