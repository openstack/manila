# Copyright 2012 NetApp
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
"""Unit tests for the LVM driver module."""

import os

import ddt
import mock
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_utils import timeutils

from manila.common import constants as const
from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers import lvm
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_utils
from manila.tests.share.drivers import test_generic


CONF = cfg.CONF


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


def fake_snapshot(**kwargs):
    snapshot = {
        'id': 'fakesnapshotid',
        'share_name': 'fakename',
        'share_id': 'fakeid',
        'name': 'fakesnapshotname',
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
        'share': {
            'id': 'fakeid',
            'name': 'fakename',
            'size': 1,
            'share_proto': 'NFS',
        },
    }
    snapshot.update(kwargs)
    return db_fakes.FakeModel(snapshot)


def fake_access(**kwargs):
    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.2',
        'access_level': 'rw',
        'state': 'active',
    }
    access.update(kwargs)
    return db_fakes.FakeModel(access)


@ddt.ddt
class LVMShareDriverTestCase(test.TestCase):
    """Tests LVMShareDriver."""

    def setUp(self):
        super(LVMShareDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self)
        self._context = context.get_admin_context()

        CONF.set_default('lvm_share_volume_group', 'fakevg')
        CONF.set_default('lvm_share_export_ips', ['10.0.0.1', '10.0.0.2'])
        CONF.set_default('driver_handles_share_servers', False)
        CONF.set_default('reserved_share_percentage', 50)

        self._helper_cifs = mock.Mock()
        self._helper_nfs = mock.Mock()
        self.fake_conf = configuration.Configuration(None)
        self._db = mock.Mock()
        self._os = lvm.os = mock.Mock()
        self._os.path.join = os.path.join
        self._driver = lvm.LVMShareDriver(self._db,
                                          configuration=self.fake_conf)
        self._driver._helpers = {
            'CIFS': self._helper_cifs,
            'NFS': self._helper_nfs,
        }

        self.share = fake_share()
        self.access = fake_access()
        self.snapshot = fake_snapshot()
        self.server = {
            'public_addresses': self.fake_conf.lvm_share_export_ips,
            'instance_id': 'LVM',
            'lock_name': 'manila_lvm',
        }

        # Used only to test compatibility with share manager
        self.share_server = "fake_share_server"

    def tearDown(self):
        super(LVMShareDriverTestCase, self).tearDown()
        fake_utils.fake_execute_set_repliers([])
        fake_utils.fake_execute_clear_log()

    def test_do_setup(self):
        CONF.set_default('lvm_share_helpers', ['NFS=fakenfs'])
        lvm.importutils = mock.Mock()
        lvm.importutils.import_class.return_value = self._helper_nfs
        self._driver.do_setup(self._context)
        lvm.importutils.import_class.assert_has_calls([
            mock.call('fakenfs')
        ])

    def test_check_for_setup_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake1\n   fakevg\n   fake2\n', ''

        expected_exec = ['vgs --noheadings -o name']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self._driver.check_for_setup_error()
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_check_for_setup_error_no_vg(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake0\n   fake1\n   fake2\n', ''

        fake_utils.fake_execute_set_repliers([('vgs --noheadings -o name',
                                               exec_runner)])
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_deprecated_export_ip(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake1\n   fakevg\n   fake2\n', ''

        fake_utils.fake_execute_set_repliers([('vgs --noheadings -o name',
                                               exec_runner)])
        CONF.set_default('lvm_share_export_ip', CONF.lvm_share_export_ips[0])
        CONF.set_default('lvm_share_export_ips', None)
        self.assertIsNone(self._driver.check_for_setup_error())

    def test_check_for_setup_error_no_export_ips(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake1\n   fakevg\n   fake2\n', ''

        fake_utils.fake_execute_set_repliers([('vgs --noheadings -o name',
                                               exec_runner)])
        CONF.set_default('lvm_share_export_ips', None)
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_both_export_ip_and_ips(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake1\n   fakevg\n   fake2\n', ''

        fake_utils.fake_execute_set_repliers([('vgs --noheadings -o name',
                                               exec_runner)])
        CONF.set_default('lvm_share_export_ip', CONF.lvm_share_export_ips[0])
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test_local_path_normal(self):
        share = fake_share(name='fake_sharename')
        CONF.set_default('lvm_share_volume_group', 'fake_vg')
        ret = self._driver._get_local_path(share)
        self.assertEqual('/dev/mapper/fake_vg-fake_sharename', ret)

    def test_local_path_escapes(self):
        share = fake_share(name='fake-sharename')
        CONF.set_default('lvm_share_volume_group', 'fake-vg')
        ret = self._driver._get_local_path(share)
        self.assertEqual('/dev/mapper/fake--vg-fake--sharename', ret)

    def test_create_share(self):
        CONF.set_default('lvm_share_mirrors', 0)
        self._driver._mount_device = mock.Mock()

        ret = self._driver.create_share(self._context, self.share,
                                        self.share_server)

        self._driver._mount_device.assert_called_with(
            self.share, '/dev/mapper/fakevg-fakename')
        expected_exec = [
            'lvcreate -L 1G -n fakename fakevg',
            'mkfs.ext4 /dev/mapper/fakevg-fakename',
        ]
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertEqual(self._helper_nfs.create_exports.return_value, ret)

    def test_create_share_from_snapshot(self):
        CONF.set_default('lvm_share_mirrors', 0)
        self._driver._mount_device = mock.Mock()
        snapshot_instance = {
            'snapshot_id': 'fakesnapshotid',
            'name': 'fakename'
        }
        mount_share = '/dev/mapper/fakevg-fakename'
        mount_snapshot = '/dev/mapper/fakevg-fakename'
        self._helper_nfs.create_export.return_value = 'fakelocation'
        self._driver.create_share_from_snapshot(self._context,
                                                self.share,
                                                snapshot_instance,
                                                self.share_server)

        self._driver._mount_device.assert_called_with(self.share,
                                                      mount_snapshot)
        expected_exec = [
            'lvcreate -L 1G -n fakename fakevg',
            'mkfs.ext4 /dev/mapper/fakevg-fakename',
            'e2fsck -y -f %s' % mount_share,
            'tune2fs -U random %s' % mount_share,
            ("dd count=0 if=%s of=%s iflag=direct oflag=direct" %
             (mount_snapshot, mount_share)),
            ("dd if=%s of=%s count=1024 bs=1M iflag=direct oflag=direct" %
             (mount_snapshot, mount_share)),
        ]
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_create_share_mirrors(self):
        share = fake_share(size='2048')
        CONF.set_default('lvm_share_mirrors', 2)
        self._driver._mount_device = mock.Mock()

        ret = self._driver.create_share(self._context, share,
                                        self.share_server)

        self._driver._mount_device.assert_called_with(
            share, '/dev/mapper/fakevg-fakename')
        expected_exec = [
            'lvcreate -L 2048G -n fakename fakevg -m 2 --nosync -R 2',
            'mkfs.ext4 /dev/mapper/fakevg-fakename',
        ]
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertEqual(self._helper_nfs.create_exports.return_value, ret)

    def test_deallocate_container(self):
        expected_exec = ['lvremove -f fakevg/fakename']
        self._driver._deallocate_container(self.share['name'])
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_deallocate_container_error(self):
        def _fake_exec(*args, **kwargs):
            raise exception.ProcessExecutionError(stderr="error")

        self.mock_object(self._driver, '_try_execute', _fake_exec)
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._deallocate_container,
                          self.share['name'])

    def test_deallocate_container_not_found_error(self):
        def _fake_exec(*args, **kwargs):
            raise exception.ProcessExecutionError(stderr="not found")

        self.mock_object(self._driver, '_try_execute', _fake_exec)
        self._driver._deallocate_container(self.share['name'])

    @mock.patch.object(lvm.LVMShareDriver, '_update_share_stats', mock.Mock())
    def test_get_share_stats(self):
        with mock.patch.object(self._driver, '_stats', mock.Mock) as stats:
            self.assertEqual(stats, self._driver.get_share_stats())
        self.assertFalse(self._driver._update_share_stats.called)

    @mock.patch.object(lvm.LVMShareDriver, '_update_share_stats', mock.Mock())
    def test_get_share_stats_refresh(self):
        with mock.patch.object(self._driver, '_stats', mock.Mock) as stats:
            self.assertEqual(stats,
                             self._driver.get_share_stats(refresh=True))
        self._driver._update_share_stats.assert_called_once_with()

    def test__unmount_device_is_busy_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='device is busy')
        self._os.path.exists.return_value = True
        mount_path = self._get_mount_path(self.share)
        expected_exec = [
            "umount -f %s" % (mount_path),
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.ShareBusyException,
                          self._driver._unmount_device,
                          self.share)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test__unmount_device_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='fake error')
        mount_path = self._get_mount_path(self.share)
        self._os.path.exists.return_value = True
        cmd = "umount -f %s" % (mount_path)
        fake_utils.fake_execute_set_repliers([(cmd, exec_runner)])
        self.assertRaises(processutils.ProcessExecutionError,
                          self._driver._unmount_device,
                          self.share)
        self._os.path.exists.assert_called_with(mount_path)

    def test__unmount_device_rmdir_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='fake error')
        mount_path = self._get_mount_path(self.share)
        self._os.path.exists.return_value = True
        cmd = "rmdir %s" % (mount_path)
        fake_utils.fake_execute_set_repliers([(cmd, exec_runner)])
        self.assertRaises(processutils.ProcessExecutionError,
                          self._driver._unmount_device,
                          self.share)
        self._os.path.exists.assert_called_with(mount_path)

    def test_create_snapshot(self):
        self._driver.create_snapshot(self._context, self.snapshot,
                                     self.share_server)
        mount_path = self._get_mount_path(self.snapshot)
        expected_exec = [
            ("lvcreate -L 1G --name fakesnapshotname --snapshot "
             "%s/fakename" % (CONF.lvm_share_volume_group,)),
            "e2fsck -y -f /dev/mapper/fakevg-%s" % self.snapshot['name'],
            "tune2fs -U random /dev/mapper/fakevg-%s" % self.snapshot['name'],
            "mkdir -p " + mount_path,
            "mount /dev/mapper/fakevg-fakesnapshotname " + mount_path,
            "chmod 777 " + mount_path,
        ]
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_ensure_share(self):
        device_name = '/dev/mapper/fakevg-fakename'
        with mock.patch.object(self._driver,
                               '_mount_device',
                               mock.Mock(return_value='fake_location')):
            self._driver.ensure_share(self._context, self.share,
                                      self.share_server)
            self._driver._mount_device.assert_called_with(self.share,
                                                          device_name)
            self._helper_nfs.create_exports.assert_called_once_with(
                self.server, self.share['name'], recreate=True)

    def test_delete_share(self):
        mount_path = self._get_mount_path(self.share)
        self._helper_nfs.remove_export(mount_path, self.share['name'])
        self._driver._delete_share(self._context, self.share)

    def test_delete_snapshot(self):
        mount_path = self._get_mount_path(self.snapshot)
        expected_exec = [
            'umount -f %s' % mount_path,
            'rmdir %s' % mount_path,
            'lvremove -f fakevg/fakesnapshotname',
        ]
        self._driver.delete_snapshot(self._context, self.snapshot,
                                     self.share_server)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_delete_share_invalid_share(self):
        self._driver._get_helper = mock.Mock(
            side_effect=exception.InvalidShare(reason='fake'))
        self._driver.delete_share(self._context, self.share, self.share_server)

    def test_delete_share_process_execution_error(self):
        self.mock_object(
            self._helper_nfs,
            'remove_export',
            mock.Mock(side_effect=exception.ProcessExecutionError))

        self._driver._delete_share(self._context, self.share)
        self._helper_nfs.remove_exports.assert_called_once_with(
            self.server,
            self.share['name'])

    @ddt.data(const.ACCESS_LEVEL_RW, const.ACCESS_LEVEL_RO)
    def test_update_access(self, access_level):
        access_rules = [test_generic.get_fake_access_rule(
            '1.1.1.1', access_level), ]
        add_rules = [test_generic.get_fake_access_rule(
            '2.2.2.2', access_level), ]
        delete_rules = [test_generic.get_fake_access_rule(
            '3.3.3.3', access_level), ]
        self._driver.update_access(self._context, self.share, access_rules,
                                   add_rules=add_rules,
                                   delete_rules=delete_rules,
                                   share_server=self.server)
        (self._driver._helpers[self.share['share_proto']].
            update_access.assert_called_once_with(
                self.server, self.share['name'],
                access_rules, add_rules=add_rules, delete_rules=delete_rules))

    @ddt.data(('1001::1001/129', None, False), ('1.1.1.256', None, False),
              ('1001::1001', None, [6]), ('1.1.1.0', None, [4]),
              (None, ['1001::1001', '1.1.1.0'], [6, 4]),
              (None, ['1001::1001'], [6]), (None, ['1.1.1.0'], [4]),
              (None, ['1001::1001/129', '1.1.1.0'], False))
    @ddt.unpack
    def test_get_configured_ip_versions(
            self, configured_ip, configured_ips, configured_ip_version):
        CONF.set_default('lvm_share_export_ip', configured_ip)
        CONF.set_default('lvm_share_export_ips', configured_ips)
        if configured_ip_version:
            self.assertEqual(configured_ip_version,
                             self._driver.get_configured_ip_versions())
        else:
            self.assertRaises(exception.InvalidInput,
                              self._driver.get_configured_ip_versions)

    def test_mount_device(self):
        mount_path = self._get_mount_path(self.share)
        ret = self._driver._mount_device(self.share, 'fakedevice')
        expected_exec = [
            "mkdir -p %s" % (mount_path,),
            "mount fakedevice %s" % (mount_path,),
            "chmod 777 %s" % (mount_path,),
        ]
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertEqual(mount_path, ret)

    def test_mount_device_already(self):
        def exec_runner(*args, **kwargs):
            if 'mount' in args and '-l' not in args:
                raise exception.ProcessExecutionError()
            else:
                return 'fakedevice', ''

        self.mock_object(self._driver, '_execute', exec_runner)
        mount_path = self._get_mount_path(self.share)

        ret = self._driver._mount_device(self.share, 'fakedevice')
        self.assertEqual(mount_path, ret)

    def test_mount_device_error(self):
        def exec_runner(*args, **kwargs):
            if 'mount' in args and '-l' not in args:
                raise exception.ProcessExecutionError()
            else:
                return 'fake', ''

        self.mock_object(self._driver, '_execute', exec_runner)
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._mount_device, self.share, 'fakedevice')

    def test_get_helper(self):
        share_cifs = fake_share(share_proto='CIFS')
        share_nfs = fake_share(share_proto='NFS')
        share_fake = fake_share(share_proto='FAKE')
        self.assertEqual(self._driver._get_helper(share_cifs),
                         self._helper_cifs)
        self.assertEqual(self._driver._get_helper(share_nfs),
                         self._helper_nfs)
        self.assertRaises(exception.InvalidShare, self._driver._get_helper,
                          share_fake)

    def _get_mount_path(self, share):
        return os.path.join(CONF.lvm_share_export_root, share['name'])

    def test__unmount_device(self):
        mount_path = self._get_mount_path(self.share)
        self._os.path.exists.return_value = True
        self.mock_object(self._driver, '_execute')
        self._driver._unmount_device(self.share)
        self._driver._execute.assert_any_call('umount', '-f', mount_path,
                                              run_as_root=True)
        self._driver._execute.assert_any_call('rmdir', mount_path,
                                              run_as_root=True)
        self._os.path.exists.assert_called_with(mount_path)

    def test_extend_share(self):
        local_path = self._driver._get_local_path(self.share)
        self.mock_object(self._driver, '_extend_container')
        self.mock_object(self._driver, '_execute')
        self._driver.extend_share(self.share, 3)
        self._driver._extend_container.assert_called_once_with(self.share,
                                                               local_path, 3)
        self._driver._execute.assert_called_once_with('resize2fs', local_path,
                                                      run_as_root=True)

    def test_ssh_exec_as_root(self):
        command = ['fake_command']
        self.mock_object(self._driver, '_execute')
        self._driver._ssh_exec_as_root('fake_server', command)
        self._driver._execute.assert_called_once_with('fake_command',
                                                      check_exit_code=True)

    def test_ssh_exec_as_root_with_sudo(self):
        command = ['sudo', 'fake_command']
        self.mock_object(self._driver, '_execute')
        self._driver._ssh_exec_as_root('fake_server', command)
        self._driver._execute.assert_called_once_with(
            'fake_command', run_as_root=True, check_exit_code=True)

    def test_extend_container(self):
        self.mock_object(self._driver, '_try_execute')
        self._driver._extend_container(self.share, 'device_name', 3)
        self._driver._try_execute.assert_called_once_with(
            'lvextend',
            '-L',
            '3G',
            '-n',
            'device_name',
            run_as_root=True)

    def test_get_share_server_pools(self):
        expected_result = [{
            'pool_name': 'lvm-single-pool',
            'total_capacity_gb': 33,
            'free_capacity_gb': 22,
            'reserved_percentage': 0,
        }, ]
        self.mock_object(
            self._driver,
            '_execute',
            mock.Mock(return_value=("VSize 33g VFree 22g", None)))

        self.assertEqual(expected_result,
                         self._driver.get_share_server_pools())
        self._driver._execute.assert_called_once_with(
            'vgs', 'fakevg', '--rows', '--units', 'g', run_as_root=True)

    def test_copy_volume_error(self):
        def _fake_exec(*args, **kwargs):
            if 'count=0' in args:
                raise exception.ProcessExecutionError()

        self.mock_object(self._driver, '_execute',
                         mock.Mock(side_effect=_fake_exec))
        self._driver._copy_volume('src', 'dest', 1)
        self._driver._execute.assert_any_call('dd', 'count=0', 'if=src',
                                              'of=dest', 'iflag=direct',
                                              'oflag=direct', run_as_root=True)
        self._driver._execute.assert_any_call('dd', 'if=src', 'of=dest',
                                              'count=1024', 'bs=1M',
                                              run_as_root=True)

    @ddt.data(('1.1.1.1', 4), ('1001::1001', 6))
    @ddt.unpack
    def test_update_share_stats(self, configured_ip, version):
        CONF.set_default('lvm_share_export_ip', configured_ip)
        self.mock_object(self._driver, 'get_share_server_pools',
                         mock.Mock(return_value='test-pool'))

        self._driver._update_share_stats()
        self.assertEqual('LVM', self._driver._stats['share_backend_name'])
        self.assertEqual('NFS_CIFS', self._driver._stats['storage_protocol'])
        self.assertEqual(50, self._driver._stats['reserved_percentage'])
        self.assertTrue(self._driver._stats['snapshot_support'])
        self.assertEqual('LVMShareDriver', self._driver._stats['driver_name'])
        self.assertEqual('test-pool', self._driver._stats['pools'])
        self.assertEqual(version == 4, self._driver._stats['ipv4_support'])
        self.assertEqual(version == 6, self._driver._stats['ipv6_support'])

    def test_revert_to_snapshot(self):
        mock_update_access = self.mock_object(self._helper_nfs,
                                              'update_access')
        self._driver.revert_to_snapshot(self._context, self.snapshot,
                                        [], [], self.share_server)
        snap_lv = "%s/fakesnapshotname" % (CONF.lvm_share_volume_group)
        share_lv = "%s/fakename" % (CONF.lvm_share_volume_group)
        share_mount_path = self._get_mount_path(self.snapshot['share'])
        snapshot_mount_path = self._get_mount_path(self.snapshot)
        expected_exec = [
            ('umount -f %s' % snapshot_mount_path),
            ("rmdir %s" % snapshot_mount_path),
            ("umount -f %s" % share_mount_path),
            ("rmdir %s" % share_mount_path),
            ("lvconvert --merge %s" % snap_lv),
            ("lvcreate -L 1G --name fakesnapshotname --snapshot %s" %
                share_lv),
            ("e2fsck -y -f /dev/mapper/%s-fakesnapshotname" %
                CONF.lvm_share_volume_group),
            ("tune2fs -U random /dev/mapper/%s-fakesnapshotname" %
                CONF.lvm_share_volume_group),
            ("mkdir -p %s" % share_mount_path),
            ("mount /dev/mapper/%s-fakename %s" %
                (CONF.lvm_share_volume_group, share_mount_path)),
            ("chmod 777 %s" % share_mount_path),
            ("mkdir -p %s" % snapshot_mount_path),
            ("mount /dev/mapper/fakevg-fakesnapshotname "
             "%s" % snapshot_mount_path),
            ("chmod 777 %s" % snapshot_mount_path),
        ]
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertEqual(4, mock_update_access.call_count)

    def test_snapshot_update_access(self):
        access_rules = [{
            'access_type': 'ip',
            'access_to': '1.1.1.1',
            'access_level': 'ro',
        }]

        add_rules = [{
            'access_type': 'ip',
            'access_to': '2.2.2.2',
            'access_level': 'ro',
        }]

        delete_rules = [{
            'access_type': 'ip',
            'access_to': '3.3.3.3',
            'access_level': 'ro',
        }]

        self._driver.snapshot_update_access(self._context, self.snapshot,
                                            access_rules, add_rules,
                                            delete_rules)

        (self._driver._helpers[self.snapshot['share']['share_proto']].
            update_access.assert_called_once_with(
            self.server, self.snapshot['name'],
            access_rules, add_rules=add_rules, delete_rules=delete_rules))

    @mock.patch.object(timeutils, 'utcnow', mock.Mock(
                       return_value='fake_date'))
    def test_update_share_usage_size(self):
        mount_path = self._get_mount_path(self.share)
        self._os.path.exists.return_value = True
        self.mock_object(
            self._driver,
            '_execute',
            mock.Mock(return_value=(
                "Mounted on                    Used "
                + mount_path + "               1G", None)))

        update_shares = self._driver.update_share_usage_size(
            self._context, [self.share, ])
        self._os.path.exists.assert_called_with(mount_path)
        self.assertEqual(
            [{'id': 'fakeid', 'used_size': '1',
              'gathered_at': 'fake_date'}],
            update_shares)
        self._driver._execute.assert_called_once_with(
            'df', '-l', '--output=target,used',
            '--block-size=g')

    @mock.patch.object(timeutils, 'utcnow', mock.Mock(
                       return_value='fake_date'))
    def test_update_share_usage_size_multiple_share(self):
        share1 = fake_share(id='fakeid_get_fail', name='get_fail')
        share2 = fake_share(id='fakeid_success', name='get_success')
        share3 = fake_share(id='fakeid_not_exist', name='get_not_exist')

        mount_path2 = self._get_mount_path(share2)
        mount_path3 = self._get_mount_path(share3)
        self._os.path.exists.side_effect = [True, True, False]
        self.mock_object(
            self._driver,
            '_execute',
            mock.Mock(return_value=(
                "Mounted on                    Used "
                + mount_path2 + "               1G", None)))

        update_shares = self._driver.update_share_usage_size(
            self._context, [share1, share2, share3])
        self._os.path.exists.assert_called_with(mount_path3)
        self.assertEqual(
            [{'gathered_at': 'fake_date',
              'id': 'fakeid_success', 'used_size': '1'}],
            update_shares)
        self._driver._execute.assert_called_with(
            'df', '-l', '--output=target,used',
            '--block-size=g')

    def test_update_share_usage_size_fail(self):
        def _fake_exec(*args, **kwargs):
            raise exception.ProcessExecutionError(stderr="error")

        self.mock_object(self._driver, '_execute', _fake_exec)
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver.update_share_usage_size,
                          self._context,
                          [self.share])

    def test_get_backend_info(self):
        backend_info = self._driver.get_backend_info(self._context)

        self.assertEqual(
            {'export_ips': ','.join(self.server['public_addresses']),
             'db_version': mock.ANY},
            backend_info)
