# vim: tabstop=4 shiftwidth=4 softtabstop=4
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
"""Unit tests for the NFS driver module."""

import mox
import os

from cinder import context
from cinder.db.sqlalchemy import models
from cinder import exception
from cinder import flags
from cinder.openstack.common import importutils
from cinder.openstack.common import log as logging
from cinder.share.configuration import Configuration
from cinder.share.drivers import lvm
from cinder import test
from cinder.tests.db import fakes as db_fakes
from cinder.tests import fake_utils


FLAGS = flags.FLAGS


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
        'share_size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    snapshot.update(kwargs)
    return db_fakes.FakeModel(snapshot)


def fake_access(**kwargs):
    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.2',
        'state': 'active',
    }
    access.update(kwargs)
    return db_fakes.FakeModel(access)


class LVMShareDriverTestCase(test.TestCase):
    """Tests LVMShareDriver."""

    def setUp(self):
        super(LVMShareDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self._execute = fake_utils.fake_execute
        self._context = context.get_admin_context()

        FLAGS.set_default('share_volume_group', 'fakevg')
        FLAGS.set_default('share_export_ip', '10.0.0.1')

        self._helper_cifs = self.mox.CreateMock(lvm.CIFSNetConfHelper)
        self._helper_nfs = self.mox.CreateMock(lvm.NFSHelper)
        self.fake_conf = Configuration(None)
        self._db = self.mox.CreateMockAnything()
        self._driver = lvm.LVMShareDriver(self._db,
                                          execute=self._execute,
                                          configuration=self.fake_conf)
        self._driver._helpers = {
            'CIFS': self._helper_cifs,
            'NFS': self._helper_nfs,
        }

        self.share = fake_share()
        self.access = fake_access()
        self.snapshot = fake_snapshot()

    def tearDown(self):
        super(LVMShareDriverTestCase, self).tearDown()
        fake_utils.fake_execute_set_repliers([])
        fake_utils.fake_execute_clear_log()

    def test_do_setup(self):
        self.mox.StubOutWithMock(importutils, 'import_class')
        helpers = [
            (self._helper_cifs, 'cinder.share.drivers.lvm.CIFSNetConfHelper'),
            (self._helper_nfs, 'cinder.share.drivers.lvm.NFSHelper'),
        ]
        for helper, path in helpers:
            importutils.import_class(path).AndReturn(helper)
            helper.__call__(fake_utils.fake_execute,
                            self.fake_conf).\
                AndReturn(helper)
            helper.init()
        self.mox.ReplayAll()
        self._driver.do_setup(self._context)
        expected_helpers = {
            'CIFS': self._helper_cifs,
            'NFS': self._helper_nfs,
        }
        self.assertEqual(self._driver._helpers, expected_helpers)

    def test_check_for_setup_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake1\n   fakevg\n   fake2\n', ''

        expected_exec = [
            'vgs --noheadings -o name',
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.mox.ReplayAll()
        ret = self._driver.check_for_setup_error()
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_check_for_setup_error_no_vg(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake0\n   fake1\n   fake2\n', ''

        fake_utils.fake_execute_set_repliers([('vgs --noheadings -o name',
                                               exec_runner)])
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_no_export_ip(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake1\n   fakevg\n   fake2\n', ''

        fake_utils.fake_execute_set_repliers([('vgs --noheadings -o name',
                                               exec_runner)])
        FLAGS.set_default('share_export_ip', None)
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test_local_path_normal(self):
        share = fake_share(name='fake_sharename')
        FLAGS.set_default('share_volume_group', 'fake_vg')
        self.mox.ReplayAll()
        ret = self._driver._local_path(share)
        self.assertEqual(ret, '/dev/mapper/fake_vg-fake_sharename')

    def test_local_path_escapes(self):
        share = fake_share(name='fake-sharename')
        FLAGS.set_default('share_volume_group', 'fake-vg')
        self.mox.ReplayAll()
        ret = self._driver._local_path(share)
        self.assertEqual(ret, '/dev/mapper/fake--vg-fake--sharename')

    def test_allocate_container_normal(self):
        FLAGS.set_default('share_lvm_mirrors', 0)
        self.mox.ReplayAll()
        ret = self._driver.allocate_container(self._context, self.share)
        expected_exec = [
            'lvcreate -L 1G -n fakename fakevg',
            'mkfs.ext4 /dev/mapper/fakevg-fakename',
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_allocate_container_from_snapshot(self):
        FLAGS.set_default('share_lvm_mirrors', 0)
        mount_share = '/dev/mapper/fakevg-fakename'
        mount_snapshot = '/dev/mapper/fakevg-fakesnapshotname'
        self.mox.ReplayAll()
        ret = self._driver.allocate_container_from_snapshot(self._context,
                                                            self.share,
                                                            self.snapshot)
        expected_exec = [
            'lvcreate -L 1G -n fakename fakevg',
            ("dd count=0 if=%s of=%s iflag=direct oflag=direct" %
             (mount_snapshot, mount_share)),
            ("dd if=%s of=%s count=1024 bs=1M iflag=direct oflag=direct" %
             (mount_snapshot, mount_share)),
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_allocate_container_from_snapshot_without_extra(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError()

        FLAGS.set_default('share_lvm_mirrors', 0)
        mount_share = '/dev/mapper/fakevg-fakename'
        mount_snapshot = '/dev/mapper/fakevg-fakesnapshotname'
        expected_exec = [
            'lvcreate -L 1G -n fakename fakevg',
            ("dd count=0 if=%s of=%s iflag=direct oflag=direct" %
             (mount_snapshot, mount_share)),
            "dd if=%s of=%s count=1024 bs=1M" % (mount_snapshot, mount_share),
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[1], exec_runner)])
        self.mox.ReplayAll()
        ret = self._driver.allocate_container_from_snapshot(self._context,
                                                            self.share,
                                                            self.snapshot)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_allocate_container_mirrors(self):
        share = fake_share(size='2048')
        FLAGS.set_default('share_lvm_mirrors', 2)
        self.mox.ReplayAll()
        ret = self._driver.allocate_container(self._context, share)
        expected_exec = [
            'lvcreate -L 2048G -n fakename fakevg -m 2 --nosync -R 2',
            'mkfs.ext4 /dev/mapper/fakevg-fakename',
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_deallocate_container(self):
        self.mox.ReplayAll()
        expected_exec = ['lvremove -f fakevg/fakename']
        ret = self._driver.deallocate_container(self._context, self.share)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_get_share_stats(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n  fakevg 5.38  4.30\n', ''

        expected_exec = [
            'vgs --noheadings --nosuffix --unit=G -o name,size,free fakevg',
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        FLAGS.set_default('reserved_percentage', 1)
        self.mox.ReplayAll()
        ret = self._driver.get_share_stats(refresh=True)
        expected_ret = {
            'share_backend_name': 'LVM',
            'vendor_name': 'Open Source',
            'driver_version': '1.0',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 5.38,
            'free_capacity_gb': 4.30,
            'reserved_percentage': 0,
            'QoS_support': False,
        }
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, expected_ret)

    def test_get_share_stats_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError()

        expected_exec = [
            'vgs --noheadings --nosuffix --unit=G -o name,size,free fakevg',
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        FLAGS.set_default('reserved_percentage', 1)
        self.mox.ReplayAll()
        ret = self._driver.get_share_stats(refresh=True)
        expected_ret = {
            'share_backend_name': 'LVM',
            'vendor_name': 'Open Source',
            'driver_version': '1.0',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 0,
            'free_capacity_gb': 0,
            'reserved_percentage': 0,
            'QoS_support': False,
        }
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, expected_ret)

    def test_create_export(self):
        self.mox.StubOutWithMock(self._driver, '_mount_device')
        self._driver._mount_device(self.share, '/dev/mapper/fakevg-fakename').\
            AndReturn('fakelocation')
        self.mox.ReplayAll()
        ret = self._driver.create_export(self._context, self.share)
        expected_ret = {
            'provider_location': 'fakelocation',
        }
        self.assertEqual(ret, expected_ret)

    def test_remove_export(self):
        mount_path = self._get_mount_path(self.share)

        self.mox.StubOutWithMock(os.path, 'exists')
        os.path.exists(mount_path).AndReturn(True)

        self.mox.StubOutWithMock(os, 'rmdir')
        os.rmdir(mount_path)

        self.mox.ReplayAll()
        self._driver.remove_export(self._context, self.share)
        expected_exec = [
            "umount -f %s" % (mount_path,),
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_remove_export_is_busy_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='device is busy')

        mount_path = self._get_mount_path(self.share)
        expected_exec = [
            "umount -f %s" % (mount_path),
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.mox.StubOutWithMock(os.path, 'exists')
        os.path.exists(mount_path).AndReturn(True)
        self.mox.ReplayAll()
        self.assertRaises(exception.ShareIsBusy, self._driver.remove_export,
                          self._context, self.share)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_remove_export_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='fake error')

        mount_path = self._get_mount_path(self.share)
        expected_exec = [
            "umount -f %s" % (mount_path),
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.mox.StubOutWithMock(os.path, 'exists')
        os.path.exists(mount_path).AndReturn(True)
        self.mox.ReplayAll()
        self._driver.remove_export(self._context, self.share)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_create_share(self):
        mount_path = self._get_mount_path(self.share)
        self._helper_nfs.create_export(mount_path, self.share['name']).\
            AndReturn('fakelocation')
        self.mox.ReplayAll()
        ret = self._driver.create_share(self._context, self.share)
        self.assertEqual(ret, 'fakelocation')

    def test_create_snapshot(self):
        self.mox.ReplayAll()
        self._driver.create_snapshot(self._context, self.snapshot)
        expected_exec = [
            ("lvcreate -L 1G --name fakesnapshotname --snapshot %s/fakename" %
             (FLAGS.share_volume_group,)),
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_ensure_share(self):
        mount_path = self._get_mount_path(self.share)
        self.mox.StubOutWithMock(self._driver, '_mount_device')
        self._driver._mount_device(self.share, '/dev/mapper/fakevg-fakename').\
            AndReturn(mount_path)
        self._helper_nfs.create_export(mount_path, self.share['name'],
                                       recreate=True).AndReturn('fakelocation')
        self.mox.ReplayAll()
        self._driver.ensure_share(self._context, self.share)

    def test_delete_share(self):
        mount_path = self._get_mount_path(self.share)
        self._helper_nfs.remove_export(mount_path, self.share['name'])
        self.mox.ReplayAll()
        self._driver.delete_share(self._context, self.share)

    def test_delete_snapshot(self):
        self.mox.ReplayAll()
        expected_exec = ['lvremove -f fakevg/fakesnapshotname']
        self._driver.delete_snapshot(self._context, self.snapshot)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_delete_share_process_error(self):
        self.mox.StubOutWithMock(self._driver, '_get_mount_path')
        self._driver._get_mount_path(self.share).AndRaise(
            exception.ProcessExecutionError())
        self.mox.ReplayAll()
        self._driver.delete_share(self._context, self.share)

    def test_delete_share_invalid_share(self):
        self.mox.StubOutWithMock(self._driver, '_get_helper')
        self._driver._get_helper(self.share).AndRaise(
            exception.InvalidShare(reason='fake'))
        self.mox.ReplayAll()
        self._driver.delete_share(self._context, self.share)

    def test_allow_access(self):
        mount_path = self._get_mount_path(self.share)
        self._helper_nfs.allow_access(mount_path,
                                      self.share['name'],
                                      self.access['access_type'],
                                      self.access['access_to'])
        self.mox.ReplayAll()
        self._driver.allow_access(self._context, self.share, self.access)

    def test_deny_access(self):
        mount_path = self._get_mount_path(self.share)
        self._helper_nfs.deny_access(mount_path,
                                     self.share['name'],
                                     self.access['access_type'],
                                     self.access['access_to'])
        self.mox.ReplayAll()
        self._driver.deny_access(self._context, self.share, self.access)

    def test_mount_device(self):
        mount_path = self._get_mount_path(self.share)
        self.mox.ReplayAll()
        ret = self._driver._mount_device(self.share, 'fakedevice')
        expected_exec = [
            "mkdir -p %s" % (mount_path,),
            "mount fakedevice %s" % (mount_path,),
            "chmod 777 %s" % (mount_path,),
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, mount_path)

    def test_mount_device_already(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='already mounted')

        mount_path = self._get_mount_path(self.share)
        expected_exec = [
            "mkdir -p %s" % (mount_path,),
            "mount fakedevice %s" % (mount_path,),
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[1], exec_runner)])
        self.mox.ReplayAll()
        ret = self._driver._mount_device(self.share, 'fakedevice')
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, mount_path)

    def test_mount_device_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='fake error')

        mount_path = self._get_mount_path(self.share)
        expected_exec = [
            "mkdir -p %s" % (mount_path,),
            "mount fakedevice %s" % (mount_path,),
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[1], exec_runner)])
        self.mox.ReplayAll()
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._mount_device, self.share, 'fakedevice')

    def test_get_helper(self):
        share_cifs = fake_share(share_proto='CIFS')
        share_nfs = fake_share(share_proto='NFS')
        share_fake = fake_share(share_proto='FAKE')
        self.mox.ReplayAll()
        self.assertEqual(self._driver._get_helper(share_cifs),
                         self._helper_cifs)
        self.assertEqual(self._driver._get_helper(share_nfs),
                         self._helper_nfs)
        self.assertRaises(exception.InvalidShare, self._driver._get_helper,
                          fake_share(share_proto='FAKE'))

    def _get_mount_path(self, share):
        return os.path.join(FLAGS.share_export_root, share['name'])


class NFSHelperTestCase(test.TestCase):
    """Test case for NFS driver."""

    def setUp(self):
        super(NFSHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        FLAGS.set_default('share_export_ip', '127.0.0.1')
        self._execute = fake_utils.fake_execute
        self.fake_conf = Configuration(None)
        self._helper = lvm.NFSHelper(self._execute, self.fake_conf)
        fake_utils.fake_execute_clear_log()

    def tearDown(self):
        super(NFSHelperTestCase, self).tearDown()
        fake_utils.fake_execute_set_repliers([])
        fake_utils.fake_execute_clear_log()

    def test_failed_init(self):
        self.mox.StubOutWithMock(self, '_execute')
        self._execute('exportfs', check_exit_code=True, run_as_root=True).\
            AndRaise(exception.ProcessExecutionError)
        self.mox.ReplayAll()
        self.assertRaises(exception.Error, lvm.NFSHelper.__init__,
                          self._helper, self._execute, self.fake_conf)

    def test_create_export(self):
        self.mox.ReplayAll()
        ret = self._helper.create_export('/opt/nfs', 'volume-00001')
        expected_location = '%s:/opt/nfs' % FLAGS.share_export_ip
        self.assertEqual(ret, expected_location)

    def test_remove_export(self):
        self.mox.ReplayAll()
        self._helper.remove_export('/opt/nfs', 'volume-00001')

    def test_allow_access(self):
        self.mox.ReplayAll()
        self._helper.allow_access('/opt/nfs', 'volume-00001', 'ip', '10.0.0.*')

        export_string = '10.0.0.*:/opt/nfs'
        expected_exec = [
            'exportfs',
            'exportfs -o rw,no_subtree_check %s' % export_string,
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_allow_access_no_ip(self):
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShareAccess,
                          self._helper.allow_access, '/opt/nfs', 'share0',
                          'fake', 'fakerule')

    def test_allow_access_negative(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n/opt/nfs\t\t10.0.0.*\n', ''

        fake_utils.fake_execute_set_repliers([('exportfs', exec_runner)])
        self.mox.ReplayAll()
        self.assertRaises(exception.ShareAccessExists,
                          self._helper.allow_access,
                          '/opt/nfs', 'volume-00001', 'ip', '10.0.0.*')

    def test_deny_access(self):
        self.mox.ReplayAll()
        self._helper.deny_access('/opt/nfs', 'volume-00001', 'ip', '10.0.0.*')
        export_string = '10.0.0.*:/opt/nfs'
        expected_exec = ['exportfs -u %s' % export_string]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)


class CIFSNetConfHelperTestCase(test.TestCase):
    """Test case for CIFS driver with net conf management."""

    def setUp(self):
        super(CIFSNetConfHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        FLAGS.set_default('share_export_ip', '127.0.0.1')
        self.share = fake_share()
        self._execute = fake_utils.fake_execute
        self.fake_conf = Configuration(None)
        self._helper = lvm.CIFSNetConfHelper(self._execute, self.fake_conf)
        fake_utils.fake_execute_clear_log()

    def tearDown(self):
        super(CIFSNetConfHelperTestCase, self).tearDown()
        fake_utils.fake_execute_set_repliers([])
        fake_utils.fake_execute_clear_log()

    def test_create_export(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_execute')
        self._helper._execute('net', 'conf', 'addshare', share_name,
                              'fakelocalpath', 'writeable=y', 'guest_ok=y',
                              run_as_root=True)
        parameters = {
            'browseable': 'yes',
            'create mask': '0755',
            'hosts deny': '0.0.0.0/0',
            'hosts allow': '127.0.0.1',
        }
        for name, value in parameters.items():
            self._helper._execute('net', 'conf', 'setparm', share_name, name,
                                  value, run_as_root=True)
        self.mox.ReplayAll()
        ret = self._helper.create_export('fakelocalpath', share_name)
        expected_ret = "//127.0.0.1/%s" % (share_name,)
        self.assertEqual(ret, expected_ret)

    def test_create_export_already_exists(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='already exists')

        expected_exec = [
            "net conf addshare %s %s writeable=y guest_ok=y" % (
                self.share['name'],
                'fakelocalpath',
            ),
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.mox.ReplayAll()
        self.assertRaises(exception.ShareBackendException,
                          self._helper.create_export, 'fakelocalpath',
                          self.share['name'])

    def test_create_export_recreate(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_execute')
        self._helper._execute('net', 'conf', 'addshare', share_name,
                              'fakelocalpath', 'writeable=y', 'guest_ok=y',
                              run_as_root=True).\
            AndRaise(exception.ProcessExecutionError(stderr='already exists'))
        self._helper._execute('net', 'conf', 'delshare', share_name,
                              run_as_root=True)
        self._helper._execute('net', 'conf', 'addshare', share_name,
                              'fakelocalpath', 'writeable=y', 'guest_ok=y',
                              run_as_root=True)
        parameters = {
            'browseable': 'yes',
            'create mask': '0755',
            'hosts deny': '0.0.0.0/0',
            'hosts allow': '127.0.0.1',
        }
        for name, value in parameters.items():
            self._helper._execute('net', 'conf', 'setparm', share_name, name,
                                  value, run_as_root=True)
        self.mox.ReplayAll()
        ret = self._helper.create_export('fakelocalpath', share_name,
                                         recreate=True)
        expected_ret = "//127.0.0.1/%s" % (share_name,)
        self.assertEqual(ret, expected_ret)

    def test_create_export_error(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_execute')
        self._helper._execute('net', 'conf', 'addshare', share_name,
                              'fakelocalpath', 'writeable=y', 'guest_ok=y',
                              run_as_root=True).\
            AndRaise(exception.ProcessExecutionError(stderr='fake error'))
        self.mox.ReplayAll()
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper.create_export, 'fakelocalpath',
                          share_name)

    def test_remove_export(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_execute')
        self._helper._execute('net', 'conf', 'delshare', share_name,
                              run_as_root=True)
        self._helper._execute('smbcontrol', 'all', 'close-share', share_name,
                              run_as_root=True)
        self.mox.ReplayAll()
        self._helper.remove_export('fakelocalpath', share_name)

    def test_remove_export_no_such_service(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_execute')
        self._helper._execute('net', 'conf', 'delshare', share_name,
                              run_as_root=True).\
            AndRaise(exception.ProcessExecutionError(
                     stderr='SBC_ERR_NO_SUCH_SERVICE'))
        self._helper._execute('smbcontrol', 'all', 'close-share', share_name,
                              run_as_root=True)
        self.mox.ReplayAll()
        self._helper.remove_export('fakelocalpath', share_name)

    def test_remove_export_error(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_execute')
        self._helper._execute('net', 'conf', 'delshare', share_name,
                              run_as_root=True).\
            AndRaise(exception.ProcessExecutionError(stderr='fake error'))
        self.mox.ReplayAll()
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper.remove_export, 'fakelocalpath',
                          share_name)

    def test_allow_access(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_get_allow_hosts')
        self.mox.StubOutWithMock(self._helper, '_set_allow_hosts')
        self._helper._get_allow_hosts(share_name).AndReturn(['127.0.0.1',
                                                             '10.0.0.1'])
        self._helper._set_allow_hosts(['127.0.0.1', '10.0.0.1', '10.0.0.2'],
                                      share_name)
        self.mox.ReplayAll()
        self._helper.allow_access('fakelocalpath', share_name, 'ip',
                                  '10.0.0.2')

    def test_allow_access_exists(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_get_allow_hosts')
        self._helper._get_allow_hosts(share_name).AndReturn(['127.0.0.1',
                                                             '10.0.0.1'])
        self.mox.ReplayAll()
        self.assertRaises(exception.ShareAccessExists,
                          self._helper.allow_access, 'fakelocalpath',
                          share_name, 'ip', '10.0.0.1')

    def test_allow_access_wrong_type(self):
        share_name = self.share['name']
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShareAccess,
                          self._helper.allow_access, 'fakelocalpath',
                          share_name, 'fake', 'fake access')

    def test_deny_access(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_get_allow_hosts')
        self.mox.StubOutWithMock(self._helper, '_set_allow_hosts')
        self._helper._get_allow_hosts(share_name).AndReturn(['127.0.0.1',
                                                             '10.0.0.1'])
        self._helper._set_allow_hosts(['127.0.0.1'], share_name)
        self.mox.ReplayAll()
        self._helper.deny_access('fakelocalpath', share_name, 'ip',
                                 '10.0.0.1')

    def test_deny_access_not_exists(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_get_allow_hosts')
        self._helper._get_allow_hosts(share_name).\
            AndRaise(exception.ProcessExecutionError(stdout='does not exist'))
        self.mox.ReplayAll()
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper.deny_access, 'fakelocalpath',
                          share_name, 'ip', '10.0.0.1')

    def test_deny_access_not_exists_force(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_get_allow_hosts')
        self._helper._get_allow_hosts(share_name).\
            AndRaise(exception.ProcessExecutionError(stdout='does not exist'))
        self.mox.ReplayAll()
        self._helper.deny_access('fakelocalpath', share_name, 'ip', '10.0.0.1',
                                 force=True)

    def test_deny_access_error(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_get_allow_hosts')
        self._helper._get_allow_hosts(share_name).\
            AndRaise(exception.ProcessExecutionError(stdout='fake out'))
        self.mox.ReplayAll()
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper.deny_access, 'fakelocalpath',
                          share_name, 'ip', '10.0.0.1')

    def test_get_allow_hosts(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_execute')
        self._helper._execute('net', 'conf', 'getparm', share_name,
                              'hosts allow', run_as_root=True).\
            AndReturn(('127.0.0.1 10.0.0.1', ''))
        self.mox.ReplayAll()
        ret = self._helper._get_allow_hosts(share_name)
        self.assertEqual(ret, ['127.0.0.1', '10.0.0.1'])

    def test_set_allow_hosts(self):
        share_name = self.share['name']
        self.mox.StubOutWithMock(self._helper, '_execute')
        self._helper._execute('net', 'conf', 'setparm', share_name,
                              'hosts allow', '127.0.0.1 10.0.0.1',
                              run_as_root=True)
        self.mox.ReplayAll()
        self._helper._set_allow_hosts(['127.0.0.1', '10.0.0.1'], share_name)
