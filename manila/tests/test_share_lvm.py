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

import os

import mock
from oslo.config import cfg

from manila import context
from manila.db.sqlalchemy import models
from manila import exception
from manila.openstack.common import importutils
from manila.openstack.common import log as logging
from manila.share.configuration import Configuration
from manila.share.drivers import lvm
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_utils


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

        CONF.set_default('share_volume_group', 'fakevg')
        CONF.set_default('share_export_ip', '10.0.0.1')

        self._helper_cifs = mock.Mock()
        self._helper_nfs = mock.Mock()
        self.fake_conf = Configuration(None)
        self._db = mock.Mock()
        self._os = lvm.os = mock.Mock()
        self._os.path.join = os.path.join
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

        # Used only to test compatibility with share manager
        self.share_server = "fake_share_server"

    def tearDown(self):
        super(LVMShareDriverTestCase, self).tearDown()
        fake_utils.fake_execute_set_repliers([])
        fake_utils.fake_execute_clear_log()

    def test_do_setup(self):
        CONF.set_default('share_lvm_helpers', ['NFS=fakenfs'])
        lvm.importutils = mock.Mock()
        lvm.importutils.import_class.return_value = self._helper_nfs
        self._driver.do_setup(self._context)
        lvm.importutils.import_class.assert_has_calls([
            mock.call('fakenfs')
        ])

    def test_check_for_setup_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake1\n   fakevg\n   fake2\n', ''

        expected_exec = [
            'vgs --noheadings -o name',
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        ret = self._driver.check_for_setup_error()
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_check_for_setup_error_no_vg(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake0\n   fake1\n   fake2\n', ''

        fake_utils.fake_execute_set_repliers([('vgs --noheadings -o name',
                                               exec_runner)])
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_no_export_ip(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n   fake1\n   fakevg\n   fake2\n', ''

        fake_utils.fake_execute_set_repliers([('vgs --noheadings -o name',
                                               exec_runner)])
        CONF.set_default('share_export_ip', None)
        self.assertRaises(exception.InvalidParameterValue,
                          self._driver.check_for_setup_error)

    def test_local_path_normal(self):
        share = fake_share(name='fake_sharename')
        CONF.set_default('share_volume_group', 'fake_vg')
        ret = self._driver._local_path(share)
        self.assertEqual(ret, '/dev/mapper/fake_vg-fake_sharename')

    def test_local_path_escapes(self):
        share = fake_share(name='fake-sharename')
        CONF.set_default('share_volume_group', 'fake-vg')
        ret = self._driver._local_path(share)
        self.assertEqual(ret, '/dev/mapper/fake--vg-fake--sharename')

    def test_create_share(self):
        self._helper_nfs.create_export.return_value = 'fakelocation'
        self._driver._mount_device = mock.Mock()
        ret = self._driver.create_share(self._context, self.share,
                                        self.share_server)
        CONF.set_default('share_lvm_mirrors', 0)
        self._driver._mount_device.assert_called_with(
            self.share, '/dev/mapper/fakevg-fakename')
        expected_exec = [
            'lvcreate -L 1G -n fakename fakevg',
            'mkfs.ext4 /dev/mapper/fakevg-fakename',
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, 'fakelocation')

    def test_create_share_from_snapshot(self):
        CONF.set_default('share_lvm_mirrors', 0)
        self._driver._mount_device = mock.Mock()
        mount_share = '/dev/mapper/fakevg-fakename'
        mount_snapshot = '/dev/mapper/fakevg-fakesnapshotname'
        self._helper_nfs.create_export.return_value = 'fakelocation'
        mount_path = self._get_mount_path(self.share)

        ret = self._driver.create_share_from_snapshot(self._context,
                                                      self.share,
                                                      self.snapshot,
                                                      self.share_server)

        self._driver._mount_device.assert_called_with(self.share,
                                                     mount_snapshot)
        expected_exec = [
            'lvcreate -L 1G -n fakename fakevg',
            'mkfs.ext4 /dev/mapper/fakevg-fakename',
            ("dd count=0 if=%s of=%s iflag=direct oflag=direct" %
             (mount_snapshot, mount_share)),
            ("dd if=%s of=%s count=1024 bs=1M iflag=direct oflag=direct" %
             (mount_snapshot, mount_share)),
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_create_share_mirrors(self):

        share = fake_share(size='2048')
        CONF.set_default('share_lvm_mirrors', 2)
        self._helper_nfs.create_export.return_value = 'fakelocation'
        self._driver._mount_device = mock.Mock()
        ret = self._driver.create_share(self._context, share,
                                        self.share_server)
        self._driver._mount_device.assert_called_with(
            share, '/dev/mapper/fakevg-fakename')
        expected_exec = [
            'lvcreate -L 2048G -n fakename fakevg -m 2 --nosync -R 2',
            'mkfs.ext4 /dev/mapper/fakevg-fakename',
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, 'fakelocation')

    def test_deallocate_container(self):
        expected_exec = ['lvremove -f fakevg/fakename']
        ret = self._driver._deallocate_container(self.share['name'])
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_get_share_stats(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n  fakevg 5.38  4.30\n', ''

        expected_exec = [
            'vgs --noheadings --nosuffix --unit=G -o name,size,free fakevg',
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        CONF.set_default('reserved_share_percentage', 1)
        ret = self._driver.get_share_stats(refresh=True)
        expected_ret = {
            'share_backend_name': 'LVM',
            'vendor_name': 'Open Source',
            'driver_version': '1.0',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 5.38,
            'free_capacity_gb': 4.30,
            'reserved_percentage': 1,
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
        CONF.set_default('reserved_share_percentage', 1)
        ret = self._driver.get_share_stats(refresh=True)
        expected_ret = {
            'share_backend_name': 'LVM',
            'vendor_name': 'Open Source',
            'driver_version': '1.0',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 0,
            'free_capacity_gb': 0,
            'reserved_percentage': 1,
            'QoS_support': False,
        }
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, expected_ret)

    def test_remove_export(self):
        mount_path = self._get_mount_path(self.share)
        self._os.path.exists.return_value = True

        self._driver._remove_export(self._context, self.share)

        expected_exec = [
            "umount -f %s" % (mount_path,),
        ]

        self._os.path.exists.assert_called_with(mount_path)
        self._os.rmdir.assert_called_with(mount_path)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_remove_export_is_busy_error(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='device is busy')
        self._os.path.exists.return_value = True
        mount_path = self._get_mount_path(self.share)
        expected_exec = [
            "umount -f %s" % (mount_path),
        ]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.ShareIsBusy, self._driver._remove_export,
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
        self._os.path.exists.return_value = True
        self._driver._remove_export(self._context, self.share)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_create_snapshot(self):
        self._driver.create_snapshot(self._context, self.snapshot,
                                     self.share_server)
        expected_exec = [
            ("lvcreate -L 1G --name fakesnapshotname --snapshot %s/fakename" %
             (CONF.share_volume_group,)),
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_ensure_share(self):
        device_name = '/dev/mapper/fakevg-fakename'
        location = 'fake_location'
        with mock.patch.object(self._driver,
                               '_mount_device',
                               mock.Mock(return_value=location)):
            self._driver.ensure_share(self._context, self.share,
                                      self.share_server)
            self._driver._mount_device.assert_called_with(self.share,
                                                          device_name)
            self._helper_nfs.create_export.assert_called_once_with(
                location, self.share['name'], recreate=True)

    def test_delete_share(self):
        mount_path = self._get_mount_path(self.share)
        self._helper_nfs.remove_export(mount_path, self.share['name'])
        self._driver._delete_share(self._context, self.share)

    def test_delete_snapshot(self):
        expected_exec = ['lvremove -f fakevg/fakesnapshotname']
        self._driver.delete_snapshot(self._context, self.snapshot,
                                     self.share_server)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_delete_share_invalid_share(self):
        self._driver._get_helper = mock.Mock(
            side_effect=exception.InvalidShare(reason='fake'))
        self._driver.delete_share(self._context, self.share, self.share_server)

    def test_allow_access(self):
        mount_path = self._get_mount_path(self.share)
        self._helper_nfs.allow_access(mount_path,
                                      self.share['name'],
                                      self.access['access_type'],
                                      self.access['access_to'])
        self._driver.allow_access(self._context, self.share, self.access,
                                  self.share_server)

    def test_deny_access(self):
        mount_path = self._get_mount_path(self.share)
        self._helper_nfs.deny_access(mount_path,
                                     self.share['name'],
                                     self.access['access_type'],
                                     self.access['access_to'])
        self._driver.deny_access(self._context, self.share, self.access,
                                 self.share_server)

    def test_mount_device(self):
        mount_path = self._get_mount_path(self.share)
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
                          fake_share(share_proto='FAKE'))

    def _get_mount_path(self, share):
        return os.path.join(CONF.share_export_root, share['name'])


class NFSHelperTestCase(test.TestCase):
    """Test case for NFS driver."""

    def setUp(self):
        super(NFSHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        CONF.set_default('share_export_ip', '127.0.0.1')
        self._execute = fake_utils.fake_execute
        self.fake_conf = Configuration(None)
        self._helper = lvm.NFSHelper(self._execute, self.fake_conf)
        fake_utils.fake_execute_clear_log()

    def tearDown(self):
        super(NFSHelperTestCase, self).tearDown()
        fake_utils.fake_execute_set_repliers([])
        fake_utils.fake_execute_clear_log()

    def test_failed_init(self):
        self._execute = mock.Mock(side_effect=exception.ProcessExecutionError)
        self.assertRaises(exception.Error, lvm.NFSHelper.__init__,
                          self._helper, self._execute, self.fake_conf)

    def test_create_export(self):
        ret = self._helper.create_export('/opt/nfs', 'volume-00001')
        expected_location = '%s:/opt/nfs' % CONF.share_export_ip
        self.assertEqual(ret, expected_location)

    def test_remove_export(self):
        self._helper.remove_export('/opt/nfs', 'volume-00001')

    def test_allow_access(self):
        self._helper.allow_access('/opt/nfs', 'volume-00001', 'ip', '10.0.0.*')

        export_string = '10.0.0.*:/opt/nfs'
        expected_exec = [
            'exportfs',
            'exportfs -o rw,no_subtree_check %s' % export_string,
        ]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_allow_access_no_ip(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._helper.allow_access, '/opt/nfs', 'share0',
                          'fake', 'fakerule')

    def test_allow_access_negative(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            return '\n/opt/nfs\t\t10.0.0.*\n', ''

        fake_utils.fake_execute_set_repliers([('exportfs', exec_runner)])
        self.assertRaises(exception.ShareAccessExists,
                          self._helper.allow_access,
                          '/opt/nfs', 'volume-00001', 'ip', '10.0.0.*')

    def test_deny_access(self):
        self._helper.deny_access('/opt/nfs', 'volume-00001', 'ip', '10.0.0.*')
        export_string = '10.0.0.*:/opt/nfs'
        expected_exec = ['exportfs -u %s' % export_string]
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)


class CIFSNetConfHelperTestCase(test.TestCase):
    """Test case for CIFS driver with net conf management."""

    def setUp(self):
        super(CIFSNetConfHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        CONF.set_default('share_export_ip', '127.0.0.1')
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
        self._helper._execute = mock.Mock()
        parameters = {
            'browseable': 'yes',
            'create mask': '0755',
            'hosts deny': '0.0.0.0/0',
            'hosts allow': '127.0.0.1',
            }
        ret = self._helper.create_export('fakelocalpath', share_name)
        calls = [mock.call('net', 'conf', 'addshare', share_name,
                           'fakelocalpath', 'writeable=y', 'guest_ok=y',
                           run_as_root=True)]
        for name, value in parameters.items():
            calls.append(mock.call('net', 'conf', 'setparm', share_name, name,
                                   value, run_as_root=True))
        self._helper._execute.assert_has_calls(calls)
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
        self.assertRaises(exception.ShareBackendException,
                          self._helper.create_export, 'fakelocalpath',
                          self.share['name'])

    def test_create_export_recreate(self):
        share_name = self.share['name']

        def raise_exec_error():
            raise exception.ProcessExecutionError(stderr="already exists")
        execute_return_values = [raise_exec_error, '']
        parameters = {
            'browseable': 'yes',
            'create mask': '0755',
            'hosts deny': '0.0.0.0/0',
            'hosts allow': '127.0.0.1',
        }
        execute_return_values.extend([''] * len(parameters))
        self._helper._execute = mock.Mock(side_effect=execute_return_values)
        ret = self._helper.create_export('fakelocalpath', share_name,
                                         recreate=True)
        expected_ret = "//127.0.0.1/%s" % (share_name,)
        calls = [mock.call('net', 'conf', 'setparm', share_name, name,
                           value, run_as_root=True) for
                 name, value in parameters.items()]
        self._helper._execute.assert_has_calls(calls)
        self.assertEqual(ret, expected_ret)

    def test_create_export_error(self):
        share_name = self.share['name']

        def raise_exec_error(*args, **kwargs):
            raise exception.ProcessExecutionError(stderr="fake_stderr")

        self._helper._execute = mock.Mock(
            side_effect=raise_exec_error)
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper.create_export, 'fakelocalpath',
                          share_name)

    def test_remove_export(self):
        share_name = self.share['name']
        self._helper._execute = mock.Mock()
        self._helper.remove_export('fakelocalpath', share_name)
        self._helper._execute.assert_called_with('smbcontrol', 'all',
                                                 'close-share', share_name,
                                                 run_as_root=True)

    def test_remove_export_no_such_service(self):
        share_name = self.share['name']

        def exec_return(*args, **kwargs):
            if 'net' in args:
                raise exception.ProcessExecutionError(
                    stderr='SBC_ERR_NO_SUCH_SERVICE')

        self._helper._execute = mock.Mock(side_effect=exec_return)
        self._helper.remove_export('fakelocalpath', share_name)
        self._helper._execute.assert_called_with(
            'smbcontrol', 'all', 'close-share', share_name, run_as_root=True)

    def test_remove_export_error(self):
        share_name = self.share['name']

        def raise_exec_error(*args, **kwargs):
            raise exception.ProcessExecutionError(stderr="fake_stderr")
        self._helper._execute = mock.Mock(
            side_effect=raise_exec_error)

        self.assertRaises(exception.ProcessExecutionError,
                          self._helper.remove_export, 'fakelocalpath',
                          share_name)

    def test_allow_access(self):
        share_name = self.share['name']
        self._helper._get_allow_hosts = mock.Mock(return_value=['127.0.0.1',
                                                                '10.0.0.1'])
        self._helper._set_allow_hosts = mock.Mock()
        self._helper.allow_access('fakelocalpath', share_name, 'ip',
                                  '10.0.0.2')
        self._helper._set_allow_hosts.assert_called_with(
            ['127.0.0.1', '10.0.0.1', '10.0.0.2'], share_name)

    def test_allow_access_exists(self):
        share_name = self.share['name']
        self._helper._get_allow_hosts = mock.Mock(return_value=['127.0.0.1',
                                                                '10.0.0.1'])
        self.assertRaises(exception.ShareAccessExists,
                          self._helper.allow_access, 'fakelocalpath',
                          share_name, 'ip', '10.0.0.1')

    def test_allow_access_wrong_type(self):
        share_name = self.share['name']
        self.assertRaises(exception.InvalidShareAccess,
                          self._helper.allow_access, 'fakelocalpath',
                          share_name, 'fake', 'fake access')

    def test_deny_access(self):
        share_name = self.share['name']
        self._helper._get_allow_hosts = mock.Mock(return_value=['127.0.0.1',
                                                                '10.0.0.1'])
        self._helper._set_allow_hosts = mock.Mock()
        self._helper.deny_access('fakelocalpath', share_name, 'ip',
                                 '10.0.0.1')
        self._helper._set_allow_hosts.assert_called_with(
            ['127.0.0.1'], share_name)

    def test_deny_access_not_exists(self):
        share_name = self.share['name']

        def raise_exec_error(*args, **kwargs):
            raise exception.ProcessExecutionError(stdout="does not exist")

        self._helper._get_allow_hosts = mock.Mock(side_effect=raise_exec_error)
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper.deny_access, 'fakelocalpath',
                          share_name, 'ip', '10.0.0.1')

    def test_deny_access_not_exists_force(self):
        share_name = self.share['name']

        def raise_exec_error(*args, **kwargs):
            raise exception.ProcessExecutionError(stdout="does not exist")

        self._helper._get_allow_hosts = mock.Mock(side_effect=raise_exec_error)
        self._helper.deny_access('fakelocalpath', share_name, 'ip', '10.0.0.1',
                                 force=True)

    def test_deny_access_error(self):
        share_name = self.share['name']

        def raise_exec_error(*args, **kwargs):
            raise exception.ProcessExecutionError(stdout="fake out")

        self._helper._get_allow_hosts = mock.Mock(side_effect=raise_exec_error)
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper.deny_access, 'fakelocalpath',
                          share_name, 'ip', '10.0.0.1')

    def test_get_allow_hosts(self):
        share_name = self.share['name']
        self._helper._execute = mock.Mock(return_value=(
            '127.0.0.1 10.0.0.1', ''))
        ret = self._helper._get_allow_hosts(share_name)
        self.assertEqual(ret, ['127.0.0.1', '10.0.0.1'])

    def test_set_allow_hosts(self):
        share_name = self.share['name']
        self._helper._execute = mock.Mock()
        self._helper._set_allow_hosts(['127.0.0.1', '10.0.0.1'], share_name)
        self._helper._execute.assert_called_with(
            'net', 'conf', 'setparm', share_name, 'hosts allow',
            '127.0.0.1 10.0.0.1', run_as_root=True)
