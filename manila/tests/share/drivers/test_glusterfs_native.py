# Copyright (c) 2014 Red Hat, Inc.
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

""" GlusterFS native protocol (glusterfs) driver for shares.

Test cases for GlusterFS native protocol driver.
"""


import shutil
import tempfile

import mock
from oslo.config import cfg

from manila import context
from manila import exception
from manila.share import configuration as config
from manila.share.drivers import glusterfs
from manila.share.drivers import glusterfs_native
from manila import test
from manila.tests import fake_utils


CONF = cfg.CONF


def fake_db_share1(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'glusterfs',
        'export_location': 'host1:/gv1',
    }
    share.update(kwargs)
    return [share]


def fake_db_share2(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'glusterfs',
        'export_location': 'host2:/gv2',
    }
    share.update(kwargs)
    return [share]


def new_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'glusterfs',
    }
    share.update(kwargs)
    return share


class GlusterfsNativeShareDriverTestCase(test.TestCase):
    """Tests GlusterfsNativeShareDriver."""

    def setUp(self):
        super(GlusterfsNativeShareDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self._execute = fake_utils.fake_execute
        self._context = context.get_admin_context()

        self.gluster_target1 = 'root@host1:/gv1'
        self.gluster_target2 = 'root@host2:/gv2'
        CONF.set_default('glusterfs_targets',
                         [self.gluster_target1, self.gluster_target2])

        self.fake_conf = config.Configuration(None)
        self._db = mock.Mock()
        self._driver = glusterfs_native.GlusterfsNativeShareDriver(
            self._db, execute=self._execute,
            configuration=self.fake_conf)
        self.stubs.Set(tempfile, 'mkdtemp',
                       mock.Mock(return_value='/tmp/tmpKGHKJ'))

        self.addCleanup(fake_utils.fake_execute_set_repliers, [])
        self.addCleanup(fake_utils.fake_execute_clear_log)

    def test_do_setup(self):
        self._driver._setup_gluster_vols = mock.Mock()
        self._db.share_get_all = mock.Mock(return_value=[])
        expected_exec = ['mount.glusterfs']
        gaddr = glusterfs.GlusterAddress

        self._driver.do_setup(self._context)

        self.assertEqual(2, len(self._driver.gluster_unused_vols_dict))
        self.assertTrue(gaddr(self.gluster_target1).export in
                        self._driver.gluster_unused_vols_dict)
        self.assertTrue(gaddr(self.gluster_target2).export in
                        self._driver.gluster_unused_vols_dict)
        self.assertTrue(self._driver._setup_gluster_vols.called)
        self.assertTrue(self._db.share_get_all.called)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_do_setup_glusterfs_targets_empty(self):
        self._driver.configuration.glusterfs_targets = []
        self.assertRaises(exception.GlusterfsException, self._driver.do_setup,
                          self._context)

    def test_update_gluster_vols_dict(self):
        self._db.share_get_all = mock.Mock(return_value=fake_db_share1())

        self._driver._update_gluster_vols_dict(self._context)

        self.assertEqual(1, len(self._driver.gluster_used_vols_dict))
        self.assertEqual(1, len(self._driver.gluster_unused_vols_dict))
        self.assertTrue(self._db.share_get_all.called)

        share_in_use = fake_db_share1()[0]
        share_not_in_use = fake_db_share2()[0]

        self.assertTrue(
            share_in_use['export_location'] in
            self._driver.gluster_used_vols_dict)
        self.assertFalse(
            share_not_in_use['export_location'] in
            self._driver.gluster_used_vols_dict)
        self.assertTrue(
            share_not_in_use['export_location'] in
            self._driver.gluster_unused_vols_dict)
        self.assertFalse(
            share_in_use['export_location'] in
            self._driver.gluster_unused_vols_dict)

    def test_setup_gluster_vols(self):
        self._driver._restart_gluster_vol = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        expected_exec = [
            'ssh root@host2 gluster volume set gv2 nfs.export-volumes off',
            'ssh root@host2 gluster volume set gv2 client.ssl on',
            'ssh root@host2 gluster volume set gv2 server.ssl on']

        self._driver._setup_gluster_vols()

        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertTrue(self._driver._restart_gluster_vol.called)

    def test_setup_gluster_vols_excp1(self):
        self._driver._restart_gluster_vol = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host2 gluster volume set gv2 nfs.export-volumes off']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._setup_gluster_vols)
        self.assertFalse(self._driver._restart_gluster_vol.called)

    def test_setup_gluster_vols_excp2(self):
        self._driver._restart_gluster_vol = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host2 gluster volume set gv2 client.ssl on']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._setup_gluster_vols)
        self.assertFalse(self._driver._restart_gluster_vol.called)

    def test_setup_gluster_vols_excp3(self):
        self._driver._restart_gluster_vol = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host2 gluster volume set gv2 server.ssl on']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._setup_gluster_vols)
        self.assertFalse(self._driver._restart_gluster_vol.called)

    def test_restart_gluster_vol(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        expected_exec = [
            'ssh root@host1 gluster volume stop gv1 --mode=script',
            'ssh root@host1 gluster volume start gv1']

        self._driver._restart_gluster_vol(gaddr1)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_restart_gluster_vol_excp1(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host1 gluster volume stop gv1 --mode=script']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._restart_gluster_vol, gaddr1)

    def test_restart_gluster_vol_excp2(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host1 gluster volume start gv1']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._restart_gluster_vol, gaddr1)

    def test_pop_gluster_vol(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        exp_locn = self._driver._pop_gluster_vol()

        self.assertEqual(0, len(self._driver.gluster_unused_vols_dict))
        self.assertFalse(
            gaddr2.export in self._driver.gluster_unused_vols_dict)
        self.assertEqual(2, len(self._driver.gluster_used_vols_dict))
        self.assertTrue(
            gaddr2.export in self._driver.gluster_used_vols_dict)
        self.assertEqual(exp_locn, gaddr2.export)

    def test_pop_gluster_vol_excp(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {
            gaddr2.export: gaddr2, gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {}

        self.assertRaises(exception.GlusterfsException,
                          self._driver._pop_gluster_vol)

    def test_push_gluster_vol(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {
            gaddr1.export: gaddr1, gaddr2.export: gaddr2}
        self._driver.gluster_unused_vols_dict = {}

        self._driver._push_gluster_vol(gaddr2.export)

        self.assertEqual(1, len(self._driver.gluster_unused_vols_dict))
        self.assertTrue(
            gaddr2.export in self._driver.gluster_unused_vols_dict)
        self.assertEqual(1, len(self._driver.gluster_used_vols_dict))
        self.assertFalse(
            gaddr2.export in self._driver.gluster_used_vols_dict)

    def test_push_gluster_vol_excp(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {}

        self.assertRaises(exception.GlusterfsException,
                          self._driver._push_gluster_vol, gaddr2.export)

    def test_do_mount(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        tmpdir = '/tmp/tmpKGHKJ'
        expected_exec = ['mount -t glusterfs host1:/gv1 /tmp/tmpKGHKJ']

        self._driver._do_mount(gaddr1.export, tmpdir)

        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_do_mount_excp(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        tmpdir = '/tmp/tmpKGHKJ'
        expected_exec = ['mount -t glusterfs host1:/gv1 /tmp/tmpKGHKJ']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._do_mount, gaddr1.export, tmpdir)

    def test_do_umount(self):
        tmpdir = '/tmp/tmpKGHKJ'
        expected_exec = ['umount /tmp/tmpKGHKJ']

        self._driver._do_umount(tmpdir)

        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_do_umount_excp(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        tmpdir = '/tmp/tmpKGHKJ'
        expected_exec = ['umount /tmp/tmpKGHKJ']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._do_umount, tmpdir)

    def test_wipe_gluster_vol(self):
        self._driver._restart_gluster_vol = mock.Mock()
        self._driver._do_mount = mock.Mock()
        self._driver._do_umount = mock.Mock()
        shutil.rmtree = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        expected_exec = [
            'ssh root@host1 gluster volume set gv1 client.ssl off',
            'ssh root@host1 gluster volume set gv1 server.ssl off',
            'find /tmp/tmpKGHKJ -mindepth 1 -delete',
            'ssh root@host1 gluster volume set gv1 client.ssl on',
            'ssh root@host1 gluster volume set gv1 server.ssl on']

        self._driver._wipe_gluster_vol(gaddr1)

        self.assertEqual(2, self._driver._restart_gluster_vol.call_count)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertTrue(tempfile.mkdtemp.called)
        self.assertTrue(self._driver._do_mount.called)
        self.assertTrue(self._driver._do_umount.called)
        self.assertTrue(shutil.rmtree.called)

    def test_wipe_gluster_vol_excp1(self):
        self._driver._restart_gluster_vol = mock.Mock()
        self._driver._do_mount = mock.Mock()
        self._driver._do_umount = mock.Mock()
        shutil.rmtree = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host1 gluster volume set gv1 client.ssl off']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gaddr1)

        self.assertFalse(self._driver._restart_gluster_vol.called)
        self.assertFalse(tempfile.mkdtemp.called)
        self.assertFalse(self._driver._do_mount.called)
        self.assertFalse(self._driver._do_umount.called)
        self.assertFalse(shutil.rmtree.called)

    def test_wipe_gluster_vol_excp2(self):
        self._driver._restart_gluster_vol = mock.Mock()
        self._driver._do_mount = mock.Mock()
        self._driver._do_umount = mock.Mock()
        shutil.rmtree = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host1 gluster volume set gv1 server.ssl off']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gaddr1)

        self.assertFalse(self._driver._restart_gluster_vol.called)
        self.assertFalse(tempfile.mkdtemp.called)
        self.assertFalse(self._driver._do_mount.called)
        self.assertFalse(self._driver._do_umount.called)
        self.assertFalse(shutil.rmtree.called)

    def test_wipe_gluster_vol_excp3(self):
        self._driver._restart_gluster_vol = mock.Mock()
        self._driver._do_mount = mock.Mock()
        self._driver._do_umount = mock.Mock()
        shutil.rmtree = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host1 gluster volume set gv1 client.ssl on']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gaddr1)

        self.assertTrue(self._driver._restart_gluster_vol.called)
        self.assertTrue(tempfile.mkdtemp.called)
        self.assertTrue(self._driver._do_mount.called)
        self.assertTrue(self._driver._do_umount.called)
        self.assertTrue(shutil.rmtree.called)

    def test_wipe_gluster_vol_excp4(self):
        self._driver._restart_gluster_vol = mock.Mock()
        self._driver._do_mount = mock.Mock()
        self._driver._do_umount = mock.Mock()
        shutil.rmtree = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host1 gluster volume set gv1 server.ssl on']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gaddr1)

        self.assertTrue(self._driver._restart_gluster_vol.called)
        self.assertTrue(tempfile.mkdtemp.called)
        self.assertTrue(self._driver._do_mount.called)
        self.assertTrue(self._driver._do_umount.called)
        self.assertTrue(shutil.rmtree.called)

    def test_wipe_gluster_vol_excp5(self):
        self._driver._restart_gluster_vol = mock.Mock()
        self._driver._do_mount = mock.Mock()
        self._driver._do_umount = mock.Mock()
        shutil.rmtree = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'find /tmp/tmpKGHKJ -mindepth 1 -delete']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gaddr1)

        self.assertTrue(self._driver._restart_gluster_vol.called)
        self.assertTrue(tempfile.mkdtemp.called)
        self.assertTrue(self._driver._do_mount.called)
        self.assertTrue(self._driver._do_umount.called)
        self.assertTrue(shutil.rmtree.called)

    def test_wipe_gluster_vol_mount_fail(self):
        self._driver._restart_gluster_vol = mock.Mock()
        self._driver._do_mount = mock.Mock()
        self._driver._do_mount.side_effect = exception.GlusterfsException
        self._driver._do_umount = mock.Mock()
        shutil.rmtree = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        expected_exec = [
            'ssh root@host1 gluster volume set gv1 client.ssl off',
            'ssh root@host1 gluster volume set gv1 server.ssl off']

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gaddr1)

        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertTrue(self._driver._restart_gluster_vol.called)
        self.assertTrue(tempfile.mkdtemp.called)
        self.assertTrue(self._driver._do_mount.called)
        self.assertFalse(self._driver._do_umount.called)
        self.assertTrue(shutil.rmtree.called)

    def test_wipe_gluster_vol_umount_fail(self):
        self._driver._restart_gluster_vol = mock.Mock()
        self._driver._do_mount = mock.Mock()
        self._driver._do_umount = mock.Mock()
        self._driver._do_umount.side_effect = exception.GlusterfsException
        shutil.rmtree = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)

        expected_exec = [
            'ssh root@host1 gluster volume set gv1 client.ssl off',
            'ssh root@host1 gluster volume set gv1 server.ssl off',
            'find /tmp/tmpKGHKJ -mindepth 1 -delete']

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gaddr1)

        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertTrue(self._driver._restart_gluster_vol.called)
        self.assertTrue(tempfile.mkdtemp.called)
        self.assertTrue(self._driver._do_mount.called)
        self.assertTrue(self._driver._do_umount.called)
        self.assertFalse(shutil.rmtree.called)

    def test_create_share(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        share = new_share()

        exp_locn = self._driver.create_share(self._context, share)

        self.assertEqual(exp_locn, gaddr2.export)

    def test_create_share_excp(self):
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {
            gaddr2.export: gaddr2, gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {}

        share = new_share()

        self.assertRaises(exception.GlusterfsException,
                          self._driver.create_share, self._context, share)

    def test_delete_share(self):
        self._driver._wipe_gluster_vol = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {
            gaddr2.export: gaddr2, gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {}

        share = fake_db_share2()[0]

        self._driver.delete_share(self._context, share)

        self.assertEqual(1, len(self._driver.gluster_used_vols_dict))
        self.assertEqual(1, len(self._driver.gluster_unused_vols_dict))
        self.assertTrue(self._driver._wipe_gluster_vol.called)

    def test_delete_share_warn(self):
        glusterfs_native.LOG.warn = mock.Mock()
        self._driver._wipe_gluster_vol = mock.Mock()
        self._driver._push_gluster_vol = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {}
        self._driver.gluster_unused_vols_dict = {
            gaddr2.export: gaddr2, gaddr1.export: gaddr1}

        share = fake_db_share2()[0]

        self._driver.delete_share(self._context, share)

        self.assertTrue(glusterfs_native.LOG.warn.called)
        self.assertFalse(self._driver._wipe_gluster_vol.called)
        self.assertFalse(self._driver._push_gluster_vol.called)

    def test_delete_share_excp1(self):
        self._driver._wipe_gluster_vol = mock.Mock()
        self._driver._wipe_gluster_vol.side_effect = (
            exception.GlusterfsException)
        self._driver._push_gluster_vol = mock.Mock()

        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {
            gaddr2.export: gaddr2, gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {}

        share = fake_db_share2()[0]

        self.assertRaises(exception.GlusterfsException,
                          self._driver.delete_share, self._context, share)

        self.assertTrue(self._driver._wipe_gluster_vol.called)
        self.assertFalse(self._driver._push_gluster_vol.called)

    def test_allow_access(self):
        self._driver._restart_gluster_vol = mock.Mock()
        access = {'access_type': 'cert', 'access_to': 'client.example.com'}
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        share = fake_db_share1()[0]

        expected_exec = [
            'ssh root@host1 gluster volume set gv1 '
            'auth.ssl-allow client.example.com']

        self._driver.allow_access(self._context, share, access)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertTrue(self._driver._restart_gluster_vol.called)

    def test_allow_access_invalid_access_type(self):
        self._driver._restart_gluster_vol = mock.Mock()
        access = {'access_type': 'invalid', 'access_to': 'client.example.com'}
        share = fake_db_share1()[0]
        expected_exec = []

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.allow_access,
                          self._context, share, access)
        self.assertFalse(self._driver._restart_gluster_vol.called)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_allow_access_excp(self):
        self._driver._restart_gluster_vol = mock.Mock()
        access = {'access_type': 'cert', 'access_to': 'client.example.com'}
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        share = fake_db_share1()[0]

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'ssh root@host1 gluster volume set gv1 '
            'auth.ssl-allow client.example.com']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver.allow_access,
                          self._context, share, access)
        self.assertFalse(self._driver._restart_gluster_vol.called)

    def test_deny_access(self):
        self._driver._restart_gluster_vol = mock.Mock()
        access = {'access_type': 'cert', 'access_to': 'NotApplicable'}
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        share = fake_db_share1()[0]

        expected_exec = [
            'ssh root@host1 gluster volume reset gv1 auth.ssl-allow']

        self._driver.deny_access(self._context, share, access)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertTrue(self._driver._restart_gluster_vol.called)

    def test_deny_access_invalid_access_type(self):
        self._driver._restart_gluster_vol = mock.Mock()
        access = {'access_type': 'invalid', 'access_to': 'NotApplicable'}
        share = fake_db_share1()[0]
        expected_exec = []

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.deny_access,
                          self._context, share, access)
        self.assertFalse(self._driver._restart_gluster_vol.called)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_deny_access_excp(self):
        self._driver._restart_gluster_vol = mock.Mock()
        access = {'access_type': 'cert', 'access_to': 'NotApplicable'}
        gaddr = glusterfs.GlusterAddress
        gaddr1 = gaddr(self.gluster_target1)
        gaddr2 = gaddr(self.gluster_target2)

        self._driver.gluster_used_vols_dict = {gaddr1.export: gaddr1}
        self._driver.gluster_unused_vols_dict = {gaddr2.export: gaddr2}

        share = fake_db_share1()[0]

        expected_exec = [
            'ssh root@host1 gluster volume reset gv1 auth.ssl-allow']

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver.deny_access,
                          self._context, share, access)
        self.assertFalse(self._driver._restart_gluster_vol.called)

    def test_get_share_stats_refresh_false(self):
        self._driver._stats = mock.Mock()
        ret = self._driver.get_share_stats()
        self.assertEqual(ret, self._driver._stats)

    def test_get_share_stats_refresh_true(self):
        def foo():
            self._driver._stats = {'key': 'value'}
        self._driver._update_share_stats = mock.Mock(side_effect=foo)
        ret = self._driver.get_share_stats(refresh=True)
        self.assertEqual(ret, {'key': 'value'})

    def test_update_share_stats(self):
        test_data = {
            'share_backend_name': 'GlusterFS-Native',
            'vendor_name': 'Red Hat',
            'driver_version': '1.1',
            'storage_protocol': 'glusterfs',
            'reserved_percentage': 0,
            'QoS_support': False,
            'total_capacity_gb': 'infinite',
            'free_capacity_gb': 'infinite',
        }

        self._driver._update_share_stats()

        self.assertEqual(self._driver._stats, test_data)
