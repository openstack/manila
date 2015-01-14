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
from oslo_config import cfg

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
        CONF.set_default('glusterfs_server_password',
                         'fake_password')
        CONF.set_default('glusterfs_path_to_private_key',
                         '/fakepath/to/privatekey')
        CONF.set_default('driver_handles_share_servers', False)

        self.fake_conf = config.Configuration(None)
        self._db = mock.Mock()
        self._driver = glusterfs_native.GlusterfsNativeShareDriver(
            self._db, execute=self._execute,
            configuration=self.fake_conf)
        self.stubs.Set(tempfile, 'mkdtemp',
                       mock.Mock(return_value='/tmp/tmpKGHKJ'))
        self.stubs.Set(glusterfs.GlusterManager, 'make_gluster_call',
                       mock.Mock())
        self.addCleanup(fake_utils.fake_execute_set_repliers, [])
        self.addCleanup(fake_utils.fake_execute_clear_log)

    def test_do_setup(self):
        self._driver._setup_gluster_vols = mock.Mock()
        self._db.share_get_all = mock.Mock(return_value=[])
        expected_exec = ['mount.glusterfs']
        gmgr = glusterfs.GlusterManager

        self._driver.do_setup(self._context)

        self.assertEqual(2, len(self._driver.gluster_unused_vols_dict))
        self.assertTrue(
            gmgr(self.gluster_target1, self._execute, None, None).export in
            self._driver.gluster_unused_vols_dict)
        self.assertTrue(
            gmgr(self.gluster_target2, self._execute, None, None).export in
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
        test_args = [
            ('volume', 'set', 'gv2', 'nfs.export-volumes', 'off'),
            ('volume', 'set', 'gv2', 'client.ssl', 'on'),
            ('volume', 'set', 'gv2', 'server.ssl', 'on')]
        self._driver._restart_gluster_vol = mock.Mock()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}

        self._driver._setup_gluster_vols()
        gmgr2.gluster_call.has_calls(
            mock.call(*test_args[0]),
            mock.call(*test_args[1]),
            mock.call(*test_args[2]))
        self.assertTrue(self._driver._restart_gluster_vol.called)

    def test_setup_gluster_vols_excp1(self):
        test_args = ('volume', 'set', 'gv2', 'nfs.export-volumes', 'off')

        def raise_exception(*args, **kwargs):
            if(args == test_args):
                raise exception.ProcessExecutionError()

        self._driver._restart_gluster_vol = mock.Mock()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}
        self.stubs.Set(gmgr2, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        self.assertRaises(exception.GlusterfsException,
                          self._driver._setup_gluster_vols)
        gmgr2.gluster_call.assert_called_once_with(*test_args)
        self.assertFalse(self._driver._restart_gluster_vol.called)

    def test_setup_gluster_vols_excp2(self):
        test_args = [
            ('volume', 'set', 'gv2', 'nfs.export-volumes', 'off'),
            ('volume', 'set', 'gv2', 'client.ssl', 'on'),
            ('volume', 'set', 'gv2', 'server.ssl', 'off')]

        def raise_exception(*args, **kwargs):
            if(args == test_args[1]):
                raise exception.ProcessExecutionError()

        self._driver._restart_gluster_vol = mock.Mock()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}
        self.stubs.Set(gmgr2, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        self.assertRaises(exception.GlusterfsException,
                          self._driver._setup_gluster_vols)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1])],
            gmgr2.gluster_call.call_args_list)
        self.assertFalse(self._driver._restart_gluster_vol.called)

    def test_setup_gluster_vols_excp3(self):
        test_args = [
            ('volume', 'set', 'gv2', 'nfs.export-volumes', 'off'),
            ('volume', 'set', 'gv2', 'client.ssl', 'on'),
            ('volume', 'set', 'gv2', 'server.ssl', 'on')]

        def raise_exception(*args, **kwargs):
            if(args == test_args[2]):
                raise exception.ProcessExecutionError()

        self._driver._restart_gluster_vol = mock.Mock()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}
        self.stubs.Set(gmgr2, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        self.assertRaises(exception.GlusterfsException,
                          self._driver._setup_gluster_vols)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1]),
             mock.call(*test_args[2])],
            gmgr2.gluster_call.call_args_list)
        self.assertFalse(self._driver._restart_gluster_vol.called)

    def test_restart_gluster_vol(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        test_args = [('volume', 'stop', 'gv1', '--mode=script'),
                     ('volume', 'start', 'gv1')]

        self._driver._restart_gluster_vol(gmgr1)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1])],
            gmgr1.gluster_call.call_args_list)

    def test_restart_gluster_vol_excp1(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        test_args = ('volume', 'stop', 'gv1', '--mode=script')

        def raise_exception(*args, **kwargs):
            if(args == test_args):
                raise exception.ProcessExecutionError()

        self.stubs.Set(gmgr1, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        self.assertRaises(exception.GlusterfsException,
                          self._driver._restart_gluster_vol, gmgr1)
        self.assertEqual(
            [mock.call(*test_args)],
            gmgr1.gluster_call.call_args_list)

    def test_restart_gluster_vol_excp2(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        test_args = [('volume', 'stop', 'gv1', '--mode=script'),
                     ('volume', 'start', 'gv1')]

        def raise_exception(*args, **kwargs):
            if(args == test_args[1]):
                raise exception.ProcessExecutionError()

        self.stubs.Set(gmgr1, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        self.assertRaises(exception.GlusterfsException,
                          self._driver._restart_gluster_vol, gmgr1)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1])],
            gmgr1.gluster_call.call_args_list)

    def test_pop_gluster_vol(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}

        exp_locn = self._driver._pop_gluster_vol()

        self.assertEqual(0, len(self._driver.gluster_unused_vols_dict))
        self.assertFalse(
            gmgr2.export in self._driver.gluster_unused_vols_dict)
        self.assertEqual(2, len(self._driver.gluster_used_vols_dict))
        self.assertTrue(
            gmgr2.export in self._driver.gluster_used_vols_dict)
        self.assertEqual(exp_locn, gmgr2.export)

    def test_pop_gluster_vol_excp(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {
            gmgr2.export: gmgr2, gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {}

        self.assertRaises(exception.GlusterfsException,
                          self._driver._pop_gluster_vol)

    def test_push_gluster_vol(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {
            gmgr1.export: gmgr1, gmgr2.export: gmgr2}
        self._driver.gluster_unused_vols_dict = {}

        self._driver._push_gluster_vol(gmgr2.export)

        self.assertEqual(1, len(self._driver.gluster_unused_vols_dict))
        self.assertTrue(
            gmgr2.export in self._driver.gluster_unused_vols_dict)
        self.assertEqual(1, len(self._driver.gluster_used_vols_dict))
        self.assertFalse(
            gmgr2.export in self._driver.gluster_used_vols_dict)

    def test_push_gluster_vol_excp(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {}

        self.assertRaises(exception.GlusterfsException,
                          self._driver._push_gluster_vol, gmgr2.export)

    def test_do_mount(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        tmpdir = '/tmp/tmpKGHKJ'
        expected_exec = ['mount -t glusterfs host1:/gv1 /tmp/tmpKGHKJ']

        self._driver._do_mount(gmgr1.export, tmpdir)

        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_do_mount_excp(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        tmpdir = '/tmp/tmpKGHKJ'
        expected_exec = ['mount -t glusterfs host1:/gv1 /tmp/tmpKGHKJ']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._do_mount, gmgr1.export, tmpdir)

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
        test_args = [
            ('volume', 'set', 'gv1', 'client.ssl', 'off'),
            ('volume', 'set', 'gv1', 'server.ssl', 'off'),
            ('volume', 'set', 'gv1', 'client.ssl', 'on'),
            ('volume', 'set', 'gv1', 'server.ssl', 'on')]

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)

        expected_exec = ['find /tmp/tmpKGHKJ -mindepth 1 -delete']

        self._driver._wipe_gluster_vol(gmgr1)

        self.assertEqual(2, self._driver._restart_gluster_vol.call_count)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1]),
             mock.call(*test_args[2]), mock.call(*test_args[3])],
            gmgr1.gluster_call.call_args_list)
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
        test_args = ('volume', 'set', 'gv1', 'client.ssl', 'off')

        def raise_exception(*args, **kwargs):
            if(args == test_args):
                raise exception.ProcessExecutionError()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        self.stubs.Set(gmgr1, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gmgr1)
        self.assertEqual(
            [mock.call(*test_args)], gmgr1.gluster_call.call_args_list)
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
        test_args = [
            ('volume', 'set', 'gv1', 'client.ssl', 'off'),
            ('volume', 'set', 'gv1', 'server.ssl', 'off')]

        def raise_exception(*args, **kwargs):
            if(args == test_args[1]):
                raise exception.ProcessExecutionError()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        self.stubs.Set(gmgr1, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gmgr1)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1])],
            gmgr1.gluster_call.call_args_list)
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
        test_args = [
            ('volume', 'set', 'gv1', 'client.ssl', 'off'),
            ('volume', 'set', 'gv1', 'server.ssl', 'off'),
            ('volume', 'set', 'gv1', 'client.ssl', 'on')]

        def raise_exception(*args, **kwargs):
            if(args == test_args[2]):
                raise exception.ProcessExecutionError()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        self.stubs.Set(gmgr1, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        expected_exec = ['find /tmp/tmpKGHKJ -mindepth 1 -delete']

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gmgr1)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1]),
             mock.call(*test_args[2])],
            gmgr1.gluster_call.call_args_list)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
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
        test_args = [
            ('volume', 'set', 'gv1', 'client.ssl', 'off'),
            ('volume', 'set', 'gv1', 'server.ssl', 'off'),
            ('volume', 'set', 'gv1', 'client.ssl', 'on'),
            ('volume', 'set', 'gv1', 'server.ssl', 'on')]

        def raise_exception(*args, **kwargs):
            if(args == test_args[3]):
                raise exception.ProcessExecutionError()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        self.stubs.Set(gmgr1, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        expected_exec = ['find /tmp/tmpKGHKJ -mindepth 1 -delete']

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gmgr1)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1]),
             mock.call(*test_args[2]), mock.call(*test_args[3])],
            gmgr1.gluster_call.call_args_list)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
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

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)

        test_args = [
            ('volume', 'set', 'gv1', 'client.ssl', 'off'),
            ('volume', 'set', 'gv1', 'server.ssl', 'off')]

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError

        expected_exec = [
            'find /tmp/tmpKGHKJ -mindepth 1 -delete']

        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gmgr1)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1])],
            gmgr1.gluster_call.call_args_list)
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

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)

        test_args = [
            ('volume', 'set', 'gv1', 'client.ssl', 'off'),
            ('volume', 'set', 'gv1', 'server.ssl', 'off')]

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gmgr1)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1])],
            gmgr1.gluster_call.call_args_list)
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

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)

        test_args = [
            ('volume', 'set', 'gv1', 'client.ssl', 'off'),
            ('volume', 'set', 'gv1', 'server.ssl', 'off')]

        expected_exec = ['find /tmp/tmpKGHKJ -mindepth 1 -delete']

        self.assertRaises(exception.GlusterfsException,
                          self._driver._wipe_gluster_vol, gmgr1)
        self.assertEqual(
            [mock.call(*test_args[0]), mock.call(*test_args[1])],
            gmgr1.gluster_call.call_args_list)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertTrue(self._driver._restart_gluster_vol.called)
        self.assertTrue(tempfile.mkdtemp.called)
        self.assertTrue(self._driver._do_mount.called)
        self.assertTrue(self._driver._do_umount.called)
        self.assertFalse(shutil.rmtree.called)

    def test_create_share(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}

        share = new_share()

        exp_locn = self._driver.create_share(self._context, share)

        self.assertEqual(exp_locn, gmgr2.export)

    def test_create_share_excp(self):
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {
            gmgr2.export: gmgr2, gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {}

        share = new_share()

        self.assertRaises(exception.GlusterfsException,
                          self._driver.create_share, self._context, share)

    def test_delete_share(self):
        self._driver._wipe_gluster_vol = mock.Mock()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {
            gmgr2.export: gmgr2, gmgr1.export: gmgr1}
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

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {}
        self._driver.gluster_unused_vols_dict = {
            gmgr2.export: gmgr2, gmgr1.export: gmgr1}

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

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)

        self._driver.gluster_used_vols_dict = {
            gmgr2.export: gmgr2, gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {}

        share = fake_db_share2()[0]

        self.assertRaises(exception.GlusterfsException,
                          self._driver.delete_share, self._context, share)

        self.assertTrue(self._driver._wipe_gluster_vol.called)
        self.assertFalse(self._driver._push_gluster_vol.called)

    def test_allow_access(self):
        self._driver._restart_gluster_vol = mock.Mock()
        access = {'access_type': 'cert', 'access_to': 'client.example.com'}
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)
        test_args = ('volume', 'set', 'gv1', 'auth.ssl-allow',
                     access['access_to'])

        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}

        share = fake_db_share1()[0]

        self._driver.allow_access(self._context, share, access)
        gmgr1.gluster_call.assert_called_once_with(*test_args)
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
        access = {'access_type': 'cert', 'access_to': 'client.example.com'}
        test_args = ('volume', 'set', 'gv1', 'auth.ssl-allow',
                     access['access_to'])

        def raise_exception(*args, **kwargs):
            if (args == test_args):
                raise exception.ProcessExecutionError()

        self._driver._restart_gluster_vol = mock.Mock()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)
        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}

        self.stubs.Set(gmgr1, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))
        share = fake_db_share1()[0]

        self.assertRaises(exception.GlusterfsException,
                          self._driver.allow_access,
                          self._context, share, access)
        gmgr1.gluster_call.assert_called_once_with(*test_args)
        self.assertFalse(self._driver._restart_gluster_vol.called)

    def test_deny_access(self):
        self._driver._restart_gluster_vol = mock.Mock()
        access = {'access_type': 'cert', 'access_to': 'NotApplicable'}
        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)
        test_args = ('volume', 'reset', 'gv1', 'auth.ssl-allow')

        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}

        share = fake_db_share1()[0]

        self._driver.deny_access(self._context, share, access)
        gmgr1.gluster_call.assert_called_once_with(*test_args)
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
        access = {'access_type': 'cert', 'access_to': 'NotApplicable'}
        test_args = ('volume', 'reset', 'gv1', 'auth.ssl-allow')

        def raise_exception(*args, **kwargs):
            if (args == test_args):
                raise exception.ProcessExecutionError()

        self._driver._restart_gluster_vol = mock.Mock()

        gmgr = glusterfs.GlusterManager
        gmgr1 = gmgr(self.gluster_target1, self._execute, None, None)
        gmgr2 = gmgr(self.gluster_target2, self._execute, None, None)
        self._driver.gluster_used_vols_dict = {gmgr1.export: gmgr1}
        self._driver.gluster_unused_vols_dict = {gmgr2.export: gmgr2}

        self.stubs.Set(gmgr1, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))

        share = fake_db_share1()[0]

        self.assertRaises(exception.GlusterfsException,
                          self._driver.deny_access,
                          self._context, share, access)
        gmgr1.gluster_call.assert_called_once_with(*test_args)
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
            'driver_handles_share_servers': False,
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
