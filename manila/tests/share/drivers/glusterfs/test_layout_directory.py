# Copyright (c) 2015 Red Hat, Inc.
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

import os

import ddt
import mock
from oslo_config import cfg

from manila import context
from manila import exception
from manila.share import configuration as config
from manila.share.drivers.glusterfs import common
from manila.share.drivers.glusterfs import layout_directory
from manila import test
from manila.tests import fake_share
from manila.tests import fake_utils


CONF = cfg.CONF


fake_gluster_manager_attrs = {
    'export': '127.0.0.1:/testvol',
    'host': '127.0.0.1',
    'qualified': 'testuser@127.0.0.1:/testvol',
    'user': 'testuser',
    'volume': 'testvol',
    'path_to_private_key': '/fakepath/to/privatekey',
    'remote_server_password': 'fakepassword',
    'components': {'user': 'testuser', 'host': '127.0.0.1',
                   'volume': 'testvol', 'path': None}
}

fake_local_share_path = '/mnt/nfs/testvol/fakename'

fake_path_to_private_key = '/fakepath/to/privatekey'
fake_remote_server_password = 'fakepassword'


@ddt.ddt
class GlusterfsDirectoryMappedLayoutTestCase(test.TestCase):
    """Tests GlusterfsDirectoryMappedLayout."""

    def setUp(self):
        super(GlusterfsDirectoryMappedLayoutTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self)
        self._execute = fake_utils.fake_execute
        self._context = context.get_admin_context()
        self.addCleanup(fake_utils.fake_execute_set_repliers, [])
        self.addCleanup(fake_utils.fake_execute_clear_log)

        CONF.set_default('glusterfs_target', '127.0.0.1:/testvol')
        CONF.set_default('glusterfs_mount_point_base', '/mnt/nfs')
        CONF.set_default('glusterfs_server_password',
                         fake_remote_server_password)
        CONF.set_default('glusterfs_path_to_private_key',
                         fake_path_to_private_key)

        self.fake_driver = mock.Mock()
        self.mock_object(self.fake_driver, '_execute',
                         self._execute)
        self.fake_driver.GLUSTERFS_VERSION_MIN = (3, 6)
        self.fake_conf = config.Configuration(None)
        self.mock_object(common.GlusterManager, 'make_gluster_call')
        self._layout = layout_directory.GlusterfsDirectoryMappedLayout(
            self.fake_driver, configuration=self.fake_conf)
        self._layout.gluster_manager = mock.Mock(**fake_gluster_manager_attrs)
        self.share = fake_share.fake_share(share_proto='NFS')

    def test_do_setup(self):
        fake_gluster_manager = mock.Mock(**fake_gluster_manager_attrs)
        self.mock_object(fake_gluster_manager, 'get_gluster_version',
                         mock.Mock(return_value=('3', '5')))
        methods = ('_check_mount_glusterfs', '_ensure_gluster_vol_mounted')
        for method in methods:
            self.mock_object(self._layout, method)
        self.mock_object(common, 'GlusterManager',
                         mock.Mock(return_value=fake_gluster_manager))

        self._layout.do_setup(self._context)

        self.assertEqual(fake_gluster_manager, self._layout.gluster_manager)
        common.GlusterManager.assert_called_once_with(
            self._layout.configuration.glusterfs_target, self._execute,
            self._layout.configuration.glusterfs_path_to_private_key,
            self._layout.configuration.glusterfs_server_password,
            requires={'volume': True})
        self._layout.gluster_manager.gluster_call.assert_called_once_with(
            'volume', 'quota', 'testvol', 'enable')
        self._layout._check_mount_glusterfs.assert_called_once_with()
        self._layout._ensure_gluster_vol_mounted.assert_called_once_with()

    def test_do_setup_glusterfs_target_not_set(self):
        self._layout.configuration.glusterfs_target = None
        self.assertRaises(exception.GlusterfsException, self._layout.do_setup,
                          self._context)

    def test_do_setup_error_enabling_creation_share_specific_size(self):
        attrs = {'volume': 'testvol',
                 'gluster_call.side_effect': exception.GlusterfsException,
                 'get_vol_option.return_value': 'off'}
        fake_gluster_manager = mock.Mock(**attrs)
        self.mock_object(layout_directory.LOG, 'exception')
        methods = ('_check_mount_glusterfs', '_ensure_gluster_vol_mounted')
        for method in methods:
            self.mock_object(self._layout, method)
        self.mock_object(common, 'GlusterManager',
                         mock.Mock(return_value=fake_gluster_manager))

        self.assertRaises(exception.GlusterfsException, self._layout.do_setup,
                          self._context)

        self.assertEqual(fake_gluster_manager, self._layout.gluster_manager)
        common.GlusterManager.assert_called_once_with(
            self._layout.configuration.glusterfs_target, self._execute,
            self._layout.configuration.glusterfs_path_to_private_key,
            self._layout.configuration.glusterfs_server_password,
            requires={'volume': True})
        self._layout.gluster_manager.gluster_call.assert_called_once_with(
            'volume', 'quota', 'testvol', 'enable')
        (self._layout.gluster_manager.get_vol_option.
         assert_called_once_with('features.quota'))
        layout_directory.LOG.exception.assert_called_once_with(mock.ANY)
        self._layout._check_mount_glusterfs.assert_called_once_with()
        self.assertFalse(self._layout._ensure_gluster_vol_mounted.called)

    def test_do_setup_error_already_enabled_creation_share_specific_size(self):
        attrs = {'volume': 'testvol',
                 'gluster_call.side_effect': exception.GlusterfsException,
                 'get_vol_option.return_value': 'on'}
        fake_gluster_manager = mock.Mock(**attrs)
        self.mock_object(layout_directory.LOG, 'error')
        methods = ('_check_mount_glusterfs', '_ensure_gluster_vol_mounted')
        for method in methods:
            self.mock_object(self._layout, method)
        self.mock_object(common, 'GlusterManager',
                         mock.Mock(return_value=fake_gluster_manager))

        self._layout.do_setup(self._context)

        self.assertEqual(fake_gluster_manager, self._layout.gluster_manager)
        common.GlusterManager.assert_called_once_with(
            self._layout.configuration.glusterfs_target, self._execute,
            self._layout.configuration.glusterfs_path_to_private_key,
            self._layout.configuration.glusterfs_server_password,
            requires={'volume': True})
        self._layout.gluster_manager.gluster_call.assert_called_once_with(
            'volume', 'quota', 'testvol', 'enable')
        (self._layout.gluster_manager.get_vol_option.
         assert_called_once_with('features.quota'))
        self.assertFalse(layout_directory.LOG.error.called)
        self._layout._check_mount_glusterfs.assert_called_once_with()
        self._layout._ensure_gluster_vol_mounted.assert_called_once_with()

    def test_share_manager(self):
        self._layout._glustermanager = mock.Mock()

        self._layout._share_manager(self.share)

        self._layout._glustermanager.assert_called_once_with(
            {'user': 'testuser', 'host': '127.0.0.1',
             'volume': 'testvol', 'path': '/fakename'})

    def test_ensure_gluster_vol_mounted(self):
        common._mount_gluster_vol = mock.Mock()

        self._layout._ensure_gluster_vol_mounted()

        self.assertTrue(common._mount_gluster_vol.called)

    def test_ensure_gluster_vol_mounted_error(self):
        common._mount_gluster_vol = (
            mock.Mock(side_effect=exception.GlusterfsException))

        self.assertRaises(exception.GlusterfsException,
                          self._layout._ensure_gluster_vol_mounted)

    def test_get_local_share_path(self):
        with mock.patch.object(os, 'access', return_value=True):

            ret = self._layout._get_local_share_path(self.share)

            self.assertEqual('/mnt/nfs/testvol/fakename', ret)

    def test_local_share_path_not_exists(self):
        with mock.patch.object(os, 'access', return_value=False):

            self.assertRaises(exception.GlusterfsException,
                              self._layout._get_local_share_path,
                              self.share)

    def test_update_share_stats(self):
        test_statvfs = mock.Mock(f_frsize=4096, f_blocks=524288,
                                 f_bavail=524288)
        self._layout._get_mount_point_for_gluster_vol = (
            mock.Mock(return_value='/mnt/nfs/testvol'))
        some_no = 42
        not_some_no = some_no + 1
        os_stat = (lambda path: mock.Mock(st_dev=some_no) if path == '/mnt/nfs'
                   else mock.Mock(st_dev=not_some_no))
        with mock.patch.object(os, 'statvfs', return_value=test_statvfs):
            with mock.patch.object(os, 'stat', os_stat):

                ret = self._layout._update_share_stats()

                test_data = {
                    'total_capacity_gb': 2,
                    'free_capacity_gb': 2,
                }
                self.assertEqual(test_data, ret)

    def test_update_share_stats_gluster_mnt_unavailable(self):
        self._layout._get_mount_point_for_gluster_vol = (
            mock.Mock(return_value='/mnt/nfs/testvol'))
        some_no = 42
        with mock.patch.object(os, 'stat',
                               return_value=mock.Mock(st_dev=some_no)):

            self.assertRaises(exception.GlusterfsException,
                              self._layout._update_share_stats)

    @ddt.data((), (None,))
    def test_create_share(self, extra_args):
        exec_cmd1 = 'mkdir %s' % fake_local_share_path
        expected_exec = [exec_cmd1, ]
        expected_ret = 'testuser@127.0.0.1:/testvol/fakename'
        self.mock_object(
            self._layout, '_get_local_share_path',
            mock.Mock(return_value=fake_local_share_path))
        gmgr = mock.Mock()
        self.mock_object(
            self._layout, '_glustermanager', mock.Mock(return_value=gmgr))
        self.mock_object(
            self._layout.driver, '_setup_via_manager',
            mock.Mock(return_value=expected_ret))

        ret = self._layout.create_share(self._context, self.share, *extra_args)

        self._layout._get_local_share_path.called_once_with(self.share)
        self._layout.gluster_manager.gluster_call.assert_called_once_with(
            'volume', 'quota', 'testvol', 'limit-usage', '/fakename', '1GB')
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self._layout._glustermanager.assert_called_once_with(
            {'user': 'testuser', 'host': '127.0.0.1',
             'volume': 'testvol', 'path': '/fakename'})
        self._layout.driver._setup_via_manager.assert_called_once_with(
            {'share': self.share, 'manager': gmgr})
        self.assertEqual(expected_ret, ret)

    @ddt.data(exception.ProcessExecutionError, exception.GlusterfsException)
    def test_create_share_unable_to_create_share(self, trouble):
        def exec_runner(*ignore_args, **ignore_kw):
            raise trouble

        self.mock_object(
            self._layout, '_get_local_share_path',
            mock.Mock(return_value=fake_local_share_path))
        self.mock_object(self._layout, '_cleanup_create_share')
        self.mock_object(layout_directory.LOG, 'error')
        expected_exec = ['mkdir %s' % fake_local_share_path]
        fake_utils.fake_execute_set_repliers([(expected_exec[0],
                                               exec_runner)])

        self.assertRaises(
            exception.GlusterfsException, self._layout.create_share,
            self._context, self.share)

        self._layout._get_local_share_path.called_once_with(self.share)
        self._layout._cleanup_create_share.assert_called_once_with(
            fake_local_share_path, self.share['name'])
        layout_directory.LOG.error.assert_called_once_with(
            mock.ANY, mock.ANY)

    def test_create_share_unable_to_create_share_weird(self):
        def exec_runner(*ignore_args, **ignore_kw):
            raise RuntimeError

        self.mock_object(
            self._layout, '_get_local_share_path',
            mock.Mock(return_value=fake_local_share_path))
        self.mock_object(self._layout, '_cleanup_create_share')
        self.mock_object(layout_directory.LOG, 'error')
        expected_exec = ['mkdir %s' % fake_local_share_path]
        fake_utils.fake_execute_set_repliers([(expected_exec[0],
                                               exec_runner)])

        self.assertRaises(
            RuntimeError, self._layout.create_share,
            self._context, self.share)

        self._layout._get_local_share_path.called_once_with(self.share)
        self.assertFalse(self._layout._cleanup_create_share.called)

    def test_cleanup_create_share_local_share_path_exists(self):
        expected_exec = ['rm -rf %s' % fake_local_share_path]
        self.mock_object(os.path, 'exists', mock.Mock(return_value=True))

        ret = self._layout._cleanup_create_share(fake_local_share_path,
                                                 self.share['name'])

        os.path.exists.assert_called_once_with(fake_local_share_path)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertIsNone(ret)

    def test_cleanup_create_share_cannot_cleanup_unusable_share(self):
        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        expected_exec = ['rm -rf %s' % fake_local_share_path]
        fake_utils.fake_execute_set_repliers([(expected_exec[0],
                                               exec_runner)])
        self.mock_object(layout_directory.LOG, 'error')
        self.mock_object(os.path, 'exists', mock.Mock(return_value=True))

        self.assertRaises(exception.GlusterfsException,
                          self._layout._cleanup_create_share,
                          fake_local_share_path, self.share['name'])

        os.path.exists.assert_called_once_with(fake_local_share_path)
        layout_directory.LOG.error.assert_called_once_with(mock.ANY, mock.ANY)

    def test_cleanup_create_share_local_share_path_does_not_exist(self):
        self.mock_object(os.path, 'exists', mock.Mock(return_value=False))

        ret = self._layout._cleanup_create_share(fake_local_share_path,
                                                 self.share['name'])

        os.path.exists.assert_called_once_with(fake_local_share_path)
        self.assertIsNone(ret)

    def test_delete_share(self):
        self._layout._get_local_share_path = (
            mock.Mock(return_value='/mnt/nfs/testvol/fakename'))

        self._layout.delete_share(self._context, self.share)

        self.assertEqual(['rm -rf /mnt/nfs/testvol/fakename'],
                         fake_utils.fake_execute_get_log())

    def test_cannot_delete_share(self):
        self._layout._get_local_share_path = (
            mock.Mock(return_value='/mnt/nfs/testvol/fakename'))

        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        expected_exec = ['rm -rf %s' % (self._layout._get_local_share_path())]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.ProcessExecutionError,
                          self._layout.delete_share, self._context, self.share)

        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())

    def test_delete_share_can_be_called_with_extra_arg_share_server(self):
        self._layout._get_local_share_path = mock.Mock()

        share_server = None
        ret = self._layout.delete_share(self._context, self.share,
                                        share_server)

        self.assertIsNone(ret)
        self._layout._get_local_share_path.assert_called_once_with(self.share)

    def test_ensure_share(self):
        self.assertIsNone(self._layout.ensure_share(self._context, self.share))

    @ddt.data(
        ('create_share_from_snapshot', ('context', 'share', 'snapshot'),
         {'share_server': None}),
        ('create_snapshot', ('context', 'snapshot'), {'share_server': None}),
        ('delete_snapshot', ('context', 'snapshot'), {'share_server': None}),
        ('manage_existing', ('share', 'driver_options'), {}),
        ('unmanage', ('share',), {}),
        ('extend_share', ('share', 'new_size'), {'share_server': None}),
        ('shrink_share', ('share', 'new_size'), {'share_server': None}))
    def test_nonimplemented_methods(self, method_invocation):
        method, args, kwargs = method_invocation
        self.assertRaises(NotImplementedError, getattr(self._layout, method),
                          *args, **kwargs)
