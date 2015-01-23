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

import errno
import os

import mock
from oslo.config import cfg

from manila import context
from manila import exception
from manila.share import configuration as config
from manila.share.drivers import glusterfs
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_utils


CONF = cfg.CONF


fake_gluster_manager_attrs = {
    'export': '127.0.0.1:/testvol',
    'host': '127.0.0.1',
    'qualified': 'testuser@127.0.0.1:/testvol',
    'remote_user': 'testuser',
    'volume': 'testvol',
    'path_to_private_key': '/fakepath/to/privatekey',
    'remote_server_password': 'fakepassword',
}

fake_local_share_path = '/mnt/nfs/testvol/fakename'


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/testvol',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)

fake_access = {'access_type': 'ip', 'access_to': '10.0.0.1'}
fake_args = ('foo', 'bar')
fake_kwargs = {'key1': 'value1', 'key2': 'value2'}
fake_path_to_private_key = '/fakepath/to/privatekey'
fake_remote_server_password = 'fakepassword'
fake_share_name = 'fakename'
NFS_EXPORT_DIR = 'nfs.export-dir'
NFS_EXPORT_VOL = 'nfs.export-volumes'


class GlusterManagerTestCase(test.TestCase):
    """Tests GlusterManager."""

    def setUp(self):
        super(GlusterManagerTestCase, self).setUp()
        self.fake_execf = mock.Mock()
        self.fake_executor = mock.Mock(return_value=('', ''))
        with mock.patch.object(glusterfs.GlusterManager, 'make_gluster_call',
                               return_value=self.fake_executor):
            self._gluster_manager = glusterfs.GlusterManager(
                'testuser@127.0.0.1:/testvol', self.fake_execf,
                fake_path_to_private_key, fake_remote_server_password)

    def test_gluster_manager_init(self):
        self.assertEqual(fake_gluster_manager_attrs['remote_user'],
                         self._gluster_manager.remote_user)
        self.assertEqual(fake_gluster_manager_attrs['host'],
                         self._gluster_manager.host)
        self.assertEqual(fake_gluster_manager_attrs['volume'],
                         self._gluster_manager.volume)
        self.assertEqual(fake_gluster_manager_attrs['qualified'],
                         self._gluster_manager.qualified)
        self.assertEqual(fake_gluster_manager_attrs['export'],
                         self._gluster_manager.export)
        self.assertEqual(fake_gluster_manager_attrs['path_to_private_key'],
                         self._gluster_manager.path_to_private_key)
        self.assertEqual(fake_gluster_manager_attrs['remote_server_password'],
                         self._gluster_manager.remote_server_password)
        self.assertEqual(self.fake_executor,
                         self._gluster_manager.gluster_call)

    def test_gluster_manager_invalid(self):
        self.assertRaises(exception.GlusterfsException,
                          glusterfs.GlusterManager, '127.0.0.1:vol',
                          'self.fake_execf')

    def test_gluster_manager_make_gluster_call_local(self):
        fake_obj = mock.Mock()
        fake_execute = mock.Mock()
        with mock.patch.object(glusterfs.ganesha_utils, 'RootExecutor',
                               mock.Mock(return_value=fake_obj)):
            gluster_manager = glusterfs.GlusterManager(
                '127.0.0.1:/testvol', self.fake_execf)
            gluster_manager.make_gluster_call(fake_execute)(*fake_args,
                                                            **fake_kwargs)
            glusterfs.ganesha_utils.RootExecutor.assert_called_with(
                fake_execute)
        fake_obj.assert_called_once_with(
            *(('gluster',) + fake_args), **fake_kwargs)

    def test_gluster_manager_make_gluster_call_remote(self):
        fake_obj = mock.Mock()
        fake_execute = mock.Mock()
        with mock.patch.object(glusterfs.ganesha_utils, 'SSHExecutor',
                               mock.Mock(return_value=fake_obj)):
            gluster_manager = glusterfs.GlusterManager(
                'testuser@127.0.0.1:/testvol', self.fake_execf,
                fake_path_to_private_key, fake_remote_server_password)
            gluster_manager.make_gluster_call(fake_execute)(*fake_args,
                                                            **fake_kwargs)
            glusterfs.ganesha_utils.SSHExecutor.assert_called_with(
                gluster_manager.host, 22, None, gluster_manager.remote_user,
                password=gluster_manager.remote_server_password,
                privatekey=gluster_manager.path_to_private_key)
        fake_obj.assert_called_once_with(
            *(('gluster',) + fake_args), **fake_kwargs)

    def test_get_gluster_vol_option_empty_volinfo(self):
        args = ('--xml', 'volume', 'info', self._gluster_manager.volume)
        self.stubs.Set(self._gluster_manager, 'gluster_call',
                       mock.Mock(return_value=('', {})))
        self.assertRaises(exception.GlusterfsException,
                          self._gluster_manager.get_gluster_vol_option,
                          NFS_EXPORT_DIR)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args)

    def test_get_gluster_vol_option_failing_volinfo(self):

        def raise_exception(*ignore_args, **ignore_kwargs):
            raise RuntimeError('fake error')

        args = ('--xml', 'volume', 'info', self._gluster_manager.volume)
        self.stubs.Set(self._gluster_manager, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))
        self.assertRaises(RuntimeError,
                          self._gluster_manager.get_gluster_vol_option,
                          NFS_EXPORT_DIR)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args)

    def test_get_gluster_vol_option_ambiguous_volinfo(self):

        def xml_output(*ignore_args, **ignore_kwargs):
            return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <volInfo>
    <volumes>
      <count>0</count>
    </volumes>
  </volInfo>
</cliOutput>""", ''

        args = ('--xml', 'volume', 'info', self._gluster_manager.volume)
        self.stubs.Set(self._gluster_manager, 'gluster_call',
                       mock.Mock(side_effect=xml_output))
        self.assertRaises(exception.InvalidShare,
                          self._gluster_manager.get_gluster_vol_option,
                          NFS_EXPORT_DIR)
        self._gluster_manager.gluster_call.assert_called_once_with(*args)

    def test_get_gluster_vol_option_trivial_volinfo(self):

        def xml_output(*ignore_args, **ignore_kwargs):
            return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <volInfo>
    <volumes>
      <volume>
      </volume>
      <count>1</count>
    </volumes>
  </volInfo>
</cliOutput>""", ''

        args = ('--xml', 'volume', 'info', self._gluster_manager.volume)
        self.stubs.Set(self._gluster_manager, 'gluster_call',
                       mock.Mock(side_effect=xml_output))
        ret = self._gluster_manager.get_gluster_vol_option(NFS_EXPORT_DIR)
        self.assertEqual(None, ret)
        self._gluster_manager.gluster_call.assert_called_once_with(*args)

    def test_get_gluster_vol_option(self):

        def xml_output(*ignore_args, **ignore_kwargs):
            return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <volInfo>
    <volumes>
      <volume>
        <options>
           <option>
              <name>nfs.export-dir</name>
              <value>/foo(10.0.0.1|10.0.0.2),/bar(10.0.0.1)</value>
           </option>
        </options>
      </volume>
      <count>1</count>
    </volumes>
  </volInfo>
</cliOutput>""", ''

        args = ('--xml', 'volume', 'info', self._gluster_manager.volume)
        self.stubs.Set(self._gluster_manager, 'gluster_call',
                       mock.Mock(side_effect=xml_output))
        ret = self._gluster_manager.get_gluster_vol_option(NFS_EXPORT_DIR)
        self.assertEqual('/foo(10.0.0.1|10.0.0.2),/bar(10.0.0.1)', ret)
        self._gluster_manager.gluster_call.assert_called_once_with(*args)


class GlusterfsShareDriverTestCase(test.TestCase):
    """Tests GlusterfsShareDriver."""

    def setUp(self):
        super(GlusterfsShareDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self._execute = fake_utils.fake_execute
        self._context = context.get_admin_context()
        self.addCleanup(fake_utils.fake_execute_set_repliers, [])
        self.addCleanup(fake_utils.fake_execute_clear_log)

        CONF.set_default('glusterfs_target', '127.0.0.1:/testvol')
        CONF.set_default('glusterfs_mount_point_base', '/mnt/nfs')
        CONF.set_default('reserved_share_percentage', 50)
        CONF.set_default('glusterfs_server_password',
                         fake_remote_server_password)
        CONF.set_default('glusterfs_path_to_private_key',
                         fake_path_to_private_key)
        CONF.set_default('driver_handles_share_servers', False)

        self.fake_conf = config.Configuration(None)
        self._db = mock.Mock()
        self._driver = glusterfs.GlusterfsShareDriver(
            self._db, execute=self._execute,
            configuration=self.fake_conf)
        self._driver.gluster_manager = mock.Mock(**fake_gluster_manager_attrs)
        self._helper_nfs = mock.Mock()
        self.share = fake_share()

    def test_do_setup(self):
        fake_gluster_manager = mock.Mock(**fake_gluster_manager_attrs)
        methods = ('_ensure_gluster_vol_mounted', '_setup_helpers')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        self.stubs.Set(glusterfs, 'GlusterManager',
                       mock.Mock(return_value=fake_gluster_manager))
        expected_exec = ['mount.glusterfs']
        exec_cmd1 = 'mount.glusterfs'
        expected_exec = [exec_cmd1]
        args = ('volume', 'quota', 'testvol', 'enable')
        self._driver.do_setup(self._context)
        self.assertEqual(fake_gluster_manager, self._driver.gluster_manager)
        glusterfs.GlusterManager.assert_called_once_with(
            self._driver.configuration.glusterfs_target, self._execute,
            self._driver.configuration.glusterfs_path_to_private_key,
            self._driver.configuration.glusterfs_server_password)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self._driver.gluster_manager.gluster_call.assert_called_once_with(
            *args)
        self._driver._setup_helpers.assert_called_once_with()
        self._driver._ensure_gluster_vol_mounted.assert_called_once_with()

    def test_do_setup_glusterfs_target_not_set(self):
        self._driver.configuration.glusterfs_target = None
        self.assertRaises(exception.GlusterfsException, self._driver.do_setup,
                          self._context)

    def test_do_setup_mount_glusterfs_not_installed(self):

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        expected_exec = ['mount.glusterfs']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException, self._driver.do_setup,
                          self._context)

    def test_do_setup_error_enabling_creation_share_specific_size(self):
        attrs = {'volume': 'testvol',
                 'gluster_call.side_effect': exception.ProcessExecutionError,
                 'get_gluster_vol_option.return_value': 'off'}
        fake_gluster_manager = mock.Mock(**attrs)
        self.stubs.Set(glusterfs.LOG, 'error', mock.Mock())
        methods = ('_ensure_gluster_vol_mounted', '_setup_helpers')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        self.stubs.Set(glusterfs, 'GlusterManager',
                       mock.Mock(return_value=fake_gluster_manager))
        expected_exec = ['mount.glusterfs']
        exec_cmd1 = 'mount.glusterfs'
        expected_exec = [exec_cmd1]
        args = ('volume', 'quota', 'testvol', 'enable')
        self.assertRaises(exception.GlusterfsException, self._driver.do_setup,
                          self._context)
        self.assertEqual(fake_gluster_manager, self._driver.gluster_manager)
        glusterfs.GlusterManager.assert_called_once_with(
            self._driver.configuration.glusterfs_target, self._execute,
            self._driver.configuration.glusterfs_path_to_private_key,
            self._driver.configuration.glusterfs_server_password)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self._driver.gluster_manager.gluster_call.assert_called_once_with(
            *args)
        (self._driver.gluster_manager.get_gluster_vol_option.
         assert_called_once_with('features.quota'))
        glusterfs.LOG.error.assert_called_once_with(mock.ANY, mock.ANY)
        self.assertFalse(self._driver._setup_helpers.called)
        self.assertFalse(self._driver._ensure_gluster_vol_mounted.called)

    def test_do_setup_error_already_enabled_creation_share_specific_size(self):
        attrs = {'volume': 'testvol',
                 'gluster_call.side_effect': exception.ProcessExecutionError,
                 'get_gluster_vol_option.return_value': 'on'}
        fake_gluster_manager = mock.Mock(**attrs)
        self.stubs.Set(glusterfs.LOG, 'error', mock.Mock())
        methods = ('_ensure_gluster_vol_mounted', '_setup_helpers')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        self.stubs.Set(glusterfs, 'GlusterManager',
                       mock.Mock(return_value=fake_gluster_manager))
        expected_exec = ['mount.glusterfs']
        exec_cmd1 = 'mount.glusterfs'
        expected_exec = [exec_cmd1]
        args = ('volume', 'quota', 'testvol', 'enable')
        self._driver.do_setup(self._context)
        self.assertEqual(fake_gluster_manager, self._driver.gluster_manager)
        glusterfs.GlusterManager.assert_called_once_with(
            self._driver.configuration.glusterfs_target, self._execute,
            self._driver.configuration.glusterfs_path_to_private_key,
            self._driver.configuration.glusterfs_server_password)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self._driver.gluster_manager.gluster_call.assert_called_once_with(
            *args)
        (self._driver.gluster_manager.get_gluster_vol_option.
         assert_called_once_with('features.quota'))
        self.assertFalse(glusterfs.LOG.error.called)
        self._driver._setup_helpers.assert_called_once_with()
        self._driver._ensure_gluster_vol_mounted.assert_called_once_with()

    def test_setup_helpers(self):
        self.stubs.Set(glusterfs, 'GlusterNFSHelper',
                       mock.Mock(return_value=self._helper_nfs))
        self._driver._setup_helpers()
        glusterfs.GlusterNFSHelper.assert_called_once_with(
            self._execute, self.fake_conf,
            gluster_manager=self._driver.gluster_manager)
        self.assertEqual(1, len(self._driver._helpers))
        self.assertEqual(self._helper_nfs, self._driver._helpers['NFS'])
        self._driver._helpers['NFS'].init_helper.assert_called_once_with()

    def test_do_mount(self):
        expected_exec = ['true']
        ret = self._driver._do_mount(expected_exec, False)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, None)

    def test_do_mount_mounted_noensure(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='already mounted')
        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.assertRaises(exception.GlusterfsException, self._driver._do_mount,
                          expected_exec, False)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_do_mount_mounted_ensure(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='already mounted')
        expected_exec = ['true']
        glusterfs.LOG.warn = mock.Mock()
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        ret = self._driver._do_mount(expected_exec, True)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, None)
        glusterfs.LOG.warn.assert_called_with(
            "%s is already mounted", self._driver.gluster_manager.export)

    def test_do_mount_fail_noensure(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise RuntimeError('fake error')
        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.assertRaises(RuntimeError, self._driver._do_mount,
                          expected_exec, False)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_do_mount_fail_ensure(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise RuntimeError('fake error')
        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.assertRaises(RuntimeError, self._driver._do_mount,
                          expected_exec, True)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_mount_gluster_vol(self):
        mount_path = '/mnt/nfs/testvol'
        self._driver._do_mount = mock.Mock()
        cmd = ['mount', '-t', 'glusterfs',
               fake_gluster_manager_attrs['export'], mount_path]
        expected_exec = ['mkdir -p %s' % (mount_path)]

        self._driver._mount_gluster_vol(mount_path)
        self._driver._do_mount.assert_called_with(cmd, False)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_ensure_gluster_vol_mounted(self):
        self._driver._mount_gluster_vol = mock.Mock()
        self._driver._ensure_gluster_vol_mounted()
        self.assertTrue(self._driver._mount_gluster_vol.called)

    def test_ensure_gluster_vol_mounted_error(self):
        self._driver._mount_gluster_vol =\
            mock.Mock(side_effect=exception.GlusterfsException)
        self.assertRaises(exception.GlusterfsException,
                          self._driver._ensure_gluster_vol_mounted)

    def test_get_local_share_path(self):
        with mock.patch.object(os, 'access', return_value=True):
            expected_ret = '/mnt/nfs/testvol/fakename'
            ret = self._driver._get_local_share_path(self.share)
            self.assertEqual(ret, expected_ret)

    def test_local_share_path_not_exists(self):
        with mock.patch.object(os, 'access', return_value=False):
            self.assertRaises(exception.GlusterfsException,
                              self._driver._get_local_share_path,
                              self.share)

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
            'share_backend_name': 'GlusterFS',
            'driver_handles_share_servers': False,
            'vendor_name': 'Red Hat',
            'driver_version': '1.0',
            'storage_protocol': 'NFS',
            'reserved_percentage': 50,
            'QoS_support': False,
            'total_capacity_gb': 2,
            'free_capacity_gb': 2,
        }
        test_statvfs = mock.Mock(f_frsize=4096, f_blocks=524288,
                                 f_bavail=524288)
        self._driver._get_mount_point_for_gluster_vol = \
            mock.Mock(return_value='/mnt/nfs/testvol')
        some_no = 42
        not_some_no = some_no + 1
        os_stat = lambda path: mock.Mock(st_dev=some_no) if path == '/mnt/nfs' \
            else mock.Mock(st_dev=not_some_no)
        with mock.patch.object(os, 'statvfs', return_value=test_statvfs):
            with mock.patch.object(os, 'stat', os_stat):
                self._driver._update_share_stats()
                self.assertEqual(self._driver._stats, test_data)

    def test_update_share_stats_gluster_mnt_unavailable(self):
        self._driver._get_mount_point_for_gluster_vol = \
            mock.Mock(return_value='/mnt/nfs/testvol')
        some_no = 42
        with mock.patch.object(os, 'stat',
                               return_value=mock.Mock(st_dev=some_no)):
            self.assertRaises(exception.GlusterfsException,
                              self._driver._update_share_stats)

    def test_create_share(self):
        self.stubs.Set(self._driver, '_get_helper', mock.Mock())
        args = ('volume', 'quota', 'testvol', 'limit-usage', '/fakename',
                '1GB')
        exec_cmd1 = 'mkdir %s' % fake_local_share_path
        expected_exec = [exec_cmd1, ]
        expected_ret = 'testuser@127.0.0.1:/testvol/fakename'
        self.stubs.Set(
            self._driver, '_get_local_share_path',
            mock.Mock(return_value=fake_local_share_path))
        ret = self._driver.create_share(self._context, self.share)
        self._driver._get_helper.assert_called_once_with(self.share)
        self._driver._get_local_share_path.called_once_with(self.share)
        self._driver.gluster_manager.gluster_call.assert_called_once_with(
            *args)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertEqual(expected_ret, ret)

    def test_create_share_unable_to_create_share(self):
        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        self.stubs.Set(self._driver, '_get_helper', mock.Mock())
        self.stubs.Set(
            self._driver, '_get_local_share_path',
            mock.Mock(return_value=fake_local_share_path))
        self.stubs.Set(
            self._driver, '_cleanup_create_share', mock.Mock())
        self.stubs.Set(
            glusterfs.LOG, 'error', mock.Mock())
        expected_exec = ['mkdir %s' % fake_local_share_path]
        fake_utils.fake_execute_set_repliers([(expected_exec[0],
                                               exec_runner)])
        self.assertRaises(
            exception.GlusterfsException, self._driver.create_share,
            self._context, self.share)
        self._driver._get_helper.assert_called_once_with(self.share)
        self._driver._get_local_share_path.called_once_with(self.share)
        self._driver._cleanup_create_share.assert_called_once_with(
            fake_local_share_path, self.share['name'])
        glusterfs.LOG.error.assert_called_once_with(
            mock.ANY, mock.ANY)

    def test_create_share_error_unsupported_share_type(self):
        self.stubs.Set(
            self._driver, '_get_helper',
            mock.Mock(side_effect=exception.
                      InvalidShare(reason="Unsupported Share type")))
        self.assertRaises(exception.InvalidShare, self._driver.create_share,
                          self._context, self.share)
        self._driver._get_helper.assert_called_once_with(self.share)

    def test_create_share_can_be_called_with_extra_arg_share_server(self):
        share_server = None
        self._driver._get_local_share_path = mock.Mock()
        self.stubs.Set(self._driver, '_get_helper', mock.Mock())
        with mock.patch.object(os.path, 'join', return_value=None):
            ret = self._driver.create_share(self._context, self.share,
                                            share_server)
            self.assertEqual(None, ret)
            self._driver._get_local_share_path.called_once_with(self.share)
            self._driver._get_local_share_path.assert_called_once_with(
                self.share)
            os.path.join.assert_called_once_with(
                self._driver.gluster_manager.qualified, self.share['name'])

    def test_cleanup_create_share_local_share_path_exists(self):
        expected_exec = ['rm -rf %s' % fake_local_share_path]
        self.stubs.Set(
            os.path, 'exists', mock.Mock(return_value=True))
        ret = self._driver._cleanup_create_share(fake_local_share_path,
                                                 self.share['name'])
        os.path.exists.assert_called_once_with(fake_local_share_path)
        self.assertEqual(expected_exec, fake_utils.fake_execute_get_log())
        self.assertEqual(None, ret)

    def test_cleanup_create_share_cannot_cleanup_unusable_share(self):
        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        expected_exec = ['rm -rf %s' % fake_local_share_path]
        fake_utils.fake_execute_set_repliers([(expected_exec[0],
                                               exec_runner)])
        self.stubs.Set(
            glusterfs.LOG, 'error', mock.Mock())
        self.stubs.Set(
            os.path, 'exists', mock.Mock(return_value=True))
        self.assertRaises(exception.GlusterfsException,
                          self._driver._cleanup_create_share,
                          fake_local_share_path, self.share['name'])
        os.path.exists.assert_called_once_with(fake_local_share_path)
        glusterfs.LOG.error.assert_called_once_with(mock.ANY, mock.ANY)

    def test_cleanup_create_share_local_share_path_does_not_exist(self):
        self.stubs.Set(
            os.path, 'exists', mock.Mock(return_value=False))
        ret = self._driver._cleanup_create_share(fake_local_share_path,
                                                 self.share['name'])
        os.path.exists.assert_called_once_with(fake_local_share_path)
        self.assertEqual(None, ret)

    def test_delete_share(self):
        self._driver._get_local_share_path =\
            mock.Mock(return_value='/mnt/nfs/testvol/fakename')

        expected_exec = ['rm -rf /mnt/nfs/testvol/fakename']

        self._driver.delete_share(self._context, self.share)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_cannot_delete_share(self):
        self._driver._get_local_share_path =\
            mock.Mock(return_value='/mnt/nfs/testvol/fakename')

        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        expected_exec = ['rm -rf %s' % (self._driver._get_local_share_path())]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver.delete_share, self._context, self.share)

    def test_delete_share_can_be_called_with_extra_arg_share_server(self):
        share_server = None
        self._driver._get_local_share_path = mock.Mock()
        ret = self._driver.delete_share(self._context, self.share,
                                        share_server)
        self.assertEqual(ret, None)
        self._driver._get_local_share_path.assert_called_once_with(self.share)

    def test_get_helper_NFS(self):
        self._driver._helpers['NFS'] = None
        ret = self._driver._get_helper(self.share)
        self.assertEqual(None, ret)

    def test_get_helper_not_implemented(self):
        share = fake_share(share_proto='Others')
        self.assertRaises(
            exception.InvalidShare, self._driver._get_helper, share)

    def test_allow_access(self):
        self.stubs.Set(self._driver, '_get_helper', mock.Mock())
        ret = self._driver.allow_access(self._context, self.share,
                                        fake_access)
        self._driver._get_helper.assert_called_once_with(self.share)
        self._driver._get_helper().\
            allow_access.assert_called_once_with('/', self.share, fake_access)
        self.assertEqual(None, ret)

    def test_allow_access_can_be_called_with_extra_arg_share_server(self):
        self.stubs.Set(self._driver, '_get_helper', mock.Mock())
        ret = self._driver.allow_access(self._context, self.share,
                                        fake_access, share_server=None)
        self._driver._get_helper.assert_called_once_with(self.share)
        self._driver._get_helper().\
            allow_access.assert_called_once_with('/', self.share, fake_access)
        self.assertEqual(None, ret)

    def test_deny_access(self):
        self.stubs.Set(self._driver, '_get_helper', mock.Mock())
        ret = self._driver.deny_access(self._context, self.share,
                                       fake_access)
        self._driver._get_helper.assert_called_once_with(self.share)
        self._driver._get_helper().\
            deny_access.assert_called_once_with('/', self.share, fake_access)
        self.assertEqual(None, ret)

    def test_deny_access_can_be_called_with_extra_arg_share_server(self):
        self.stubs.Set(self._driver, '_get_helper', mock.Mock())
        ret = self._driver.deny_access(self._context, self.share,
                                       fake_access, share_server=None)
        self._driver._get_helper.assert_called_once_with(self.share)
        self._driver._get_helper().\
            deny_access.assert_called_once_with('/', self.share, fake_access)
        self.assertEqual(None, ret)


class GlusterNFSHelperTestCase(test.TestCase):
    """Tests GlusterNFSHelper."""

    def setUp(self):
        super(GlusterNFSHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        gluster_manager = mock.Mock(**fake_gluster_manager_attrs)
        self._execute = mock.Mock(return_value=('', ''))
        self.fake_conf = config.Configuration(None)
        self._helper = glusterfs.GlusterNFSHelper(
            self._execute, self.fake_conf, gluster_manager=gluster_manager)

    def test_init_helper(self):
        args = ('volume', 'set', self._helper.gluster_manager.volume,
                NFS_EXPORT_VOL, 'off')
        self._helper.init_helper()
        self._helper.gluster_manager.gluster_call.assert_called_once_with(
            *args)

    def test_init_helper_vol_error_gluster_vol_set(self):
        args = ('volume', 'set', self._helper.gluster_manager.volume,
                NFS_EXPORT_VOL, 'off')

        def raise_exception(*args, **kwargs):
            raise exception.ProcessExecutionError()

        self.stubs.Set(glusterfs.LOG, 'error', mock.Mock())
        self.stubs.Set(self._helper.gluster_manager, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))
        self.assertRaises(exception.GlusterfsException,
                          self._helper.init_helper)
        self._helper.gluster_manager.gluster_call.assert_called_once_with(
            *args)
        glusterfs.LOG.error.assert_called_once_with(mock.ANY, mock.ANY)

    def test_get_export_dir_dict(self):
        output_str = '/foo(10.0.0.1|10.0.0.2),/bar(10.0.0.1)'
        self.stubs.Set(self._helper.gluster_manager, 'get_gluster_vol_option',
                       mock.Mock(return_value=output_str))
        ret = self._helper._get_export_dir_dict()
        self.assertEqual(
            {'foo': ['10.0.0.1', '10.0.0.2'], 'bar': ['10.0.0.1']}, ret)
        (self._helper.gluster_manager.get_gluster_vol_option.
         assert_called_once_with(NFS_EXPORT_DIR))

    def test_manage_access_bad_access_type(self):
        cbk = None
        access = {'access_type': 'bad', 'access_to': None}
        self.assertRaises(exception.InvalidShareAccess,
                          self._helper._manage_access, fake_share_name,
                          access['access_type'], access['access_to'], cbk)

    def test_manage_access_noop(self):
        cbk = mock.Mock(return_value=True)
        access = fake_access
        export_dir_dict = mock.Mock()
        self.stubs.Set(self._helper, '_get_export_dir_dict',
                       mock.Mock(return_value=export_dir_dict))
        ret = self._helper._manage_access(fake_share_name,
                                          access['access_type'],
                                          access['access_to'], cbk)
        self._helper._get_export_dir_dict.assert_called_once_with()
        cbk.assert_called_once_with(export_dir_dict, fake_share_name,
                                    access['access_to'])
        self.assertEqual(None, ret)

    def test_manage_access_adding_entry(self):

        def cbk(d, key, value):
            d[key].append(value)

        access = fake_access
        export_dir_dict = {
            'example.com': ['10.0.0.1'],
            'fakename': ['10.0.0.2'],
        }
        export_str = '/example.com(10.0.0.1),/fakename(10.0.0.2|10.0.0.1)'
        args = ('volume', 'set', self._helper.gluster_manager.volume,
                NFS_EXPORT_DIR, export_str)
        self.stubs.Set(self._helper, '_get_export_dir_dict',
                       mock.Mock(return_value=export_dir_dict))
        ret = self._helper._manage_access(fake_share_name,
                                          access['access_type'],
                                          access['access_to'], cbk)
        self.assertEqual(None, ret)
        self._helper._get_export_dir_dict.assert_called_once_with()
        self._helper.gluster_manager.gluster_call.assert_called_once_with(
            *args)

    def test_manage_access_adding_entry_cmd_fail(self):

        def cbk(d, key, value):
            d[key].append(value)

        def raise_exception(*args, **kwargs):
            raise exception.ProcessExecutionError()

        access = fake_access
        export_dir_dict = {
            'example.com': ['10.0.0.1'],
            'fakename': ['10.0.0.2'],
        }
        export_str = '/example.com(10.0.0.1),/fakename(10.0.0.2|10.0.0.1)'
        args = ('volume', 'set', self._helper.gluster_manager.volume,
                NFS_EXPORT_DIR, export_str)
        self.stubs.Set(self._helper, '_get_export_dir_dict',
                       mock.Mock(return_value=export_dir_dict))
        self.stubs.Set(self._helper.gluster_manager, 'gluster_call',
                       mock.Mock(side_effect=raise_exception))
        self.stubs.Set(glusterfs.LOG, 'error', mock.Mock())
        self.assertRaises(exception.ProcessExecutionError,
                          self._helper._manage_access,
                          fake_share_name, access['access_type'],
                          access['access_to'], cbk)
        self._helper._get_export_dir_dict.assert_called_once_with()
        self._helper.gluster_manager.gluster_call.assert_called_once_with(
            *args)
        glusterfs.LOG.error.assert_called_once_with(mock.ANY, mock.ANY)

    def test_manage_access_removing_last_entry(self):

        def cbk(d, key, value):
            d.pop(key)

        access = fake_access
        args = ('volume', 'reset', self._helper.gluster_manager.volume,
                NFS_EXPORT_DIR)
        export_dir_dict = {'fakename': ['10.0.0.1']}
        self.stubs.Set(self._helper, '_get_export_dir_dict',
                       mock.Mock(return_value=export_dir_dict))
        ret = self._helper._manage_access(fake_share_name,
                                          access['access_type'],
                                          access['access_to'], cbk)
        self.assertEqual(None, ret)
        self._helper._get_export_dir_dict.assert_called_once_with()
        self._helper.gluster_manager.gluster_call.assert_called_once_with(
            *args)

    def test_allow_access_with_share_having_noaccess(self):
        access = fake_access
        share = fake_share()
        export_dir_dict = {'example.com': ['10.0.0.1']}
        export_str = '/example.com(10.0.0.1),/fakename(10.0.0.1)'
        args = ('volume', 'set', self._helper.gluster_manager.volume,
                NFS_EXPORT_DIR, export_str)
        self.stubs.Set(self._helper, '_get_export_dir_dict',
                       mock.Mock(return_value=export_dir_dict))
        self._helper.allow_access(None, share, access)
        self._helper._get_export_dir_dict.assert_called_once_with()
        self._helper.gluster_manager.gluster_call.assert_called_once_with(
            *args)

    def test_allow_access_with_share_having_access(self):
        access = fake_access
        share = fake_share()
        export_dir_dict = {'fakename': ['10.0.0.1']}
        self.stubs.Set(self._helper, '_get_export_dir_dict',
                       mock.Mock(return_value=export_dir_dict))
        self._helper.allow_access(None, share, access)
        self._helper._get_export_dir_dict.assert_called_once_with()
        self.assertFalse(self._helper.gluster_manager.gluster_call.called)

    def test_deny_access_with_share_having_noaccess(self):
        access = fake_access
        share = fake_share()
        export_dir_dict = {}
        self.stubs.Set(self._helper, '_get_export_dir_dict',
                       mock.Mock(return_value=export_dir_dict))
        self._helper.deny_access(None, share, access)
        self._helper._get_export_dir_dict.assert_called_once_with()
        self.assertFalse(self._helper.gluster_manager.gluster_call.called)

    def test_deny_access_with_share_having_access(self):
        access = fake_access
        share = fake_share()
        export_dir_dict = {
            'example.com': ['10.0.0.1'],
            'fakename': ['10.0.0.1'],
        }
        export_str = '/example.com(10.0.0.1)'
        args = ('volume', 'set', self._helper.gluster_manager.volume,
                NFS_EXPORT_DIR, export_str)
        self.stubs.Set(self._helper, '_get_export_dir_dict',
                       mock.Mock(return_value=export_dir_dict))
        self._helper.deny_access(None, share, access)
        self._helper._get_export_dir_dict.assert_called_once_with()
        self._helper.gluster_manager.gluster_call.assert_called_once_with(
            *args)
