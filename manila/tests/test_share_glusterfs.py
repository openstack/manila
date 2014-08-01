# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
import subprocess

from mock import Mock
from mock import patch
from oslo.config import cfg

from manila import context
from manila.db.sqlalchemy import models
from manila import exception
from manila.openstack.common import importutils
from manila.openstack.common import log as logging
from manila.share import configuration as config
from manila.share.drivers import glusterfs
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_utils


CONF = cfg.CONF


gluster_address_attrs = {
    'export': '127.0.0.1:/testvol',
    'host': '127.0.0.1',
    'qualified': 'testuser@127.0.0.1:/testvol',
    'remote_user': 'testuser',
    'volume': 'testvol',
}


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


class GlusterAddressTestCase(test.TestCase):
    """Tests GlusterAddress."""

    _gluster_args = ('foo', 'bar', "b'a'z")

    def test_gluster_address_init(self):
        self._gluster_address = glusterfs.GlusterAddress(
            'testuser@127.0.0.1:/testvol')
        self.assertEqual(self._gluster_address.remote_user,
                         gluster_address_attrs['remote_user'])
        self.assertEqual(self._gluster_address.host,
                         gluster_address_attrs['host'])
        self.assertEqual(self._gluster_address.volume,
                         gluster_address_attrs['volume'])
        self.assertEqual(self._gluster_address.qualified,
                         gluster_address_attrs['qualified'])
        self.assertEqual(self._gluster_address.export,
                         gluster_address_attrs['export'])

    def test_gluster_address_invalid(self):
        self.assertRaises(exception.GlusterfsException,
                          glusterfs.GlusterAddress, '127.0.0.1:vol')

    def test_gluster_address_make_gluster_args_local(self):
        self._gluster_address = glusterfs.GlusterAddress(
            '127.0.0.1:/testvol')
        ret = self._gluster_address.make_gluster_args(*self._gluster_args)
        self.assertEqual(ret, (('gluster',) + self._gluster_args,
                               {'run_as_root': True}))

    def test_gluster_address_make_gluster_args_remote(self):
        self._gluster_address = glusterfs.GlusterAddress(
            'testuser@127.0.0.1:/testvol')
        ret = self._gluster_address.make_gluster_args(*self._gluster_args)
        self.assertEqual(len(ret), 2)
        self.assertEqual(len(ret[0]), 3)
        # python 2.6 compat thingy
        check_output = lambda cmd:\
            subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).\
                communicate()[0]
        # shell unescaping thru echo(1)
        self.assertEqual(check_output('echo ' + ' '.join(ret[0]),)[:-1],
                         'ssh testuser@127.0.0.1 gluster ' +
                            ' '.join(self._gluster_args))
        self.assertEqual(ret[1], {})


class GlusterfsShareDriverTestCase(test.TestCase):
    """Tests GlusterfsShareDriver."""

    def setUp(self):
        super(GlusterfsShareDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self._execute = fake_utils.fake_execute
        self._context = context.get_admin_context()

        CONF.set_default('glusterfs_mount_point_base', '/mnt/nfs')
        CONF.set_default('reserved_share_percentage', 50)

        self.fake_conf = config.Configuration(None)
        self._db = Mock()
        self._driver = glusterfs.GlusterfsShareDriver(
                        self._db, execute=self._execute,
                        configuration=self.fake_conf)
        self._driver.gluster_address = Mock(**gluster_address_attrs)
        self.share = fake_share()

    def tearDown(self):
        super(GlusterfsShareDriverTestCase, self).tearDown()
        fake_utils.fake_execute_set_repliers([])
        fake_utils.fake_execute_clear_log()

    def test_do_setup(self):
        self._driver._read_gluster_vol_from_config =\
            Mock(return_value='127.0.0.1:/testvol')
        self._driver._ensure_gluster_vol_mounted = Mock()
        exec_cmd1 = 'mount.glusterfs'
        exec_cmd2 = 'gluster volume set testvol nfs.export-volumes off'
        expected_exec = [exec_cmd1, exec_cmd2]
        self._driver.do_setup(self._context)
        self._driver._ensure_gluster_vol_mounted.assert_called_once_with()
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_do_setup_mount_glusterfs_not_installed(self):
        self._driver._read_gluster_vol_from_config =\
            Mock(return_value='127.0.0.1:/testvol')
        self._driver._ensure_gluster_vol_mounted = Mock()

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        expected_exec = ['mount.glusterfs']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        self.assertRaises(exception.GlusterfsException, self._driver.do_setup,
                          self._context)

    def test_do_setup_mount_glusterfs_error_gluster_vol_set(self):
        self._driver._read_gluster_vol_from_config =\
            Mock(return_value='127.0.0.1:/testvol')
        self._driver._ensure_gluster_vol_mounted = Mock()
        glusterfs.LOG.error = Mock()

        def exec_runner(*ignore_args, **ignore_kwargs):
                raise exception.ProcessExecutionError(stderr='testvol')
        expected_exec = ['gluster volume set testvol nfs.export-volumes off']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])

        try:
            self._driver.do_setup(self._context)
        except exception.ProcessExecutionError:
            pass
        else:
            self.fail('Expecting exception.ProcessExecutionError')

        glusterfs.LOG.error.assert_called_with("Error in gluster volume set: "
                                               "testvol")

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
        glusterfs.LOG.warn = Mock()
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        ret = self._driver._do_mount(expected_exec, True)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, None)
        glusterfs.LOG.warn.assert_called_with(
            "%s is already mounted", self._driver.gluster_address.export)

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
        self._driver._do_mount = Mock()
        cmd = ['mount', '-t', 'glusterfs', gluster_address_attrs['export'],
               mount_path]
        expected_exec = ['mkdir -p %s' % (mount_path)]

        self._driver._mount_gluster_vol(mount_path)
        self._driver._do_mount.assert_called_with(cmd, False)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_ensure_gluster_vol_mounted(self):
        mount_path = 'mnt/nfs/testvol'
        self._driver._mount_gluster_vol = Mock()
        self._driver._ensure_gluster_vol_mounted()
        self.assertTrue(self._driver._mount_gluster_vol.called)

    def test_ensure_gluster_vol_mounted_error(self):
        self._driver._mount_gluster_vol =\
            Mock(side_effect=exception.GlusterfsException)
        self.assertRaises(exception.GlusterfsException,
                          self._driver._ensure_gluster_vol_mounted)

    def test_get_export_dir_dict_empty_volinfo(self):
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))
        expected_exec = ['true']
        self.assertRaises(exception.GlusterfsException,
                          self._driver._get_export_dir_dict)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_get_export_dir_dict_failing_volinfo(self):
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))

        def exec_runner(*ignore_args, **ignore_kwargs):
            raise RuntimeError('fake error')
        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.assertRaises(RuntimeError, self._driver._get_export_dir_dict)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_get_export_dir_dict_ambiguous_volinfo(self):
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))

        def exec_runner(*ignore_args, **ignore_kwargs):
            return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <volInfo>
    <volumes>
      <count>0</count>
    </volumes>
  </volInfo>
</cliOutput>""", ''
        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.assertRaises(exception.InvalidShare,
                          self._driver._get_export_dir_dict)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_get_export_dir_dict_trivial_volinfo(self):
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))

        def exec_runner(*ignore_args, **ignore_kwargs):
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
        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        ret = self._driver._get_export_dir_dict()
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, {})

    def test_get_export_dir_dict(self):
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))

        def exec_runner(*ignore_args, **ignore_kwargs):
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
        expected_exec = ['true']
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        ret = self._driver._get_export_dir_dict()
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret,
                         {'foo': ['10.0.0.1', '10.0.0.2'], 'bar': ['10.0.0.1']}
                        )

    def test_get_local_share_path(self):
        with patch.object(os, 'access', return_value=True):
            expected_ret = '/mnt/nfs/testvol/fakename'
            ret = self._driver._get_local_share_path(self.share)
            self.assertEqual(ret, expected_ret)

    def test_local_share_path_not_exists(self):
        with patch.object(os, 'access', return_value=False):
            self.assertRaises(exception.GlusterfsException,
                              self._driver._get_local_share_path,
                              self.share)

    def test_get_share_stats_refresh_false(self):
        self._driver._stats = Mock()
        ret = self._driver.get_share_stats()
        self.assertEqual(ret, self._driver._stats)

    def test_get_share_stats_refresh_true(self):
        def foo():
            self._driver._stats = {'key': 'value'}
        self._driver._update_share_stats = Mock(side_effect=foo)
        ret = self._driver.get_share_stats(refresh=True)
        self.assertEqual(ret, {'key': 'value'})

    def test_update_share_stats(self):
        test_data = {
            'share_backend_name': 'GlusterFS',
            'vendor_name': 'Red Hat',
            'driver_version': '1.0',
            'storage_protocol': 'NFS',
            'reserved_percentage': 50,
            'QoS_support': False,
            'total_capacity_gb': 2,
            'free_capacity_gb': 2,
        }
        test_statvfs = Mock(f_frsize=4096, f_blocks=524288, f_bavail=524288)
        self._driver._get_mount_point_for_gluster_vol = \
            Mock(return_value='/mnt/nfs/testvol')
        some_no = 42
        not_some_no = some_no + 1
        os_stat = lambda path: Mock(st_dev=some_no) if path == '/mnt/nfs' \
                    else Mock(st_dev=not_some_no)
        with patch.object(os, 'statvfs', return_value=test_statvfs):
            with patch.object(os, 'stat', os_stat):
                ret = self._driver._update_share_stats()
                self.assertEqual(self._driver._stats, test_data)

    def test_update_share_stats_gluster_mnt_unavailable(self):
        self._driver._get_mount_point_for_gluster_vol = \
            Mock(return_value='/mnt/nfs/testvol')
        some_no = 42
        with patch.object(os, 'stat', return_value=Mock(st_dev=some_no)):
            self.assertRaises(exception.GlusterfsException,
                              self._driver._update_share_stats)

    def test_create_share(self):
        self._driver._get_local_share_path =\
            Mock(return_value='/mnt/nfs/testvol/fakename')
        expected_exec = ['mkdir /mnt/nfs/testvol/fakename', ]
        expected_ret = 'testuser@127.0.0.1:/testvol/fakename'

        ret = self._driver.create_share(self._context, self.share)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, expected_ret)

    def test_cannot_create_share(self):
        self._driver._get_local_share_path =\
            Mock(return_value='/mnt/nfs/testvol/fakename')

        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        expected_exec = ['mkdir %s' % (self._driver._get_local_share_path())]
        fake_utils.fake_execute_set_repliers([(expected_exec[0],
                                               exec_runner)])
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver.create_share, self._context, self.share)

    def test_create_share_can_be_called_with_extra_arg_share_server(self):
        share_server = None
        self._driver._get_local_share_path = Mock()
        with patch.object(os.path, 'join', return_value=None):
            ret = self._driver.create_share(self._context, self.share,
                                            share_server)
            self.assertEqual(ret, None)
            self._driver._get_local_share_path.assert_called_once_with(
                self.share)
            os.path.join.assert_called_once_with(
                self._driver.gluster_address.qualified, self.share['name'])

    def test_delete_share(self):
        self._driver._get_local_share_path =\
            Mock(return_value='/mnt/nfs/testvol/fakename')

        expected_exec = ['rm -rf /mnt/nfs/testvol/fakename']

        self._driver.delete_share(self._context, self.share)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_cannot_delete_share(self):
        self._driver._get_local_share_path =\
            Mock(return_value='/mnt/nfs/testvol/fakename')

        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError

        expected_exec = ['rm -rf %s' % (self._driver._get_local_share_path())]
        fake_utils.fake_execute_set_repliers([(expected_exec[0], exec_runner)])
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver.delete_share, self._context, self.share)

    def test_delete_share_can_be_called_with_extra_arg_share_server(self):
        share_server = None
        self._driver._get_local_share_path = Mock()
        ret = self._driver.delete_share(self._context, self.share,
                                        share_server)
        self.assertEqual(ret, None)
        self._driver._get_local_share_path.assert_called_once_with(self.share)

    def test_manage_access_bad_access_type(self):
        cbk = Mock()
        access = {'access_type': 'bad'}
        self.assertRaises(exception.InvalidShareAccess,
                          self._driver._manage_access,
                          self._context, self.share, access, cbk)

    def test_manage_access_noop(self):
        cbk = Mock(return_value=True)
        access = {'access_type': 'ip', 'access_to': '10.0.0.1'}
        self._driver._get_export_dir_dict = Mock()
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))
        expected_exec = []
        ret = self._driver._manage_access(self._context, self.share, access,
                                          cbk)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, None)

    def test_manage_access_adding_entry(self):
        def cbk(d, key, value):
            d[key].append(value)
        access = {'access_type': 'ip', 'access_to': '10.0.0.2'}
        self._driver._get_export_dir_dict =\
            Mock(return_value={'example.com': ['10.0.0.1'],
                               'fakename': ['10.0.0.1']})
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))
        expected_exec = ['true']
        ret = self._driver._manage_access(self._context, self.share, access,
                                          cbk)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, None)
        self.assertTrue(self._driver.gluster_address.make_gluster_args.called)
        self.assertEqual(
          self._driver.gluster_address.make_gluster_args.call_args[0][-1],
          '/example.com(10.0.0.1),/fakename(10.0.0.1|10.0.0.2)')

    def test_manage_access_adding_entry_cmd_fail(self):
        def cbk(d, key, value):
            d[key].append(value)
        access = {'access_type': 'ip', 'access_to': '10.0.0.2'}
        self._driver._get_export_dir_dict =\
            Mock(return_value={'example.com': ['10.0.0.1'],
                               'fakename': ['10.0.0.1']})
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))
        expected_exec = ['true']

        def exec_runner(*ignore_args, **ignore_kw):
            raise exception.ProcessExecutionError
        fake_utils.fake_execute_set_repliers([(expected_exec[0],
                                               exec_runner)])
        self.assertRaises(exception.ProcessExecutionError,
                          self._driver._manage_access,
                          self._context, self.share, access, cbk)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertTrue(self._driver.gluster_address.make_gluster_args.called)
        self.assertEqual(
          self._driver.gluster_address.make_gluster_args.call_args[0][-1],
          '/example.com(10.0.0.1),/fakename(10.0.0.1|10.0.0.2)')

    def test_manage_access_removing_last_entry(self):
        def cbk(d, key, value):
            d.pop(key)
        access = {'access_type': 'ip', 'access_to': '10.0.0.1'}
        self._driver._get_export_dir_dict =\
            Mock(return_value={'fakename': ['10.0.0.1']})
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))
        expected_exec = ['true']
        ret = self._driver._manage_access(self._context, self.share, access,
                                          cbk)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertEqual(ret, None)
        self.assertTrue(self._driver.gluster_address.make_gluster_args.called)
        self.assertEqual(
          self._driver.gluster_address.make_gluster_args.call_args[0][1],
          'reset')
        self.assertEqual(
          self._driver.gluster_address.make_gluster_args.call_args[0][-1],
          'nfs.export-dir')

    def test_allow_access_with_share_having_noaccess(self):
        access = {'access_type': 'ip', 'access_to': '10.0.0.1'}
        self._driver._get_export_dir_dict =\
            Mock(return_value={'example.com': ['10.0.0.1']})
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))
        self._driver.allow_access(self._context, self.share, access)
        self.assertTrue(self._driver.gluster_address.make_gluster_args.called)
        self.assertEqual(
          self._driver.gluster_address.make_gluster_args.call_args[0][-1],
          '/example.com(10.0.0.1),/fakename(10.0.0.1)')

    def test_allow_access_with_share_having_access(self):
        access = {'access_type': 'ip', 'access_to': '10.0.0.1'}
        self._driver._get_export_dir_dict = \
            Mock(return_value={'fakename': ['10.0.0.1']})
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))
        self._driver.allow_access(self._context, self.share, access)
        self.assertFalse(self._driver.gluster_address.make_gluster_args.called)

    def test_allow_access_can_be_called_with_extra_arg_share_server(self):
        access = None
        share_server = None
        self._driver._manage_access = Mock()
        ret = self._driver.allow_access(self._context, self.share, access,
                                        share_server)
        self.assertEqual(ret, None)
        self._driver._manage_access.assert_called_once()

    def test_deny_access_with_share_having_noaccess(self):
        access = {'access_type': 'ip', 'access_to': '10.0.0.1'}
        self._driver._get_export_dir_dict = Mock(return_value={})
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))
        self._driver.deny_access(self._context, self.share, access)
        self.assertFalse(self._driver.gluster_address.make_gluster_args.called)

    def test_deny_access_with_share_having_access(self):
        access = {'access_type': 'ip', 'access_to': '10.0.0.1'}
        self._driver._get_export_dir_dict = \
            Mock(return_value={'fakename': ['10.0.0.1'],
                               'example.com': ['10.0.0.1']})
        self._driver.gluster_address = Mock(
            make_gluster_args=Mock(return_value=(('true',), {})))
        self._driver.deny_access(self._context, self.share, access)
        self.assertTrue(self._driver.gluster_address.make_gluster_args.called)
        self.assertEqual(
          self._driver.gluster_address.make_gluster_args.call_args[0][-1],
          '/example.com(10.0.0.1)')

    def test_deny_access_can_be_called_with_extra_arg_share_server(self):
        access = None
        share_server = None
        self._driver._manage_access = Mock()
        ret = self._driver.deny_access(self._context, self.share, access,
                                       share_server)
        self.assertEqual(ret, None)
        self._driver._manage_access.assert_called_once()
