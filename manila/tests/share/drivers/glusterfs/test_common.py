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

"""Test cases for GlusterFS common routines."""

import ddt
import mock
from oslo_config import cfg

from manila import exception
from manila.share.drivers.glusterfs import common
from manila import test
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
}
fake_args = ('foo', 'bar')
fake_kwargs = {'key1': 'value1', 'key2': 'value2'}
fake_path_to_private_key = '/fakepath/to/privatekey'
fake_remote_server_password = 'fakepassword'
NFS_EXPORT_DIR = 'nfs.export-dir'

fakehost = 'example.com'
fakevol = 'testvol'
fakeexport = ':/'.join((fakehost, fakevol))
fakemnt = '/mnt/glusterfs'


@ddt.ddt
class GlusterManagerTestCase(test.TestCase):
    """Tests GlusterManager."""

    def setUp(self):
        super(GlusterManagerTestCase, self).setUp()
        self.fake_execf = mock.Mock()
        self.fake_executor = mock.Mock(return_value=('', ''))
        with mock.patch.object(common.GlusterManager, 'make_gluster_call',
                               return_value=self.fake_executor):
            self._gluster_manager = common.GlusterManager(
                'testuser@127.0.0.1:/testvol', self.fake_execf,
                fake_path_to_private_key, fake_remote_server_password)

    def test_gluster_manager_init(self):
        self.assertEqual(fake_gluster_manager_attrs['user'],
                         self._gluster_manager.user)
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

    @ddt.data(None, True)
    def test_gluster_manager_init_has_vol(self, has_volume):
        test_gluster_manager = common.GlusterManager(
            'testuser@127.0.0.1:/testvol', self.fake_execf,
            requires={'volume': has_volume})
        self.assertEqual('testvol', test_gluster_manager.volume)

    @ddt.data(None, False)
    def test_gluster_manager_init_no_vol(self, has_volume):
        test_gluster_manager = common.GlusterManager(
            'testuser@127.0.0.1', self.fake_execf,
            requires={'volume': has_volume})
        self.assertIsNone(test_gluster_manager.volume)

    def test_gluster_manager_init_has_shouldnt_have_vol(self):
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager,
                          'testuser@127.0.0.1:/testvol',
                          self.fake_execf, requires={'volume': False})

    def test_gluster_manager_hasnt_should_have_vol(self):
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager, 'testuser@127.0.0.1',
                          self.fake_execf, requires={'volume': True})

    def test_gluster_manager_invalid(self):
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager, '127.0.0.1:vol',
                          'self.fake_execf')

    def test_gluster_manager_getattr(self):
        self.assertEqual('testvol', self._gluster_manager.volume)

    def test_gluster_manager_getattr_called(self):
        class FakeGlusterManager(common.GlusterManager):
            pass

        _gluster_manager = FakeGlusterManager('127.0.0.1:/testvol',
                                              self.fake_execf)
        FakeGlusterManager.__getattr__ = mock.Mock()
        _gluster_manager.volume
        _gluster_manager.__getattr__.assert_called_once_with('volume')

    def test_gluster_manager_getattr_noattr(self):
        self.assertRaises(AttributeError, getattr, self._gluster_manager,
                          'fakeprop')

    def test_gluster_manager_make_gluster_call_local(self):
        fake_obj = mock.Mock()
        fake_execute = mock.Mock()
        with mock.patch.object(common.ganesha_utils, 'RootExecutor',
                               mock.Mock(return_value=fake_obj)):
            gluster_manager = common.GlusterManager(
                '127.0.0.1:/testvol', self.fake_execf)
            gluster_manager.make_gluster_call(fake_execute)(*fake_args,
                                                            **fake_kwargs)
            common.ganesha_utils.RootExecutor.assert_called_with(
                fake_execute)
        fake_obj.assert_called_once_with(
            *(('gluster',) + fake_args), **fake_kwargs)

    def test_gluster_manager_make_gluster_call_remote(self):
        fake_obj = mock.Mock()
        fake_execute = mock.Mock()
        with mock.patch.object(common.ganesha_utils, 'SSHExecutor',
                               mock.Mock(return_value=fake_obj)):
            gluster_manager = common.GlusterManager(
                'testuser@127.0.0.1:/testvol', self.fake_execf,
                fake_path_to_private_key, fake_remote_server_password)
            gluster_manager.make_gluster_call(fake_execute)(*fake_args,
                                                            **fake_kwargs)
            common.ganesha_utils.SSHExecutor.assert_called_with(
                gluster_manager.host, 22, None, gluster_manager.user,
                password=gluster_manager.remote_server_password,
                privatekey=gluster_manager.path_to_private_key)
        fake_obj.assert_called_once_with(
            *(('gluster',) + fake_args), **fake_kwargs)

    @ddt.data({'trouble': exception.ProcessExecutionError,
               '_exception': exception.GlusterfsException, 'xkw': {}},
              {'trouble': exception.ProcessExecutionError,
               '_exception': exception.GlusterfsException,
               'xkw': {'raw_error': False}},
              {'trouble': exception.ProcessExecutionError,
               '_exception': exception.ProcessExecutionError,
               'xkw': {'raw_error': True}},
              {'trouble': RuntimeError, '_exception': RuntimeError, 'xkw': {}})
    @ddt.unpack
    def test_gluster_manager_make_gluster_call_error(self, trouble,
                                                     _exception, xkw):
        fake_obj = mock.Mock(side_effect=trouble)
        fake_execute = mock.Mock()
        kwargs = fake_kwargs.copy()
        kwargs.update(xkw)
        with mock.patch.object(common.ganesha_utils, 'RootExecutor',
                               mock.Mock(return_value=fake_obj)):
            gluster_manager = common.GlusterManager(
                '127.0.0.1:/testvol', self.fake_execf)

            self.assertRaises(_exception,
                              gluster_manager.make_gluster_call(fake_execute),
                              *fake_args, **kwargs)

            common.ganesha_utils.RootExecutor.assert_called_with(
                fake_execute)
        fake_obj.assert_called_once_with(
            *(('gluster',) + fake_args), **fake_kwargs)

    def test_get_gluster_vol_option_empty_volinfo(self):
        args = ('--xml', 'volume', 'info', self._gluster_manager.volume)
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(return_value=('', {})))
        self.assertRaises(exception.GlusterfsException,
                          self._gluster_manager.get_gluster_vol_option,
                          NFS_EXPORT_DIR)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, log=mock.ANY)

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
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(side_effect=xml_output))
        self.assertRaises(exception.InvalidShare,
                          self._gluster_manager.get_gluster_vol_option,
                          NFS_EXPORT_DIR)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, log=mock.ANY)

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
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(side_effect=xml_output))
        ret = self._gluster_manager.get_gluster_vol_option(NFS_EXPORT_DIR)
        self.assertIsNone(ret)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, log=mock.ANY)

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
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(side_effect=xml_output))
        ret = self._gluster_manager.get_gluster_vol_option(NFS_EXPORT_DIR)
        self.assertEqual('/foo(10.0.0.1|10.0.0.2),/bar(10.0.0.1)', ret)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, log=mock.ANY)

    def test_get_gluster_version(self):
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(return_value=('glusterfs 3.6.2beta3', '')))
        ret = self._gluster_manager.get_gluster_version()
        self.assertEqual(['3', '6', '2beta3'], ret)
        self._gluster_manager.gluster_call.assert_called_once_with(
            '--version', log=mock.ANY)

    @ddt.data("foo 1.1.1", "glusterfs 3-6", "glusterfs 3.6beta3")
    def test_get_gluster_version_exception(self, versinfo):
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(return_value=(versinfo, '')))
        self.assertRaises(exception.GlusterfsException,
                          self._gluster_manager.get_gluster_version)
        self._gluster_manager.gluster_call.assert_called_once_with(
            '--version', log=mock.ANY)

    def test_check_gluster_version(self):
        self.mock_object(self._gluster_manager, 'get_gluster_version',
                         mock.Mock(return_value=('3', '6')))

        ret = self._gluster_manager.check_gluster_version((3, 5, 2))
        self.assertIsNone(ret)
        self._gluster_manager.get_gluster_version.assert_called_once_with()

    def test_check_gluster_version_unmet(self):
        self.mock_object(self._gluster_manager, 'get_gluster_version',
                         mock.Mock(return_value=('3', '5', '2')))

        self.assertRaises(exception.GlusterfsException,
                          self._gluster_manager.check_gluster_version, (3, 6))
        self._gluster_manager.get_gluster_version.assert_called_once_with()

    @ddt.data(('3', '6'),
              ('3', '6', '2beta'),
              ('3', '6', '2beta', '4'))
    def test_numreduct(self, vers):
        ret = common.GlusterManager.numreduct(vers)
        self.assertEqual((3, 6), ret)


@ddt.ddt
class GlusterFSCommonTestCase(test.TestCase):
    """Tests common GlusterFS utility functions."""

    def setUp(self):
        super(GlusterFSCommonTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self)
        self._execute = fake_utils.fake_execute
        self.addCleanup(fake_utils.fake_execute_set_repliers, [])
        self.addCleanup(fake_utils.fake_execute_clear_log)
        self.mock_object(common.GlusterManager, 'make_gluster_call')

    @staticmethod
    def _mount_exec(vol, mnt):
        return ['mkdir -p %s' % mnt,
                'mount -t glusterfs %(exp)s %(mnt)s' % {'exp': vol,
                                                        'mnt': mnt}]

    def test_mount_gluster_vol(self):
        expected_exec = self._mount_exec(fakeexport, fakemnt)
        ret = common._mount_gluster_vol(self._execute, fakeexport, fakemnt,
                                        False)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertIsNone(ret)

    def test_mount_gluster_vol_mounted_noensure(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='already mounted')
        expected_exec = self._mount_exec(fakeexport, fakemnt)
        fake_utils.fake_execute_set_repliers([('mount', exec_runner)])
        self.assertRaises(exception.GlusterfsException,
                          common._mount_gluster_vol,
                          self._execute, fakeexport, fakemnt, False)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_mount_gluster_vol_mounted_ensure(self):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise exception.ProcessExecutionError(stderr='already mounted')
        expected_exec = self._mount_exec(fakeexport, fakemnt)
        common.LOG.warning = mock.Mock()
        fake_utils.fake_execute_set_repliers([('mount', exec_runner)])
        ret = common._mount_gluster_vol(self._execute, fakeexport, fakemnt,
                                        True)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertIsNone(ret)
        common.LOG.warning.assert_called_with(
            "%s is already mounted.", fakeexport)

    @ddt.data(True, False)
    def test_mount_gluster_vol_fail(self, ensure):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise RuntimeError('fake error')
        expected_exec = self._mount_exec(fakeexport, fakemnt)
        fake_utils.fake_execute_set_repliers([('mount', exec_runner)])
        self.assertRaises(RuntimeError, common._mount_gluster_vol,
                          self._execute, fakeexport, fakemnt, ensure)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_umount_gluster_vol(self):
        expected_exec = ['umount %s' % fakemnt]
        ret = common._umount_gluster_vol(self._execute, fakemnt)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)
        self.assertIsNone(ret)

    @ddt.data({'in_exc': exception.ProcessExecutionError,
               'out_exc': exception.GlusterfsException},
              {'in_exc': RuntimeError, 'out_exc': RuntimeError})
    @ddt.unpack
    def test_umount_gluster_vol_fail(self, in_exc, out_exc):
        def exec_runner(*ignore_args, **ignore_kwargs):
            raise in_exc('fake error')
        expected_exec = ['umount %s' % fakemnt]
        fake_utils.fake_execute_set_repliers([('umount', exec_runner)])
        self.assertRaises(out_exc, common._umount_gluster_vol,
                          self._execute, fakemnt)
        self.assertEqual(fake_utils.fake_execute_get_log(), expected_exec)

    def test_restart_gluster_vol(self):
        gmgr = common.GlusterManager(fakeexport, self._execute, None, None)
        test_args = [(('volume', 'stop', fakevol, '--mode=script'),
                      {'log': mock.ANY}),
                     (('volume', 'start', fakevol), {'log': mock.ANY})]

        common._restart_gluster_vol(gmgr)
        self.assertEqual(
            [mock.call(*arg[0], **arg[1]) for arg in test_args],
            gmgr.gluster_call.call_args_list)
