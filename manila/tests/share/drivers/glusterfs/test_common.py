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
            fake_gluster_manager_dict = {
                'host': '127.0.0.1',
                'user': 'testuser',
                'volume': 'testvol'
            }
            self._gluster_manager_dict = common.GlusterManager(
                fake_gluster_manager_dict, self.fake_execf,
                fake_path_to_private_key, fake_remote_server_password)
            self._gluster_manager_array = [self._gluster_manager,
                                           self._gluster_manager_dict]

    def test_check_volume_presence(self):
        common._check_volume_presence(mock.Mock())(self._gluster_manager)

    def test_check_volume_presence_error(self):
        gmgr = common.GlusterManager('testuser@127.0.0.1')

        self.assertRaises(
            exception.GlusterfsException,
            common._check_volume_presence(mock.Mock()), gmgr)

    def test_volxml_get(self):
        xmlout = mock.Mock()
        value = mock.Mock()
        value.text = 'foobar'
        xmlout.find = mock.Mock(return_value=value)

        ret = common.volxml_get(xmlout, 'some/path')

        self.assertEqual('foobar', ret)

    @ddt.data(None, 'some-value')
    def test_volxml_get_notfound_fallback(self, default):
        xmlout = mock.Mock()
        xmlout.find = mock.Mock(return_value=None)

        ret = common.volxml_get(xmlout, 'some/path', default)

        self.assertEqual(default, ret)

    def test_volxml_get_notfound(self):
        xmlout = mock.Mock()
        xmlout.find = mock.Mock(return_value=None)

        self.assertRaises(exception.InvalidShare, common.volxml_get,
                          xmlout, 'some/path')

    def test_gluster_manager_common_init(self):
        for gmgr in self._gluster_manager_array:
            self.assertEqual(
                fake_gluster_manager_attrs['user'],
                gmgr.user)
            self.assertEqual(
                fake_gluster_manager_attrs['host'],
                gmgr.host)
            self.assertEqual(
                fake_gluster_manager_attrs['volume'],
                gmgr.volume)
            self.assertEqual(
                fake_gluster_manager_attrs['qualified'],
                gmgr.qualified)
            self.assertEqual(
                fake_gluster_manager_attrs['export'],
                gmgr.export)
            self.assertEqual(
                fake_gluster_manager_attrs['path_to_private_key'],
                gmgr.path_to_private_key)
            self.assertEqual(
                fake_gluster_manager_attrs['remote_server_password'],
                gmgr.remote_server_password)
            self.assertEqual(
                self.fake_executor,
                gmgr.gluster_call)

    @ddt.data({'user': 'testuser', 'host': '127.0.0.1',
               'volume': 'testvol', 'path': None},
              {'user': None, 'host': '127.0.0.1',
               'volume': 'testvol', 'path': '/testpath'},
              {'user': None, 'host': '127.0.0.1',
               'volume': 'testvol', 'path': None},
              {'user': None, 'host': '127.0.0.1',
               'volume': None, 'path': None},
              {'user': 'testuser', 'host': '127.0.0.1',
               'volume': None, 'path': None},
              {'user': 'testuser', 'host': '127.0.0.1',
               'volume': 'testvol', 'path': '/testpath'})
    def test_gluster_manager_init_check(self, test_addr_dict):
        test_gluster_manager = common.GlusterManager(
            test_addr_dict, self.fake_execf)
        self.assertEqual(test_addr_dict, test_gluster_manager.components)

    @ddt.data(None, True)
    def test_gluster_manager_init_has_vol(self, has_volume):
        test_gluster_manager = common.GlusterManager(
            'testuser@127.0.0.1:/testvol', self.fake_execf,
            requires={'volume': has_volume})
        self.assertEqual('testvol', test_gluster_manager.volume)

    @ddt.data(None, True)
    def test_gluster_manager_dict_init_has_vol(self, has_volume):
        test_addr_dict = {'user': 'testuser',
                          'host': '127.0.0.1',
                          'volume': 'testvol',
                          'path': '/testdir'}
        test_gluster_manager = common.GlusterManager(
            test_addr_dict, self.fake_execf,
            requires={'volume': has_volume})
        self.assertEqual('testvol', test_gluster_manager.volume)

    @ddt.data(None, False)
    def test_gluster_manager_init_no_vol(self, has_volume):
        test_gluster_manager = common.GlusterManager(
            'testuser@127.0.0.1', self.fake_execf,
            requires={'volume': has_volume})
        self.assertIsNone(test_gluster_manager.volume)

    @ddt.data(None, False)
    def test_gluster_manager_dict_init_no_vol(self, has_volume):
        test_addr_dict = {'user': 'testuser',
                          'host': '127.0.0.1'}
        test_gluster_manager = common.GlusterManager(
            test_addr_dict, self.fake_execf,
            requires={'volume': has_volume})
        self.assertIsNone(test_gluster_manager.volume)

    def test_gluster_manager_init_has_shouldnt_have_vol(self):
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager,
                          'testuser@127.0.0.1:/testvol',
                          self.fake_execf, requires={'volume': False})

    def test_gluster_manager_dict_init_has_shouldnt_have_vol(self):
        test_addr_dict = {'user': 'testuser',
                          'host': '127.0.0.1',
                          'volume': 'testvol'}
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager,
                          test_addr_dict,
                          self.fake_execf, requires={'volume': False})

    def test_gluster_manager_hasnt_should_have_vol(self):
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager, 'testuser@127.0.0.1',
                          self.fake_execf, requires={'volume': True})

    def test_gluster_manager_dict_hasnt_should_have_vol(self):
        test_addr_dict = {'user': 'testuser',
                          'host': '127.0.0.1'}
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager, test_addr_dict,
                          self.fake_execf, requires={'volume': True})

    def test_gluster_manager_invalid(self):
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager, '127.0.0.1:vol',
                          'self.fake_execf')

    def test_gluster_manager_dict_invalid_req_host(self):
        test_addr_dict = {'user': 'testuser',
                          'volume': 'testvol'}
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager, test_addr_dict,
                          'self.fake_execf')

    @ddt.data({'user': 'testuser'},
              {'host': 'johndoe@example.com'},
              {'host': 'example.com/so', 'volume': 'me/path'},
              {'user': 'user@error', 'host': "example.com", 'volume': 'vol'},
              {'host': 'example.com', 'volume': 'vol', 'pith': '/path'},
              {'host': 'example.com', 'path': '/path'},
              {'user': 'user@error', 'host': "example.com", 'path': '/path'})
    def test_gluster_manager_dict_invalid_input(self, test_addr_dict):
        self.assertRaises(exception.GlusterfsException,
                          common.GlusterManager, test_addr_dict,
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

    @ddt.data({'mockargs': {}, 'kwargs': {}},
              {'mockargs': {'side_effect': exception.ProcessExecutionError},
               'kwargs': {'error_policy': 'suppress'}},
              {'mockargs': {
                  'side_effect': exception.ProcessExecutionError(exit_code=2)},
               'kwargs': {'error_policy': (2,)}})
    @ddt.unpack
    def test_gluster_manager_make_gluster_call_local(self, mockargs, kwargs):
        fake_obj = mock.Mock(**mockargs)
        fake_execute = mock.Mock()
        kwargs.update(fake_kwargs)
        with mock.patch.object(common.ganesha_utils, 'RootExecutor',
                               mock.Mock(return_value=fake_obj)):
            gluster_manager = common.GlusterManager(
                '127.0.0.1:/testvol', self.fake_execf)
            gluster_manager.make_gluster_call(fake_execute)(*fake_args,
                                                            **kwargs)
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
              {'trouble': exception.ProcessExecutionError(exit_code=2),
               '_exception': exception.GlusterfsException,
               'xkw': {'error_policy': (1,)}},
              {'trouble': exception.ProcessExecutionError,
               '_exception': exception.GlusterfsException,
               'xkw': {'error_policy': 'coerce'}},
              {'trouble': exception.ProcessExecutionError,
               '_exception': exception.ProcessExecutionError,
               'xkw': {'error_policy': 'raw'}},
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

    def test_gluster_manager_make_gluster_call_bad_policy(self):
        fake_obj = mock.Mock()
        fake_execute = mock.Mock()
        with mock.patch.object(common.ganesha_utils, 'RootExecutor',
                               mock.Mock(return_value=fake_obj)):
            gluster_manager = common.GlusterManager(
                '127.0.0.1:/testvol', self.fake_execf)

            self.assertRaises(TypeError,
                              gluster_manager.make_gluster_call(fake_execute),
                              *fake_args, error_policy='foobar')

    @ddt.data({}, {'opErrstr': None}, {'opErrstr': 'error'})
    def test_xml_response_check(self, xdict):
        fdict = {'opRet': '0', 'opErrno': '0', 'some/count': '1'}
        fdict.update(xdict)

        def vxget(x, e, *a):
            if a:
                return fdict.get(e, a[0])
            else:
                return fdict[e]

        xtree = mock.Mock()
        command = ['volume', 'command', 'fake']

        with mock.patch.object(common, 'volxml_get', side_effect=vxget):
            self._gluster_manager.xml_response_check(xtree, command,
                                                     'some/count')

            self.assertTrue(common.volxml_get.called)

    @ddt.data('1', '2')
    def test_xml_response_check_failure(self, count):
        fdict = {'opRet': '-1', 'opErrno': '0', 'some/count': count}

        def vxget(x, e, *a):
            if a:
                return fdict.get(e, a[0])
            else:
                return fdict[e]

        xtree = mock.Mock()
        command = ['volume', 'command', 'fake']

        with mock.patch.object(common, 'volxml_get', side_effect=vxget):
            self.assertRaises(exception.GlusterfsException,
                              self._gluster_manager.xml_response_check,
                              xtree, command, 'some/count')

            self.assertTrue(common.volxml_get.called)

    @ddt.data({'opRet': '-2', 'opErrno': '0', 'some/count': '1'},
              {'opRet': '0', 'opErrno': '1', 'some/count': '1'},
              {'opRet': '0', 'opErrno': '0', 'some/count': '0'},
              {'opRet': '0', 'opErrno': '0', 'some/count': '2'})
    def test_xml_response_check_invalid(self, fdict):

        def vxget(x, e, *a):
            if a:
                return fdict.get(e, a[0])
            else:
                return fdict[e]

        xtree = mock.Mock()
        command = ['volume', 'command', 'fake']

        with mock.patch.object(common, 'volxml_get', side_effect=vxget):
            self.assertRaises(exception.InvalidShare,
                              self._gluster_manager.xml_response_check,
                              xtree, command, 'some/count')

            self.assertTrue(common.volxml_get.called)

    @ddt.data({'opRet': '0', 'opErrno': '0'},
              {'opRet': '0', 'opErrno': '0', 'some/count': '2'})
    def test_xml_response_check_count_ignored(self, fdict):

        def vxget(x, e, *a):
            if a:
                return fdict.get(e, a[0])
            else:
                return fdict[e]

        xtree = mock.Mock()
        command = ['volume', 'command', 'fake']

        with mock.patch.object(common, 'volxml_get', side_effect=vxget):
            self._gluster_manager.xml_response_check(xtree, command)

            self.assertTrue(common.volxml_get.called)

    def test_get_vol_option_via_info_empty_volinfo(self):
        args = ('--xml', 'volume', 'info', self._gluster_manager.volume)
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(return_value=('', {})))
        self.assertRaises(exception.GlusterfsException,
                          self._gluster_manager._get_vol_option_via_info,
                          'foobar')
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, log=mock.ANY)

    def test_get_vol_option_via_info_ambiguous_volinfo(self):

        def xml_output(*ignore_args, **ignore_kwargs):
            return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <opRet>0</opRet>
  <opErrno>0</opErrno>
  <opErrstr/>
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
                          self._gluster_manager._get_vol_option_via_info,
                          'foobar')
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, log=mock.ANY)

    def test_get_vol_option_via_info_trivial_volinfo(self):

        def xml_output(*ignore_args, **ignore_kwargs):
            return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <opRet>0</opRet>
  <opErrno>0</opErrno>
  <opErrstr/>
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
        ret = self._gluster_manager._get_vol_option_via_info('foobar')
        self.assertIsNone(ret)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, log=mock.ANY)

    def test_get_vol_option_via_info(self):

        def xml_output(*ignore_args, **ignore_kwargs):
            return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <opRet>0</opRet>
  <opErrno>0</opErrno>
  <opErrstr/>
  <volInfo>
    <volumes>
      <volume>
        <options>
           <option>
              <name>foobar</name>
              <value>FIRE MONKEY!</value>
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
        ret = self._gluster_manager._get_vol_option_via_info('foobar')
        self.assertEqual('FIRE MONKEY!', ret)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, log=mock.ANY)

    def test_get_vol_user_option(self):
        self.mock_object(self._gluster_manager, '_get_vol_option_via_info',
                         mock.Mock(return_value='VALUE'))

        ret = self._gluster_manager._get_vol_user_option('OPT')

        self.assertEqual(ret, 'VALUE')
        (self._gluster_manager._get_vol_option_via_info.
         assert_called_once_with('user.OPT'))

    def test_get_vol_regular_option_empty_reponse(self):
        args = ('--xml', 'volume', 'get', self._gluster_manager.volume,
                NFS_EXPORT_DIR)
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(return_value=('', {})))

        ret = self._gluster_manager._get_vol_regular_option(NFS_EXPORT_DIR)

        self.assertIsNone(ret)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, check_exit_code=False)

    @ddt.data(0, 2)
    def test_get_vol_regular_option_ambiguous_volinfo(self, count):

        def xml_output(*ignore_args, **ignore_kwargs):
            return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <opRet>0</opRet>
  <opErrno>0</opErrno>
  <opErrstr/>
  <volGetopts>
    <count>%d</count>
  </volGetopts>
</cliOutput>""" % count, ''

        args = ('--xml', 'volume', 'get', self._gluster_manager.volume,
                NFS_EXPORT_DIR)
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(side_effect=xml_output))

        self.assertRaises(exception.InvalidShare,
                          self._gluster_manager._get_vol_regular_option,
                          NFS_EXPORT_DIR)

        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, check_exit_code=False)

    def test_get_vol_regular_option(self):

        def xml_output(*ignore_args, **ignore_kwargs):
            return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cliOutput>
  <opRet>0</opRet>
  <opErrno>0</opErrno>
  <opErrstr/>
  <volGetopts>
    <count>1</count>
    <Option>nfs.export-dir</Option>
    <Value>/foo(10.0.0.1|10.0.0.2),/bar(10.0.0.1)</Value>
  </volGetopts>
</cliOutput>""", ''

        args = ('--xml', 'volume', 'get', self._gluster_manager.volume,
                NFS_EXPORT_DIR)
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(side_effect=xml_output))

        ret = self._gluster_manager._get_vol_regular_option(NFS_EXPORT_DIR)

        self.assertEqual('/foo(10.0.0.1|10.0.0.2),/bar(10.0.0.1)', ret)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, check_exit_code=False)

    def test_get_vol_regular_option_not_suppored(self):
        args = ('--xml', 'volume', 'get', self._gluster_manager.volume,
                NFS_EXPORT_DIR)
        self.mock_object(self._gluster_manager, 'gluster_call',
                         mock.Mock(return_value=(
                                   """Ceci n'est pas un XML.""", '')))
        self.mock_object(self._gluster_manager, '_get_vol_option_via_info',
                         mock.Mock(return_value="VALUE"))

        ret = self._gluster_manager._get_vol_regular_option(NFS_EXPORT_DIR)

        self.assertEqual("VALUE", ret)
        self._gluster_manager.gluster_call.assert_called_once_with(
            *args, check_exit_code=False)
        (self._gluster_manager._get_vol_option_via_info.
         assert_called_once_with(NFS_EXPORT_DIR))

    @ddt.data({'opt': 'some.option', 'opttype': 'regular',
               'lowopt': 'some.option'},
              {'opt': 'user.param', 'opttype': 'user', 'lowopt': 'param'})
    @ddt.unpack
    def test_get_vol_option(self, opt, opttype, lowopt):
        for t in ('user', 'regular'):
            self.mock_object(self._gluster_manager, '_get_vol_%s_option' % t,
                             mock.Mock(return_value='value-%s' % t))

        ret = self._gluster_manager.get_vol_option(opt)

        self.assertEqual('value-%s' % opttype, ret)
        for t in ('user', 'regular'):
            func = getattr(self._gluster_manager, '_get_vol_%s_option' % t)
            if opttype == t:
                func.assert_called_once_with(lowopt)
            else:
                self.assertFalse(func.called)

    def test_get_vol_option_unset(self):
        self.mock_object(self._gluster_manager, '_get_vol_regular_option',
                         mock.Mock(return_value=None))

        ret = self._gluster_manager.get_vol_option('some.option')

        self.assertIsNone(ret)

    @ddt.data({'value': '0', 'boolval': False},
              {'value': 'Off', 'boolval': False},
              {'value': 'no', 'boolval': False},
              {'value': '1', 'boolval': True},
              {'value': 'true', 'boolval': True},
              {'value': 'enAble', 'boolval': True},
              {'value': None, 'boolval': None})
    @ddt.unpack
    def test_get_vol_option_boolean(self, value, boolval):
        self.mock_object(self._gluster_manager, '_get_vol_regular_option',
                         mock.Mock(return_value=value))

        ret = self._gluster_manager.get_vol_option('some.option',
                                                   boolean=True)

        self.assertEqual(boolval, ret)

    def test_get_vol_option_boolean_bad(self):
        self.mock_object(self._gluster_manager, '_get_vol_regular_option',
                         mock.Mock(return_value='jabberwocky'))

        self.assertRaises(exception.GlusterfsException,
                          self._gluster_manager.get_vol_option,
                          'some.option', boolean=True)

    @ddt.data({'setting': 'some_value', 'args': ('set', 'some_value')},
              {'setting': None, 'args': ('reset',)},
              {'setting': True, 'args': ('set', 'ON')},
              {'setting': False, 'args': ('set', 'OFF')})
    @ddt.unpack
    def test_set_vol_option(self, setting, args):
        self.mock_object(self._gluster_manager, 'gluster_call', mock.Mock())

        self._gluster_manager.set_vol_option('an_option', setting)

        self._gluster_manager.gluster_call.assert_called_once_with(
            'volume', args[0], 'testvol', 'an_option', *args[1:],
            error_policy=mock.ANY)

    @ddt.data({}, {'ignore_failure': False})
    def test_set_vol_option_error(self, kwargs):
        fake_obj = mock.Mock(
            side_effect=exception.ProcessExecutionError(exit_code=1))
        with mock.patch.object(common.ganesha_utils, 'RootExecutor',
                               mock.Mock(return_value=fake_obj)):
            gluster_manager = common.GlusterManager(
                '127.0.0.1:/testvol', self.fake_execf)

            self.assertRaises(exception.GlusterfsException,
                              gluster_manager.set_vol_option,
                              'an_option', "some_value", **kwargs)

            self.assertTrue(fake_obj.called)

    def test_set_vol_option_error_relaxed(self):
        fake_obj = mock.Mock(
            side_effect=exception.ProcessExecutionError(exit_code=1))
        with mock.patch.object(common.ganesha_utils, 'RootExecutor',
                               mock.Mock(return_value=fake_obj)):
            gluster_manager = common.GlusterManager(
                '127.0.0.1:/testvol', self.fake_execf)

            gluster_manager.set_vol_option('an_option', "some_value",
                                           ignore_failure=True)

            self.assertTrue(fake_obj.called)

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
        ret = common.numreduct(vers)
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
