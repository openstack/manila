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

import copy
import re

import ddt
import mock
from oslo_serialization import jsonutils
import six

from manila import exception
from manila.share.drivers.ganesha import manager
from manila import test
from manila import utils


test_export_id = 101
test_name = 'fakefile'
test_path = '/fakedir0/export.d/fakefile.conf'
test_tmp_path = '/fakedir0/export.d/fakefile.conf.RANDOM'
test_ganesha_cnf = """EXPORT {
    Export_Id = 101;
    CLIENT {
        Clients = ip1;
        Access_Level = ro;
    }
    CLIENT {
        Clients = ip2;
        Access_Level = rw;
    }
}"""
test_dict_unicode = {
    u'EXPORT': {
        u'Export_Id': 101,
        u'CLIENT': [
            {u'Clients': u"ip1", u'Access_Level': u'ro'},
            {u'Clients': u"ip2", u'Access_Level': u'rw'}]
    }
}
test_dict_str = {
    'EXPORT': {
        'Export_Id': 101,
        'CLIENT': [
            {'Clients': 'ip1', 'Access_Level': 'ro'},
            {'Clients': 'ip2', 'Access_Level': 'rw'}]
    }
}

manager_fake_kwargs = {
    'ganesha_config_path': '/fakedir0/fakeconfig',
    'ganesha_db_path': '/fakedir1/fake.db',
    'ganesha_export_dir': '/fakedir0/export.d',
    'ganesha_service_name': 'ganesha.fakeservice'
}


class MockRadosClientModule(object):
    """Mocked up version of Ceph's RADOS client interface."""

    class ObjectNotFound(Exception):
        pass


@ddt.ddt
class MiscTests(test.TestCase):

    @ddt.data({'import_exc': None},
              {'import_exc': ImportError})
    @ddt.unpack
    def test_setup_rados(self, import_exc):
        manager.rados = None
        with mock.patch.object(
                manager.importutils,
                'import_module',
                side_effect=import_exc) as mock_import_module:
            if import_exc:
                self.assertRaises(
                    exception.ShareBackendException, manager.setup_rados)
            else:
                manager.setup_rados()
                self.assertEqual(mock_import_module.return_value,
                                 manager.rados)
            mock_import_module.assert_called_once_with('rados')


class GaneshaConfigTests(test.TestCase):
    """Tests Ganesha config file format convertor functions."""

    ref_ganesha_cnf = """EXPORT {
    CLIENT {
        Clients = ip1;
        Access_Level = "ro";
    }
    CLIENT {
        Clients = ip2;
        Access_Level = "rw";
    }
    Export_Id = 101;
}"""

    @staticmethod
    def conf_mangle(*confs):
        """A "mangler" for the conf format.

        Its purpose is to transform conf data in a way so that semantically
        equivalent confs yield identical results. Besides this objective
        criteria, we seek a good trade-off between the following
        requirements:
        - low lossiness;
        - low code complexity.
        """
        def _conf_mangle(conf):
            # split to expressions by the delimiter ";"
            # (braces are forced to be treated as expressions
            # by sandwiching them in ";"-s)
            conf = re.sub('[{}]', ';\g<0>;', conf).split(';')
            # whitespace-split expressions to tokens with
            # (equality is forced to be treated as token by
            # sandwiching in space)
            conf = map(lambda l: l.replace("=", " = ").split(), conf)
            # get rid of by-product empty lists (derived from superflouous
            # ";"-s that might have crept in due to "sandwiching")
            conf = map(lambda x: x, conf)
            # handle the non-deterministic order of confs
            conf = list(conf)
            conf.sort()
            return conf

        return (_conf_mangle(conf) for conf in confs)

    def test_conf2json(self):
        test_ganesha_cnf_with_comment = """EXPORT {
# fake_export_block
    Export_Id = 101;
    CLIENT {
        Clients = ip1;
    }
}"""
        result_dict_unicode = {
            u'EXPORT': {
                u'CLIENT': {u'Clients': u'ip1'},
                u'Export_Id': 101
            }
        }
        ret = manager._conf2json(test_ganesha_cnf_with_comment)
        self.assertEqual(result_dict_unicode, jsonutils.loads(ret))

    def test_parseconf_ganesha_cnf_input(self):
        ret = manager.parseconf(test_ganesha_cnf)
        self.assertEqual(test_dict_unicode, ret)

    def test_parseconf_json_input(self):
        ret = manager.parseconf(jsonutils.dumps(test_dict_str))
        self.assertEqual(test_dict_unicode, ret)

    def test_dump_to_conf(self):
        ganesha_cnf = six.StringIO()
        manager._dump_to_conf(test_dict_str, ganesha_cnf)
        self.assertEqual(*self.conf_mangle(self.ref_ganesha_cnf,
                                           ganesha_cnf.getvalue()))

    def test_mkconf(self):
        ganesha_cnf = manager.mkconf(test_dict_str)
        self.assertEqual(*self.conf_mangle(self.ref_ganesha_cnf,
                                           ganesha_cnf))


@ddt.ddt
class GaneshaManagerTestCase(test.TestCase):
    """Tests GaneshaManager."""

    def instantiate_ganesha_manager(self, *args, **kwargs):
        ganesha_rados_store_enable = kwargs.get('ganesha_rados_store_enable',
                                                False)
        if ganesha_rados_store_enable:
            with mock.patch.object(
                    manager.GaneshaManager,
                    '_get_rados_object') as self.mock_get_rados_object:
                return manager.GaneshaManager(*args, **kwargs)
        else:
            with mock.patch.object(
                    manager.GaneshaManager,
                    'get_export_id',
                    return_value=100) as self.mock_get_export_id:
                return manager.GaneshaManager(*args, **kwargs)

    def setUp(self):
        super(GaneshaManagerTestCase, self).setUp()
        self._execute = mock.Mock(return_value=('', ''))
        self._manager = self.instantiate_ganesha_manager(
            self._execute, 'faketag', **manager_fake_kwargs)
        self._ceph_vol_client = mock.Mock()
        self._setup_rados = mock.Mock()
        self._execute2 = mock.Mock(return_value=('', ''))
        self.mock_object(manager, 'rados', MockRadosClientModule)
        self.mock_object(manager, 'setup_rados', self._setup_rados)
        fake_kwargs = copy.copy(manager_fake_kwargs)
        fake_kwargs.update(
            ganesha_rados_store_enable=True,
            ganesha_rados_store_pool_name='fakepool',
            ganesha_rados_export_counter='fakecounter',
            ganesha_rados_export_index='fakeindex',
            ceph_vol_client=self._ceph_vol_client
        )
        self._manager_with_rados_store = self.instantiate_ganesha_manager(
            self._execute2, 'faketag', **fake_kwargs)
        self.mock_object(utils, 'synchronized',
                         mock.Mock(return_value=lambda f: f))

    def test_init(self):
        self.mock_object(self._manager, 'reset_exports')
        self.mock_object(self._manager, 'restart_service')
        self.assertEqual('/fakedir0/fakeconfig',
                         self._manager.ganesha_config_path)
        self.assertEqual('faketag', self._manager.tag)
        self.assertEqual('/fakedir0/export.d',
                         self._manager.ganesha_export_dir)
        self.assertEqual('/fakedir1/fake.db', self._manager.ganesha_db_path)
        self.assertEqual('ganesha.fakeservice', self._manager.ganesha_service)
        self.assertEqual(
            [mock.call('mkdir', '-p', self._manager.ganesha_export_dir),
             mock.call('mkdir', '-p', '/fakedir1'),
             mock.call('sqlite3', self._manager.ganesha_db_path,
                       'create table ganesha(key varchar(20) primary key, '
                       'value int); insert into ganesha values("exportid", '
                       '100);', run_as_root=False, check_exit_code=False)],
            self._execute.call_args_list)
        self.mock_get_export_id.assert_called_once_with(bump=False)

    def test_init_execute_error_log_message(self):
        fake_args = ('foo', 'bar')

        def raise_exception(*args, **kwargs):
            if args == fake_args:
                raise exception.GaneshaCommandFailure()

        test_execute = mock.Mock(side_effect=raise_exception)
        self.mock_object(manager.LOG, 'error')
        test_manager = self.instantiate_ganesha_manager(
            test_execute, 'faketag', **manager_fake_kwargs)
        self.assertRaises(
            exception.GaneshaCommandFailure,
            test_manager.execute,
            *fake_args, message='fakemsg')
        manager.LOG.error.assert_called_once_with(
            mock.ANY, {'tag': 'faketag', 'msg': 'fakemsg'})

    def test_init_execute_error_no_log_message(self):
        fake_args = ('foo', 'bar')

        def raise_exception(*args, **kwargs):
            if args == fake_args:
                raise exception.GaneshaCommandFailure()

        test_execute = mock.Mock(side_effect=raise_exception)
        self.mock_object(manager.LOG, 'error')
        test_manager = self.instantiate_ganesha_manager(
            test_execute, 'faketag', **manager_fake_kwargs)
        self.assertRaises(
            exception.GaneshaCommandFailure,
            test_manager.execute,
            *fake_args, message='fakemsg', makelog=False)
        self.assertFalse(manager.LOG.error.called)

    @ddt.data(False, True)
    def test_init_with_rados_store_and_export_counter_exists(
            self, counter_exists):
        fake_execute = mock.Mock(return_value=('', ''))
        fake_kwargs = copy.copy(manager_fake_kwargs)
        fake_kwargs.update(
            ganesha_rados_store_enable=True,
            ganesha_rados_store_pool_name='fakepool',
            ganesha_rados_export_counter='fakecounter',
            ganesha_rados_export_index='fakeindex',
            ceph_vol_client=self._ceph_vol_client
        )
        if counter_exists:
            self.mock_object(
                manager.GaneshaManager, '_get_rados_object', mock.Mock())
        else:
            self.mock_object(
                manager.GaneshaManager, '_get_rados_object',
                mock.Mock(side_effect=MockRadosClientModule.ObjectNotFound))
        self.mock_object(manager.GaneshaManager, '_put_rados_object')

        test_mgr = manager.GaneshaManager(
            fake_execute, 'faketag', **fake_kwargs)

        self.assertEqual('/fakedir0/fakeconfig', test_mgr.ganesha_config_path)
        self.assertEqual('faketag', test_mgr.tag)
        self.assertEqual('/fakedir0/export.d', test_mgr.ganesha_export_dir)
        self.assertEqual('ganesha.fakeservice', test_mgr.ganesha_service)
        fake_execute.assert_called_once_with(
            'mkdir', '-p', '/fakedir0/export.d')
        self.assertTrue(test_mgr.ganesha_rados_store_enable)
        self.assertEqual('fakepool', test_mgr.ganesha_rados_store_pool_name)
        self.assertEqual('fakecounter', test_mgr.ganesha_rados_export_counter)
        self.assertEqual('fakeindex', test_mgr.ganesha_rados_export_index)
        self.assertEqual(self._ceph_vol_client, test_mgr.ceph_vol_client)
        self._setup_rados.assert_called_with()
        test_mgr._get_rados_object.assert_called_once_with('fakecounter')
        if counter_exists:
            self.assertFalse(test_mgr._put_rados_object.called)
        else:
            test_mgr._put_rados_object.assert_called_once_with(
                'fakecounter', six.text_type(1000))

    def test_ganesha_export_dir(self):
        self.assertEqual(
            '/fakedir0/export.d', self._manager.ganesha_export_dir)

    def test_getpath(self):
        self.assertEqual(
            '/fakedir0/export.d/fakefile.conf',
            self._manager._getpath('fakefile'))

    def test_get_export_rados_object_name(self):
        self.assertEqual(
            'ganesha-export-fakeobj',
            self._manager._get_export_rados_object_name('fakeobj'))

    def test_write_tmp_conf_file(self):
        self.mock_object(manager.pipes, 'quote',
                         mock.Mock(side_effect=['fakedata',
                                                test_tmp_path]))
        test_args = [
            ('mktemp', '-p', '/fakedir0/export.d', '-t',
             'fakefile.conf.XXXXXX'),
            ('sh', '-c', 'echo fakedata > %s' % test_tmp_path)]
        test_kwargs = {
            'message': 'writing %s' % test_tmp_path
        }

        def return_tmpfile(*args, **kwargs):
            if args == test_args[0]:
                return (test_tmp_path + '\n', '')
        self.mock_object(self._manager, 'execute',
                         mock.Mock(side_effect=return_tmpfile))

        ret = self._manager._write_tmp_conf_file(test_path, 'fakedata')

        self._manager.execute.assert_has_calls([
            mock.call(*test_args[0]),
            mock.call(*test_args[1], **test_kwargs)])
        manager.pipes.quote.assert_has_calls([
            mock.call('fakedata'),
            mock.call(test_tmp_path)])
        self.assertEqual(test_tmp_path, ret)

    @ddt.data(True, False)
    def test_write_conf_file_with_mv_error(self, mv_error):
        test_data = 'fakedata'
        test_args = [
            ('mv', test_tmp_path, test_path),
            ('rm', test_tmp_path)]
        self.mock_object(self._manager, '_getpath',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_write_tmp_conf_file',
                         mock.Mock(return_value=test_tmp_path))

        def mock_return(*args, **kwargs):
            if args == test_args[0]:
                if mv_error:
                    raise exception.ProcessExecutionError()
                else:
                    return ('', '')

        self.mock_object(self._manager, 'execute',
                         mock.Mock(side_effect=mock_return))

        if mv_error:
            self.assertRaises(
                exception.ProcessExecutionError,
                self._manager._write_conf_file, test_name, test_data)
        else:
            ret = self._manager._write_conf_file(test_name, test_data)

        self._manager._getpath.assert_called_once_with(test_name)
        self._manager._write_tmp_conf_file.assert_called_once_with(
            test_path, test_data)
        if mv_error:
            self._manager.execute.assert_has_calls([
                mock.call(*test_args[0]),
                mock.call(*test_args[1])])
        else:
            self._manager.execute.assert_has_calls([
                mock.call(*test_args[0])])
            self.assertEqual(test_path, ret)

    def test_mkindex(self):
        test_ls_output = 'INDEX.conf\nfakefile.conf\nfakefile.txt'
        test_index = '%include /fakedir0/export.d/fakefile.conf\n'
        self.mock_object(self._manager, 'execute',
                         mock.Mock(return_value=(test_ls_output, '')))
        self.mock_object(self._manager, '_write_conf_file')
        ret = self._manager._mkindex()
        self._manager.execute.assert_called_once_with(
            'ls', '/fakedir0/export.d', run_as_root=False)
        self._manager._write_conf_file.assert_called_once_with(
            'INDEX', test_index)
        self.assertIsNone(ret)

    def test_read_export_rados_object(self):
        self.mock_object(self._manager_with_rados_store,
                         '_get_export_rados_object_name',
                         mock.Mock(return_value='fakeobj'))
        self.mock_object(self._manager_with_rados_store, '_get_rados_object',
                         mock.Mock(return_value=test_ganesha_cnf))
        self.mock_object(manager, 'parseconf',
                         mock.Mock(return_value=test_dict_unicode))

        ret = self._manager_with_rados_store._read_export_rados_object(
            test_name)

        (self._manager_with_rados_store._get_export_rados_object_name.
         assert_called_once_with(test_name))
        (self._manager_with_rados_store._get_rados_object.
         assert_called_once_with('fakeobj'))
        manager.parseconf.assert_called_once_with(test_ganesha_cnf)
        self.assertEqual(test_dict_unicode, ret)

    def test_read_export_file(self):
        test_args = ('cat', test_path)
        test_kwargs = {'message': 'reading export fakefile'}
        self.mock_object(self._manager, '_getpath',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, 'execute',
                         mock.Mock(return_value=(test_ganesha_cnf,)))
        self.mock_object(manager, 'parseconf',
                         mock.Mock(return_value=test_dict_unicode))
        ret = self._manager._read_export_file(test_name)
        self._manager._getpath.assert_called_once_with(test_name)
        self._manager.execute.assert_called_once_with(
            *test_args, **test_kwargs)
        manager.parseconf.assert_called_once_with(test_ganesha_cnf)
        self.assertEqual(test_dict_unicode, ret)

    @ddt.data(False, True)
    def test_read_export_with_rados_store(self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        self.mock_object(self._manager, '_read_export_file',
                         mock.Mock(return_value=test_dict_unicode))
        self.mock_object(self._manager, '_read_export_rados_object',
                         mock.Mock(return_value=test_dict_unicode))

        ret = self._manager._read_export(test_name)

        if rados_store_enable:
            self._manager._read_export_rados_object.assert_called_once_with(
                test_name)
            self.assertFalse(self._manager._read_export_file.called)
        else:
            self._manager._read_export_file.assert_called_once_with(test_name)
            self.assertFalse(self._manager._read_export_rados_object.called)
        self.assertEqual(test_dict_unicode, ret)

    @ddt.data(True, False)
    def test_check_export_rados_object_exists(self, exists):
        self.mock_object(
            self._manager_with_rados_store,
            '_get_export_rados_object_name', mock.Mock(return_value='fakeobj'))
        if exists:
            self.mock_object(
                self._manager_with_rados_store, '_get_rados_object')
        else:
            self.mock_object(
                self._manager_with_rados_store, '_get_rados_object',
                mock.Mock(side_effect=MockRadosClientModule.ObjectNotFound))

        ret = self._manager_with_rados_store._check_export_rados_object_exists(
            test_name)

        (self._manager_with_rados_store._get_export_rados_object_name.
         assert_called_once_with(test_name))
        (self._manager_with_rados_store._get_rados_object.
         assert_called_once_with('fakeobj'))
        if exists:
            self.assertTrue(ret)
        else:
            self.assertFalse(ret)

    def test_check_file_exists(self):
        self.mock_object(self._manager, 'execute',
                         mock.Mock(return_value=(test_ganesha_cnf,)))

        ret = self._manager._check_file_exists(test_path)

        self._manager.execute.assert_called_once_with(
            'test', '-f', test_path, makelog=False, run_as_root=False)
        self.assertTrue(ret)

    @ddt.data(1, 4)
    def test_check_file_exists_error(self, exit_code):
        self.mock_object(
            self._manager, 'execute',
            mock.Mock(side_effect=exception.GaneshaCommandFailure(
                exit_code=exit_code))
        )

        if exit_code == 1:
            ret = self._manager._check_file_exists(test_path)
            self.assertFalse(ret)
        else:
            self.assertRaises(exception.GaneshaCommandFailure,
                              self._manager._check_file_exists,
                              test_path)

        self._manager.execute.assert_called_once_with(
            'test', '-f', test_path, makelog=False, run_as_root=False)

    def test_check_export_file_exists(self):
        self.mock_object(self._manager, '_getpath',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_check_file_exists',
                         mock.Mock(return_value=True))

        ret = self._manager._check_export_file_exists(test_name)

        self._manager._getpath.assert_called_once_with(test_name)
        self._manager._check_file_exists.assert_called_once_with(test_path)
        self.assertTrue(ret)

    @ddt.data(False, True)
    def test_check_export_exists_with_rados_store(self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        self.mock_object(self._manager, '_check_export_file_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self._manager, '_check_export_rados_object_exists',
                         mock.Mock(return_value=True))

        ret = self._manager.check_export_exists(test_name)

        if rados_store_enable:
            (self._manager._check_export_rados_object_exists.
             assert_called_once_with(test_name))
            self.assertFalse(self._manager._check_export_file_exists.called)
        else:
            self._manager._check_export_file_exists.assert_called_once_with(
                test_name)
            self.assertFalse(
                self._manager._check_export_rados_object_exists.called)
        self.assertTrue(ret)

    def test_write_export_rados_object(self):
        self.mock_object(self._manager, '_get_export_rados_object_name',
                         mock.Mock(return_value='fakeobj'))
        self.mock_object(self._manager, '_put_rados_object')
        self.mock_object(self._manager, '_getpath',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_write_tmp_conf_file',
                         mock.Mock(return_value=test_tmp_path))

        ret = self._manager._write_export_rados_object(test_name, 'fakedata')

        self._manager._get_export_rados_object_name.assert_called_once_with(
            test_name)
        self._manager._put_rados_object.assert_called_once_with(
            'fakeobj', 'fakedata')
        self._manager._getpath.assert_called_once_with(test_name)
        self._manager._write_tmp_conf_file.assert_called_once_with(
            test_path, 'fakedata')
        self.assertEqual(test_tmp_path, ret)

    @ddt.data(True, False)
    def test_write_export_with_rados_store(self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        self.mock_object(manager, 'mkconf',
                         mock.Mock(return_value=test_ganesha_cnf))
        self.mock_object(self._manager, '_write_conf_file',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_write_export_rados_object',
                         mock.Mock(return_value=test_path))

        ret = self._manager._write_export(test_name, test_dict_str)

        manager.mkconf.assert_called_once_with(test_dict_str)
        if rados_store_enable:
            self._manager._write_export_rados_object.assert_called_once_with(
                test_name, test_ganesha_cnf)
            self.assertFalse(self._manager._write_conf_file.called)
        else:
            self._manager._write_conf_file.assert_called_once_with(
                test_name, test_ganesha_cnf)
            self.assertFalse(self._manager._write_export_rados_object.called)
        self.assertEqual(test_path, ret)

    def test_write_export_error_incomplete_export_block(self):
        test_errordict = {
            u'EXPORT': {
                u'Export_Id': '@config',
                u'CLIENT': {u'Clients': u"'ip1','ip2'"}
            }
        }
        self.mock_object(manager, 'mkconf',
                         mock.Mock(return_value=test_ganesha_cnf))
        self.mock_object(self._manager, '_write_conf_file',
                         mock.Mock(return_value=test_path))

        self.assertRaises(exception.InvalidParameterValue,
                          self._manager._write_export,
                          test_name, test_errordict)

        self.assertFalse(manager.mkconf.called)
        self.assertFalse(self._manager._write_conf_file.called)

    def test_rm_file(self):
        self.mock_object(self._manager, 'execute',
                         mock.Mock(return_value=('', '')))
        ret = self._manager._rm_export_file(test_name)

        self._manager.execute.assert_called_once_with('rm', '-f', test_path)
        self.assertIsNone(ret)

    def test_rm_export_file(self):
        self.mock_object(self._manager, '_getpath',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_rm_file')

        ret = self._manager._rm_export_file(test_name)

        self._manager._getpath.assert_called_once_with(test_name)
        self._manager._rm_file.assert_called_once_with(test_path)
        self.assertIsNone(ret)

    def test_rm_export_rados_object(self):
        self.mock_object(self._manager_with_rados_store,
                         '_get_export_rados_object_name',
                         mock.Mock(return_value='fakeobj'))
        self.mock_object(self._manager_with_rados_store,
                         '_delete_rados_object')

        ret = self._manager_with_rados_store._rm_export_rados_object(
            test_name)

        (self._manager_with_rados_store._get_export_rados_object_name.
         assert_called_once_with(test_name))
        (self._manager_with_rados_store._delete_rados_object.
         assert_called_once_with('fakeobj'))
        self.assertIsNone(ret)

    def test_dbus_send_ganesha(self):
        test_args = ('arg1', 'arg2')
        test_kwargs = {'key': 'value'}
        self.mock_object(self._manager, 'execute',
                         mock.Mock(return_value=('', '')))
        ret = self._manager._dbus_send_ganesha('fakemethod', *test_args,
                                               **test_kwargs)
        self._manager.execute.assert_called_once_with(
            'dbus-send', '--print-reply', '--system',
            '--dest=org.ganesha.nfsd', '/org/ganesha/nfsd/ExportMgr',
            'org.ganesha.nfsd.exportmgr.fakemethod',
            *test_args, message='dbus call exportmgr.fakemethod',
            **test_kwargs)
        self.assertIsNone(ret)

    def test_remove_export_dbus(self):
        self.mock_object(self._manager, '_dbus_send_ganesha')
        ret = self._manager._remove_export_dbus(test_export_id)
        self._manager._dbus_send_ganesha.assert_called_once_with(
            'RemoveExport', 'uint16:101')
        self.assertIsNone(ret)

    @ddt.data('',
              '%url rados://fakepool/fakeobj2')
    def test_add_rados_object_url_to_index_with_index_data(
            self, index_data):
        self.mock_object(
            self._manager_with_rados_store, '_get_rados_object',
            mock.Mock(return_value=index_data))
        self.mock_object(
            self._manager_with_rados_store, '_get_export_rados_object_name',
            mock.Mock(return_value='fakeobj1'))
        self.mock_object(
            self._manager_with_rados_store, '_put_rados_object')

        ret = (self._manager_with_rados_store.
               _add_rados_object_url_to_index('fakename'))

        (self._manager_with_rados_store._get_rados_object.
         assert_called_once_with('fakeindex'))
        (self._manager_with_rados_store._get_export_rados_object_name.
         assert_called_once_with('fakename'))
        if index_data:
            urls = ('%url rados://fakepool/fakeobj2\n'
                    '%url rados://fakepool/fakeobj1')
        else:
            urls = '%url rados://fakepool/fakeobj1'
        (self._manager_with_rados_store._put_rados_object.
         assert_called_once_with('fakeindex', urls))
        self.assertIsNone(ret)

    @ddt.data('',
              '%url rados://fakepool/fakeobj1\n'
              '%url rados://fakepool/fakeobj2')
    def test_remove_rados_object_url_from_index_with_index_data(
            self, index_data):
        self.mock_object(
            self._manager_with_rados_store, '_get_rados_object',
            mock.Mock(return_value=index_data))
        self.mock_object(
            self._manager_with_rados_store, '_get_export_rados_object_name',
            mock.Mock(return_value='fakeobj1'))
        self.mock_object(
            self._manager_with_rados_store, '_put_rados_object')

        ret = (self._manager_with_rados_store.
               _remove_rados_object_url_from_index('fakename'))

        if index_data:
            (self._manager_with_rados_store._get_rados_object.
             assert_called_once_with('fakeindex'))
            (self._manager_with_rados_store._get_export_rados_object_name.
             assert_called_once_with('fakename'))
            urls = '%url rados://fakepool/fakeobj2'
            (self._manager_with_rados_store._put_rados_object.
             assert_called_once_with('fakeindex', urls))
        else:
            (self._manager_with_rados_store._get_rados_object.
             assert_called_once_with('fakeindex'))
            self.assertFalse(self._manager_with_rados_store.
                             _get_export_rados_object_name.called)
            self.assertFalse(self._manager_with_rados_store.
                             _put_rados_object.called)
        self.assertIsNone(ret)

    @ddt.data(False, True)
    def test_add_export_with_rados_store(self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        self.mock_object(self._manager, '_write_export',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_dbus_send_ganesha')
        self.mock_object(self._manager, '_rm_file')
        self.mock_object(self._manager, '_add_rados_object_url_to_index')
        self.mock_object(self._manager, '_mkindex')

        ret = self._manager.add_export(test_name, test_dict_str)

        self._manager._write_export.assert_called_once_with(
            test_name, test_dict_str)
        self._manager._dbus_send_ganesha.assert_called_once_with(
            'AddExport', 'string:' + test_path,
            'string:EXPORT(Export_Id=101)')
        if rados_store_enable:
            self._manager._rm_file.assert_called_once_with(test_path)
            self._manager._add_rados_object_url_to_index(test_name)
            self.assertFalse(self._manager._mkindex.called)
        else:
            self._manager._mkindex.assert_called_once_with()
            self.assertFalse(self._manager._rm_file.called)
            self.assertFalse(
                self._manager._add_rados_object_url_to_index.called)
        self.assertIsNone(ret)

    def test_add_export_error_during_mkindex(self):
        self.mock_object(self._manager, '_write_export',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_dbus_send_ganesha')
        self.mock_object(
            self._manager, '_mkindex',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        self.mock_object(self._manager, '_rm_export_file')
        self.mock_object(self._manager, '_remove_export_dbus')

        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.add_export, test_name, test_dict_str)

        self._manager._write_export.assert_called_once_with(
            test_name, test_dict_str)
        self._manager._dbus_send_ganesha.assert_called_once_with(
            'AddExport', 'string:' + test_path,
            'string:EXPORT(Export_Id=101)')
        self._manager._mkindex.assert_called_once_with()
        self._manager._rm_export_file.assert_called_once_with(test_name)
        self._manager._remove_export_dbus.assert_called_once_with(
            test_export_id)

    @ddt.data(True, False)
    def test_add_export_error_during_write_export_with_rados_store(
            self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        self.mock_object(
            self._manager, '_write_export',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        self.mock_object(self._manager, '_mkindex')

        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.add_export, test_name, test_dict_str)

        self._manager._write_export.assert_called_once_with(
            test_name, test_dict_str)
        if rados_store_enable:
            self.assertFalse(self._manager._mkindex.called)
        else:
            self._manager._mkindex.assert_called_once_with()

    @ddt.data(True, False)
    def test_add_export_error_during_dbus_send_ganesha_with_rados_store(
            self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        self.mock_object(self._manager, '_write_export',
                         mock.Mock(return_value=test_path))
        self.mock_object(
            self._manager, '_dbus_send_ganesha',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        self.mock_object(self._manager, '_mkindex')
        self.mock_object(self._manager, '_rm_export_file')
        self.mock_object(self._manager, '_rm_export_rados_object')
        self.mock_object(self._manager, '_rm_file')
        self.mock_object(self._manager, '_remove_export_dbus')

        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.add_export, test_name, test_dict_str)

        self._manager._write_export.assert_called_once_with(
            test_name, test_dict_str)
        self._manager._dbus_send_ganesha.assert_called_once_with(
            'AddExport', 'string:' + test_path,
            'string:EXPORT(Export_Id=101)')
        if rados_store_enable:
            self._manager._rm_export_rados_object.assert_called_once_with(
                test_name)
            self._manager._rm_file.assert_called_once_with(test_path)
            self.assertFalse(self._manager._rm_export_file.called)
            self.assertFalse(self._manager._mkindex.called)
        else:
            self._manager._rm_export_file.assert_called_once_with(test_name)
            self._manager._mkindex.assert_called_once_with()
            self.assertFalse(self._manager._rm_export_rados_object.called)
            self.assertFalse(self._manager._rm_file.called)
        self.assertFalse(self._manager._remove_export_dbus.called)

    @ddt.data(True, False)
    def test_update_export_with_rados_store(self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        confdict = {
            'EXPORT': {
                'Export_Id': 101,
                'CLIENT': {'Clients': 'ip1', 'Access_Level': 'ro'},
            }
        }
        self.mock_object(self._manager, '_read_export',
                         mock.Mock(return_value=test_dict_unicode))
        self.mock_object(self._manager, '_write_export',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_dbus_send_ganesha')
        self.mock_object(self._manager, '_rm_file')

        self._manager.update_export(test_name, confdict)

        self._manager._read_export.assert_called_once_with(test_name)
        self._manager._write_export.assert_called_once_with(test_name,
                                                            confdict)
        self._manager._dbus_send_ganesha.assert_called_once_with(
            'UpdateExport', 'string:' + test_path,
            'string:EXPORT(Export_Id=101)')
        if rados_store_enable:
            self._manager._rm_file.assert_called_once_with(test_path)
        else:
            self.assertFalse(self._manager._rm_file.called)

    @ddt.data(True, False)
    def test_update_export_error_with_rados_store(self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        confdict = {
            'EXPORT': {
                'Export_Id': 101,
                'CLIENT': {'Clients': 'ip1', 'Access_Level': 'ro'},
            }
        }
        self.mock_object(self._manager, '_read_export',
                         mock.Mock(return_value=test_dict_unicode))
        self.mock_object(self._manager, '_write_export',
                         mock.Mock(return_value=test_path))
        self.mock_object(
            self._manager, '_dbus_send_ganesha',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        self.mock_object(self._manager, '_rm_file')

        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.update_export, test_name, confdict)

        self._manager._read_export.assert_called_once_with(test_name)
        self._manager._write_export.assert_has_calls([
            mock.call(test_name, confdict),
            mock.call(test_name, test_dict_unicode)])
        self._manager._dbus_send_ganesha.assert_called_once_with(
            'UpdateExport', 'string:' + test_path,
            'string:EXPORT(Export_Id=101)')
        if rados_store_enable:
            self._manager._rm_file.assert_called_once_with(test_path)
        else:
            self.assertFalse(self._manager._rm_file.called)

    @ddt.data(True, False)
    def test_remove_export_with_rados_store(self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        self.mock_object(self._manager, '_read_export',
                         mock.Mock(return_value=test_dict_unicode))
        self.mock_object(self._manager, '_get_export_rados_object_name',
                         mock.Mock(return_value='fakeobj'))
        methods = ('_remove_export_dbus', '_rm_export_file', '_mkindex',
                   '_remove_rados_object_url_from_index',
                   '_delete_rados_object')
        for method in methods:
            self.mock_object(self._manager, method)

        ret = self._manager.remove_export(test_name)

        self._manager._read_export.assert_called_once_with(test_name)
        self._manager._remove_export_dbus.assert_called_once_with(
            test_dict_unicode['EXPORT']['Export_Id'])
        if rados_store_enable:
            (self._manager._get_export_rados_object_name.
             assert_called_once_with(test_name))
            self._manager._delete_rados_object.assert_called_once_with(
                'fakeobj')
            (self._manager._remove_rados_object_url_from_index.
             assert_called_once_with(test_name))
            self.assertFalse(self._manager._rm_export_file.called)
            self.assertFalse(self._manager._mkindex.called)
        else:
            self._manager._rm_export_file.assert_called_once_with(test_name)
            self._manager._mkindex.assert_called_once_with()
            self.assertFalse(
                self._manager._get_export_rados_object_name.called)
            self.assertFalse(self._manager._delete_rados_object.called)
            self.assertFalse(
                self._manager._remove_rados_object_url_from_index.called)
        self.assertIsNone(ret)

    @ddt.data(True, False)
    def test_remove_export_error_during_read_export_with_rados_store(
            self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        self.mock_object(
            self._manager, '_read_export',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        self.mock_object(self._manager, '_get_export_rados_object_name',
                         mock.Mock(return_value='fakeobj'))
        methods = ('_remove_export_dbus', '_rm_export_file', '_mkindex',
                   '_remove_rados_object_url_from_index',
                   '_delete_rados_object')
        for method in methods:
            self.mock_object(self._manager, method)

        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.remove_export, test_name)

        self._manager._read_export.assert_called_once_with(test_name)
        self.assertFalse(self._manager._remove_export_dbus.called)
        if rados_store_enable:
            (self._manager._get_export_rados_object_name.
             assert_called_once_with(test_name))
            self._manager._delete_rados_object.assert_called_once_with(
                'fakeobj')
            (self._manager._remove_rados_object_url_from_index.
             assert_called_once_with(test_name))
            self.assertFalse(self._manager._rm_export_file.called)
            self.assertFalse(self._manager._mkindex.called)
        else:
            self._manager._rm_export_file.assert_called_once_with(test_name)
            self._manager._mkindex.assert_called_once_with()
            self.assertFalse(
                self._manager._get_export_rados_object_name.called)
            self.assertFalse(self._manager._delete_rados_object.called)
            self.assertFalse(
                self._manager._remove_rados_object_url_from_index.called)

    @ddt.data(True, False)
    def test_remove_export_error_during_remove_export_dbus_with_rados_store(
            self, rados_store_enable):
        self._manager.ganesha_rados_store_enable = rados_store_enable
        self.mock_object(self._manager, '_read_export',
                         mock.Mock(return_value=test_dict_unicode))
        self.mock_object(self._manager, '_get_export_rados_object_name',
                         mock.Mock(return_value='fakeobj'))
        self.mock_object(
            self._manager, '_remove_export_dbus',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        methods = ('_rm_export_file', '_mkindex',
                   '_remove_rados_object_url_from_index',
                   '_delete_rados_object')
        for method in methods:
            self.mock_object(self._manager, method)

        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.remove_export, test_name)

        self._manager._read_export.assert_called_once_with(test_name)
        self._manager._remove_export_dbus.assert_called_once_with(
            test_dict_unicode['EXPORT']['Export_Id'])
        if rados_store_enable:
            (self._manager._get_export_rados_object_name.
             assert_called_once_with(test_name))
            self._manager._delete_rados_object.assert_called_once_with(
                'fakeobj')
            (self._manager._remove_rados_object_url_from_index.
             assert_called_once_with(test_name))
            self.assertFalse(self._manager._rm_export_file.called)
            self.assertFalse(self._manager._mkindex.called)
        else:
            self._manager._rm_export_file.assert_called_once_with(test_name)
            self._manager._mkindex.assert_called_once_with()
            self.assertFalse(
                self._manager._get_export_rados_object_name.called)
            self.assertFalse(self._manager._delete_rados_object.called)
            self.assertFalse(
                self._manager._remove_rados_object_url_from_index.called)

    def test_get_rados_object(self):
        fakebin = six.unichr(246).encode('utf-8')
        self.mock_object(self._ceph_vol_client, 'get_object',
                         mock.Mock(return_value=fakebin))

        ret = self._manager_with_rados_store._get_rados_object('fakeobj')

        self._ceph_vol_client.get_object.assert_called_once_with(
            'fakepool', 'fakeobj')
        self.assertEqual(fakebin.decode('utf-8'), ret)

    def test_put_rados_object(self):
        faketext = six.unichr(246)
        self.mock_object(self._ceph_vol_client, 'put_object',
                         mock.Mock(return_value=None))

        ret = self._manager_with_rados_store._put_rados_object(
            'fakeobj', faketext)

        self._ceph_vol_client.put_object.assert_called_once_with(
            'fakepool', 'fakeobj', faketext.encode('utf-8'))
        self.assertIsNone(ret)

    def test_delete_rados_object(self):
        self.mock_object(self._ceph_vol_client, 'delete_object',
                         mock.Mock(return_value=None))

        ret = self._manager_with_rados_store._delete_rados_object('fakeobj')

        self._ceph_vol_client.delete_object.assert_called_once_with(
            'fakepool', 'fakeobj')
        self.assertIsNone(ret)

    def test_get_export_id(self):
        self.mock_object(self._manager, 'execute',
                         mock.Mock(return_value=('exportid|101', '')))
        ret = self._manager.get_export_id()
        self._manager.execute.assert_called_once_with(
            'sqlite3', self._manager.ganesha_db_path,
            'update ganesha set value = value + 1;'
            'select * from ganesha where key = "exportid";',
            run_as_root=False)
        self.assertEqual(101, ret)

    def test_get_export_id_nobump(self):
        self.mock_object(self._manager, 'execute',
                         mock.Mock(return_value=('exportid|101', '')))
        ret = self._manager.get_export_id(bump=False)
        self._manager.execute.assert_called_once_with(
            'sqlite3', self._manager.ganesha_db_path,
            'select * from ganesha where key = "exportid";',
            run_as_root=False)
        self.assertEqual(101, ret)

    def test_get_export_id_error_invalid_export_db(self):
        self.mock_object(self._manager, 'execute',
                         mock.Mock(return_value=('invalid', '')))
        self.mock_object(manager.LOG, 'error')
        self.assertRaises(exception.InvalidSqliteDB,
                          self._manager.get_export_id)
        manager.LOG.error.assert_called_once_with(
            mock.ANY, mock.ANY)
        self._manager.execute.assert_called_once_with(
            'sqlite3', self._manager.ganesha_db_path,
            'update ganesha set value = value + 1;'
            'select * from ganesha where key = "exportid";',
            run_as_root=False)

    @ddt.data(True, False)
    def test_get_export_id_with_rados_store_and_bump(self, bump):
        self.mock_object(self._manager_with_rados_store,
                         '_get_rados_object', mock.Mock(return_value='1000'))
        self.mock_object(self._manager_with_rados_store, '_put_rados_object')

        ret = self._manager_with_rados_store.get_export_id(bump=bump)

        if bump:
            (self._manager_with_rados_store._get_rados_object.
             assert_called_once_with('fakecounter'))
            (self._manager_with_rados_store._put_rados_object.
             assert_called_once_with('fakecounter', '1001'))
            self.assertEqual(1001, ret)
        else:
            (self._manager_with_rados_store._get_rados_object.
             assert_called_once_with('fakecounter'))
            self.assertFalse(
                self._manager_with_rados_store._put_rados_object.called)
            self.assertEqual(1000, ret)

    def test_restart_service(self):
        self.mock_object(self._manager, 'execute')
        ret = self._manager.restart_service()
        self._manager.execute.assert_called_once_with(
            'service', 'ganesha.fakeservice', 'restart')
        self.assertIsNone(ret)

    def test_reset_exports(self):
        self.mock_object(self._manager, 'execute')
        self.mock_object(self._manager, '_mkindex')
        ret = self._manager.reset_exports()
        self._manager.execute.assert_called_once_with(
            'sh', '-c', 'rm -f /fakedir0/export.d/*.conf')
        self._manager._mkindex.assert_called_once_with()
        self.assertIsNone(ret)
