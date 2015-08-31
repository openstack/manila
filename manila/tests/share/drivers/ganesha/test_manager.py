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

import re

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
test_ganesha_cnf = """EXPORT {
    Export_Id = 101;
    CLIENT {
        Clients = ip1;
    }
}"""
test_dict_unicode = {
    u'EXPORT': {
        u'Export_Id': 101,
        u'CLIENT': {u'Clients': u"ip1"}
    }
}
test_dict_str = {
    'EXPORT': {
        'Export_Id': 101,
        'CLIENT': {'Clients': "ip1"}
    }
}

manager_fake_kwargs = {
    'ganesha_config_path': '/fakedir0/fakeconfig',
    'ganesha_db_path': '/fakedir1/fake.db',
    'ganesha_export_dir': '/fakedir0/export.d',
    'ganesha_service_name': 'ganesha.fakeservice'
}


class GaneshaConfigTests(test.TestCase):
    """Tests Ganesha config file format convertor functions."""

    ref_ganesha_cnf = """EXPORT {
    CLIENT {
        Clients = ip1;
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
        ret = manager._conf2json(test_ganesha_cnf_with_comment)
        self.assertEqual(test_dict_unicode, jsonutils.loads(ret))

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


class GaneshaManagerTestCase(test.TestCase):
    """Tests GaneshaManager."""

    def instantiate_ganesha_manager(self, *args, **kwargs):
        with mock.patch.object(
                manager.GaneshaManager,
                'get_export_id',
                return_value=100) as self.mock_get_export_id:
            with mock.patch.object(
                    manager.GaneshaManager,
                    'reset_exports') as self.mock_reset_exports:
                with mock.patch.object(
                        manager.GaneshaManager,
                        'restart_service') as self.mock_restart_service:
                    return manager.GaneshaManager(*args, **kwargs)

    def setUp(self):
        super(GaneshaManagerTestCase, self).setUp()
        self._execute = mock.Mock(return_value=('', ''))
        self._manager = self.instantiate_ganesha_manager(
            self._execute, 'faketag', **manager_fake_kwargs)
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
        self.mock_reset_exports.assert_called_once_with()
        self.mock_restart_service.assert_called_once_with()

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

    def test_ganesha_export_dir(self):
        self.assertEqual(
            '/fakedir0/export.d', self._manager.ganesha_export_dir)

    def test_getpath(self):
        self.assertEqual(
            '/fakedir0/export.d/fakefile.conf',
            self._manager._getpath('fakefile'))

    def test_write_file(self):
        test_data = 'fakedata'
        self.mock_object(manager.pipes, 'quote',
                         mock.Mock(side_effect=['fakedata',
                                                'fakefile.conf.RANDOM']))
        test_args = [
            ('mktemp', '-p', '/fakedir0/export.d', '-t',
             'fakefile.conf.XXXXXX'),
            ('sh', '-c', 'echo fakedata > fakefile.conf.RANDOM'),
            ('mv', 'fakefile.conf.RANDOM', test_path)]
        test_kwargs = {
            'message': 'writing fakefile.conf.RANDOM'
        }

        def return_tmpfile(*args, **kwargs):
            if args == test_args[0]:
                return ('fakefile.conf.RANDOM\n', '')

        self.mock_object(self._manager, 'execute',
                         mock.Mock(side_effect=return_tmpfile))
        self._manager._write_file(test_path, test_data)
        self._manager.execute.assert_has_calls([
            mock.call(*test_args[0]),
            mock.call(*test_args[1], **test_kwargs),
            mock.call(*test_args[2])])
        manager.pipes.quote.assert_has_calls([
            mock.call('fakedata'),
            mock.call('fakefile.conf.RANDOM')])

    def test_write_conf_file(self):
        test_data = 'fakedata'
        self.mock_object(self._manager, '_getpath',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_write_file')
        ret = self._manager._write_conf_file(test_name, test_data)
        self.assertEqual(test_path, ret)
        self._manager._getpath.assert_called_once_with(test_name)
        self._manager._write_file.assert_called_once_with(
            test_path, test_data)

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

    def test_write_export_file(self):
        self.mock_object(manager, 'mkconf',
                         mock.Mock(return_value=test_ganesha_cnf))
        self.mock_object(self._manager, '_write_conf_file',
                         mock.Mock(return_value=test_path))
        ret = self._manager._write_export_file(test_name, test_dict_str)
        manager.mkconf.assert_called_once_with(test_dict_str)
        self._manager._write_conf_file.assert_called_once_with(
            test_name, test_ganesha_cnf)
        self.assertEqual(test_path, ret)

    def test_write_export_file_error_incomplete_export_block(self):

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
                          self._manager._write_export_file,
                          test_name, test_errordict)
        self.assertFalse(manager.mkconf.called)
        self.assertFalse(self._manager._write_conf_file.called)

    def test_rm_export_file(self):
        self.mock_object(self._manager, 'execute',
                         mock.Mock(return_value=('', '')))
        self.mock_object(self._manager, '_getpath',
                         mock.Mock(return_value=test_path))
        ret = self._manager._rm_export_file(test_name)
        self._manager._getpath.assert_called_once_with(test_name)
        self._manager.execute.assert_called_once_with('rm', test_path)
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

    def test_add_export(self):
        self.mock_object(self._manager, '_write_export_file',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_dbus_send_ganesha')
        self.mock_object(self._manager, '_mkindex')
        ret = self._manager.add_export(test_name, test_dict_str)
        self._manager._write_export_file.assert_called_once_with(
            test_name, test_dict_str)
        self._manager._dbus_send_ganesha.assert_called_once_with(
            'AddExport', 'string:' + test_path,
            'string:EXPORT(Export_Id=101)')
        self._manager._mkindex.assert_called_once_with()
        self.assertIsNone(ret)

    def test_add_export_error_during_mkindex(self):
        self.mock_object(self._manager, '_write_export_file',
                         mock.Mock(return_value=test_path))
        self.mock_object(self._manager, '_dbus_send_ganesha')
        self.mock_object(
            self._manager, '_mkindex',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        self.mock_object(self._manager, '_rm_export_file')
        self.mock_object(self._manager, '_remove_export_dbus')
        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.add_export, test_name, test_dict_str)
        self._manager._write_export_file.assert_called_once_with(
            test_name, test_dict_str)
        self._manager._dbus_send_ganesha.assert_called_once_with(
            'AddExport', 'string:' + test_path,
            'string:EXPORT(Export_Id=101)')
        self._manager._mkindex.assert_called_once_with()
        self._manager._rm_export_file.assert_called_once_with(test_name)
        self._manager._remove_export_dbus.assert_called_once_with(
            test_export_id)

    def test_add_export_error_during_write_export_file(self):
        self.mock_object(
            self._manager, '_write_export_file',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        self.mock_object(self._manager, '_dbus_send_ganesha')
        self.mock_object(self._manager, '_mkindex')
        self.mock_object(self._manager, '_rm_export_file')
        self.mock_object(self._manager, '_remove_export_dbus')
        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.add_export, test_name, test_dict_str)
        self._manager._write_export_file.assert_called_once_with(
            test_name, test_dict_str)
        self.assertFalse(self._manager._dbus_send_ganesha.called)
        self._manager._mkindex.assert_called_once_with()
        self.assertFalse(self._manager._rm_export_file.called)
        self.assertFalse(self._manager._remove_export_dbus.called)

    def test_add_export_error_during_dbus_send_ganesha(self):
        self.mock_object(self._manager, '_write_export_file',
                         mock.Mock(return_value=test_path))
        self.mock_object(
            self._manager, '_dbus_send_ganesha',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        self.mock_object(self._manager, '_mkindex')
        self.mock_object(self._manager, '_rm_export_file')
        self.mock_object(self._manager, '_remove_export_dbus')
        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.add_export, test_name, test_dict_str)
        self._manager._write_export_file.assert_called_once_with(
            test_name, test_dict_str)
        self._manager._dbus_send_ganesha.assert_called_once_with(
            'AddExport', 'string:' + test_path,
            'string:EXPORT(Export_Id=101)')
        self._manager._rm_export_file.assert_called_once_with(test_name)
        self._manager._mkindex.assert_called_once_with()
        self.assertFalse(self._manager._remove_export_dbus.called)

    def test_remove_export(self):
        self.mock_object(self._manager, '_read_export_file',
                         mock.Mock(return_value=test_dict_unicode))
        methods = ('_remove_export_dbus', '_rm_export_file', '_mkindex')
        for method in methods:
            self.mock_object(self._manager, method)
        ret = self._manager.remove_export(test_name)
        self._manager._read_export_file.assert_called_once_with(test_name)
        self._manager._remove_export_dbus.assert_called_once_with(
            test_dict_unicode['EXPORT']['Export_Id'])
        self._manager._rm_export_file.assert_called_once_with(test_name)
        self._manager._mkindex.assert_called_once_with()
        self.assertIsNone(ret)

    def test_remove_export_error_during_read_export_file(self):
        self.mock_object(
            self._manager, '_read_export_file',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        methods = ('_remove_export_dbus', '_rm_export_file', '_mkindex')
        for method in methods:
            self.mock_object(self._manager, method)
        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.remove_export, test_name)
        self._manager._read_export_file.assert_called_once_with(test_name)
        self.assertFalse(self._manager._remove_export_dbus.called)
        self._manager._rm_export_file.assert_called_once_with(test_name)
        self._manager._mkindex.assert_called_once_with()

    def test_remove_export_error_during_remove_export_dbus(self):
        self.mock_object(self._manager, '_read_export_file',
                         mock.Mock(return_value=test_dict_unicode))
        self.mock_object(
            self._manager, '_remove_export_dbus',
            mock.Mock(side_effect=exception.GaneshaCommandFailure))
        methods = ('_rm_export_file', '_mkindex')
        for method in methods:
            self.mock_object(self._manager, method)
        self.assertRaises(exception.GaneshaCommandFailure,
                          self._manager.remove_export, test_name)
        self._manager._read_export_file.assert_called_once_with(test_name)
        self._manager._remove_export_dbus.assert_called_once_with(
            test_dict_unicode['EXPORT']['Export_Id'])
        self._manager._rm_export_file.assert_called_once_with(test_name)
        self._manager._mkindex.assert_called_once_with()

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
