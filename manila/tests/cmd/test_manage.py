# Copyright 2015 Mirantis Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import code
import io
import readline
import sys
from unittest import mock

import ddt
from oslo_config import cfg

from manila.cmd import manage as manila_manage
from manila import context
from manila import db
from manila.db import migration
from manila import test
from manila import utils
from manila import version

CONF = cfg.CONF


@ddt.ddt
class ManilaCmdManageTestCase(test.TestCase):
    def setUp(self):
        super(ManilaCmdManageTestCase, self).setUp()
        sys.argv = ['manila-share']
        CONF(sys.argv[1:], project='manila', version=version.version_string())
        self.shell_commands = manila_manage.ShellCommands()
        self.host_commands = manila_manage.HostCommands()
        self.db_commands = manila_manage.DbCommands()
        self.version_commands = manila_manage.VersionCommands()
        self.config_commands = manila_manage.ConfigCommands()
        self.get_log_cmds = manila_manage.GetLogCommands()
        self.service_cmds = manila_manage.ServiceCommands()
        self.share_cmds = manila_manage.ShareCommands()
        self.server_cmds = manila_manage.ShareServerCommands()

    @mock.patch.object(manila_manage.ShellCommands, 'run', mock.Mock())
    def test_shell_commands_bpython(self):
        self.shell_commands.bpython()
        manila_manage.ShellCommands.run.assert_called_once_with('bpython')

    @mock.patch.object(manila_manage.ShellCommands, 'run', mock.Mock())
    def test_shell_commands_ipython(self):
        self.shell_commands.ipython()
        manila_manage.ShellCommands.run.assert_called_once_with('ipython')

    @mock.patch.object(manila_manage.ShellCommands, 'run', mock.Mock())
    def test_shell_commands_python(self):
        self.shell_commands.python()
        manila_manage.ShellCommands.run.assert_called_once_with('python')

    @ddt.data({}, {'shell': 'bpython'})
    def test_run_bpython(self, kwargs):
        try:
            import bpython
        except ImportError as e:
            self.skipTest(str(e))
        self.mock_object(bpython, 'embed')
        self.shell_commands.run(**kwargs)
        bpython.embed.assert_called_once_with()

    def test_run_bpython_import_error(self):
        try:
            import bpython
            import IPython
        except ImportError as e:
            self.skipTest(str(e))
        self.mock_object(bpython, 'embed',
                         mock.Mock(side_effect=ImportError()))
        self.mock_object(IPython, 'embed')

        self.shell_commands.run(shell='bpython')

        IPython.embed.assert_called_once_with()

    def test_run(self):
        try:
            import bpython
        except ImportError as e:
            self.skipTest(str(e))
        self.mock_object(bpython, 'embed')

        self.shell_commands.run()

        bpython.embed.assert_called_once_with()

    def test_run_ipython(self):
        try:
            import IPython
        except ImportError as e:
            self.skipTest(str(e))
        self.mock_object(IPython, 'embed')

        self.shell_commands.run(shell='ipython')

        IPython.embed.assert_called_once_with()

    def test_run_ipython_import_error(self):
        try:
            import IPython
            if not hasattr(IPython, 'Shell'):
                setattr(IPython, 'Shell', mock.Mock())
                setattr(IPython.Shell, 'IPShell',
                        mock.Mock(side_effect=ImportError()))
        except ImportError as e:
            self.skipTest(str(e))
        self.mock_object(IPython, 'embed',
                         mock.Mock(side_effect=ImportError()))
        self.mock_object(readline, 'parse_and_bind')
        self.mock_object(code, 'interact')
        shell = IPython.embed.return_value

        self.shell_commands.run(shell='ipython')
        IPython.Shell.IPShell.assert_called_once_with(argv=[])
        self.assertFalse(shell.mainloop.called)
        self.assertTrue(readline.parse_and_bind.called)
        code.interact.assert_called_once_with()

    def test_run_python(self):
        self.mock_object(readline, 'parse_and_bind')
        self.mock_object(code, 'interact')

        self.shell_commands.run(shell='python')

        readline.parse_and_bind.assert_called_once_with("tab:complete")
        code.interact.assert_called_once_with()

    def test_run_python_import_error(self):
        self.mock_object(readline, 'parse_and_bind')
        self.mock_object(code, 'interact')

        self.shell_commands.run(shell='python')

        readline.parse_and_bind.assert_called_once_with("tab:complete")
        code.interact.assert_called_once_with()

    @mock.patch('builtins.print')
    def test_list(self, print_mock):
        serv_1 = {
            'host': 'fake_host1',
            'availability_zone': {'name': 'avail_zone1'},
        }
        serv_2 = {
            'host': 'fake_host2',
            'availability_zone': {'name': 'avail_zone2'},
        }
        self.mock_object(db, 'service_get_all',
                         mock.Mock(return_value=[serv_1, serv_2]))
        self.mock_object(context, 'get_admin_context',
                         mock.Mock(return_value='admin_ctxt'))

        self.host_commands.list(zone='avail_zone1')
        context.get_admin_context.assert_called_once_with()
        db.service_get_all.assert_called_once_with('admin_ctxt')
        print_mock.assert_has_calls([
            mock.call(u'host                     \tzone           '),
            mock.call('fake_host1               \tavail_zone1    ')])

    @mock.patch('builtins.print')
    def test_list_zone_is_none(self, print_mock):
        serv_1 = {
            'host': 'fake_host1',
            'availability_zone': {'name': 'avail_zone1'},
        }
        serv_2 = {
            'host': 'fake_host2',
            'availability_zone': {'name': 'avail_zone2'},
        }
        self.mock_object(db, 'service_get_all',
                         mock.Mock(return_value=[serv_1, serv_2]))
        self.mock_object(context, 'get_admin_context',
                         mock.Mock(return_value='admin_ctxt'))

        self.host_commands.list()
        context.get_admin_context.assert_called_once_with()
        db.service_get_all.assert_called_once_with('admin_ctxt')
        print_mock.assert_has_calls([
            mock.call(u'host                     \tzone           '),
            mock.call('fake_host1               \tavail_zone1    '),
            mock.call('fake_host2               \tavail_zone2    ')])

    def test_sync(self):
        self.mock_object(migration, 'upgrade')
        self.db_commands.sync(version='123')
        migration.upgrade.assert_called_once_with('123')

    def test_version(self):
        self.mock_object(migration, 'version')
        self.db_commands.version()
        migration.version.assert_called_once_with()

    def test_downgrade(self):
        self.mock_object(migration, 'downgrade')
        self.db_commands.downgrade(version='123')
        migration.downgrade.assert_called_once_with('123')

    def test_revision(self):
        self.mock_object(migration, 'revision')
        self.db_commands.revision('message', True)
        migration.revision.assert_called_once_with('message', True)

    def test_stamp(self):
        self.mock_object(migration, 'stamp')
        self.db_commands.stamp(version='123')
        migration.stamp.assert_called_once_with('123')

    def test_version_commands_list(self):
        self.mock_object(version, 'version_string',
                         mock.Mock(return_value='123'))
        with mock.patch('sys.stdout', new=io.StringIO()) as fake_out:
            self.version_commands.list()
        version.version_string.assert_called_once_with()
        self.assertEqual('123\n', fake_out.getvalue())

    def test_version_commands_call(self):
        self.mock_object(version, 'version_string',
                         mock.Mock(return_value='123'))
        with mock.patch('sys.stdout', new=io.StringIO()) as fake_out:
            self.version_commands()
        version.version_string.assert_called_once_with()
        self.assertEqual('123\n', fake_out.getvalue())

    def test_get_log_commands_no_errors(self):
        with mock.patch('sys.stdout', new=io.StringIO()) as fake_out:
            CONF.set_override('log_dir', None)
            expected_out = 'No errors in logfiles!\n'

            self.get_log_cmds.errors()

            self.assertEqual(expected_out, fake_out.getvalue())

    @mock.patch('builtins.open')
    @mock.patch('os.listdir')
    def test_get_log_commands_errors(self, listdir, open):
        CONF.set_override('log_dir', 'fake-dir')
        listdir.return_value = ['fake-error.log']

        with mock.patch('sys.stdout', new=io.StringIO()) as fake_out:
            open.return_value = io.StringIO(
                '[ ERROR ] fake-error-message')
            expected_out = ('fake-dir/fake-error.log:-\n'
                            'Line 1 : [ ERROR ] fake-error-message\n')
            self.get_log_cmds.errors()

            self.assertEqual(expected_out, fake_out.getvalue())
            open.assert_called_once_with('fake-dir/fake-error.log', 'r')
            listdir.assert_called_once_with(CONF.log_dir)

    @mock.patch('builtins.open')
    @mock.patch('os.path.exists')
    def test_get_log_commands_syslog_no_log_file(self, path_exists, open):
        path_exists.return_value = False
        exit = self.assertRaises(SystemExit, self.get_log_cmds.syslog)
        self.assertEqual(1, exit.code)
        path_exists.assert_any_call('/var/log/syslog')
        path_exists.assert_any_call('/var/log/messages')

    @mock.patch('manila.utils.service_is_up')
    @mock.patch('manila.db.service_get_all')
    @mock.patch('manila.context.get_admin_context')
    def test_service_commands_list(self, get_admin_context, service_get_all,
                                   service_is_up):
        ctxt = context.RequestContext('fake-user', 'fake-project')
        get_admin_context.return_value = ctxt
        service = {'binary': 'manila-binary',
                   'host': 'fake-host.fake-domain',
                   'availability_zone': {'name': 'fake-zone'},
                   'updated_at': '2014-06-30 11:22:33',
                   'disabled': False}
        service_get_all.return_value = [service]
        service_is_up.return_value = True
        with mock.patch('sys.stdout', new=io.StringIO()) as fake_out:
            format = "%-16s %-36s %-16s %-10s %-5s %-10s"
            print_format = format % ('Binary',
                                     'Host',
                                     'Zone',
                                     'Status',
                                     'State',
                                     'Updated At')
            service_format = format % (service['binary'],
                                       service['host'].partition('.')[0],
                                       service['availability_zone']['name'],
                                       'enabled',
                                       ':-)',
                                       service['updated_at'])
            expected_out = print_format + '\n' + service_format + '\n'
            self.service_cmds.list()
            self.assertEqual(expected_out, fake_out.getvalue())
            get_admin_context.assert_called_with()
            service_get_all.assert_called_with(ctxt)
            service_is_up.assert_called_with(service)

    @ddt.data(True, False)
    def test_service_commands_cleanup(self, service_is_up):
        ctxt = context.RequestContext('fake-user', 'fake-project')
        self.mock_object(context, 'get_admin_context',
                         mock.Mock(return_value=ctxt))
        service = {'id': 17,
                   'binary': 'manila-binary',
                   'host': 'fake-host.fake-domain',
                   'availability_zone': {'name': 'fake-zone'},
                   'updated_at': '2020-06-17 07:22:33',
                   'disabled': False}
        self.mock_object(db, 'service_get_all',
                         mock.Mock(return_value=[service]))
        self.mock_object(db, 'service_destroy')
        self.mock_object(utils, 'service_is_up',
                         mock.Mock(return_value=service_is_up))

        with mock.patch('sys.stdout', new=io.StringIO()) as fake_out:
            if not service_is_up:
                expected_out = "Cleaned up service %s" % service['host']
            else:
                expected_out = ''
            self.service_cmds.cleanup()

            self.assertEqual(expected_out, fake_out.getvalue().strip())
            context.get_admin_context.assert_called_with()
            db.service_get_all.assert_called_with(ctxt)
            utils.service_is_up.assert_called_with(service)
            if not service_is_up:
                db.service_destroy.assert_called_with(ctxt, service['id'])
            else:
                self.assertFalse(db.service_destroy.called)

    def test_methods_of(self):
        obj = type('Fake', (object,),
                   {name: lambda: 'fake_' for name in ('_a', 'b', 'c')})
        expected = [('b', obj.b), ('c', obj.c)]
        self.assertEqual(expected, manila_manage.methods_of(obj))

    @mock.patch('oslo_config.cfg.ConfigOpts.register_cli_opt')
    def test_main_argv_lt_2(self, register_cli_opt):
        script_name = 'manila-manage'
        sys.argv = [script_name]
        CONF(sys.argv[1:], project='manila', version=version.version_string())
        exit = self.assertRaises(SystemExit, manila_manage.main)

        self.assertTrue(register_cli_opt.called)
        self.assertEqual(2, exit.code)

    @mock.patch('oslo_config.cfg.ConfigOpts.__call__')
    @mock.patch('oslo_log.log.register_options')
    @mock.patch('oslo_log.log.setup')
    @mock.patch('oslo_config.cfg.ConfigOpts.register_cli_opt')
    def test_main_sudo_failed(self, register_cli_opt, log_setup,
                              register_log_opts, config_opts_call):
        script_name = 'manila-manage'
        sys.argv = [script_name, 'fake_category', 'fake_action']
        config_opts_call.side_effect = cfg.ConfigFilesNotFoundError(
            mock.sentinel._namespace)

        exit = self.assertRaises(SystemExit, manila_manage.main)

        self.assertTrue(register_cli_opt.called)
        register_log_opts.assert_called_once_with(CONF)
        config_opts_call.assert_called_once_with(
            sys.argv[1:], project='manila',
            version=version.version_string())
        self.assertFalse(log_setup.called)
        self.assertEqual(2, exit.code)

    @mock.patch('oslo_config.cfg.ConfigOpts.__call__')
    @mock.patch('oslo_config.cfg.ConfigOpts.register_cli_opt')
    @mock.patch('oslo_log.log.register_options')
    def test_main(self, register_log_opts, register_cli_opt, config_opts_call):
        script_name = 'manila-manage'
        sys.argv = [script_name, 'config', 'list']
        action_fn = mock.MagicMock()
        CONF.category = mock.MagicMock(action_fn=action_fn)

        manila_manage.main()

        self.assertTrue(register_cli_opt.called)
        register_log_opts.assert_called_once_with(CONF)
        config_opts_call.assert_called_once_with(
            sys.argv[1:], project='manila', version=version.version_string())
        self.assertTrue(action_fn.called)

    @ddt.data('bar', '-bar', '--bar')
    def test_get_arg_string(self, arg):
        parsed_arg = manila_manage.get_arg_string(arg)
        self.assertEqual('bar', parsed_arg)

    @ddt.data({'current_host': 'controller-0@fancystore01#pool100',
               'new_host': 'controller-0@fancystore01'},
              {'current_host': 'controller-0@fancystore01',
               'new_host': 'controller-0'})
    @ddt.unpack
    def test_share_update_host_fail_validation(self, current_host, new_host):
        self.mock_object(context, 'get_admin_context',
                         mock.Mock(return_value='admin_ctxt'))
        self.mock_object(db, 'share_resources_host_update')

        self.assertRaises(SystemExit,
                          self.share_cmds.update_host,
                          current_host, new_host)

        self.assertFalse(db.share_resources_host_update.called)

    @ddt.data({'current_host': 'controller-0@fancystore01#pool100',
               'new_host': 'controller-0@fancystore02#pool0'},
              {'current_host': 'controller-0@fancystore01',
               'new_host': 'controller-1@fancystore01'},
              {'current_host': 'controller-0',
               'new_host': 'controller-1'},
              {'current_host': 'controller-0@fancystore01#pool100',
               'new_host': 'controller-1@fancystore02', 'force': True})
    @ddt.unpack
    def test_share_update_host(self, current_host, new_host, force=False):
        db_op = {'instances': 3, 'groups': 4, 'servers': 2}
        self.mock_object(context, 'get_admin_context',
                         mock.Mock(return_value='admin_ctxt'))
        self.mock_object(db, 'share_resources_host_update',
                         mock.Mock(return_value=db_op))

        with mock.patch('sys.stdout', new=io.StringIO()) as intercepted_op:
            self.share_cmds.update_host(current_host, new_host, force)

        expected_op = ("Updated host of 3 share instances, 4 share groups and "
                       "2 share servers on %(chost)s to %(nhost)s." %
                       {'chost': current_host, 'nhost': new_host})
        self.assertEqual(expected_op, intercepted_op.getvalue().strip())
        db.share_resources_host_update.assert_called_once_with(
            'admin_ctxt', current_host, new_host)

    def test_share_server_update_capability(self):
        self.mock_object(context, 'get_admin_context',
                         mock.Mock(return_value='admin_ctxt'))
        self.mock_object(db, 'share_servers_update')
        share_servers = 'server_id_a,server_id_b'
        share_server_list = [server.strip()
                             for server in share_servers.split(",")]
        capabilities = "security_service_update_support" \
                       ",network_allocation_update_support"
        capabilities_list = capabilities.split(",")
        values_to_update = [
            {capabilities_list[0]: True,
             capabilities_list[1]: True}]

        with mock.patch('sys.stdout', new=io.StringIO()) as output:
            self.server_cmds.update_share_server_capabilities(
                share_servers, capabilities, True)

        expected_op = ("The capability(ies) %(cap)s of the following share "
                       "server(s) %(servers)s was(were) updated to "
                       "%(value)s.") % {
            'cap': capabilities_list,
            'servers': share_server_list,
            'value': True,
        }

        self.assertEqual(expected_op, output.getvalue().strip())
        db.share_servers_update.assert_called_once_with(
            'admin_ctxt', share_server_list, values_to_update[0])

    def test_share_server_update_capability_not_supported(self):
        share_servers = 'server_id_a'
        capabilities = 'invalid_capability'

        exit = self.assertRaises(
            SystemExit,
            self.server_cmds.update_share_server_capabilities,
            share_servers,
            capabilities,
            True)

        self.assertEqual(1, exit.code)
