# Copyright (c) 2015 Cloudbase Solutions SRL
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

import ddt
import mock
from oslo_concurrency import processutils
from oslo_utils import importutils
from oslo_utils import strutils

from manila import exception
from manila.share.drivers.windows import winrm_helper
from manila import test


@ddt.ddt
class WinRMHelperTestCase(test.TestCase):
    _FAKE_SERVER = {'ip': mock.sentinel.ip}

    @mock.patch.object(importutils, 'import_module')
    def setUp(self, mock_import_module):
        self._winrm = winrm_helper.WinRMHelper()
        super(WinRMHelperTestCase, self).setUp()

    @ddt.data({'import_exc': None},
              {'import_exc': ImportError})
    @mock.patch.object(importutils, 'import_module')
    @ddt.unpack
    def test_setup_winrm(self, mock_import_module, import_exc):
        winrm_helper.winrm = None
        mock_import_module.side_effect = import_exc

        if import_exc:
            self.assertRaises(exception.ShareBackendException,
                              winrm_helper.setup_winrm)
        else:
            winrm_helper.setup_winrm()
            self.assertEqual(mock_import_module.return_value,
                             winrm_helper.winrm)
        mock_import_module.assert_called_once_with('winrm')

    @mock.patch.object(winrm_helper.WinRMHelper, '_get_auth')
    @mock.patch.object(winrm_helper, 'WinRMConnection')
    def test_get_conn(self, mock_conn_cls, mock_get_auth):
        mock_auth = {'mock_auth_key': mock.sentinel.auth_opt}
        mock_get_auth.return_value = mock_auth

        conn = self._winrm._get_conn(self._FAKE_SERVER)

        mock_get_auth.assert_called_once_with(self._FAKE_SERVER)
        mock_conn_cls.assert_called_once_with(
            ip=self._FAKE_SERVER['ip'],
            conn_timeout=self._winrm._config.winrm_conn_timeout,
            operation_timeout=self._winrm._config.winrm_operation_timeout,
            **mock_auth)
        self.assertEqual(mock_conn_cls.return_value, conn)

    @ddt.data({},
              {'exit_code': 1},
              {'exit_code': 1, 'check_exit_code': False})
    @mock.patch.object(strutils, 'mask_password')
    @mock.patch.object(winrm_helper.WinRMHelper, '_parse_command')
    @mock.patch.object(winrm_helper.WinRMHelper, '_get_conn')
    @ddt.unpack
    def test_execute(self, mock_get_conn, mock_parse_command,
                     mock_mask_password,
                     check_exit_code=True, exit_code=0):
        mock_parse_command.return_value = (mock.sentinel.parsed_cmd,
                                           mock.sentinel.sanitized_cmd)
        mock_conn = mock_get_conn.return_value
        mock_conn.execute.return_value = (mock.sentinel.stdout,
                                          mock.sentinel.stderr,
                                          exit_code)

        if exit_code == 0 or not check_exit_code:
            result = self._winrm.execute(mock.sentinel.server,
                                         mock.sentinel.command,
                                         check_exit_code=check_exit_code,
                                         retry=False)
            expected_result = (mock.sentinel.stdout, mock.sentinel.stderr)
            self.assertEqual(expected_result, result)
        else:
            self.assertRaises(processutils.ProcessExecutionError,
                              self._winrm.execute,
                              mock.sentinel.server,
                              mock.sentinel.command,
                              check_exit_code=check_exit_code,
                              retry=False)

        mock_get_conn.assert_called_once_with(mock.sentinel.server)
        mock_parse_command.assert_called_once_with(mock.sentinel.command)
        mock_conn.execute.assert_called_once_with(mock.sentinel.parsed_cmd)
        mock_mask_password.assert_has_calls([mock.call(mock.sentinel.stdout),
                                             mock.call(mock.sentinel.stderr)])

    @mock.patch('base64.b64encode')
    @mock.patch.object(strutils, 'mask_password')
    def test_parse_command(self, mock_mask_password, mock_base64):
        mock_mask_password.return_value = mock.sentinel.sanitized_cmd
        mock_base64.return_value = mock.sentinel.encoded_string

        cmd = ('Get-Disk', '-Number', 1)
        result = self._winrm._parse_command(cmd)

        joined_cmd = 'Get-Disk -Number 1'
        expected_command = ("powershell.exe -ExecutionPolicy RemoteSigned "
                            "-NonInteractive -EncodedCommand %s" %
                            mock.sentinel.encoded_string)
        expected_result = expected_command, mock.sentinel.sanitized_cmd

        mock_mask_password.assert_called_once_with(joined_cmd)
        mock_base64.assert_called_once_with(joined_cmd.encode("utf_16_le"))
        self.assertEqual(expected_result, result)

    def _test_get_auth(self, use_cert_auth=False):
        mock_server = {'use_cert_auth': use_cert_auth,
                       'cert_pem_path': mock.sentinel.pem_path,
                       'cert_key_pem_path': mock.sentinel.key_path,
                       'username': mock.sentinel.username,
                       'password': mock.sentinel.password}

        result = self._winrm._get_auth(mock_server)

        expected_result = {'username': mock_server['username']}
        if use_cert_auth:
            expected_result['cert_pem_path'] = mock_server['cert_pem_path']
            expected_result['cert_key_pem_path'] = (
                mock_server['cert_key_pem_path'])
        else:
            expected_result['password'] = mock_server['password']

        self.assertEqual(expected_result, result)

    def test_get_auth_using_certificates(self):
        self._test_get_auth(use_cert_auth=True)

    def test_get_auth_using_password(self):
        self._test_get_auth()


class WinRMConnectionTestCase(test.TestCase):
    @mock.patch.object(winrm_helper, 'setup_winrm')
    @mock.patch.object(winrm_helper, 'winrm')
    @mock.patch.object(winrm_helper.WinRMConnection, '_get_url')
    @mock.patch.object(winrm_helper.WinRMConnection, '_get_default_port')
    def setUp(self, mock_get_port, mock_get_url, mock_winrm,
              mock_setup_winrm):
        self._winrm = winrm_helper.WinRMConnection()
        self._mock_conn = mock_winrm.protocol.Protocol.return_value
        super(WinRMConnectionTestCase, self).setUp()

    @mock.patch.object(winrm_helper, 'setup_winrm')
    @mock.patch.object(winrm_helper, 'winrm')
    @mock.patch.object(winrm_helper.WinRMConnection, '_get_url')
    @mock.patch.object(winrm_helper.WinRMConnection, '_get_default_port')
    def test_init_conn(self, mock_get_port, mock_get_url, mock_winrm,
                       mock_setup_winrm):
        # certificates are passed so we expect cert auth to be used
        cert_auth = True
        winrm_conn = winrm_helper.WinRMConnection(
            ip=mock.sentinel.ip, username=mock.sentinel.username,
            password=mock.sentinel.password,
            cert_pem_path=mock.sentinel.cert_pem_path,
            cert_key_pem_path=mock.sentinel.cert_key_pem_path,
            operation_timeout=mock.sentinel.operation_timeout,
            conn_timeout=mock.sentinel.conn_timeout)

        mock_get_port.assert_called_once_with(cert_auth)
        mock_get_url.assert_called_once_with(mock.sentinel.ip,
                                             mock_get_port.return_value,
                                             cert_auth)
        mock_winrm.protocol.Protocol.assert_called_once_with(
            endpoint=mock_get_url.return_value,
            transport=winrm_helper.TRANSPORT_SSL,
            username=mock.sentinel.username,
            password=mock.sentinel.password,
            cert_pem=mock.sentinel.cert_pem_path,
            cert_key_pem=mock.sentinel.cert_key_pem_path)
        self.assertEqual(mock_winrm.protocol.Protocol.return_value,
                         winrm_conn._conn)
        self.assertEqual(mock.sentinel.conn_timeout,
                         winrm_conn._conn.transport.timeout)
        winrm_conn._conn.set_timeout.assert_called_once_with(
            mock.sentinel.operation_timeout)

    def test_get_default_port_https(self):
        port = self._winrm._get_default_port(use_ssl=True)
        self.assertEqual(winrm_helper.DEFAULT_PORT_HTTPS, port)

    def test_get_default_port_http(self):
        port = self._winrm._get_default_port(use_ssl=False)
        self.assertEqual(winrm_helper.DEFAULT_PORT_HTTP, port)

    def _test_get_url(self, ip=None, use_ssl=True):
        if not ip:
            self.assertRaises(exception.ShareBackendException,
                              self._winrm._get_url,
                              ip=ip,
                              port=mock.sentinel.port,
                              use_ssl=use_ssl)
        else:
            url = self._winrm._get_url(ip=ip,
                                       port=mock.sentinel.port,
                                       use_ssl=use_ssl)
            expected_protocol = 'https' if use_ssl else 'http'
            expected_url = self._winrm._URL_TEMPLATE % dict(
                protocol=expected_protocol,
                port=mock.sentinel.port,
                ip=ip)
            self.assertEqual(expected_url, url)

    def test_get_url_using_ssl(self):
        self._test_get_url(ip=mock.sentinel.ip)

    def test_get_url_using_plaintext(self):
        self._test_get_url(ip=mock.sentinel.ip, use_ssl=False)

    def test_get_url_missing_ip(self):
        self._test_get_url()

    def _test_execute(self, get_output_exception=None):
        self._mock_conn.open_shell.return_value = mock.sentinel.shell_id
        self._mock_conn.run_command.return_value = mock.sentinel.cmd_id

        command_output = (mock.sentinel.stdout,
                          mock.sentinel.stderr,
                          mock.sentinel.exit_code)
        if get_output_exception:
            self._mock_conn.get_command_output.side_effect = (
                get_output_exception)
            self.assertRaises(
                get_output_exception,
                self._winrm.execute,
                mock.sentinel.cmd)
        else:
            self._mock_conn.get_command_output.return_value = command_output
            result = self._winrm.execute(mock.sentinel.cmd)
            self.assertEqual(command_output, result)

        self._mock_conn.open_shell.assert_called_once_with()
        self._mock_conn.run_command.assert_called_once_with(
            mock.sentinel.shell_id, mock.sentinel.cmd)

        self._mock_conn.cleanup_command.assert_called_once_with(
            mock.sentinel.shell_id, mock.sentinel.cmd_id)
        self._mock_conn.close_shell.assert_called_once_with(
            mock.sentinel.shell_id)

    def test_execute(self):
        self._test_execute()

    def test_execute_exception(self):
        self._test_execute(get_output_exception=Exception)
