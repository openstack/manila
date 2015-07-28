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

import base64

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from oslo_utils import strutils
import six

from manila import exception
from manila.i18n import _
from manila import utils

LOG = log.getLogger(__name__)
CONF = cfg.CONF

winrm_opts = [
    cfg.IntOpt(
        'winrm_conn_timeout',
        default=60,
        help='WinRM connection timeout.'),
    cfg.IntOpt(
        'winrm_operation_timeout',
        default=60,
        help='WinRM operation timeout.'),
    cfg.IntOpt(
        'winrm_retry_count',
        default=3,
        help='WinRM retry count.'),
    cfg.IntOpt(
        'winrm_retry_interval',
        default=5,
        help='WinRM retry interval in seconds'),
]

CONF.register_opts(winrm_opts)

DEFAULT_PORT_HTTP = 5985
DEFAULT_PORT_HTTPS = 5986

TRANSPORT_PLAINTEXT = 'plaintext'
TRANSPORT_SSL = 'ssl'

winrm = None


def setup_winrm():
    global winrm
    if not winrm:
        try:
            winrm = importutils.import_module('winrm')
        except ImportError:
            raise exception.ShareBackendException(
                _("PyWinrm is not installed"))


class WinRMHelper(object):
    def __init__(self, configuration=None):
        if configuration:
            configuration.append_config_values(winrm_opts)
            self._config = configuration
        else:
            self._config = CONF

        setup_winrm()

    def _get_conn(self, server):
        auth = self._get_auth(server)
        conn = WinRMConnection(
            ip=server['ip'],
            conn_timeout=self._config.winrm_conn_timeout,
            operation_timeout=self._config.winrm_operation_timeout,
            **auth)
        return conn

    def execute(self, server, command, check_exit_code=True,
                retry=True):
        retries = self._config.winrm_retry_count if retry else 1
        conn = self._get_conn(server)

        @utils.retry(exception=Exception,
                     interval=self._config.winrm_retry_interval,
                     retries=retries)
        def _execute():
            parsed_cmd, sanitized_cmd = self._parse_command(command)

            LOG.debug("Executing command: %s", sanitized_cmd)
            (stdout, stderr, exit_code) = conn.execute(parsed_cmd)

            sanitized_stdout = strutils.mask_password(stdout)
            sanitized_stderr = strutils.mask_password(stderr)
            LOG.debug("Executed command: %(cmd)s. Stdout: %(stdout)s. "
                      "Stderr: %(stderr)s. Exit code %(exit_code)s",
                      dict(cmd=sanitized_cmd, stdout=sanitized_stdout,
                           stderr=sanitized_stderr, exit_code=exit_code))

            if check_exit_code and exit_code != 0:
                raise processutils.ProcessExecutionError(
                    stdout=sanitized_stdout,
                    stderr=sanitized_stderr,
                    exit_code=exit_code,
                    cmd=sanitized_cmd)
            return (stdout, stderr)
        return _execute()

    def _parse_command(self, command):
        if isinstance(command, list) or isinstance(command, tuple):
            command = " ".join([six.text_type(c) for c in command])

        sanitized_cmd = strutils.mask_password(command)

        b64_command = base64.b64encode(command.encode("utf_16_le"))
        command = ("powershell.exe -ExecutionPolicy RemoteSigned "
                   "-NonInteractive -EncodedCommand %s" % b64_command)
        return command, sanitized_cmd

    def _get_auth(self, server):
        auth = {'username': server['username']}

        if server['use_cert_auth']:
            auth['cert_pem_path'] = server['cert_pem_path']
            auth['cert_key_pem_path'] = server['cert_key_pem_path']
        else:
            auth['password'] = server['password']
        return auth


class WinRMConnection(object):
    _URL_TEMPLATE = '%(protocol)s://%(ip)s:%(port)s/wsman'

    def __init__(self, ip=None, port=None, use_ssl=False,
                 transport=None, username=None, password=None,
                 cert_pem_path=None, cert_key_pem_path=None,
                 operation_timeout=None, conn_timeout=None):
        setup_winrm()

        use_cert = bool(cert_pem_path and cert_key_pem_path)
        transport = (TRANSPORT_SSL
                     if use_cert else TRANSPORT_PLAINTEXT)

        _port = port or self._get_default_port(use_cert)
        _url = self._get_url(ip, _port, use_cert)

        self._conn = winrm.protocol.Protocol(
            endpoint=_url, transport=transport,
            username=username, password=password,
            cert_pem=cert_pem_path, cert_key_pem=cert_key_pem_path)
        self._conn.transport.timeout = conn_timeout
        self._conn.set_timeout(operation_timeout)

    def _get_default_port(self, use_ssl):
        port = (DEFAULT_PORT_HTTPS
                if use_ssl else DEFAULT_PORT_HTTP)
        return port

    def _get_url(self, ip, port, use_ssl):
        if not ip:
            err_msg = _("No IP provided.")
            raise exception.ShareBackendException(msg=err_msg)

        protocol = 'https' if use_ssl else 'http'
        return self._URL_TEMPLATE % {'protocol': protocol,
                                     'ip': ip,
                                     'port': port}

    def execute(self, cmd):
        shell_id = None
        cmd_id = None

        try:
            shell_id = self._conn.open_shell()

            cmd_id = self._conn.run_command(shell_id, cmd)

            (stdout,
             stderr,
             exit_code) = self._conn.get_command_output(shell_id, cmd_id)
        finally:
            if cmd_id:
                self._conn.cleanup_command(shell_id, cmd_id)
            if shell_id:
                self._conn.close_shell(shell_id)

        return (stdout, stderr, exit_code)
