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

import six
import sys

from oslo_log import log

from tempest import config
from tempest.lib.common import ssh
from tempest.lib.common.utils import test_utils
import tempest.lib.exceptions

CONF = config.CONF

LOG = log.getLogger(__name__)


def debug_ssh(function):
    """Decorator to generate extra debug info in case of ssh failure"""
    def wrapper(self, *args, **kwargs):
        try:
            return function(self, *args, **kwargs)
        except tempest.lib.exceptions.SSHTimeout:
            try:
                original_exception = sys.exc_info()
                caller = test_utils.find_test_caller() or "not found"
                if self.server:
                    msg = 'Caller: %s. Timeout trying to ssh to server %s'
                    LOG.debug(msg, caller, self.server)
                    if self.log_console and self.servers_client:
                        try:
                            msg = 'Console log for server %s: %s'
                            console_log = (
                                self.servers_client.get_console_output(
                                    self.server['id'])['output'])
                            LOG.debug(msg, self.server['id'], console_log)
                        except Exception:
                            msg = 'Could not get console_log for server %s'
                            LOG.debug(msg, self.server['id'])
                # re-raise the original ssh timeout exception
                six.reraise(*original_exception)
            finally:
                # Delete the traceback to avoid circular references
                _, _, trace = original_exception
                del trace
    return wrapper


class RemoteClient(object):

    def __init__(self, ip_address, username, password=None, pkey=None,
                 server=None, servers_client=None):
        """Executes commands in a VM over ssh

        :param ip_address: IP address to ssh to
        :param username: ssh username
        :param password: ssh password (optional)
        :param pkey: ssh public key (optional)
        :param server: server dict, used for debugging purposes
        :param servers_client: servers client, used for debugging purposes
        """
        self.server = server
        self.servers_client = servers_client
        self.log_console = CONF.compute_feature_enabled.console_output

        self.ssh_client = ssh.Client(ip_address, username, password, pkey=pkey)

    @debug_ssh
    def exec_command(self, cmd):
        # Shell options below add more clearness on failures,
        # path is extended for some non-cirros guest oses (centos7)
        cmd = CONF.validation.ssh_shell_prologue + " " + cmd
        LOG.debug("Remote command: %s", cmd)
        return self.ssh_client.exec_command(cmd)

    @debug_ssh
    def validate_authentication(self):
        """Validate ssh connection and authentication

           This method raises an Exception when the validation fails.
        """
        self.ssh_client.test_connection_auth()
