# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Ssh utilities."""

import logging
import os

from eventlet import pools
from oslo_config import cfg
from oslo_log import log
from oslo_utils.secretutils import md5

from manila import exception
from manila.i18n import _


try:
    import paramiko
except ImportError:
    paramiko = None

CONF = cfg.CONF
LOG = log.getLogger(__name__)
if getattr(CONF, 'debug', False):
    logging.getLogger("paramiko").setLevel(logging.DEBUG)


def get_fingerprint(self):
    """Patch paramiko

    This method needs to be patched to allow paramiko to work under FIPS.
    Until the patch to do this merges, patch paramiko here.

    TODO(carloss) Remove this when paramiko is patched.
    See https://github.com/paramiko/paramiko/pull/1928
    """
    return md5(self.asbytes(), usedforsecurity=False).digest()


if paramiko is None:
    raise exception.RequirementMissing(req='paramiko')

paramiko.pkey.PKey.get_fingerprint = get_fingerprint


class SSHPool(pools.Pool):
    """A simple eventlet pool to hold ssh connections."""

    def __init__(self, ip, port, conn_timeout, login, password=None,
                 privatekey=None, *args, **kwargs):
        self.ip = ip
        self.port = port
        self.login = login
        self.password = password
        self.conn_timeout = conn_timeout if conn_timeout else None
        self.path_to_private_key = privatekey
        super(SSHPool, self).__init__(*args, **kwargs)

    def create(self):  # pylint: disable=method-hidden
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        look_for_keys = True
        if self.path_to_private_key:
            self.path_to_private_key = os.path.expanduser(
                self.path_to_private_key)
            look_for_keys = False
        elif self.password:
            look_for_keys = False
        try:
            LOG.debug("ssh.connect: ip: %s, port: %s, look_for_keys: %s, "
                      "timeout: %s, banner_timeout: %s",
                      self.ip,
                      self.port,
                      look_for_keys,
                      self.conn_timeout,
                      self.conn_timeout)
            ssh.connect(self.ip,
                        port=self.port,
                        username=self.login,
                        password=self.password,
                        key_filename=self.path_to_private_key,
                        look_for_keys=look_for_keys,
                        timeout=self.conn_timeout,
                        banner_timeout=self.conn_timeout)
            if self.conn_timeout:
                transport = ssh.get_transport()
                transport.set_keepalive(self.conn_timeout)
            return ssh
        except Exception as e:
            msg = _("Check whether private key or password are correctly "
                    "set. Error connecting via ssh: %s") % e
            LOG.error(msg)
            raise exception.SSHException(msg)

    def get(self):
        """Return an item from the pool, when one is available.

        This may cause the calling greenthread to block. Check if a
        connection is active before returning it. For dead connections
        create and return a new connection.
        """
        if self.free_items:
            conn = self.free_items.popleft()
            if conn:
                if conn.get_transport().is_active():
                    return conn
                else:
                    conn.close()
            return self.create()
        if self.current_size < self.max_size:
            created = self.create()
            self.current_size += 1
            return created
        return self.channel.get()

    def remove(self, ssh):
        """Close an ssh client and remove it from free_items."""
        ssh.close()
        if ssh in self.free_items:
            self.free_items.remove(ssh)
            if self.current_size > 0:
                self.current_size -= 1
