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

from collections import deque
from contextlib import contextmanager
import hashlib
import logging
import os
import threading

from oslo_config import cfg
from oslo_log import log

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
    return hashlib.md5(self.asbytes(), usedforsecurity=False).digest()


if paramiko is None:
    raise exception.RequirementMissing(req='paramiko')

paramiko.pkey.PKey.get_fingerprint = get_fingerprint


class SSHPool:
    """A thread-safe SSH connection pool."""

    def __init__(self, ip, port, conn_timeout, login, password=None,
                 privatekey=None, min_size=1, max_size=10):
        self.ip = ip
        self.port = port
        self.login = login
        self.password = password
        self.conn_timeout = conn_timeout if conn_timeout else None
        self.path_to_private_key = privatekey
        self.min_size = min_size
        self.max_size = max_size

        # Concurrent connection management
        self._lock = threading.RLock()
        self._connections = deque()
        self._current_size = 0
        self._condition = threading.Condition(self._lock)

    def create(self, quiet=False):
        """Create one new SSH connection."""
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
            if quiet:
                LOG.debug(msg)
            else:
                LOG.error(msg)
            raise exception.SSHException(msg)

    def get(self):
        """Return an item from the pool, when one is available.

        This method will block if no connections are available and the pool
        is at maximum capacity. Check if a connection is active before
        returning it. For dead connections create and return a new connection.
        """
        with self._condition:
            # Try to get an existing connection
            while True:
                if self._connections:
                    conn = self._connections.popleft()
                    if conn and self._is_connection_active(conn):
                        return conn
                    else:
                        # Connection is dead, close it and try again
                        if conn:
                            self._close_connection(conn)
                            self._current_size -= 1
                        continue

                # No active connections available
                if self._current_size < self.max_size:
                    # Create new connection
                    conn = self.create()
                    if conn:
                        self._current_size += 1
                        return conn

                # Pool is at max capacity, wait for a connection
                self._condition.wait(timeout=30)
                # If we timeout, try to create anyway
                if (not self._connections and
                        self._current_size < self.max_size):
                    conn = self.create()
                    if conn:
                        self._current_size += 1
                        return conn

    def put(self, conn):
        """Return a connection to the pool."""
        if not conn:
            return

        with self._condition:
            if self._is_connection_active(conn):
                self._connections.append(conn)
            else:
                self._close_connection(conn)
                if self._current_size > 0:
                    self._current_size -= 1
            self._condition.notify()

    def remove(self, ssh):
        """Close an ssh client and remove it from the pool."""
        with self._lock:
            if ssh in self._connections:
                self._connections.remove(ssh)
            self._close_connection(ssh)
            if self._current_size > 0:
                self._current_size -= 1

    @contextmanager
    def item(self):
        """Context manager for getting/returning connections."""
        conn = self.get()
        try:
            yield conn
        finally:
            self.put(conn)

    def _is_connection_active(self, conn):
        """Check if SSH connection is still active."""
        try:
            return (conn and
                    conn.get_transport() and
                    conn.get_transport().is_active())
        except Exception:
            return False

    def _close_connection(self, conn):
        """Safely close an SSH connection."""
        try:
            if conn:
                conn.close()
        except Exception:
            pass  # Ignore errors when closing

    # Properties for backward compatibility with eventlet.pools.Pool
    @property
    def current_size(self):
        """Current number of connections in the pool."""
        with self._lock:
            return self._current_size

    @property
    def free_items(self):
        """Available connections (for backward compatibility)."""
        with self._lock:
            return self._connections
