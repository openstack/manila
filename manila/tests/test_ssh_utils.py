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

import threading
import time
from unittest import mock

from oslo_utils import uuidutils
import paramiko

from manila import exception
from manila import ssh_utils
from manila import test


class FakeSock(object):
    def settimeout(self, timeout):
        pass


class FakeTransport(object):

    def __init__(self):
        self.active = True
        self.sock = FakeSock()

    def set_keepalive(self, timeout):
        pass

    def is_active(self):
        return self.active


class FakeSSHClient(object):

    def __init__(self):
        self.id = uuidutils.generate_uuid()
        self.transport = FakeTransport()

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, ip, port=22, username=None, password=None,
                key_filename=None, look_for_keys=None, timeout=10,
                banner_timeout=10):
        pass

    def get_transport(self):
        return self.transport

    def close(self):
        pass

    def __call__(self, *args, **kwargs):
        pass


class SSHPoolTestCase(test.TestCase):
    """Unit test for SSH Connection Pool."""

    def test_single_ssh_connect(self):
        with mock.patch.object(paramiko, "SSHClient",
                               mock.Mock(return_value=FakeSSHClient())):
            sshpool = ssh_utils.SSHPool("127.0.0.1", 22, 10, "test",
                                        password="test", min_size=1,
                                        max_size=1)
            with sshpool.item() as ssh:
                first_id = ssh.id

            with sshpool.item() as ssh:
                second_id = ssh.id

            self.assertEqual(first_id, second_id)
            paramiko.SSHClient.assert_called_once_with()

    def test_create_ssh_with_password(self):
        fake_ssh_client = mock.Mock()
        fake_transport = mock.Mock()
        fake_ssh_client.get_transport.return_value = fake_transport
        ssh_pool = ssh_utils.SSHPool("127.0.0.1", 22, 10, "test",
                                     password="test")
        with mock.patch.object(paramiko, "SSHClient",
                               return_value=fake_ssh_client):
            ssh_pool.create()

            fake_ssh_client.connect.assert_called_once_with(
                "127.0.0.1", port=22, username="test",
                password="test", key_filename=None, look_for_keys=False,
                timeout=10, banner_timeout=10)
            fake_transport.set_keepalive.assert_called_once_with(10)

    def test_create_ssh_with_key(self):
        path_to_private_key = "/fakepath/to/privatekey"
        fake_ssh_client = mock.Mock()
        fake_transport = mock.Mock()
        fake_ssh_client.get_transport.return_value = fake_transport
        ssh_pool = ssh_utils.SSHPool("127.0.0.1", 22, 10,
                                     "test",
                                     privatekey="/fakepath/to/privatekey")
        with mock.patch.object(paramiko, "SSHClient",
                               return_value=fake_ssh_client):
            ssh_pool.create()
            fake_ssh_client.connect.assert_called_once_with(
                "127.0.0.1", port=22, username="test", password=None,
                key_filename=path_to_private_key, look_for_keys=False,
                timeout=10, banner_timeout=10)
            fake_transport.set_keepalive.assert_called_once_with(10)

    def test_create_ssh_with_nothing(self):
        fake_ssh_client = mock.Mock()
        fake_transport = mock.Mock()
        fake_ssh_client.get_transport.return_value = fake_transport
        ssh_pool = ssh_utils.SSHPool("127.0.0.1", 22, 10, "test")
        with mock.patch.object(paramiko, "SSHClient",
                               return_value=fake_ssh_client):
            ssh_pool.create()
            fake_ssh_client.connect.assert_called_once_with(
                "127.0.0.1", port=22, username="test", password=None,
                key_filename=None, look_for_keys=True,
                timeout=10, banner_timeout=10)
            fake_transport.set_keepalive.assert_called_once_with(10)

    def test_create_ssh_error_connecting(self):
        attrs = {'connect.side_effect': paramiko.SSHException, }
        fake_ssh_client = mock.Mock(**attrs)
        ssh_pool = ssh_utils.SSHPool("127.0.0.1", 22, 10, "test")
        with mock.patch.object(paramiko, "SSHClient",
                               return_value=fake_ssh_client):
            self.assertRaises(exception.SSHException, ssh_pool.create)
            fake_ssh_client.connect.assert_called_once_with(
                "127.0.0.1", port=22, username="test", password=None,
                key_filename=None, look_for_keys=True,
                timeout=10, banner_timeout=10)

    def test_closed_reopend_ssh_connections(self):
        with mock.patch.object(paramiko, "SSHClient",
                               mock.Mock(return_value=FakeSSHClient())):
            sshpool = ssh_utils.SSHPool("127.0.0.1", 22, 10,
                                        "test", password="test",
                                        min_size=1, max_size=2)
            with sshpool.item() as ssh:
                first_id = ssh.id
            with sshpool.item() as ssh:
                second_id = ssh.id
                # Close the connection and test for a new connection
                ssh.get_transport().active = False
            self.assertEqual(first_id, second_id)
            paramiko.SSHClient.assert_called_once_with()

        # Expected new ssh pool
        with mock.patch.object(paramiko, "SSHClient",
                               mock.Mock(return_value=FakeSSHClient())):
            with sshpool.item() as ssh:
                third_id = ssh.id
            self.assertNotEqual(first_id, third_id)
            paramiko.SSHClient.assert_called_once_with()

    @mock.patch('builtins.open')
    @mock.patch('paramiko.SSHClient')
    @mock.patch('os.path.isfile', return_value=True)
    def test_sshpool_remove(self, mock_isfile, mock_sshclient, mock_open):
        ssh_to_remove = mock.Mock()
        ssh_to_remove.get_transport.return_value.is_active.return_value = True
        mock_sshclient.side_effect = [mock.Mock(), ssh_to_remove, mock.Mock()]
        sshpool = ssh_utils.SSHPool("127.0.0.1", 22, 10,
                                    "test", password="test",
                                    min_size=3, max_size=3)

        # Get connections to populate the pool
        conn1 = sshpool.get()
        conn2 = sshpool.get()
        conn3 = sshpool.get()

        # Put them back so they're in free_items
        sshpool.put(conn1)
        sshpool.put(conn2)
        sshpool.put(conn3)

        self.assertIn(ssh_to_remove, list(sshpool.free_items))

        sshpool.remove(ssh_to_remove)

        self.assertNotIn(ssh_to_remove, list(sshpool.free_items))

    @mock.patch('builtins.open')
    @mock.patch('paramiko.SSHClient')
    @mock.patch('os.path.isfile', return_value=True)
    def test_sshpool_remove_object_not_in_pool(self, mock_isfile,
                                               mock_sshclient, mock_open):
        # create an SSH Client that is not a part of sshpool.
        ssh_to_remove = mock.Mock()
        mock_conn1 = mock.Mock()
        mock_conn2 = mock.Mock()
        mock_conn1.get_transport.return_value.is_active.return_value = True
        mock_conn2.get_transport.return_value.is_active.return_value = True
        mock_sshclient.side_effect = [mock_conn1, mock_conn2]

        sshpool = ssh_utils.SSHPool("127.0.0.1", 22, 10,
                                    "test", password="test",
                                    min_size=2, max_size=2)

        # Get and put back connections to populate free_items
        conn1 = sshpool.get()
        conn2 = sshpool.get()
        sshpool.put(conn1)
        sshpool.put(conn2)

        listBefore = list(sshpool.free_items)

        self.assertNotIn(ssh_to_remove, listBefore)

        sshpool.remove(ssh_to_remove)

        self.assertEqual(listBefore, list(sshpool.free_items))

    def test_sshpool_thread_safety(self):
        """Test that the pool is thread-safe."""
        with mock.patch.object(paramiko, "SSHClient",
                               mock.Mock(return_value=FakeSSHClient())):
            sshpool = ssh_utils.SSHPool("127.0.0.1", 22, 10,
                                        "test", password="test",
                                        min_size=1, max_size=5)

            connections_acquired = []
            errors = []

            def acquire_connection():
                try:
                    with sshpool.item() as ssh:
                        connections_acquired.append(ssh.id)
                        time.sleep(0.1)  # Simulate work
                except Exception as e:
                    errors.append(str(e))

            # Start multiple threads
            threads = []
            for _ in range(10):
                thread = threading.Thread(target=acquire_connection)
                threads.append(thread)
                thread.start()

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            # Verify no errors
            self.assertEqual([], errors)
            self.assertEqual(10, len(connections_acquired))
            self.assertLessEqual(sshpool.current_size, 5)

    def test_sshpool_put_get_behavior(self):
        with mock.patch.object(paramiko, "SSHClient",
                               mock.Mock(return_value=FakeSSHClient())):
            sshpool = ssh_utils.SSHPool("127.0.0.1", 22, 10,
                                        "test", password="test",
                                        min_size=1, max_size=3)

            conn1 = sshpool.get()
            self.assertIsNotNone(conn1)
            self.assertEqual(1, sshpool.current_size)

            sshpool.put(conn1)
            self.assertEqual(1, len(sshpool.free_items))

            conn2 = sshpool.get()
            self.assertEqual(conn1.id, conn2.id)
