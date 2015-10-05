#    Copyright 2011 Justin Santa Barbara
#    Copyright 2014 NetApp, Inc.
#    Copyright 2014 Mirantis, Inc.
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

import datetime
import errno
import os
import os.path
import socket
import tempfile
import time
import uuid

import ddt
import mock
from oslo_config import cfg
from oslo_utils import timeutils
import paramiko
from six.moves import builtins

import manila
from manila import exception
from manila import test
from manila import utils

CONF = cfg.CONF


class GetFromPathTestCase(test.TestCase):
    def test_tolerates_nones(self):
        f = utils.get_from_path

        input = []
        self.assertEqual([], f(input, "a"))
        self.assertEqual([], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [None]
        self.assertEqual([], f(input, "a"))
        self.assertEqual([], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': None}]
        self.assertEqual([], f(input, "a"))
        self.assertEqual([], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': {'b': None}}]
        self.assertEqual([{'b': None}], f(input, "a"))
        self.assertEqual([], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': {'b': {'c': None}}}]
        self.assertEqual([{'b': {'c': None}}], f(input, "a"))
        self.assertEqual([{'c': None}], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': {'b': {'c': None}}}, {'a': None}]
        self.assertEqual([{'b': {'c': None}}], f(input, "a"))
        self.assertEqual([{'c': None}], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': {'b': {'c': None}}}, {'a': {'b': None}}]
        self.assertEqual([{'b': {'c': None}}, {'b': None}], f(input, "a"))
        self.assertEqual([{'c': None}], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

    def test_does_select(self):
        f = utils.get_from_path

        input = [{'a': 'a_1'}]
        self.assertEqual(['a_1'], f(input, "a"))
        self.assertEqual([], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': {'b': 'b_1'}}]
        self.assertEqual([{'b': 'b_1'}], f(input, "a"))
        self.assertEqual(['b_1'], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': {'b': {'c': 'c_1'}}}]
        self.assertEqual([{'b': {'c': 'c_1'}}], f(input, "a"))
        self.assertEqual([{'c': 'c_1'}], f(input, "a/b"))
        self.assertEqual(['c_1'], f(input, "a/b/c"))

        input = [{'a': {'b': {'c': 'c_1'}}}, {'a': None}]
        self.assertEqual([{'b': {'c': 'c_1'}}], f(input, "a"))
        self.assertEqual([{'c': 'c_1'}], f(input, "a/b"))
        self.assertEqual(['c_1'], f(input, "a/b/c"))

        input = [{'a': {'b': {'c': 'c_1'}}},
                 {'a': {'b': None}}]
        self.assertEqual([{'b': {'c': 'c_1'}}, {'b': None}], f(input, "a"))
        self.assertEqual([{'c': 'c_1'}], f(input, "a/b"))
        self.assertEqual(['c_1'], f(input, "a/b/c"))

        input = [{'a': {'b': {'c': 'c_1'}}},
                 {'a': {'b': {'c': 'c_2'}}}]
        self.assertEqual([{'b': {'c': 'c_1'}}, {'b': {'c': 'c_2'}}],
                         f(input, "a"))
        self.assertEqual([{'c': 'c_1'}, {'c': 'c_2'}], f(input, "a/b"))
        self.assertEqual(['c_1', 'c_2'], f(input, "a/b/c"))

        self.assertEqual([], f(input, "a/b/c/d"))
        self.assertEqual([], f(input, "c/a/b/d"))
        self.assertEqual([], f(input, "i/r/t"))

    def test_flattens_lists(self):
        f = utils.get_from_path

        input = [{'a': [1, 2, 3]}]
        self.assertEqual([1, 2, 3], f(input, "a"))
        self.assertEqual([], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': {'b': [1, 2, 3]}}]
        self.assertEqual([{'b': [1, 2, 3]}], f(input, "a"))
        self.assertEqual([1, 2, 3], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': {'b': [1, 2, 3]}}, {'a': {'b': [4, 5, 6]}}]
        self.assertEqual([1, 2, 3, 4, 5, 6], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': [{'b': [1, 2, 3]}, {'b': [4, 5, 6]}]}]
        self.assertEqual([1, 2, 3, 4, 5, 6], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = [{'a': [1, 2, {'b': 'b_1'}]}]
        self.assertEqual([1, 2, {'b': 'b_1'}], f(input, "a"))
        self.assertEqual(['b_1'], f(input, "a/b"))

    def test_bad_xpath(self):
        f = utils.get_from_path

        self.assertRaises(exception.Error, f, [], None)
        self.assertRaises(exception.Error, f, [], "")
        self.assertRaises(exception.Error, f, [], "/")
        self.assertRaises(exception.Error, f, [], "/a")
        self.assertRaises(exception.Error, f, [], "/a/")
        self.assertRaises(exception.Error, f, [], "//")
        self.assertRaises(exception.Error, f, [], "//a")
        self.assertRaises(exception.Error, f, [], "a//a")
        self.assertRaises(exception.Error, f, [], "a//a/")
        self.assertRaises(exception.Error, f, [], "a/a/")

    def test_real_failure1(self):
        # Real world failure case...
        #  We weren't coping when the input was a Dictionary instead of a List
        # This led to test_accepts_dictionaries
        f = utils.get_from_path

        inst = {'fixed_ip': {'floating_ips': [{'address': '1.2.3.4'}],
                             'address': '192.168.0.3'},
                'hostname': ''}

        private_ips = f(inst, 'fixed_ip/address')
        public_ips = f(inst, 'fixed_ip/floating_ips/address')
        self.assertEqual(['192.168.0.3'], private_ips)
        self.assertEqual(['1.2.3.4'], public_ips)

    def test_accepts_dictionaries(self):
        f = utils.get_from_path

        input = {'a': [1, 2, 3]}
        self.assertEqual([1, 2, 3], f(input, "a"))
        self.assertEqual([], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = {'a': {'b': [1, 2, 3]}}
        self.assertEqual([{'b': [1, 2, 3]}], f(input, "a"))
        self.assertEqual([1, 2, 3], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = {'a': [{'b': [1, 2, 3]}, {'b': [4, 5, 6]}]}
        self.assertEqual([1, 2, 3, 4, 5, 6], f(input, "a/b"))
        self.assertEqual([], f(input, "a/b/c"))

        input = {'a': [1, 2, {'b': 'b_1'}]}
        self.assertEqual([1, 2, {'b': 'b_1'}], f(input, "a"))
        self.assertEqual(['b_1'], f(input, "a/b"))


@ddt.ddt
class GenericUtilsTestCase(test.TestCase):
    def test_read_cached_file(self):
        cache_data = {"data": 1123, "mtime": 1}
        with mock.patch.object(os.path, "getmtime", mock.Mock(return_value=1)):
            data = utils.read_cached_file("/this/is/a/fake", cache_data)
            self.assertEqual(cache_data["data"], data)
            os.path.getmtime.assert_called_once_with("/this/is/a/fake")

    def test_read_modified_cached_file(self):
        with mock.patch.object(os.path, "getmtime", mock.Mock(return_value=2)):
            fake_contents = "lorem ipsum"
            fake_file = mock.Mock()
            fake_file.read = mock.Mock(return_value=fake_contents)
            fake_context_manager = mock.Mock()
            fake_context_manager.__enter__ = mock.Mock(return_value=fake_file)
            fake_context_manager.__exit__ = mock.Mock()
            with mock.patch.object(
                    builtins, 'open',
                    mock.Mock(return_value=fake_context_manager)):
                cache_data = {"data": 1123, "mtime": 1}
                self.reload_called = False

                def test_reload(reloaded_data):
                    self.assertEqual(fake_contents, reloaded_data)
                    self.reload_called = True

                data = utils.read_cached_file("/this/is/a/fake",
                                              cache_data,
                                              reload_func=test_reload)
                self.assertEqual(fake_contents, data)
                self.assertTrue(self.reload_called)
                fake_file.read.assert_called_once_with()
                fake_context_manager.__enter__.assert_any_call()
                builtins.open.assert_called_once_with("/this/is/a/fake")
                os.path.getmtime.assert_called_once_with("/this/is/a/fake")

    def test_read_file_as_root(self):
        def fake_execute(*args, **kwargs):
            if args[1] == 'bad':
                raise exception.ProcessExecutionError
            return 'fakecontents', None

        self.mock_object(utils, 'execute', fake_execute)
        contents = utils.read_file_as_root('good')
        self.assertEqual('fakecontents', contents)
        self.assertRaises(exception.FileNotFound,
                          utils.read_file_as_root, 'bad')

    def test_temporary_chown(self):
        def fake_execute(*args, **kwargs):
            if args[0] == 'chown':
                fake_execute.uid = args[1]
        self.mock_object(utils, 'execute', fake_execute)

        with tempfile.NamedTemporaryFile() as f:
            with utils.temporary_chown(f.name, owner_uid=2):
                self.assertEqual(2, fake_execute.uid)
            self.assertEqual(os.getuid(), fake_execute.uid)

    def test_service_is_up(self):
        fts_func = datetime.datetime.fromtimestamp
        fake_now = 1000
        down_time = 5
        self.flags(service_down_time=down_time)
        with mock.patch.object(timeutils, 'utcnow',
                               mock.Mock(return_value=fts_func(fake_now))):

            # Up (equal)
            service = {'updated_at': fts_func(fake_now - down_time),
                       'created_at': fts_func(fake_now - down_time)}
            result = utils.service_is_up(service)
            self.assertTrue(result)
            timeutils.utcnow.assert_called_once_with()

        with mock.patch.object(timeutils, 'utcnow',
                               mock.Mock(return_value=fts_func(fake_now))):
            # Up
            service = {'updated_at': fts_func(fake_now - down_time + 1),
                       'created_at': fts_func(fake_now - down_time + 1)}
            result = utils.service_is_up(service)
            self.assertTrue(result)
            timeutils.utcnow.assert_called_once_with()

        with mock.patch.object(timeutils, 'utcnow',
                               mock.Mock(return_value=fts_func(fake_now))):
            # Down
            service = {'updated_at': fts_func(fake_now - down_time - 1),
                       'created_at': fts_func(fake_now - down_time - 1)}
            result = utils.service_is_up(service)
            self.assertFalse(result)
            timeutils.utcnow.assert_called_once_with()

    def test_is_ipv6_configured0(self):
        fake_fd = mock.Mock()
        fake_fd.read.return_value = 'test'
        with mock.patch('six.moves.builtins.open',
                        mock.Mock(return_value=fake_fd)) as open:
            self.assertTrue(utils.is_ipv6_configured())

            open.assert_called_once_with('/proc/net/if_inet6')
            fake_fd.read.assert_called_once_with(32)

    def test_is_ipv6_configured1(self):
        fake_fd = mock.Mock()
        fake_fd.read.return_value = ''
        with mock.patch(
                'six.moves.builtins.open', mock.Mock(return_value=fake_fd)):
            self.assertFalse(utils.is_ipv6_configured())

    def test_is_ipv6_configured2(self):
        with mock.patch('six.moves.builtins.open',
                        mock.Mock(side_effect=IOError(
                            errno.ENOENT, 'Fake no such file error.'))):
            self.assertFalse(utils.is_ipv6_configured())

    def test_is_ipv6_configured3(self):
        with mock.patch('six.moves.builtins.open',
                        mock.Mock(side_effect=IOError(
                            errno.EPERM, 'Fake no such file error.'))):
            self.assertRaises(IOError, utils.is_ipv6_configured)

    def test_is_eventlet_bug105(self):
        fake_dns = mock.Mock()
        fake_dns.getaddrinfo.side_effect = socket.gaierror(errno.EBADF)
        with mock.patch.dict('sys.modules', {
                'eventlet.support.greendns': fake_dns}):
            self.assertTrue(utils.is_eventlet_bug105())
            self.assertTrue(fake_dns.getaddrinfo.called)

    def test_is_eventlet_bug105_neg(self):
        fake_dns = mock.Mock()
        fake_dns.getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, '', (u'127.0.0.1', 80)),
        ]
        with mock.patch.dict('sys.modules', {
                'eventlet.support.greendns': fake_dns}):
            self.assertFalse(utils.is_eventlet_bug105())
            fake_dns.getaddrinfo.assert_called_once_with('::1', 80)

    @ddt.data(['ssh', '-D', 'my_name@name_of_remote_computer'],
              ['echo', '"quoted arg with space"'],
              ['echo', "'quoted arg with space'"])
    def test_check_ssh_injection(self, cmd):
        cmd_list = cmd
        self.assertIsNone(utils.check_ssh_injection(cmd_list))

    @ddt.data(['ssh', 'my_name@      name_of_remote_computer'],
              ['||', 'my_name@name_of_remote_computer'],
              ['cmd', 'virus;ls'],
              ['cmd', '"arg\"withunescaped"'],
              ['cmd', 'virus;"quoted argument"'],
              ['echo', '"quoted argument";rm -rf'],
              ['echo', "'quoted argument `rm -rf`'"],
              ['echo', '"quoted";virus;"quoted"'],
              ['echo', '"quoted";virus;\'quoted\''])
    def test_check_ssh_injection_on_error0(self, cmd):
        self.assertRaises(exception.SSHInjectionThreat,
                          utils.check_ssh_injection, cmd)


class MonkeyPatchTestCase(test.TestCase):
    """Unit test for utils.monkey_patch()."""
    def setUp(self):
        super(MonkeyPatchTestCase, self).setUp()
        self.example_package = 'manila.tests.monkey_patch_example.'
        self.flags(
            monkey_patch=True,
            monkey_patch_modules=[self.example_package + 'example_a' + ':'
                                  + self.example_package
                                  + 'example_decorator'])

    def test_monkey_patch(self):
        utils.monkey_patch()
        manila.tests.monkey_patch_example.CALLED_FUNCTION = []
        from manila.tests.monkey_patch_example import example_a
        from manila.tests.monkey_patch_example import example_b

        self.assertEqual('Example function', example_a.example_function_a())
        exampleA = example_a.ExampleClassA()
        exampleA.example_method()
        ret_a = exampleA.example_method_add(3, 5)
        self.assertEqual(8, ret_a)

        self.assertEqual('Example function', example_b.example_function_b())
        exampleB = example_b.ExampleClassB()
        exampleB.example_method()
        ret_b = exampleB.example_method_add(3, 5)

        self.assertEqual(8, ret_b)
        package_a = self.example_package + 'example_a.'
        self.assertTrue(package_a + 'example_function_a'
                        in manila.tests.monkey_patch_example.CALLED_FUNCTION)

        self.assertTrue(package_a + 'ExampleClassA.example_method'
                        in manila.tests.monkey_patch_example.CALLED_FUNCTION)
        self.assertTrue(package_a + 'ExampleClassA.example_method_add'
                        in manila.tests.monkey_patch_example.CALLED_FUNCTION)
        package_b = self.example_package + 'example_b.'
        self.assertFalse(package_b + 'example_function_b'
                         in manila.tests.monkey_patch_example.CALLED_FUNCTION)
        self.assertFalse(package_b + 'ExampleClassB.example_method'
                         in manila.tests.monkey_patch_example.CALLED_FUNCTION)
        self.assertFalse(package_b + 'ExampleClassB.example_method_add'
                         in manila.tests.monkey_patch_example.CALLED_FUNCTION)


class FakeSSHClient(object):

    def __init__(self):
        self.id = uuid.uuid4()
        self.transport = FakeTransport()

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, ip, port=22, username=None, password=None,
                key_filename=None, look_for_keys=None, timeout=10):
        pass

    def get_transport(self):
        return self.transport

    def close(self):
        pass

    def __call__(self, *args, **kwargs):
        pass


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


class SSHPoolTestCase(test.TestCase):
    """Unit test for SSH Connection Pool."""

    def test_single_ssh_connect(self):
        with mock.patch.object(paramiko, "SSHClient",
                               mock.Mock(return_value=FakeSSHClient())):
            sshpool = utils.SSHPool("127.0.0.1", 22, 10, "test",
                                    password="test", min_size=1, max_size=1)
            with sshpool.item() as ssh:
                first_id = ssh.id

            with sshpool.item() as ssh:
                second_id = ssh.id

            self.assertEqual(first_id, second_id)
            paramiko.SSHClient.assert_called_once_with()

    def test_create_ssh_with_password(self):
        fake_ssh_client = mock.Mock()
        ssh_pool = utils.SSHPool("127.0.0.1", 22, 10, "test",
                                 password="test")
        with mock.patch.object(paramiko, "SSHClient",
                               return_value=fake_ssh_client):
            ssh_pool.create()

            fake_ssh_client.connect.assert_called_once_with(
                "127.0.0.1", port=22, username="test",
                password="test", key_filename=None, look_for_keys=False,
                timeout=10)

    def test_create_ssh_with_key(self):
        path_to_private_key = "/fakepath/to/privatekey"
        fake_ssh_client = mock.Mock()
        ssh_pool = utils.SSHPool("127.0.0.1", 22, 10, "test",
                                 privatekey="/fakepath/to/privatekey")
        with mock.patch.object(paramiko, "SSHClient",
                               return_value=fake_ssh_client):
            ssh_pool.create()
            fake_ssh_client.connect.assert_called_once_with(
                "127.0.0.1", port=22, username="test", password=None,
                key_filename=path_to_private_key, look_for_keys=False,
                timeout=10)

    def test_create_ssh_with_nothing(self):
        fake_ssh_client = mock.Mock()
        ssh_pool = utils.SSHPool("127.0.0.1", 22, 10, "test")
        with mock.patch.object(paramiko, "SSHClient",
                               return_value=fake_ssh_client):
            ssh_pool.create()
            fake_ssh_client.connect.assert_called_once_with(
                "127.0.0.1", port=22, username="test", password=None,
                key_filename=None, look_for_keys=True,
                timeout=10)

    def test_create_ssh_error_connecting(self):
        attrs = {'connect.side_effect': paramiko.SSHException, }
        fake_ssh_client = mock.Mock(**attrs)
        ssh_pool = utils.SSHPool("127.0.0.1", 22, 10, "test")
        with mock.patch.object(paramiko, "SSHClient",
                               return_value=fake_ssh_client):
            self.assertRaises(exception.SSHException, ssh_pool.create)
            fake_ssh_client.connect.assert_called_once_with(
                "127.0.0.1", port=22, username="test", password=None,
                key_filename=None, look_for_keys=True,
                timeout=10)

    def test_closed_reopend_ssh_connections(self):
        with mock.patch.object(paramiko, "SSHClient",
                               mock.Mock(return_value=FakeSSHClient())):
            sshpool = utils.SSHPool("127.0.0.1", 22, 10, "test",
                                    password="test", min_size=1, max_size=2)
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


class CidrToNetmaskTestCase(test.TestCase):
    """Unit test for cidr to netmask."""

    def test_cidr_to_netmask_01(self):
        cidr = '10.0.0.0/0'
        expected_netmask = '0.0.0.0'
        result = utils.cidr_to_netmask(cidr)
        self.assertEqual(expected_netmask, result)

    def test_cidr_to_netmask_02(self):
        cidr = '10.0.0.0/24'
        expected_netmask = '255.255.255.0'
        result = utils.cidr_to_netmask(cidr)
        self.assertEqual(expected_netmask, result)

    def test_cidr_to_netmask_03(self):
        cidr = '10.0.0.0/5'
        expected_netmask = '248.0.0.0'
        result = utils.cidr_to_netmask(cidr)
        self.assertEqual(expected_netmask, result)

    def test_cidr_to_netmask_04(self):
        cidr = '10.0.0.0/32'
        expected_netmask = '255.255.255.255'
        result = utils.cidr_to_netmask(cidr)
        self.assertEqual(expected_netmask, result)

    def test_cidr_to_netmask_05(self):
        cidr = '10.0.0.1'
        expected_netmask = '255.255.255.255'
        result = utils.cidr_to_netmask(cidr)
        self.assertEqual(expected_netmask, result)

    def test_cidr_to_netmask_invalid_01(self):
        cidr = '10.0.0.0/33'
        self.assertRaises(exception.InvalidInput, utils.cidr_to_netmask, cidr)

    def test_cidr_to_netmask_invalid_02(self):
        cidr = ''
        self.assertRaises(exception.InvalidInput, utils.cidr_to_netmask, cidr)

    def test_cidr_to_netmask_invalid_03(self):
        cidr = '10.0.0.0/33'
        self.assertRaises(exception.InvalidInput, utils.cidr_to_netmask, cidr)

    def test_cidr_to_netmask_invalid_04(self):
        cidr = '10.0.0.555/33'
        self.assertRaises(exception.InvalidInput, utils.cidr_to_netmask, cidr)


@ddt.ddt
class IsValidIPVersion(test.TestCase):
    """Test suite for function 'is_valid_ip_address'."""

    @ddt.data('0.0.0.0', '255.255.255.255', '192.168.0.1')
    def test_valid_v4(self, addr):
        for vers in (4, '4'):
            self.assertTrue(utils.is_valid_ip_address(addr, vers))

    @ddt.data(
        '2001:cdba:0000:0000:0000:0000:3257:9652',
        '2001:cdba:0:0:0:0:3257:9652',
        '2001:cdba::3257:9652')
    def test_valid_v6(self, addr):
        for vers in (6, '6'):
            self.assertTrue(utils.is_valid_ip_address(addr, vers))

    @ddt.data(
        {'addr': '1.1.1.1', 'vers': 3},
        {'addr': '1.1.1.1', 'vers': 5},
        {'addr': '1.1.1.1', 'vers': 7},
        {'addr': '2001:cdba::3257:9652', 'vers': '3'},
        {'addr': '2001:cdba::3257:9652', 'vers': '5'},
        {'addr': '2001:cdba::3257:9652', 'vers': '7'})
    @ddt.unpack
    def test_provided_invalid_version(self, addr, vers):
        self.assertRaises(
            exception.ManilaException, utils.is_valid_ip_address, addr, vers)

    def test_provided_none_version(self):
        self.assertRaises(TypeError, utils.is_valid_ip_address, '', None)

    @ddt.data(None, 'fake', '1.1.1.1')
    def test_provided_invalid_v6_address(self, addr):
        for vers in (6, '6'):
            self.assertFalse(utils.is_valid_ip_address(addr, vers))

    @ddt.data(None, 'fake', '255.255.255.256', '2001:cdba::3257:9652')
    def test_provided_invalid_v4_address(self, addr):
        for vers in (4, '4'):
            self.assertFalse(utils.is_valid_ip_address(addr, vers))


class Comparable(utils.ComparableMixin):
    def __init__(self, value):
        self.value = value

    def _cmpkey(self):
        return self.value


class TestComparableMixin(test.TestCase):

    def setUp(self):
        super(TestComparableMixin, self).setUp()
        self.one = Comparable(1)
        self.two = Comparable(2)

    def test_lt(self):
        self.assertTrue(self.one < self.two)
        self.assertFalse(self.two < self.one)
        self.assertFalse(self.one < self.one)

    def test_le(self):
        self.assertTrue(self.one <= self.two)
        self.assertFalse(self.two <= self.one)
        self.assertTrue(self.one <= self.one)

    def test_eq(self):
        self.assertFalse(self.one == self.two)
        self.assertFalse(self.two == self.one)
        self.assertTrue(self.one == self.one)

    def test_ge(self):
        self.assertFalse(self.one >= self.two)
        self.assertTrue(self.two >= self.one)
        self.assertTrue(self.one >= self.one)

    def test_gt(self):
        self.assertFalse(self.one > self.two)
        self.assertTrue(self.two > self.one)
        self.assertFalse(self.one > self.one)

    def test_ne(self):
        self.assertTrue(self.one != self.two)
        self.assertTrue(self.two != self.one)
        self.assertFalse(self.one != self.one)

    def test_compare(self):
        self.assertEqual(NotImplemented,
                         self.one._compare(1, self.one._cmpkey))


class TestRetryDecorator(test.TestCase):
    def setUp(self):
        super(TestRetryDecorator, self).setUp()

    def test_no_retry_required(self):
        self.counter = 0

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exception.ManilaException,
                         interval=2,
                         retries=3,
                         backoff_rate=2)
            def succeeds():
                self.counter += 1
                return 'success'

            ret = succeeds()
            self.assertFalse(mock_sleep.called)
            self.assertEqual('success', ret)
            self.assertEqual(1, self.counter)

    def test_no_retry_required_random(self):
        self.counter = 0

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exception.ManilaException,
                         interval=2,
                         retries=3,
                         backoff_rate=2,
                         wait_random=True)
            def succeeds():
                self.counter += 1
                return 'success'

            ret = succeeds()
            self.assertFalse(mock_sleep.called)
            self.assertEqual('success', ret)
            self.assertEqual(1, self.counter)

    def test_retries_once_random(self):
        self.counter = 0
        interval = 2
        backoff_rate = 2
        retries = 3

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exception.ManilaException,
                         interval,
                         retries,
                         backoff_rate,
                         wait_random=True)
            def fails_once():
                self.counter += 1
                if self.counter < 2:
                    raise exception.ManilaException(data='fake')
                else:
                    return 'success'

            ret = fails_once()
            self.assertEqual('success', ret)
            self.assertEqual(2, self.counter)
            self.assertEqual(1, mock_sleep.call_count)
            self.assertTrue(mock_sleep.called)

    def test_retries_once(self):
        self.counter = 0
        interval = 2
        backoff_rate = 2
        retries = 3

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exception.ManilaException,
                         interval,
                         retries,
                         backoff_rate)
            def fails_once():
                self.counter += 1
                if self.counter < 2:
                    raise exception.ManilaException(data='fake')
                else:
                    return 'success'

            ret = fails_once()
            self.assertEqual('success', ret)
            self.assertEqual(2, self.counter)
            self.assertEqual(1, mock_sleep.call_count)
            mock_sleep.assert_called_with(interval * backoff_rate)

    def test_limit_is_reached(self):
        self.counter = 0
        retries = 3
        interval = 2
        backoff_rate = 4

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exception.ManilaException,
                         interval,
                         retries,
                         backoff_rate)
            def always_fails():
                self.counter += 1
                raise exception.ManilaException(data='fake')

            self.assertRaises(exception.ManilaException,
                              always_fails)
            self.assertEqual(retries, self.counter)

            expected_sleep_arg = []

            for i in range(retries):
                if i > 0:
                    interval *= backoff_rate
                    expected_sleep_arg.append(float(interval))

            mock_sleep.assert_has_calls(map(mock.call, expected_sleep_arg))

    def test_wrong_exception_no_retry(self):

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exception.ManilaException)
            def raise_unexpected_error():
                raise ValueError("value error")

            self.assertRaises(ValueError, raise_unexpected_error)
            self.assertFalse(mock_sleep.called)


@ddt.ddt
class RequireDriverInitializedTestCase(test.TestCase):

    @ddt.data(True, False)
    def test_require_driver_initialized(self, initialized):

        class FakeDriver(object):
            @property
            def initialized(self):
                return initialized

        class FakeException(Exception):
            pass

        class FakeManager(object):
            driver = FakeDriver()

            @utils.require_driver_initialized
            def call_me(self):
                raise FakeException(
                    "Should be raised only if manager.driver.initialized "
                    "('%s') is equal to 'True'." % initialized)

        if initialized:
            expected_exception = FakeException
        else:
            expected_exception = exception.DriverNotInitialized

        self.assertRaises(expected_exception, FakeManager().call_me)
