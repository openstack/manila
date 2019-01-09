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
import json
import socket
import time

import ddt
import mock
from oslo_config import cfg
from oslo_utils import timeutils
from oslo_utils import uuidutils
import paramiko
import six
from webob import exc

import manila
from manila.common import constants
from manila import context
from manila.db import api as db
from manila import exception
from manila import test
from manila import utils

CONF = cfg.CONF


@ddt.ddt
class GenericUtilsTestCase(test.TestCase):
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

    @ddt.data(
        (("3G", "G"), 3.0),
        (("4.1G", "G"), 4.1),
        (("4,1G", "G"), 4.1),
        (("5.23G", "G"), 5.23),
        (("5,23G", "G"), 5.23),
        (("9728M", "G"), 9.5),
        (("8192K", "G"), 0.0078125),
        (("2T", "G"), 2048.0),
        (("2.1T", "G"), 2150.4),
        (("2,1T", "G"), 2150.4),
        (("3P", "G"), 3145728.0),
        (("3.4P", "G"), 3565158.4),
        (("3,4P", "G"), 3565158.4),
        (("9728M", "M"), 9728.0),
        (("9728.2381T", "T"), 9728.2381),
        (("9728,2381T", "T"), 9728.2381),
        (("0", "G"), 0.0),
        (("512", "M"), 0.00048828125),
        (("2097152.", "M"), 2.0),
        ((".1024", "K"), 0.0001),
        ((",1024", "K"), 0.0001),
        (("2048G", "T"), 2.0),
        (("65536G", "P"), 0.0625),
    )
    @ddt.unpack
    def test_translate_string_size_to_float_positive(self, request, expected):
        actual = utils.translate_string_size_to_float(*request)
        self.assertEqual(expected, actual)

    @ddt.data(
        (None, "G"),
        ("fake", "G"),
        ("1fake", "G"),
        ("2GG", "G"),
        ("1KM", "G"),
        ("K1M", "G"),
        ("M1K", "G"),
        ("1.2fake", "G"),
        ("1,2fake", "G"),
        ("2.2GG", "G"),
        ("1.1KM", "G"),
        ("K2.2M", "G"),
        ("K2,2M", "G"),
        ("M2.2K", "G"),
        ("M2,2K", "G"),
        ("", "G"),
        (23, "G"),
        (23.0, "G"),
    )
    @ddt.unpack
    def test_translate_string_size_to_float_negative(self, string, multiplier):
        actual = utils.translate_string_size_to_float(string, multiplier)
        self.assertIsNone(actual)


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
        self.assertIn(package_a + 'example_function_a',
                      manila.tests.monkey_patch_example.CALLED_FUNCTION)

        self.assertIn(package_a + 'ExampleClassA.example_method',
                      manila.tests.monkey_patch_example.CALLED_FUNCTION)
        self.assertIn(package_a + 'ExampleClassA.example_method_add',
                      manila.tests.monkey_patch_example.CALLED_FUNCTION)
        package_b = self.example_package + 'example_b.'
        self.assertNotIn(package_b + 'example_function_b',
                         manila.tests.monkey_patch_example.CALLED_FUNCTION)
        self.assertNotIn(package_b + 'ExampleClassB.example_method',
                         manila.tests.monkey_patch_example.CALLED_FUNCTION)
        self.assertNotIn(package_b + 'ExampleClassB.example_method_add',
                         manila.tests.monkey_patch_example.CALLED_FUNCTION)


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
                timeout=10, banner_timeout=10)

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
                timeout=10, banner_timeout=10)

    def test_create_ssh_with_nothing(self):
        fake_ssh_client = mock.Mock()
        ssh_pool = utils.SSHPool("127.0.0.1", 22, 10, "test")
        with mock.patch.object(paramiko, "SSHClient",
                               return_value=fake_ssh_client):
            ssh_pool.create()
            fake_ssh_client.connect.assert_called_once_with(
                "127.0.0.1", port=22, username="test", password=None,
                key_filename=None, look_for_keys=True,
                timeout=10, banner_timeout=10)

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
                timeout=10, banner_timeout=10)

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


@ddt.ddt
class CidrToNetmaskTestCase(test.TestCase):
    """Unit test for cidr to netmask."""

    @ddt.data(
        ('10.0.0.0/0', '0.0.0.0'),
        ('10.0.0.0/24', '255.255.255.0'),
        ('10.0.0.0/5', '248.0.0.0'),
        ('10.0.0.0/32', '255.255.255.255'),
        ('10.0.0.1', '255.255.255.255'),
    )
    @ddt.unpack
    def test_cidr_to_netmask(self, cidr, expected_netmask):
        result = utils.cidr_to_netmask(cidr)
        self.assertEqual(expected_netmask, result)

    @ddt.data(
        '10.0.0.0/33',
        '',
        '10.0.0.555/33'
    )
    def test_cidr_to_netmask_invalid(self, cidr):
        self.assertRaises(exception.InvalidInput, utils.cidr_to_netmask, cidr)


@ddt.ddt
class CidrToPrefixLenTestCase(test.TestCase):
    """Unit test for cidr to prefix length."""

    @ddt.data(
        ('10.0.0.0/0', 0),
        ('10.0.0.0/24', 24),
        ('10.0.0.1', 32),
        ('fdf8:f53b:82e1::1/0', 0),
        ('fdf8:f53b:82e1::1/64', 64),
        ('fdf8:f53b:82e1::1', 128),
    )
    @ddt.unpack
    def test_cidr_to_prefixlen(self, cidr, expected_prefixlen):
        result = utils.cidr_to_prefixlen(cidr)
        self.assertEqual(expected_prefixlen, result)

    @ddt.data(
        '10.0.0.0/33',
        '',
        '10.0.0.555/33',
        'fdf8:f53b:82e1::1/129',
        'fdf8:f53b:82e1::fffff'
    )
    def test_cidr_to_prefixlen_invalid(self, cidr):
        self.assertRaises(exception.InvalidInput,
                          utils.cidr_to_prefixlen, cidr)


@ddt.ddt
class ParseBoolValueTestCase(test.TestCase):

    @ddt.data(
        ('t', True),
        ('on', True),
        ('1', True),
        ('false', False),
        ('n', False),
        ('no', False),
        ('0', False),)
    @ddt.unpack
    def test_bool_with_valid_string(self, string, value):
        fake_dict = {'fake_key': string}
        result = utils.get_bool_from_api_params('fake_key', fake_dict)
        self.assertEqual(value, result)

    @ddt.data('None', 'invalid', 'falses')
    def test_bool_with_invalid_string(self, string):
        fake_dict = {'fake_key': string}
        self.assertRaises(exc.HTTPBadRequest,
                          utils.get_bool_from_api_params,
                          'fake_key', fake_dict)

    @ddt.data('undefined', None)
    def test_bool_with_key_not_found_raise_error(self, def_val):
        fake_dict = {'fake_key1': 'value1'}
        self.assertRaises(exc.HTTPBadRequest,
                          utils.get_bool_from_api_params,
                          'fake_key2',
                          fake_dict,
                          def_val)

    @ddt.data((False, False, False),
              (True, True, False),
              ('true', True, False),
              ('false', False, False),
              ('undefined', 'undefined', False),
              (False, False, True),
              ('true', True, True))
    @ddt.unpack
    def test_bool_with_key_not_found(self, def_val, expected, strict):
        fake_dict = {'fake_key1': 'value1'}
        invalid_default = utils.get_bool_from_api_params('fake_key2',
                                                         fake_dict,
                                                         def_val,
                                                         strict)
        self.assertEqual(expected, invalid_default)


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

    @ddt.data(None, 'fake', '255.255.255.256', '2001:cdba::3257:9652', '')
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

    def test_wrong_retries_num(self):
        self.assertRaises(ValueError, utils.retry, exception.ManilaException,
                          retries=-1)

    def test_max_backoff_sleep(self):
        self.counter = 0

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exception.ManilaException,
                         retries=0,
                         backoff_rate=2,
                         backoff_sleep_max=4)
            def fails_then_passes():
                self.counter += 1
                if self.counter < 5:
                    raise exception.ManilaException(data='fake')
                else:
                    return 'success'

            self.assertEqual('success', fails_then_passes())
            mock_sleep.assert_has_calls(map(mock.call, [2, 4, 4, 4]))


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


@ddt.ddt
class ShareMigrationHelperTestCase(test.TestCase):
    """Tests DataMigrationHelper."""

    def setUp(self):
        super(ShareMigrationHelperTestCase, self).setUp()
        self.context = context.get_admin_context()

    def test_wait_for_access_update(self):
        sid = 1
        fake_share_instances = [
            {
                'id': sid,
                'access_rules_status': constants.SHARE_INSTANCE_RULES_SYNCING,
            },
            {
                'id': sid,
                'access_rules_status': constants.STATUS_ACTIVE,
            },
        ]

        self.mock_object(time, 'sleep')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=fake_share_instances))

        utils.wait_for_access_update(self.context, db,
                                     fake_share_instances[0], 1)

        db.share_instance_get.assert_has_calls(
            [mock.call(mock.ANY, sid), mock.call(mock.ANY, sid)]
        )
        time.sleep.assert_called_once_with(1.414)

    @ddt.data(
        (
            {
                'id': '1',
                'access_rules_status': constants.SHARE_INSTANCE_RULES_ERROR,
            },
            exception.ShareMigrationFailed
        ),
        (
            {
                'id': '1',
                'access_rules_status': constants.SHARE_INSTANCE_RULES_SYNCING,
            },
            exception.ShareMigrationFailed
        ),
    )
    @ddt.unpack
    def test_wait_for_access_update_invalid(self, fake_instance, expected_exc):
        self.mock_object(time, 'sleep')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=fake_instance))

        now = time.time()
        timeout = now + 100

        self.mock_object(time, 'time',
                         mock.Mock(side_effect=[now, timeout]))

        self.assertRaises(expected_exc,
                          utils.wait_for_access_update, self.context,
                          db, fake_instance, 1)


@ddt.ddt
class ConvertStrTestCase(test.TestCase):

    def test_convert_str_str_input(self):
        self.mock_object(utils.encodeutils, 'safe_encode')
        input_value = six.text_type("string_input")

        output_value = utils.convert_str(input_value)

        if six.PY2:
            utils.encodeutils.safe_encode.assert_called_once_with(input_value)
            self.assertEqual(
                utils.encodeutils.safe_encode.return_value, output_value)
        else:
            self.assertEqual(0, utils.encodeutils.safe_encode.call_count)
            self.assertEqual(input_value, output_value)

    def test_convert_str_bytes_input(self):
        self.mock_object(utils.encodeutils, 'safe_encode')
        if six.PY2:
            input_value = six.binary_type("binary_input")
        else:
            input_value = six.binary_type("binary_input", "utf-8")

        output_value = utils.convert_str(input_value)

        if six.PY2:
            utils.encodeutils.safe_encode.assert_called_once_with(input_value)
            self.assertEqual(
                utils.encodeutils.safe_encode.return_value, output_value)
        else:
            self.assertEqual(0, utils.encodeutils.safe_encode.call_count)
            self.assertIsInstance(output_value, six.string_types)
            self.assertEqual(six.text_type("binary_input"), output_value)


@ddt.ddt
class TestDisableNotifications(test.TestCase):
    def test_do_nothing_getter(self):
        """Test any attribute will always return the same instance (self)."""
        donothing = utils.DoNothing()
        self.assertIs(donothing, donothing.anyname)

    def test_do_nothing_caller(self):
        """Test calling the object will always return the same instance."""
        donothing = utils.DoNothing()
        self.assertIs(donothing, donothing())

    def test_do_nothing_json_serializable(self):
        """Test calling the object will always return the same instance."""
        donothing = utils.DoNothing()
        self.assertEqual('""', json.dumps(donothing))

    @utils.if_notifications_enabled
    def _decorated_method(self):
        return mock.sentinel.success

    def test_if_notification_enabled_when_enabled(self):
        """Test method is called when notifications are enabled."""
        result = self._decorated_method()
        self.assertEqual(mock.sentinel.success, result)

    @ddt.data([], ['noop'], ['noop', 'noop'])
    def test_if_notification_enabled_when_disabled(self, driver):
        """Test method is not called when notifications are disabled."""
        self.override_config('driver', driver,
                             group='oslo_messaging_notifications')
        result = self._decorated_method()
        self.assertEqual(utils.DO_NOTHING, result)


@ddt.ddt
class TestAllTenantsValueCase(test.TestCase):
    @ddt.data(None, '', '1', 'true', 'True')
    def test_is_all_tenants_true(self, value):
        search_opts = {'all_tenants': value}
        self.assertTrue(utils.is_all_tenants(search_opts))
        self.assertIn('all_tenants', search_opts)

    @ddt.data('0', 'false', 'False')
    def test_is_all_tenants_false(self, value):
        search_opts = {'all_tenants': value}
        self.assertFalse(utils.is_all_tenants(search_opts))
        self.assertIn('all_tenants', search_opts)

    def test_is_all_tenants_missing(self):
        self.assertFalse(utils.is_all_tenants({}))

    def test_is_all_tenants_invalid(self):
        search_opts = {'all_tenants': 'wonk'}
        self.assertRaises(exception.InvalidInput, utils.is_all_tenants,
                          search_opts)
