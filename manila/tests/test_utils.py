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

import __builtin__
import datetime
import errno
import hashlib
import os
import os.path
import socket
import StringIO
import tempfile
import uuid

import mock
from oslo.config import cfg
import paramiko

import manila
from manila import exception
from manila.openstack.common import timeutils
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


class GenericUtilsTestCase(test.TestCase):
    def test_hostname_unicode_sanitization(self):
        hostname = u"\u7684.test.example.com"
        self.assertEqual("test.example.com",
                         utils.sanitize_hostname(hostname))

    def test_hostname_sanitize_periods(self):
        hostname = "....test.example.com..."
        self.assertEqual("test.example.com",
                         utils.sanitize_hostname(hostname))

    def test_hostname_sanitize_dashes(self):
        hostname = "----test.example.com---"
        self.assertEqual("test.example.com",
                         utils.sanitize_hostname(hostname))

    def test_hostname_sanitize_characters(self):
        hostname = "(#@&$!(@*--#&91)(__=+--test-host.example!!.com-0+"
        self.assertEqual("91----test-host.example.com-0",
                         utils.sanitize_hostname(hostname))

    def test_hostname_translate(self):
        hostname = "<}\x1fh\x10e\x08l\x02l\x05o\x12!{>"
        self.assertEqual("hello", utils.sanitize_hostname(hostname))

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
                    __builtin__, 'open',
                    mock.Mock(return_value=fake_context_manager)):
                cache_data = {"data": 1123, "mtime": 1}
                self.reload_called = False

                def test_reload(reloaded_data):
                    self.assertEqual(reloaded_data, fake_contents)
                    self.reload_called = True

                data = utils.read_cached_file("/this/is/a/fake",
                                              cache_data,
                                              reload_func=test_reload)
                self.assertEqual(data, fake_contents)
                self.assertTrue(self.reload_called)
                fake_file.read.assert_called_once_with()
                fake_context_manager.__enter__.assert_any_call()
                __builtin__.open.assert_called_once_with("/this/is/a/fake")
                os.path.getmtime.assert_called_once_with("/this/is/a/fake")

    def test_generate_password(self):
        password = utils.generate_password()
        self.assertTrue([c for c in password if c in '0123456789'])
        self.assertTrue([c for c in password
                         if c in 'abcdefghijklmnopqrstuvwxyz'])
        self.assertTrue([c for c in password
                         if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'])

    def test_read_file_as_root(self):
        def fake_execute(*args, **kwargs):
            if args[1] == 'bad':
                raise exception.ProcessExecutionError
            return 'fakecontents', None

        self.stubs.Set(utils, 'execute', fake_execute)
        contents = utils.read_file_as_root('good')
        self.assertEqual(contents, 'fakecontents')
        self.assertRaises(exception.FileNotFound,
                          utils.read_file_as_root, 'bad')

    def test_strcmp_const_time(self):
        self.assertTrue(utils.strcmp_const_time('abc123', 'abc123'))
        self.assertFalse(utils.strcmp_const_time('a', 'aaaaa'))
        self.assertFalse(utils.strcmp_const_time('ABC123', 'abc123'))

    def test_temporary_chown(self):
        def fake_execute(*args, **kwargs):
            if args[0] == 'chown':
                fake_execute.uid = args[1]
        self.stubs.Set(utils, 'execute', fake_execute)

        with tempfile.NamedTemporaryFile() as f:
            with utils.temporary_chown(f.name, owner_uid=2):
                self.assertEqual(fake_execute.uid, 2)
            self.assertEqual(fake_execute.uid, os.getuid())

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

    def test_safe_parse_xml(self):

        normal_body = ('<?xml version="1.0" ?>'
                       '<foo><bar><v1>hey</v1><v2>there</v2></bar></foo>')

        def killer_body():
            return (("""<!DOCTYPE x [
                    <!ENTITY a "%(a)s">
                    <!ENTITY b "%(b)s">
                    <!ENTITY c "%(c)s">]>
                <foo>
                    <bar>
                        <v1>%(d)s</v1>
                    </bar>
                </foo>""") % {
                'a': 'A' * 10,
                'b': '&a;' * 10,
                'c': '&b;' * 10,
                'd': '&c;' * 9999,
            }).strip()

        dom = utils.safe_minidom_parse_string(normal_body)
        # Some versions of minidom inject extra newlines so we ignore them
        result = str(dom.toxml()).replace('\n', '')
        self.assertEqual(normal_body, result)

        self.assertRaises(ValueError,
                          utils.safe_minidom_parse_string,
                          killer_body())

    def test_xhtml_escape(self):
        self.assertEqual('&quot;foo&quot;', utils.xhtml_escape('"foo"'))
        self.assertEqual('&apos;foo&apos;', utils.xhtml_escape("'foo'"))

    def test_hash_file(self):
        data = 'Mary had a little lamb, its fleece as white as snow'
        flo = StringIO.StringIO(data)
        h1 = utils.hash_file(flo)
        h2 = hashlib.sha1(data).hexdigest()
        self.assertEqual(h1, h2)

    def test_is_ipv6_configured0(self):
        fake_fd = mock.Mock()
        fake_fd.read.return_value = 'test'
        with mock.patch(
                '__builtin__.open', mock.Mock(return_value=fake_fd)) as open:
            self.assertTrue(utils.is_ipv6_configured())

            open.assert_called_once_with('/proc/net/if_inet6')
            fake_fd.read.assert_called_once()

    def test_is_ipv6_configured1(self):
        fake_fd = mock.Mock()
        fake_fd.read.return_value = ''
        with mock.patch(
                '__builtin__.open', mock.Mock(return_value=fake_fd)):
            self.assertFalse(utils.is_ipv6_configured())

    def test_is_ipv6_configured2(self):
        with mock.patch('__builtin__.open', mock.Mock(side_effect=IOError(
                errno.ENOENT, 'Fake no such file error.'))):
            self.assertFalse(utils.is_ipv6_configured())

    def test_is_ipv6_configured3(self):
        with mock.patch('__builtin__.open', mock.Mock(side_effect=IOError(
                errno.EPERM, 'Fake no such file error.'))):
            self.assertRaises(IOError, utils.is_ipv6_configured)

    def test_is_eventlet_bug105(self):
        fake_dns = mock.Mock()
        fake_dns.getaddrinfo.side_effect = socket.gaierror(errno.EBADF)
        with mock.patch.dict('sys.modules', {
                'eventlet.support.greendns': fake_dns}):
            self.assertTrue(utils.is_eventlet_bug105())
            fake_dns.getaddrinfo.assert_called_once()

    def test_is_eventlet_bug105_neg(self):
        fake_dns = mock.Mock()
        fake_dns.getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, '', (u'127.0.0.1', 80)),
        ]
        with mock.patch.dict('sys.modules', {
                'eventlet.support.greendns': fake_dns}):
            self.assertFalse(utils.is_eventlet_bug105())
            fake_dns.getaddrinfo.assert_called_once()


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
        self.assertEqual(ret_a, 8)

        self.assertEqual('Example function', example_b.example_function_b())
        exampleB = example_b.ExampleClassB()
        exampleB.example_method()
        ret_b = exampleB.example_method_add(3, 5)

        self.assertEqual(ret_b, 8)
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


class AuditPeriodTest(test.TestCase):

    def setUp(self):
        super(AuditPeriodTest, self).setUp()
        # a fairly random time to test with
        self.test_time = datetime.datetime(second=23,
                                           minute=12,
                                           hour=8,
                                           day=5,
                                           month=3,
                                           year=2012)
        self.patcher = mock.patch.object(timeutils, 'utcnow')
        self.mock_utcnow = self.patcher.start()
        self.mock_utcnow.return_value = self.test_time

    def tearDown(self):
        self.patcher.stop()
        super(AuditPeriodTest, self).tearDown()

    def test_hour(self):
        begin, end = utils.last_completed_audit_period(unit='hour')
        self.assertEqual(begin,
                         datetime.datetime(hour=7,
                                           day=5,
                                           month=3,
                                           year=2012))
        self.assertEqual(end, datetime.datetime(hour=8,
                                                day=5,
                                                month=3,
                                                year=2012))

    def test_hour_with_offset_before_current(self):
        begin, end = utils.last_completed_audit_period(unit='hour@10')
        self.assertEqual(begin, datetime.datetime(minute=10,
                                                  hour=7,
                                                  day=5,
                                                  month=3,
                                                  year=2012))
        self.assertEqual(end, datetime.datetime(minute=10,
                                                hour=8,
                                                day=5,
                                                month=3,
                                                year=2012))

    def test_hour_with_offset_after_current(self):
        begin, end = utils.last_completed_audit_period(unit='hour@30')
        self.assertEqual(begin, datetime.datetime(minute=30,
                                                  hour=6,
                                                  day=5,
                                                  month=3,
                                                  year=2012))
        self.assertEqual(end, datetime.datetime(minute=30,
                                                hour=7,
                                                day=5,
                                                month=3,
                                                year=2012))

    def test_day(self):
        begin, end = utils.last_completed_audit_period(unit='day')
        self.assertEqual(begin, datetime.datetime(day=4,
                                                  month=3,
                                                  year=2012))
        self.assertEqual(end, datetime.datetime(day=5,
                                                month=3,
                                                year=2012))

    def test_day_with_offset_before_current(self):
        begin, end = utils.last_completed_audit_period(unit='day@6')
        self.assertEqual(begin, datetime.datetime(hour=6,
                                                  day=4,
                                                  month=3,
                                                  year=2012))
        self.assertEqual(end, datetime.datetime(hour=6,
                                                day=5,
                                                month=3,
                                                year=2012))

    def test_day_with_offset_after_current(self):
        begin, end = utils.last_completed_audit_period(unit='day@10')
        self.assertEqual(begin, datetime.datetime(hour=10,
                                                  day=3,
                                                  month=3,
                                                  year=2012))
        self.assertEqual(end, datetime.datetime(hour=10,
                                                day=4,
                                                month=3,
                                                year=2012))

    def test_month(self):
        begin, end = utils.last_completed_audit_period(unit='month')
        self.assertEqual(begin, datetime.datetime(day=1,
                                                  month=2,
                                                  year=2012))
        self.assertEqual(end, datetime.datetime(day=1,
                                                month=3,
                                                year=2012))

    def test_month_with_offset_before_current(self):
        begin, end = utils.last_completed_audit_period(unit='month@2')
        self.assertEqual(begin, datetime.datetime(day=2,
                                                  month=2,
                                                  year=2012))
        self.assertEqual(end, datetime.datetime(day=2,
                                                month=3,
                                                year=2012))

    def test_month_with_offset_after_current(self):
        begin, end = utils.last_completed_audit_period(unit='month@15')
        self.assertEqual(begin, datetime.datetime(day=15,
                                                  month=1,
                                                  year=2012))
        self.assertEqual(end, datetime.datetime(day=15,
                                                month=2,
                                                year=2012))

    def test_year(self):
        begin, end = utils.last_completed_audit_period(unit='year')
        self.assertEqual(begin, datetime.datetime(day=1,
                                                  month=1,
                                                  year=2011))
        self.assertEqual(end, datetime.datetime(day=1,
                                                month=1,
                                                year=2012))

    def test_year_with_offset_before_current(self):
        begin, end = utils.last_completed_audit_period(unit='year@2')
        self.assertEqual(begin, datetime.datetime(day=1,
                                                  month=2,
                                                  year=2011))
        self.assertEqual(end, datetime.datetime(day=1,
                                                month=2,
                                                year=2012))

    def test_year_with_offset_after_current(self):
        begin, end = utils.last_completed_audit_period(unit='year@6')
        self.assertEqual(begin, datetime.datetime(day=1,
                                                  month=6,
                                                  year=2010))
        self.assertEqual(end, datetime.datetime(day=1,
                                                month=6,
                                                year=2011))


class FakeSSHClient(object):

    def __init__(self):
        self.id = uuid.uuid4()
        self.transport = FakeTransport()

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, ip, port=22, username=None, password=None,
                pkey=None, timeout=10):
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
