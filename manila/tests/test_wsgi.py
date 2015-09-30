# Copyright 2011 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Unit tests for `manila.wsgi`."""

import os.path
import ssl
import tempfile

import ddt
import eventlet
import mock
from oslo_config import cfg
import six
from six.moves import urllib
import testtools
import webob
import webob.dec

from manila.api.middleware import fault
from manila import exception
from manila import test
from manila import utils
import manila.wsgi

CONF = cfg.CONF

TEST_VAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                               'var'))


class TestLoaderNothingExists(test.TestCase):
    """Loader tests where os.path.exists always returns False."""

    def test_config_not_found(self):
        self.assertRaises(
            manila.exception.ConfigNotFound,
            manila.wsgi.Loader,
            'nonexistent_file.ini',
        )


class TestLoaderNormalFilesystem(test.TestCase):
    """Loader tests with normal filesystem (unmodified os.path module)."""

    _paste_config = """
[app:test_app]
use = egg:Paste#static
document_root = /tmp
    """

    def setUp(self):
        super(TestLoaderNormalFilesystem, self).setUp()
        self.config = tempfile.NamedTemporaryFile(mode="w+t")
        self.config.write(self._paste_config.lstrip())
        self.config.seek(0)
        self.config.flush()
        self.loader = manila.wsgi.Loader(self.config.name)
        self.addCleanup(self.config.close)

    def test_config_found(self):
        self.assertEqual(self.config.name, self.loader.config_path)

    def test_app_not_found(self):
        self.assertRaises(
            manila.exception.PasteAppNotFound,
            self.loader.load_app,
            "non-existent app",
        )

    def test_app_found(self):
        url_parser = self.loader.load_app("test_app")
        self.assertEqual("/tmp", url_parser.directory)


@ddt.ddt
class TestWSGIServer(test.TestCase):
    """WSGI server tests."""

    def test_no_app(self):
        server = manila.wsgi.Server("test_app", None, host="127.0.0.1", port=0)
        self.assertEqual("test_app", server.name)

    def test_start_random_port(self):
        server = manila.wsgi.Server("test_random_port", None, host="127.0.0.1")
        server.start()
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()

    @testtools.skipIf(not utils.is_ipv6_configured(),
                      "Test requires an IPV6 configured interface")
    @testtools.skipIf(utils.is_eventlet_bug105(),
                      'Eventlet bug #105 affect test results.')
    def test_start_random_port_with_ipv6(self):
        server = manila.wsgi.Server("test_random_port",
                                    None,
                                    host="::1")
        server.start()
        self.assertEqual("::1", server.host)
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()

    def test_app(self):
        self.mock_object(
            eventlet, 'spawn', mock.Mock(side_effect=eventlet.spawn))
        greetings = 'Hello, World!!!'

        def hello_world(env, start_response):
            if env['PATH_INFO'] != '/':
                start_response('404 Not Found',
                               [('Content-Type', 'text/plain')])
                return ['Not Found\r\n']
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [greetings]

        server = manila.wsgi.Server(
            "test_app", hello_world, host="127.0.0.1", port=0)
        server.start()

        response = urllib.request.urlopen('http://127.0.0.1:%d/' % server.port)
        self.assertEqual(six.b(greetings), response.read())

        # Verify provided parameters to eventlet.spawn func
        eventlet.spawn.assert_called_once_with(
            func=eventlet.wsgi.server,
            sock=mock.ANY,
            site=server.app,
            protocol=server._protocol,
            custom_pool=server._pool,
            log=server._logger,
            socket_timeout=server.client_socket_timeout,
            keepalive=manila.wsgi.CONF.wsgi_keep_alive,
        )

        server.stop()

    @ddt.data(0, 0.1, 1, None)
    def test_init_server_with_socket_timeout(self, client_socket_timeout):
        CONF.set_default("client_socket_timeout", client_socket_timeout)
        server = manila.wsgi.Server(
            "test_app", lambda *args, **kwargs: None, host="127.0.0.1", port=0)
        self.assertEqual(client_socket_timeout, server.client_socket_timeout)

    @testtools.skipIf(six.PY3, "bug/1482633")
    def test_app_using_ssl(self):
        CONF.set_default("ssl_cert_file",
                         os.path.join(TEST_VAR_DIR, 'certificate.crt'))
        CONF.set_default("ssl_key_file",
                         os.path.join(TEST_VAR_DIR, 'privatekey.key'))

        greetings = 'Hello, World!!!'

        @webob.dec.wsgify
        def hello_world(req):
            return greetings

        server = manila.wsgi.Server(
            "test_app", hello_world, host="127.0.0.1", port=0)
        server.start()

        if hasattr(ssl, '_create_unverified_context'):
            response = urllib.request.urlopen(
                'https://127.0.0.1:%d/' % server.port,
                context=ssl._create_unverified_context())
        else:
            response = urllib.request.urlopen(
                'https://127.0.0.1:%d/' % server.port)

        self.assertEqual(greetings, response.read())

        server.stop()

    @testtools.skipIf(not utils.is_ipv6_configured(),
                      "Test requires an IPV6 configured interface")
    @testtools.skipIf(utils.is_eventlet_bug105(),
                      'Eventlet bug #105 affect test results.')
    @testtools.skipIf(six.PY3, "bug/1482633")
    def test_app_using_ipv6_and_ssl(self):
        CONF.set_default("ssl_cert_file",
                         os.path.join(TEST_VAR_DIR, 'certificate.crt'))
        CONF.set_default("ssl_key_file",
                         os.path.join(TEST_VAR_DIR, 'privatekey.key'))

        greetings = 'Hello, World!!!'

        @webob.dec.wsgify
        def hello_world(req):
            return greetings

        server = manila.wsgi.Server("test_app",
                                    hello_world,
                                    host="::1",
                                    port=0)
        server.start()

        if hasattr(ssl, '_create_unverified_context'):
            response = urllib.request.urlopen(
                'https://[::1]:%d/' % server.port,
                context=ssl._create_unverified_context())
        else:
            response = urllib.request.urlopen(
                'https://[::1]:%d/' % server.port)

        self.assertEqual(greetings, response.read())

        server.stop()

    def test_reset_pool_size_to_default(self):
        server = manila.wsgi.Server("test_resize", None, host="127.0.0.1")
        server.start()

        # Stopping the server, which in turn sets pool size to 0
        server.stop()
        self.assertEqual(0, server._pool.size)

        # Resetting pool size to default
        server.reset()
        server.start()
        self.assertEqual(1000, server._pool.size)


class ExceptionTest(test.TestCase):

    def _wsgi_app(self, inner_app):
        return fault.FaultWrapper(inner_app)

    def _do_test_exception_safety_reflected_in_faults(self, expose):
        class ExceptionWithSafety(exception.ManilaException):
            safe = expose

        @webob.dec.wsgify
        def fail(req):
            raise ExceptionWithSafety('some explanation')

        api = self._wsgi_app(fail)
        resp = webob.Request.blank('/').get_response(api)
        self.assertIn('{"computeFault', six.text_type(resp.body), resp.body)
        expected = ('ExceptionWithSafety: some explanation' if expose else
                    'The server has either erred or is incapable '
                    'of performing the requested operation.')
        self.assertIn(expected, six.text_type(resp.body), resp.body)
        self.assertEqual(500, resp.status_int, resp.body)

    def test_safe_exceptions_are_described_in_faults(self):
        self._do_test_exception_safety_reflected_in_faults(True)

    def test_unsafe_exceptions_are_not_described_in_faults(self):
        self._do_test_exception_safety_reflected_in_faults(False)

    def _do_test_exception_mapping(self, exception_type, msg):
        @webob.dec.wsgify
        def fail(req):
            raise exception_type(msg)

        api = self._wsgi_app(fail)
        resp = webob.Request.blank('/').get_response(api)
        self.assertIn(msg, six.text_type(resp.body), resp.body)
        self.assertEqual(exception_type.code, resp.status_int, resp.body)

        if hasattr(exception_type, 'headers'):
            for (key, value) in six.iteritems(exception_type.headers):
                self.assertTrue(key in resp.headers)
                self.assertEqual(value, resp.headers[key])

    def test_quota_error_mapping(self):
        self._do_test_exception_mapping(exception.QuotaError, 'too many used')

    def test_non_manila_notfound_exception_mapping(self):
        class ExceptionWithCode(Exception):
            code = 404

        self._do_test_exception_mapping(ExceptionWithCode,
                                        'NotFound')

    def test_non_manila_exception_mapping(self):
        class ExceptionWithCode(Exception):
            code = 417

        self._do_test_exception_mapping(ExceptionWithCode,
                                        'Expectation failed')

    def test_exception_with_none_code_throws_500(self):
        class ExceptionWithNoneCode(Exception):
            code = None

        @webob.dec.wsgify
        def fail(req):
            raise ExceptionWithNoneCode()

        api = self._wsgi_app(fail)
        resp = webob.Request.blank('/').get_response(api)
        self.assertEqual(500, resp.status_int)
