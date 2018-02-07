# Copyright 2010 OpenStack LLC.
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

from oslo_serialization import jsonutils
import six
import webob
import webob.dec
import webob.exc

from manila.api.middleware import fault
from manila.api.openstack import wsgi
from manila import exception
from manila import test


class TestFaults(test.TestCase):
    """Tests covering `manila.api.openstack.faults:Fault` class."""

    def _prepare_xml(self, xml_string):
        """Remove characters from string which hinder XML equality testing."""
        xml_string = xml_string.replace("  ", "")
        xml_string = xml_string.replace("\n", "")
        xml_string = xml_string.replace("\t", "")
        return xml_string

    def test_400_fault_json(self):
        """Test fault serialized to JSON via file-extension and/or header."""
        requests = [
            webob.Request.blank('/.json'),
            webob.Request.blank('/', headers={"Accept": "application/json"}),
        ]

        for request in requests:
            fault = wsgi.Fault(webob.exc.HTTPBadRequest(explanation='scram'))
            response = request.get_response(fault)

            expected = {
                "badRequest": {
                    "message": "scram",
                    "code": 400,
                },
            }
            actual = jsonutils.loads(response.body)

            self.assertEqual("application/json", response.content_type)
            self.assertEqual(expected, actual)

    def test_413_fault_json(self):
        """Test fault serialized to JSON via file-extension and/or header."""
        requests = [
            webob.Request.blank('/.json'),
            webob.Request.blank('/', headers={"Accept": "application/json"}),
        ]

        for request in requests:
            exc = webob.exc.HTTPRequestEntityTooLarge
            fault = wsgi.Fault(exc(explanation='sorry',
                                   headers={'Retry-After': 4}))
            response = request.get_response(fault)

            expected = {
                "overLimit": {
                    "message": "sorry",
                    "code": 413,
                    "retryAfter": '4',
                },
            }
            actual = jsonutils.loads(response.body)

            self.assertEqual("application/json", response.content_type)
            self.assertEqual(expected, actual)

    def test_raise(self):
        """Ensure the ability to raise :class:`Fault` in WSGI-ified methods."""
        @webob.dec.wsgify
        def raiser(req):
            raise wsgi.Fault(webob.exc.HTTPNotFound(explanation='whut?'))

        req = webob.Request.blank('/.json')
        resp = req.get_response(raiser)
        self.assertEqual("application/json", resp.content_type)
        self.assertEqual(404, resp.status_int)
        self.assertIn(six.b('whut?'), resp.body)

    def test_raise_403(self):
        """Ensure the ability to raise :class:`Fault` in WSGI-ified methods."""
        @webob.dec.wsgify
        def raiser(req):
            raise wsgi.Fault(webob.exc.HTTPForbidden(explanation='whut?'))

        req = webob.Request.blank('/.json')
        resp = req.get_response(raiser)
        self.assertEqual("application/json", resp.content_type)
        self.assertEqual(403, resp.status_int)
        self.assertNotIn(six.b('resizeNotAllowed'), resp.body)
        self.assertIn(six.b('forbidden'), resp.body)

    def test_fault_has_status_int(self):
        """Ensure the status_int is set correctly on faults."""
        fault = wsgi.Fault(webob.exc.HTTPBadRequest(explanation='what?'))
        self.assertEqual(400, fault.status_int)


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
            for (key, value) in exception_type.headers.items():
                self.assertIn(key, resp.headers)
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

    def test_validate_request_unicode_decode_fault(self):
        @webob.dec.wsgify
        def unicode_error(req):
            raise UnicodeDecodeError("ascii", "test".encode(), 0, 1, "bad")

        api = self._wsgi_app(unicode_error)
        resp = webob.Request.blank('/test?foo=%88').get_response(api)
        self.assertEqual(400, resp.status_int)
