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

from manila.api.openstack import wsgi
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
                    "retryAfter": 4,
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
        self.assertTrue(six.b('whut?') in resp.body)

    def test_raise_403(self):
        """Ensure the ability to raise :class:`Fault` in WSGI-ified methods."""
        @webob.dec.wsgify
        def raiser(req):
            raise wsgi.Fault(webob.exc.HTTPForbidden(explanation='whut?'))

        req = webob.Request.blank('/.json')
        resp = req.get_response(raiser)
        self.assertEqual("application/json", resp.content_type)
        self.assertEqual(403, resp.status_int)
        self.assertTrue(six.b('resizeNotAllowed') not in resp.body)
        self.assertTrue(six.b('forbidden') in resp.body)

    def test_fault_has_status_int(self):
        """Ensure the status_int is set correctly on faults."""
        fault = wsgi.Fault(webob.exc.HTTPBadRequest(explanation='what?'))
        self.assertEqual(400, fault.status_int)
