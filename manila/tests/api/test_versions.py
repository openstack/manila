# Copyright 2015 Clinton Knight
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

import ddt
import mock
from oslo_serialization import jsonutils

from manila.api.openstack import api_version_request
from manila.api.openstack import wsgi
from manila.api.v1 import router
from manila.api import versions
from manila import test
from manila.tests.api import fakes


version_header_name = 'X-OpenStack-Manila-API-Version'
experimental_header_name = 'X-OpenStack-Manila-API-Experimental'


@ddt.ddt
class VersionsControllerTestCase(test.TestCase):

    def setUp(self):
        super(VersionsControllerTestCase, self).setUp()
        self.wsgi_apps = (versions.VersionsRouter(), router.APIRouter())

    @ddt.data(('', 302), ('/', 200))
    @ddt.unpack
    def test_versions_return_codes(self, request_path, return_code):
        req = fakes.HTTPRequest.blank(request_path)
        req.method = 'GET'
        req.content_type = 'application/json'

        for app in self.wsgi_apps:
            response = req.get_response(app)
            self.assertEqual(return_code, response.status_int)

    @ddt.data(
        ('http://localhost/', True),
        (None, True),
        ('http://localhost/', False),
        (None, False),
    )
    @ddt.unpack
    def test_versions_index_v10(self, base_url, include_header):
        req = fakes.HTTPRequest.blank('/', base_url=base_url)
        req.method = 'GET'
        req.content_type = 'application/json'
        if include_header:
            req.headers = {version_header_name: '1.0'}

        for app in self.wsgi_apps:
            response = req.get_response(app)
            body = jsonutils.loads(response.body)
            version_list = body['versions']

            ids = [v['id'] for v in version_list]
            self.assertEqual({'v1.0'}, set(ids))
            self.assertEqual('1.0', response.headers[version_header_name])
            self.assertEqual(version_header_name, response.headers['Vary'])
            self.assertIsNone(version_list[0].get('min_version'))
            self.assertIsNone(version_list[0].get('version'))

    @ddt.data(
        ('http://localhost/', '1.1'),
        (None, '1.1'),
        ('http://localhost/', 'latest'),
        (None, 'latest')
    )
    @ddt.unpack
    def test_versions_index_v11(self, base_url, req_version):
        req = fakes.HTTPRequest.blank('/', base_url=base_url)
        req.method = 'GET'
        req.content_type = 'application/json'
        req.headers = {version_header_name: req_version}

        for app in self.wsgi_apps:
            response = req.get_response(app)
            body = jsonutils.loads(response.body)
            version_list = body['versions']

            ids = [v['id'] for v in version_list]
            self.assertEqual({'v1.0'}, set(ids))

            if req_version == 'latest':
                self.assertEqual(api_version_request._MAX_API_VERSION,
                                 response.headers[version_header_name])
            else:
                self.assertEqual(req_version,
                                 response.headers[version_header_name])

            self.assertEqual(version_header_name, response.headers['Vary'])
            self.assertEqual(api_version_request._MIN_API_VERSION,
                             version_list[0].get('min_version'))
            self.assertEqual(api_version_request._MAX_API_VERSION,
                             version_list[0].get('version'))

    @ddt.data('http://localhost/', None)
    def test_versions_index_v2(self, base_url):
        req = fakes.HTTPRequest.blank('/', base_url=base_url)
        req.method = 'GET'
        req.content_type = 'application/json'
        req.headers = {version_header_name: '2.0'}

        for app in self.wsgi_apps:
            response = req.get_response(app)

            self.assertEqual(406, response.status_int)
            self.assertEqual('2.0', response.headers[version_header_name])
            self.assertEqual(version_header_name, response.headers['Vary'])

    @ddt.data('http://localhost/', None)
    def test_versions_index_invalid_version_request(self, base_url):
        req = fakes.HTTPRequest.blank('/', base_url=base_url)
        req.method = 'GET'
        req.content_type = 'application/json'
        req.headers = {version_header_name: '2.0.1'}

        for app in self.wsgi_apps:
            response = req.get_response(app)

            self.assertEqual(400, response.status_int)
            self.assertEqual('1.0', response.headers[version_header_name])
            self.assertEqual(version_header_name, response.headers['Vary'])

    def test_versions_version_not_found(self):
        api_version_request_3_0 = api_version_request.APIVersionRequest('3.0')
        self.mock_object(api_version_request,
                         'max_api_version',
                         mock.Mock(return_value=api_version_request_3_0))

        class Controller(wsgi.Controller):
            @wsgi.Controller.api_version('1.0', '1.0')
            def index(self, req):
                return 'off'

        req = fakes.HTTPRequest.blank('/tests')
        req.headers = {version_header_name: '2.0'}
        app = fakes.TestRouter(Controller())
        response = req.get_response(app)

        self.assertEqual(404, response.status_int)


@ddt.ddt
class ExperimentalAPITestCase(test.TestCase):

    class Controller(wsgi.Controller):
        @wsgi.Controller.api_version('1.0', '1.0')
        def index(self, req):
            return {'fake_key': 'fake_value'}

        @wsgi.Controller.api_version('1.1', '1.1', experimental=True)  # noqa
        def index(self, req):  # pylint: disable=E0102
            return {'fake_key': 'fake_value'}

    def setUp(self):
        super(ExperimentalAPITestCase, self).setUp()
        self.app = fakes.TestRouter(ExperimentalAPITestCase.Controller())

    @ddt.data(True, False)
    def test_stable_api_always_called(self, experimental):

        req = fakes.HTTPRequest.blank('/tests')
        req.headers = {version_header_name: '1.0'}
        if experimental:
            req.headers[experimental_header_name] = experimental
        response = req.get_response(self.app)

        self.assertEqual(200, response.status_int)
        self.assertEqual('1.0', response.headers[version_header_name])

        if experimental:
            self.assertEqual(experimental,
                             response.headers.get(experimental_header_name))
        else:
            self.assertFalse(experimental_header_name in response.headers)

    def test_experimental_api_called_when_requested(self):

        req = fakes.HTTPRequest.blank('/tests')
        req.headers = {
            version_header_name: '1.1',
            experimental_header_name: 'True',
        }
        response = req.get_response(self.app)

        self.assertEqual(200, response.status_int)
        self.assertEqual('1.1', response.headers[version_header_name])
        self.assertTrue(response.headers.get(experimental_header_name))

    def test_experimental_api_not_called_when_not_requested(self):

        req = fakes.HTTPRequest.blank('/tests')
        req.headers = {version_header_name: '1.1'}
        response = req.get_response(self.app)

        self.assertEqual(404, response.status_int)
        self.assertFalse(experimental_header_name in response.headers)

    def test_experimental_header_returned_in_exception(self):

        api_version_request_3_0 = api_version_request.APIVersionRequest('3.0')
        self.mock_object(api_version_request,
                         'max_api_version',
                         mock.Mock(return_value=api_version_request_3_0))

        req = fakes.HTTPRequest.blank('/tests')
        req.headers = {
            version_header_name: '1.2',
            experimental_header_name: 'True',
        }
        response = req.get_response(self.app)

        self.assertEqual(404, response.status_int)
        self.assertTrue(response.headers.get(experimental_header_name))