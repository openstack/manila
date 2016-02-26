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
from oslo_utils import encodeutils

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

    @ddt.data('1.0', '1.1', '2.0', '3.0')
    def test_versions_root(self, version):
        req = fakes.HTTPRequest.blank('/', base_url='http://localhost')
        req.method = 'GET'
        req.content_type = 'application/json'
        req.headers = {version_header_name: version}

        response = req.get_response(versions.VersionsRouter())
        self.assertEqual(300, response.status_int)
        body = jsonutils.loads(response.body)
        version_list = body['versions']

        ids = [v['id'] for v in version_list]
        self.assertEqual({'v1.0', 'v2.0'}, set(ids))
        self.assertNotIn(version_header_name, response.headers)
        self.assertNotIn('Vary', response.headers)

        v1 = [v for v in version_list if v['id'] == 'v1.0'][0]
        self.assertEqual('', v1.get('min_version'))
        self.assertEqual('', v1.get('version'))
        self.assertEqual('DEPRECATED', v1.get('status'))

        v2 = [v for v in version_list if v['id'] == 'v2.0'][0]
        self.assertEqual(api_version_request._MIN_API_VERSION,
                         v2.get('min_version'))
        self.assertEqual(api_version_request._MAX_API_VERSION,
                         v2.get('version'))
        self.assertEqual('CURRENT', v2.get('status'))

    @ddt.data('1.0',
              '1.1',
              api_version_request._MIN_API_VERSION,
              api_version_request._MAX_API_VERSION)
    def test_versions_v1(self, version):
        req = fakes.HTTPRequest.blank('/', base_url='http://localhost/v1')
        req.method = 'GET'
        req.content_type = 'application/json'
        req.headers = {version_header_name: version}

        response = req.get_response(router.APIRouter())
        self.assertEqual(200, response.status_int)
        body = jsonutils.loads(response.body)
        version_list = body['versions']

        ids = [v['id'] for v in version_list]
        self.assertEqual({'v1.0'}, set(ids))
        self.assertEqual('1.0', response.headers[version_header_name])
        self.assertEqual(version_header_name, response.headers['Vary'])
        self.assertEqual('', version_list[0].get('min_version'))
        self.assertEqual('', version_list[0].get('version'))
        self.assertEqual('DEPRECATED', version_list[0].get('status'))

    @ddt.data(api_version_request._MIN_API_VERSION,
              api_version_request._MAX_API_VERSION)
    def test_versions_v2(self, version):
        req = fakes.HTTPRequest.blank('/', base_url='http://localhost/v2')
        req.method = 'GET'
        req.content_type = 'application/json'
        req.headers = {version_header_name: version}

        response = req.get_response(router.APIRouter())
        self.assertEqual(200, response.status_int)
        body = jsonutils.loads(response.body)
        version_list = body['versions']

        ids = [v['id'] for v in version_list]
        self.assertEqual({'v2.0'}, set(ids))
        self.assertEqual(version, response.headers[version_header_name])
        self.assertEqual(version_header_name, response.headers['Vary'])

        v2 = [v for v in version_list if v['id'] == 'v2.0'][0]
        self.assertEqual(api_version_request._MIN_API_VERSION,
                         v2.get('min_version'))
        self.assertEqual(api_version_request._MAX_API_VERSION,
                         v2.get('version'))

    def test_versions_version_invalid(self):
        req = fakes.HTTPRequest.blank('/', base_url='http://localhost/v2')
        req.method = 'GET'
        req.content_type = 'application/json'
        req.headers = {version_header_name: '2.0.1'}

        for app in self.wsgi_apps:
            response = req.get_response(app)

            self.assertEqual(400, response.status_int)

    def test_versions_version_not_found(self):
        api_version_request_3_0 = api_version_request.APIVersionRequest('3.0')
        self.mock_object(api_version_request,
                         'max_api_version',
                         mock.Mock(return_value=api_version_request_3_0))

        class Controller(wsgi.Controller):
            @wsgi.Controller.api_version('2.0', '2.0')
            def index(self, req):
                return 'off'

        req = fakes.HTTPRequest.blank('/tests', base_url='http://localhost/v2')
        req.headers = {version_header_name: '2.5'}
        app = fakes.TestRouter(Controller())

        response = req.get_response(app)

        self.assertEqual(404, response.status_int)

    def test_versions_version_not_acceptable(self):
        req = fakes.HTTPRequest.blank('/', base_url='http://localhost/v2')
        req.method = 'GET'
        req.content_type = 'application/json'
        req.headers = {version_header_name: '3.0'}

        response = req.get_response(router.APIRouter())

        self.assertEqual(406, response.status_int)
        self.assertEqual('3.0', response.headers[version_header_name])
        self.assertEqual(version_header_name, response.headers['Vary'])

    @ddt.data(['2.5', 200], ['2.55', 404])
    @ddt.unpack
    def test_req_version_matches(self, version, HTTP_ret):
        version_request = api_version_request.APIVersionRequest(version)
        self.mock_object(api_version_request,
                         'max_api_version',
                         mock.Mock(return_value=version_request))

        class Controller(wsgi.Controller):

            @wsgi.Controller.api_version('2.0', '2.6')
            def index(self, req):
                return 'off'

        req = fakes.HTTPRequest.blank('/tests', base_url='http://localhost/v2')
        req.headers = {version_header_name: version}
        app = fakes.TestRouter(Controller())

        response = req.get_response(app)

        if HTTP_ret == 200:
            self.assertEqual(b'off', response.body)
        elif HTTP_ret == 404:
            self.assertNotEqual(b'off', response.body)
        self.assertEqual(HTTP_ret, response.status_int)

    @ddt.data(['2.5', 'older'], ['2.37', 'newer'])
    @ddt.unpack
    def test_req_version_matches_with_if(self, version, ret_val):
        version_request = api_version_request.APIVersionRequest(version)
        self.mock_object(api_version_request,
                         'max_api_version',
                         mock.Mock(return_value=version_request))

        class Controller(wsgi.Controller):

            def index(self, req):
                req_version = req.api_version_request
                if req_version.matches('2.1', '2.8'):
                    return 'older'
                if req_version.matches('2.9', '2.88'):
                    return 'newer'

        req = fakes.HTTPRequest.blank('/tests', base_url='http://localhost/v2')
        req.headers = {version_header_name: version}
        app = fakes.TestRouter(Controller())

        response = req.get_response(app)

        resp = encodeutils.safe_decode(response.body, incoming='utf-8')
        self.assertEqual(ret_val, resp)
        self.assertEqual(200, response.status_int)

    @ddt.data(['2.5', 'older'], ['2.37', 'newer'])
    @ddt.unpack
    def test_req_version_matches_with_None(self, version, ret_val):
        version_request = api_version_request.APIVersionRequest(version)
        self.mock_object(api_version_request,
                         'max_api_version',
                         mock.Mock(return_value=version_request))

        class Controller(wsgi.Controller):

            def index(self, req):
                req_version = req.api_version_request
                if req_version.matches(None, '2.8'):
                    return 'older'
                if req_version.matches('2.9', None):
                    return 'newer'

        req = fakes.HTTPRequest.blank('/tests', base_url='http://localhost/v2')
        req.headers = {version_header_name: version}
        app = fakes.TestRouter(Controller())

        response = req.get_response(app)

        resp = encodeutils.safe_decode(response.body, incoming='utf-8')
        self.assertEqual(ret_val, resp)
        self.assertEqual(200, response.status_int)

    def test_req_version_matches_with_None_None(self):
        version_request = api_version_request.APIVersionRequest('2.39')
        self.mock_object(api_version_request,
                         'max_api_version',
                         mock.Mock(return_value=version_request))

        class Controller(wsgi.Controller):

            def index(self, req):
                req_version = req.api_version_request
                # This case is artificial, and will return True
                if req_version.matches(None, None):
                    return "Pass"

        req = fakes.HTTPRequest.blank('/tests', base_url='http://localhost/v2')
        req.headers = {version_header_name: '2.39'}
        app = fakes.TestRouter(Controller())

        response = req.get_response(app)

        resp = encodeutils.safe_decode(response.body, incoming='utf-8')
        self.assertEqual("Pass", resp)
        self.assertEqual(200, response.status_int)


@ddt.ddt
class ExperimentalAPITestCase(test.TestCase):

    class Controller(wsgi.Controller):
        @wsgi.Controller.api_version('2.0', '2.0')
        def index(self, req):
            return {'fake_key': 'fake_value'}

        @wsgi.Controller.api_version('2.1', '2.1', experimental=True)  # noqa
        def index(self, req):  # pylint: disable=E0102
            return {'fake_key': 'fake_value'}

    def setUp(self):
        super(ExperimentalAPITestCase, self).setUp()
        self.app = fakes.TestRouter(ExperimentalAPITestCase.Controller())
        self.req = fakes.HTTPRequest.blank('/tests',
                                           base_url='http://localhost/v2')

    @ddt.data(True, False)
    def test_stable_api_always_called(self, experimental):

        self.req.headers = {version_header_name: '2.0'}
        if experimental:
            self.req.headers[experimental_header_name] = experimental
        response = self.req.get_response(self.app)

        self.assertEqual(200, response.status_int)
        self.assertEqual('2.0', response.headers[version_header_name])

        if experimental:
            self.assertEqual('%s' % experimental,
                             response.headers.get(experimental_header_name))
        else:
            self.assertNotIn(experimental_header_name, response.headers)

    def test_experimental_api_called_when_requested(self):

        self.req.headers = {
            version_header_name: '2.1',
            experimental_header_name: 'True',
        }
        response = self.req.get_response(self.app)

        self.assertEqual(200, response.status_int)
        self.assertEqual('2.1', response.headers[version_header_name])
        self.assertTrue(response.headers.get(experimental_header_name))

    def test_experimental_api_not_called_when_not_requested(self):

        self.req.headers = {version_header_name: '2.1'}
        response = self.req.get_response(self.app)

        self.assertEqual(404, response.status_int)
        self.assertNotIn(experimental_header_name, response.headers)

    def test_experimental_header_returned_in_exception(self):

        api_version_request_3_0 = api_version_request.APIVersionRequest('3.0')
        self.mock_object(api_version_request,
                         'max_api_version',
                         mock.Mock(return_value=api_version_request_3_0))

        self.req.headers = {
            version_header_name: '2.2',
            experimental_header_name: 'True',
        }
        response = self.req.get_response(self.app)

        self.assertEqual(404, response.status_int)
        self.assertTrue(response.headers.get(experimental_header_name))
