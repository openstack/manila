# Copyright 2011 Denali Systems, Inc.
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


from manila.api.openstack import wsgi
from manila.api.v1 import router
from manila.api import versions
from manila import flags
from manila.openstack.common import log as logging
from manila import test
from manila.tests.api import fakes

FLAGS = flags.FLAGS

LOG = logging.getLogger(__name__)


class FakeController(object):
    def __init__(self, ext_mgr=None):
        self.ext_mgr = ext_mgr

    def index(self, req):
        return {}

    def detail(self, req):
        return {}


def create_resource(ext_mgr):
    return wsgi.Resource(FakeController(ext_mgr))


class VolumeRouterTestCase(test.TestCase):
    def setUp(self):
        super(VolumeRouterTestCase, self).setUp()
        # NOTE(vish): versions is just returning text so, no need to stub.
        self.app = router.APIRouter()

    def test_versions(self):
        req = fakes.HTTPRequest.blank('')
        req.method = 'GET'
        req.content_type = 'application/json'
        response = req.get_response(self.app)
        self.assertEqual(302, response.status_int)
        req = fakes.HTTPRequest.blank('/')
        req.method = 'GET'
        req.content_type = 'application/json'
        response = req.get_response(self.app)
        self.assertEqual(200, response.status_int)

    def test_versions_multi(self):
        req = fakes.HTTPRequest.blank('/')
        req.method = 'GET'
        req.content_type = 'application/json'
        resource = versions.Versions()
        result = resource.dispatch(resource.multi, req, {})
        ids = [v['id'] for v in result['choices']]
        self.assertEqual(set(ids), set(['v1.0', 'v2.0']))

    def test_versions_multi_disable_v1(self):
        self.flags(enable_v1_api=False)
        req = fakes.HTTPRequest.blank('/')
        req.method = 'GET'
        req.content_type = 'application/json'
        resource = versions.Versions()
        result = resource.dispatch(resource.multi, req, {})
        ids = [v['id'] for v in result['choices']]
        self.assertEqual(set(ids), set(['v2.0']))

    def test_versions_multi_disable_v2(self):
        self.flags(enable_v2_api=False)
        req = fakes.HTTPRequest.blank('/')
        req.method = 'GET'
        req.content_type = 'application/json'
        resource = versions.Versions()
        result = resource.dispatch(resource.multi, req, {})
        ids = [v['id'] for v in result['choices']]
        self.assertEqual(set(ids), set(['v1.0']))

    def test_versions_index(self):
        req = fakes.HTTPRequest.blank('/')
        req.method = 'GET'
        req.content_type = 'application/json'
        resource = versions.Versions()
        result = resource.dispatch(resource.index, req, {})
        ids = [v['id'] for v in result['versions']]
        self.assertEqual(set(ids), set(['v1.0', 'v2.0']))

    def test_versions_index_disable_v1(self):
        self.flags(enable_v1_api=False)
        req = fakes.HTTPRequest.blank('/')
        req.method = 'GET'
        req.content_type = 'application/json'
        resource = versions.Versions()
        result = resource.dispatch(resource.index, req, {})
        ids = [v['id'] for v in result['versions']]
        self.assertEqual(set(ids), set(['v2.0']))

    def test_versions_index_disable_v2(self):
        self.flags(enable_v2_api=False)
        req = fakes.HTTPRequest.blank('/')
        req.method = 'GET'
        req.content_type = 'application/json'
        resource = versions.Versions()
        result = resource.dispatch(resource.index, req, {})
        ids = [v['id'] for v in result['versions']]
        self.assertEqual(set(ids), set(['v1.0']))

