#   Copyright 2012 OpenStack LLC.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

from oslo_config import cfg
import webob

from manila.api.contrib import share_actions
from manila.share import api as share_api
from manila import test
from manila.tests.api.contrib import stubs
from manila.tests.api import fakes

CONF = cfg.CONF


def _fake_access_get(self, ctxt, access_id):

    class Access(object):
        def __init__(self, **kwargs):
            self.STATE_NEW = 'fake_new'
            self.STATE_ACTIVE = 'fake_active'
            self.STATE_ERROR = 'fake_error'
            self.params = kwargs
            self.params['state'] = self.STATE_NEW
            self.share_id = kwargs.get('share_id')
            self.id = access_id

        def __getitem__(self, item):
            return self.params[item]

    access = Access(access_id=access_id, share_id='fake_share_id')
    return access


class ShareActionsTest(test.TestCase):
    def setUp(self):
        super(ShareActionsTest, self).setUp()
        self.controller = share_actions.ShareActionsController()

        self.stubs.Set(share_api.API, 'get', stubs.stub_share_get)

    def test_allow_access(self):
        def _stub_allow_access(*args, **kwargs):
            return {'fake': 'fake'}
        self.stubs.Set(share_api.API, "allow_access", _stub_allow_access)

        id = 'fake_share_id'
        body = {
            "os-allow_access": {
                "access_type": 'ip',
                "access_to": '127.0.0.1',
            }
        }
        expected = {'access': {'fake': 'fake'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res = self.controller._allow_access(req, id, body)
        self.assertEqual(res, expected)

    def test_allow_access_cert_min_accessto(self):
        def _stub_allow_access(*args, **kwargs):
            return {'fake': 'fake'}
        self.stubs.Set(share_api.API, "allow_access", _stub_allow_access)

        body = {
            "os-allow_access": {
                "access_type": 'cert',
                "access_to": 'x',
            }
        }
        expected = {'access': {'fake': 'fake'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res = self.controller._allow_access(req, id, body)
        self.assertEqual(res, expected)

    def test_allow_access_cert_typical_accessto(self):
        def _stub_allow_access(*args, **kwargs):
            return {'fake': 'fake'}
        self.stubs.Set(share_api.API, "allow_access", _stub_allow_access)

        body = {
            "os-allow_access": {
                "access_type": 'cert',
                "access_to": 'tenant.example.com',
            }
        }
        expected = {'access': {'fake': 'fake'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res = self.controller._allow_access(req, id, body)
        self.assertEqual(res, expected)

    def test_allow_access_cert_max_accessto(self):
        def _stub_allow_access(*args, **kwargs):
            return {'fake': 'fake'}
        self.stubs.Set(share_api.API, "allow_access", _stub_allow_access)

        access_to = 'x' * 64
        body = {
            "os-allow_access": {
                "access_type": 'cert',
                "access_to": access_to,
            }
        }
        expected = {'access': {'fake': 'fake'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res = self.controller._allow_access(req, id, body)
        self.assertEqual(res, expected)

    def test_allow_access_error(self):
        id = 'fake_share_id'

        body = {"os-allow_access": {"access_type": 'error_type',
                                    "access_to": '127.0.0.1'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

        body = {"os-allow_access": {"access_type": 'ip',
                                    "access_to": '127.0.0.*'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

        body = {"os-allow_access": {"access_type": 'ip',
                                    "access_to": '127.0.0.0/33'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

        body = {"os-allow_access": {"access_type": 'ip',
                                    "access_to": '127.0.0.256'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

        body = {"os-allow_access": {"access_type": 'user', "access_to": '1'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

        body = {
            "os-allow_access": {
                "access_type": 'user',
                "access_to": '1' * 33,
            }
        }
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

    def test_allow_access_cert_error_invalid_accessto_gt64(self):
        id = 'fake_share_id'

        access_to = 'x' * 65
        body = {
            "os-allow_access": {
                "access_type": 'cert',
                "access_to": access_to,
            }
        }
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

    def test_allow_access_cert_error_invalid_accessto_zero(self):
        id = 'fake_share_id'

        access_to = ''
        body = {
            "os-allow_access": {
                "access_type": 'cert',
                "access_to": access_to,
            }
        }
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

    def test_allow_access_cert_error_invalid_accessto_whitespace(self):
        id = 'fake_share_id'

        access_to = ' '
        body = {
            "os-allow_access": {
                "access_type": 'cert',
                "access_to": access_to,
            }
        }
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

    def test_deny_access(self):
        def _stub_deny_access(*args, **kwargs):
            pass

        self.stubs.Set(share_api.API, "deny_access", _stub_deny_access)
        self.stubs.Set(share_api.API, "access_get", _fake_access_get)

        id = 'fake_share_id'
        body = {"os-deny_access": {"access_id": 'fake_acces_id'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res = self.controller._deny_access(req, id, body)
        self.assertEqual(res.status_int, 202)

    def test_deny_access_not_found(self):
        def _stub_deny_access(*args, **kwargs):
            pass

        self.stubs.Set(share_api.API, "deny_access", _stub_deny_access)
        self.stubs.Set(share_api.API, "access_get", _fake_access_get)

        id = 'super_fake_share_id'
        body = {"os-deny_access": {"access_id": 'fake_acces_id'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller._deny_access,
                          req,
                          id,
                          body)

    def test_access_list(self):
        def _fake_access_get_all(*args, **kwargs):
            return [{"state": "fakestatus",
                     "id": "fake_share_id",
                     "access_type": "fakeip",
                     "access_to": "127.0.0.1"}]

        self.stubs.Set(share_api.API, "access_get_all", _fake_access_get_all)
        id = 'fake_share_id'
        body = {"os-access_list": None}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res_dict = self.controller._access_list(req, id, body)
        expected = _fake_access_get_all()
        self.assertEqual(res_dict['access_list'], expected)
