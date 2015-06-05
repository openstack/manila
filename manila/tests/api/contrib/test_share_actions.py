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

import ddt
import mock
from oslo_config import cfg
import webob

from manila.api.contrib import share_actions
from manila import exception
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


@ddt.ddt
class ShareActionsTest(test.TestCase):
    def setUp(self):
        super(ShareActionsTest, self).setUp()
        self.controller = share_actions.ShareActionsController()

        self.mock_object(share_api.API, 'get', stubs.stub_share_get)

    @ddt.data(
        {'access_type': 'ip', 'access_to': '127.0.0.1'},
        {'access_type': 'user', 'access_to': '1' * 4},
        {'access_type': 'user', 'access_to': '1' * 32},
        {'access_type': 'user', 'access_to': 'fake\\]{.-_\'`;}['},
        {'access_type': 'user', 'access_to': 'MYDOMAIN\\Administrator'},
        {'access_type': 'cert', 'access_to': 'x'},
        {'access_type': 'cert', 'access_to': 'tenant.example.com'},
        {'access_type': 'cert', 'access_to': 'x' * 64},
    )
    def test_allow_access(self, access):
        self.mock_object(share_api.API,
                         'allow_access',
                         mock.Mock(return_value={'fake': 'fake'}))

        id = 'fake_share_id'
        body = {'os-allow_access': access}
        expected = {'access': {'fake': 'fake'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res = self.controller._allow_access(req, id, body)
        self.assertEqual(res, expected)

    @ddt.data(
        {'access_type': 'error_type', 'access_to': '127.0.0.1'},
        {'access_type': 'ip', 'access_to': 'localhost'},
        {'access_type': 'ip', 'access_to': '127.0.0.*'},
        {'access_type': 'ip', 'access_to': '127.0.0.0/33'},
        {'access_type': 'ip', 'access_to': '127.0.0.256'},
        {'access_type': 'user', 'access_to': '1'},
        {'access_type': 'user', 'access_to': '1' * 3},
        {'access_type': 'user', 'access_to': '1' * 33},
        {'access_type': 'user', 'access_to': 'root^'},
        {'access_type': 'cert', 'access_to': ''},
        {'access_type': 'cert', 'access_to': ' '},
        {'access_type': 'cert', 'access_to': 'x' * 65},
    )
    def test_allow_access_error(self, access):
        id = 'fake_share_id'
        body = {'os-allow_access': access}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

    def test_deny_access(self):
        def _stub_deny_access(*args, **kwargs):
            pass

        self.mock_object(share_api.API, "deny_access", _stub_deny_access)
        self.mock_object(share_api.API, "access_get", _fake_access_get)

        id = 'fake_share_id'
        body = {"os-deny_access": {"access_id": 'fake_acces_id'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res = self.controller._deny_access(req, id, body)
        self.assertEqual(res.status_int, 202)

    def test_deny_access_not_found(self):
        def _stub_deny_access(*args, **kwargs):
            pass

        self.mock_object(share_api.API, "deny_access", _stub_deny_access)
        self.mock_object(share_api.API, "access_get", _fake_access_get)

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

        self.mock_object(share_api.API, "access_get_all",
                         _fake_access_get_all)
        id = 'fake_share_id'
        body = {"os-access_list": None}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res_dict = self.controller._access_list(req, id, body)
        expected = _fake_access_get_all()
        self.assertEqual(res_dict['access_list'], expected)

    def test_extend(self):
        id = 'fake_share_id'
        share = stubs.stub_share_get(None, None, id)
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        self.mock_object(share_api.API, "extend")

        size = '123'
        body = {"os-extend": {'new_size': size}}
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)

        actual_response = self.controller._extend(req, id, body)

        share_api.API.get.assert_called_once_with(mock.ANY, id)
        share_api.API.extend.assert_called_once_with(
            mock.ANY, share, int(size))
        self.assertEqual(202, actual_response.status_int)

    @ddt.data({"os-extend": ""},
              {"os-extend": {"new_size": "foo"}},
              {"os-extend": {"new_size": {'foo': 'bar'}}})
    def test_extend_invalid_body(self, body):
        id = 'fake_share_id'
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._extend, req, id, body)

    @ddt.data({'source': exception.InvalidInput,
               'target': webob.exc.HTTPBadRequest},
              {'source': exception.InvalidShare,
               'target': webob.exc.HTTPBadRequest},
              {'source': exception.ShareSizeExceedsAvailableQuota,
               'target': webob.exc.HTTPForbidden})
    @ddt.unpack
    def test_extend_exception(self, source, target):
        id = 'fake_share_id'
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)
        body = {"os-extend": {'new_size': '123'}}
        self.mock_object(share_api.API, "extend",
                         mock.Mock(side_effect=source('fake')))

        self.assertRaises(target, self.controller._extend, req, id, body)

    def test_shrink(self):
        id = 'fake_share_id'
        share = stubs.stub_share_get(None, None, id)
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        self.mock_object(share_api.API, "shrink")

        size = '123'
        body = {"os-shrink": {'new_size': size}}
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)

        actual_response = self.controller._shrink(req, id, body)

        share_api.API.get.assert_called_once_with(mock.ANY, id)
        share_api.API.shrink.assert_called_once_with(
            mock.ANY, share, int(size))
        self.assertEqual(202, actual_response.status_int)

    @ddt.data({"os-shrink": ""},
              {"os-shrink": {"new_size": "foo"}},
              {"os-shrink": {"new_size": {'foo': 'bar'}}})
    def test_shrink_invalid_body(self, body):
        id = 'fake_share_id'
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._shrink, req, id, body)

    @ddt.data({'source': exception.InvalidInput,
               'target': webob.exc.HTTPBadRequest},
              {'source': exception.InvalidShare,
               'target': webob.exc.HTTPBadRequest})
    @ddt.unpack
    def test_shrink_exception(self, source, target):
        id = 'fake_share_id'
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)
        body = {"os-shrink": {'new_size': '123'}}
        self.mock_object(share_api.API, "shrink",
                         mock.Mock(side_effect=source('fake')))

        self.assertRaises(target, self.controller._shrink, req, id, body)