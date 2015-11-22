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

import uuid

from oslo_utils import timeutils
import routes
import webob
import webob.dec
import webob.request

from manila.api.middleware import auth
from manila.api.middleware import fault
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi as os_wsgi
from manila.api import urlmap
from manila.api.v1 import limits
from manila.api.v1 import router as router_v1
from manila.api.v2 import router as router_v2
from manila.api import versions
from manila.common import constants
from manila import context
from manila import exception
from manila import wsgi


FAKE_UUID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
FAKE_UUIDS = {}


class Context(object):
    pass


class FakeRouter(wsgi.Router):
    def __init__(self, ext_mgr=None):
        pass

    @webob.dec.wsgify
    def __call__(self, req):
        res = webob.Response()
        res.status = '200'
        res.headers['X-Test-Success'] = 'True'
        return res


@webob.dec.wsgify
def fake_wsgi(self, req):
    return self.application


def wsgi_app(inner_app_v2=None, fake_auth=True, fake_auth_context=None,
             use_no_auth=False, ext_mgr=None):
    if not inner_app_v2:
        inner_app_v2 = router_v2.APIRouter(ext_mgr)

    if fake_auth:
        if fake_auth_context is not None:
            ctxt = fake_auth_context
        else:
            ctxt = context.RequestContext('fake', 'fake', auth_token=True)
        api_v2 = fault.FaultWrapper(auth.InjectContext(ctxt,
                                                       inner_app_v2))
    elif use_no_auth:
        api_v2 = fault.FaultWrapper(auth.NoAuthMiddleware(
            limits.RateLimitingMiddleware(inner_app_v2)))
    else:
        api_v2 = fault.FaultWrapper(auth.AuthMiddleware(
            limits.RateLimitingMiddleware(inner_app_v2)))

    mapper = urlmap.URLMap()
    mapper['/v2'] = api_v2
    mapper['/'] = fault.FaultWrapper(versions.Versions())
    return mapper


class FakeToken(object):
    id_count = 0

    def __getitem__(self, key):
        return getattr(self, key)

    def __init__(self, **kwargs):
        FakeToken.id_count += 1
        self.id = FakeToken.id_count
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakeRequestContext(context.RequestContext):
    def __init__(self, *args, **kwargs):
        kwargs['auth_token'] = kwargs.get('auth_token', 'fake_auth_token')
        super(FakeRequestContext, self).__init__(*args, **kwargs)


class HTTPRequest(os_wsgi.Request):

    @classmethod
    def blank(cls, *args, **kwargs):
        if not kwargs.get('base_url'):
            kwargs['base_url'] = 'http://localhost/v1'
        use_admin_context = kwargs.pop('use_admin_context', False)
        version = kwargs.pop('version', api_version.DEFAULT_API_VERSION)
        experimental = kwargs.pop('experimental', False)
        out = os_wsgi.Request.blank(*args, **kwargs)
        out.environ['manila.context'] = FakeRequestContext(
            'fake_user',
            'fake',
            is_admin=use_admin_context)
        out.api_version_request = api_version.APIVersionRequest(
            version, experimental=experimental)
        return out


class TestRouter(wsgi.Router):
    def __init__(self, controller):
        mapper = routes.Mapper()
        mapper.resource("test", "tests",
                        controller=os_wsgi.Resource(controller))
        super(TestRouter, self).__init__(mapper)


class FakeAuthDatabase(object):
    data = {}

    @staticmethod
    def auth_token_get(context, token_hash):
        return FakeAuthDatabase.data.get(token_hash, None)

    @staticmethod
    def auth_token_create(context, token):
        fake_token = FakeToken(created_at=timeutils.utcnow(), **token)
        FakeAuthDatabase.data[fake_token.token_hash] = fake_token
        FakeAuthDatabase.data['id_%i' % fake_token.id] = fake_token
        return fake_token

    @staticmethod
    def auth_token_destroy(context, token_id):
        token = FakeAuthDatabase.data.get('id_%i' % token_id)
        if token and token.token_hash in FakeAuthDatabase.data:
            del FakeAuthDatabase.data[token.token_hash]
            del FakeAuthDatabase.data['id_%i' % token_id]


class FakeRateLimiter(object):
    def __init__(self, application):
        self.application = application

    @webob.dec.wsgify
    def __call__(self, req):
        return self.application


def get_fake_uuid(token=0):
    if token not in FAKE_UUIDS:
        FAKE_UUIDS[token] = str(uuid.uuid4())
    return FAKE_UUIDS[token]


def app():
    """API application.

    No auth, just let environ['manila.context'] pass through.
    """
    mapper = urlmap.URLMap()
    mapper['/v1'] = router_v1.APIRouter()
    mapper['/v2'] = router_v2.APIRouter()
    return mapper

fixture_reset_status_with_different_roles_v1 = (
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.STATUS_ERROR,
    },
    {
        'role': 'member',
        'valid_code': 403,
        'valid_status': constants.STATUS_AVAILABLE,
    },
)

fixture_reset_status_with_different_roles = (
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.STATUS_ERROR,
        'version': '2.6',
    },
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.STATUS_ERROR,
        'version': '2.7',
    },
    {
        'role': 'member',
        'valid_code': 403,
        'valid_status': constants.STATUS_AVAILABLE,
        'version': '2.6',
    },
    {
        'role': 'member',
        'valid_code': 403,
        'valid_status': constants.STATUS_AVAILABLE,
        'version': '2.7',
    },
)


fixture_reset_replica_status_with_different_roles = (
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.STATUS_ERROR,
    },
    {
        'role': 'member',
        'valid_code': 403,
        'valid_status': constants.STATUS_AVAILABLE,
    },
)


fixture_reset_replica_state_with_different_roles = (
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.REPLICA_STATE_ACTIVE,
    },
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.REPLICA_STATE_OUT_OF_SYNC,
    },
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.REPLICA_STATE_IN_SYNC,
    },
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.STATUS_ERROR,
    },
    {
        'role': 'member',
        'valid_code': 403,
        'valid_status': constants.REPLICA_STATE_IN_SYNC,
    },
)


fixture_force_delete_with_different_roles = (
    {'role': 'admin', 'resp_code': 202, 'version': '2.6'},
    {'role': 'admin', 'resp_code': 202, 'version': '2.7'},
    {'role': 'member', 'resp_code': 403, 'version': '2.6'},
    {'role': 'member', 'resp_code': 403, 'version': '2.7'},
)


fixture_invalid_reset_status_body = (
    {'os-reset_status': {'x-status': 'bad'}},
    {'os-reset_status': {'status': 'invalid'}}
)


def mock_fake_admin_check(context, resource_name, action, *args, **kwargs):
    if context.is_admin:
        return
    else:
        raise exception.PolicyNotAuthorized(action=action)
