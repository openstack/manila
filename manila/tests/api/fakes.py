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

from oslo_service import wsgi
from oslo_utils import timeutils
from oslo_utils import uuidutils
import routes
import webob
import webob.dec
import webob.request

from manila.api import common as api_common
from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi as os_wsgi
from manila.api import urlmap
from manila.api.v1 import router as router_v1
from manila.api.v2 import router as router_v2
from manila.common import constants
from manila import context
from manila import exception


CONTEXT = context.get_admin_context()
driver_opts = {}
FAKE_UUID = '123e4567-e89b-12d3-a456-426614174000'
FAKE_UUIDS = {}
host = 'host_name'
identifier = '7cf7c200-d3af-4e05-b87e-9167c95dfcad'


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


class FakeToken(object):
    id_count = 0

    def __getitem__(self, key):
        return getattr(self, key)

    def __init__(self, **kwargs):
        FakeToken.id_count += 1
        self.id = FakeToken.id_count
        self.token_hash = None
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
            method_url = args[0]
            if method_url.startswith('/v2'):
                kwargs['base_url'] = 'http://localhost/share/v2'
            else:
                kwargs['base_url'] = 'http://localhost/share/v1'
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
        FAKE_UUIDS[token] = uuidutils.generate_uuid()
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
        'microversion': '2.55'
    },
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.STATUS_ERROR,
        'microversion': '2.56'
    },
    {
        'role': 'member',
        'valid_code': 403,
        'valid_status': constants.STATUS_AVAILABLE,
        'microversion': '2.55'
    },
)


fixture_reset_replica_state_with_different_roles = (
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.REPLICA_STATE_ACTIVE,
        'microversion': '2.55'
    },
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.REPLICA_STATE_OUT_OF_SYNC,
        'microversion': '2.56'
    },
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.REPLICA_STATE_IN_SYNC,
        'microversion': '2.55'
    },
    {
        'role': 'admin',
        'valid_code': 202,
        'valid_status': constants.STATUS_ERROR,
        'microversion': '2.56'
    },
    {
        'role': 'member',
        'valid_code': 403,
        'valid_status': constants.REPLICA_STATE_IN_SYNC,
        'microversion': '2.55'
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


fixture_valid_reset_status_body = (
    ({'os-reset_status': {'status': 'creating'}}, '2.6'),
    ({'os-reset_status': {'status': 'available'}}, '2.6'),
    ({'os-reset_status': {'status': 'deleting'}}, '2.6'),
    ({'os-reset_status': {'status': 'error_deleting'}}, '2.6'),
    ({'os-reset_status': {'status': 'error'}}, '2.6'),
    ({'os-reset_status': {'status': 'migrating'}}, '2.6'),
    ({'os-reset_status': {'status': 'migrating_to'}}, '2.6'),
    ({'reset_status': {'status': 'creating'}}, '2.7'),
    ({'reset_status': {'status': 'available'}}, '2.7'),
    ({'reset_status': {'status': 'deleting'}}, '2.7'),
    ({'reset_status': {'status': 'error_deleting'}}, '2.7'),
    ({'reset_status': {'status': 'error'}}, '2.7'),
    ({'reset_status': {'status': 'migrating'}}, '2.7'),
    ({'reset_status': {'status': 'migrating_to'}}, '2.7'),
)


def mock_fake_admin_check(context, resource_name, action, *args, **kwargs):
    if context.is_admin:
        return
    else:
        raise exception.PolicyNotAuthorized(action=action)


class FakeResourceViewBuilder(api_common.ViewBuilder):

    _collection_name = 'fake_resource'
    _detail_version_modifiers = [
        "add_field_xyzzy",
        "add_field_spoon_for_admins",
        "remove_field_foo",
    ]

    def view(self, req, resource):

        keys = ('id', 'foo', 'fred', 'alice')
        resource_dict = {key: resource.get(key) for key in keys}

        self.update_versioned_resource_dict(req, resource_dict, resource)

        return resource_dict

    @api_common.ViewBuilder.versioned_method("1.41")
    def add_field_xyzzy(self, context, resource_dict, resource):
        resource_dict['xyzzy'] = resource.get('xyzzy')

    @api_common.ViewBuilder.versioned_method("1.6")
    def add_field_spoon_for_admins(self, context, resource_dict, resource):
        if context.is_admin:
            resource_dict['spoon'] = resource.get('spoon')

    @api_common.ViewBuilder.versioned_method("3.14")
    def remove_field_foo(self, context, resource_dict, resource):
        resource_dict.pop('foo', None)
