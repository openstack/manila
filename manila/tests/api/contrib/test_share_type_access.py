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

import datetime

import mock
import webob

from manila.api.contrib import share_type_access as type_access
from manila.api.v1 import share_types
from manila import context
from manila import db
from manila import exception
from manila.share import share_types as share_types_api
from manila import test
from manila.tests.api import fakes


def generate_type(type_id, is_public):
    return {
        'id': type_id,
        'name': u'test',
        'deleted': False,
        'created_at': datetime.datetime(2012, 1, 1, 1, 1, 1, 1),
        'updated_at': None,
        'deleted_at': None,
        'is_public': bool(is_public),
        'extra_specs': {}
    }


SHARE_TYPES = {
    '0': generate_type('0', True),
    '1': generate_type('1', True),
    '2': generate_type('2', False),
    '3': generate_type('3', False)}

PROJ1_UUID = '11111111-1111-1111-1111-111111111111'
PROJ2_UUID = '22222222-2222-2222-2222-222222222222'
PROJ3_UUID = '33333333-3333-3333-3333-333333333333'

ACCESS_LIST = [{'share_type_id': '2', 'project_id': PROJ2_UUID},
               {'share_type_id': '2', 'project_id': PROJ3_UUID},
               {'share_type_id': '3', 'project_id': PROJ3_UUID}]


def fake_share_type_get(context, id, inactive=False, expected_fields=None):
    vol = SHARE_TYPES[id]
    if expected_fields and 'projects' in expected_fields:
        vol['projects'] = [a['project_id']
                           for a in ACCESS_LIST if a['share_type_id'] == id]
    return vol


def _has_type_access(type_id, project_id):
    for access in ACCESS_LIST:
        if (access['share_type_id'] == type_id
                and access['project_id'] == project_id):
            return True
    return False


def fake_share_type_get_all(context, inactive=False, filters=None):
    if filters is None or filters.get('is_public', None) is None:
        return SHARE_TYPES
    res = {}
    for k, v in SHARE_TYPES.iteritems():
        if filters['is_public'] and _has_type_access(k, context.project_id):
            res.update({k: v})
            continue
        if v['is_public'] == filters['is_public']:
            res.update({k: v})
    return res


class FakeResponse(object):
    obj = {'share_type': {'id': '0'},
           'share_types': [
               {'id': '0'},
               {'id': '2'}]}

    def attach(self, **kwargs):
        pass


class FakeRequest(object):
    environ = {"manila.context": context.get_admin_context()}

    def get_db_share_type(self, resource_id):
        return SHARE_TYPES[resource_id]


class ShareTypeAccessTest(test.TestCase):

    def setUp(self):
        super(ShareTypeAccessTest, self).setUp()
        self.type_access_controller = type_access.ShareTypeAccessController()
        self.type_action_controller = type_access.ShareTypeActionController()
        self.type_controller = share_types.ShareTypesController()
        self.req = FakeRequest()
        self.context = self.req.environ['manila.context']
        self.mock_object(db, 'share_type_get',
                         fake_share_type_get)
        self.mock_object(db, 'share_type_get_all',
                         fake_share_type_get_all)

    def assertShareTypeListEqual(self, expected, observed):
        self.assertEqual(len(expected), len(observed))
        expected = sorted(expected, key=lambda item: item['id'])
        observed = sorted(observed, key=lambda item: item['id'])
        for d1, d2 in zip(expected, observed):
            self.assertEqual(d1['id'], d2['id'])

    def test_list_type_access_public(self):
        """Querying os-share-type-access on public type should return 404."""
        req = fakes.HTTPRequest.blank('/v1/fake/types/os-share-type-access',
                                      use_admin_context=True)
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.type_access_controller.index,
                          req, '1')

    def test_list_type_access_private(self):
        expected = {'share_type_access': [
            {'share_type_id': '2', 'project_id': PROJ2_UUID},
            {'share_type_id': '2', 'project_id': PROJ3_UUID}]}
        result = self.type_access_controller.index(self.req, '2')
        self.assertEqual(expected, result)

    def test_list_with_no_context(self):
        req = fakes.HTTPRequest.blank('/v1/types/fake/types')

        def fake_authorize(context, target=None, action=None):
            raise exception.PolicyNotAuthorized(action='index')
        self.mock_object(type_access, 'authorize', fake_authorize)

        self.assertRaises(exception.PolicyNotAuthorized,
                          self.type_access_controller.index,
                          req, 'fake')

    def test_list_type_with_admin_default_proj1(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v1/fake/types',
                                      use_admin_context=True)
        req.environ['manila.context'].project_id = PROJ1_UUID
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_default_proj2(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}, {'id': '2'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types',
                                      use_admin_context=True)
        req.environ['manila.context'].project_id = PROJ2_UUID
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_ispublic_true(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=true',
                                      use_admin_context=True)
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_ispublic_false(self):
        expected = {'share_types': [{'id': '2'}, {'id': '3'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=false',
                                      use_admin_context=True)
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_ispublic_false_proj2(self):
        expected = {'share_types': [{'id': '2'}, {'id': '3'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=false',
                                      use_admin_context=True)
        req.environ['manila.context'].project_id = PROJ2_UUID
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_ispublic_none(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}, {'id': '2'},
                                    {'id': '3'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=all',
                                      use_admin_context=True)
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_no_admin_default(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types',
                                      use_admin_context=False)
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_no_admin_ispublic_true(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=true',
                                      use_admin_context=False)
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_no_admin_ispublic_false(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=false',
                                      use_admin_context=False)
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_no_admin_ispublic_none(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=all',
                                      use_admin_context=False)
        result = self.type_controller.index(req)
        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_show(self):
        resp = FakeResponse()
        self.type_action_controller.show(self.req, resp, '0')
        self.assertEqual({'id': '0', 'os-share-type-access:is_public': True},
                         resp.obj['share_type'])
        self.type_action_controller.show(self.req, resp, '2')
        self.assertEqual({'id': '0', 'os-share-type-access:is_public': False},
                         resp.obj['share_type'])

    def test_create(self):
        resp = FakeResponse()
        self.type_action_controller.create(self.req, {}, resp)
        self.assertEqual({'id': '0', 'os-share-type-access:is_public': True},
                         resp.obj['share_type'])

    def test_add_project_access(self):
        def stub_add_share_type_access(context, type_id, project_id):
            self.assertEqual('3', type_id, "type_id")
            self.assertEqual(PROJ2_UUID, project_id, "project_id")
        self.mock_object(db, 'share_type_access_add',
                         stub_add_share_type_access)
        body = {'addProjectAccess': {'project': PROJ2_UUID}}
        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=True)
        result = self.type_action_controller._addProjectAccess(req, '3', body)
        self.assertEqual(202, result.status_code)

    def test_add_project_access_with_no_admin_user(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=False)
        body = {'addProjectAccess': {'project': PROJ2_UUID}}
        self.assertRaises(exception.PolicyNotAuthorized,
                          self.type_action_controller._addProjectAccess,
                          req, '2', body)

    def test_add_project_access_with_already_added_access(self):
        def stub_add_share_type_access(context, type_id, project_id):
            raise exception.ShareTypeAccessExists(share_type_id=type_id,
                                                  project_id=project_id)
        self.mock_object(db, 'share_type_access_add',
                         stub_add_share_type_access)
        body = {'addProjectAccess': {'project': PROJ2_UUID}}
        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=True)
        self.assertRaises(webob.exc.HTTPConflict,
                          self.type_action_controller._addProjectAccess,
                          req, '3', body)

    def test_add_project_access_to_public_share_type(self):
        share_type_id = '3'
        body = {'addProjectAccess': {'project': PROJ2_UUID}}
        self.mock_object(share_types_api, 'get_share_type',
                         mock.Mock(return_value={"is_public": True}))

        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=True)

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.type_action_controller._addProjectAccess,
                          req, share_type_id, body)
        share_types_api.get_share_type.assert_called_once_with(
            mock.ANY, share_type_id)

    def test_remove_project_access_with_bad_access(self):
        def stub_remove_share_type_access(context, type_id, project_id):
            raise exception.ShareTypeAccessNotFound(share_type_id=type_id,
                                                    project_id=project_id)
        self.mock_object(db, 'share_type_access_remove',
                         stub_remove_share_type_access)
        body = {'removeProjectAccess': {'project': PROJ2_UUID}}
        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=True)
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.type_action_controller._removeProjectAccess,
                          req, '3', body)

    def test_remove_project_access_with_no_admin_user(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=False)
        body = {'removeProjectAccess': {'project': PROJ2_UUID}}
        self.assertRaises(exception.PolicyNotAuthorized,
                          self.type_action_controller._removeProjectAccess,
                          req, '2', body)
