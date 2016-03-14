# Copyright 2011 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime

import ddt
import mock
from oslo_utils import timeutils
import webob

from manila.api.v2 import share_types as types
from manila.api.views import types as views_types
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila import policy
from manila.share import share_types
from manila import test
from manila.tests.api import fakes
from manila.tests import fake_notifier


def stub_share_type(id):
    specs = {
        "key1": "value1",
        "key2": "value2",
        "key3": "value3",
        "key4": "value4",
        "key5": "value5",
        constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: "true",
    }
    return dict(
        id=id,
        name='share_type_%s' % str(id),
        extra_specs=specs,
        required_extra_specs={
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: "true",
        }
    )


def return_share_types_get_all_types(context, search_opts=None):
    return dict(
        share_type_1=stub_share_type(1),
        share_type_2=stub_share_type(2),
        share_type_3=stub_share_type(3)
    )


def return_empty_share_types_get_all_types(context, search_opts=None):
    return {}


def return_share_types_get_share_type(context, id=1):
    if id == "777":
        raise exception.ShareTypeNotFound(share_type_id=id)
    return stub_share_type(int(id))


def return_share_types_get_by_name(context, name):
    if name == "777":
        raise exception.ShareTypeNotFoundByName(share_type_name=name)
    return stub_share_type(int(name.split("_")[2]))


def return_share_types_destroy(context, name):
    if name == "777":
        raise exception.ShareTypeNotFoundByName(share_type_name=name)
    pass


def return_share_types_with_volumes_destroy(context, id):
    if id == "1":
        raise exception.ShareTypeInUse(share_type_id=id)
    pass


def return_share_types_create(context, name, specs, is_public):
    pass


def make_create_body(name="test_share_1", extra_specs=None,
                     spec_driver_handles_share_servers=True):
    if not extra_specs:
        extra_specs = {}

    if spec_driver_handles_share_servers is not None:
        extra_specs[constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS] =\
            spec_driver_handles_share_servers

    body = {
        "share_type": {
            "name": name,
            "extra_specs": extra_specs
        }
    }

    return body


@ddt.ddt
class ShareTypesAPITest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.flags(host='fake')
        self.controller = types.ShareTypesController()
        self.resource_name = self.controller.resource_name
        self.mock_object(policy, 'check_policy',
                         mock.Mock(return_value=True))
        fake_notifier.reset()
        self.addCleanup(fake_notifier.reset)
        self.mock_object(share_types, 'create',
                         return_share_types_create)
        self.mock_object(share_types, 'get_share_type_by_name',
                         return_share_types_get_by_name)
        self.mock_object(share_types, 'get_share_type',
                         return_share_types_get_share_type)
        self.mock_object(share_types, 'destroy',
                         return_share_types_destroy)

    @ddt.data(True, False)
    def test_share_types_index(self, admin):
        self.mock_object(share_types, 'get_all_types',
                         return_share_types_get_all_types)

        req = fakes.HTTPRequest.blank('/v2/fake/types',
                                      use_admin_context=admin)

        res_dict = self.controller.index(req)

        self.assertEqual(3, len(res_dict['share_types']))

        expected_names = ['share_type_1', 'share_type_2', 'share_type_3']
        actual_names = map(lambda e: e['name'], res_dict['share_types'])
        self.assertEqual(set(expected_names), set(actual_names))
        for entry in res_dict['share_types']:
            if admin:
                self.assertEqual('value1', entry['extra_specs'].get('key1'))
            else:
                self.assertIsNone(entry['extra_specs'].get('key1'))
            self.assertTrue('required_extra_specs' in entry)
            required_extra_spec = entry['required_extra_specs'].get(
                constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS, '')
            self.assertEqual('true', required_extra_spec)
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    def test_share_types_index_no_data(self):
        self.mock_object(share_types, 'get_all_types',
                         return_empty_share_types_get_all_types)

        req = fakes.HTTPRequest.blank('/v2/fake/types')
        res_dict = self.controller.index(req)

        self.assertEqual(0, len(res_dict['share_types']))
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    def test_share_types_show(self):
        self.mock_object(share_types, 'get_share_type',
                         return_share_types_get_share_type)

        req = fakes.HTTPRequest.blank('/v2/fake/types/1')
        res_dict = self.controller.show(req, 1)

        self.assertEqual(2, len(res_dict))
        self.assertEqual('1', res_dict['share_type']['id'])
        self.assertEqual('share_type_1', res_dict['share_type']['name'])
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'show')

    def test_share_types_show_not_found(self):
        self.mock_object(share_types, 'get_share_type',
                         return_share_types_get_share_type)

        req = fakes.HTTPRequest.blank('/v2/fake/types/777')
        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          req, '777')
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'show')

    def test_share_types_default(self):
        self.mock_object(share_types, 'get_default_share_type',
                         return_share_types_get_share_type)

        req = fakes.HTTPRequest.blank('/v2/fake/types/default')
        res_dict = self.controller.default(req)

        self.assertEqual(2, len(res_dict))
        self.assertEqual('1', res_dict['share_type']['id'])
        self.assertEqual('share_type_1', res_dict['share_type']['name'])
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'default')

    def test_share_types_default_not_found(self):
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(side_effect=exception.ShareTypeNotFound(
                             share_type_id="fake")))
        req = fakes.HTTPRequest.blank('/v2/fake/types/default')

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.default, req)
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'default')

    @ddt.data(
        ('1.0', 'os-share-type-access'),
        ('2.0', 'os-share-type-access'),
        ('2.6', 'os-share-type-access'),
        ('2.7', 'share_type_access'),
    )
    @ddt.unpack
    def test_view_builder_show(self, version, prefix):
        view_builder = views_types.ViewBuilder()

        now = timeutils.utcnow().isoformat()
        raw_share_type = dict(
            name='new_type',
            deleted=False,
            created_at=now,
            updated_at=now,
            extra_specs={},
            deleted_at=None,
            required_extra_specs={},
            id=42,
        )

        request = fakes.HTTPRequest.blank("/v%s" % version[0], version=version)
        request.headers['X-Openstack-Manila-Api-Version'] = version

        output = view_builder.show(request, raw_share_type)

        self.assertIn('share_type', output)
        expected_share_type = {
            'name': 'new_type',
            'extra_specs': {},
            '%s:is_public' % prefix: True,
            'required_extra_specs': {},
            'id': 42,
        }
        self.assertDictMatch(output['share_type'], expected_share_type)

    def test_view_builder_list(self):
        view_builder = views_types.ViewBuilder()

        now = timeutils.utcnow().isoformat()
        raw_share_types = []
        for i in range(0, 10):
            raw_share_types.append(
                dict(
                    name='new_type',
                    deleted=False,
                    created_at=now,
                    updated_at=now,
                    extra_specs={},
                    required_extra_specs={},
                    deleted_at=None,
                    id=42 + i
                )
            )

        request = fakes.HTTPRequest.blank("/v2")
        output = view_builder.index(request, raw_share_types)

        self.assertIn('share_types', output)
        for i in range(0, 10):
            expected_share_type = {
                'name': 'new_type',
                'extra_specs': {},
                'os-share-type-access:is_public': True,
                'required_extra_specs': {},
                'id': 42 + i,
            }
            self.assertDictMatch(output['share_types'][i],
                                 expected_share_type)

    @ddt.data(None, True, 'true', 'false', 'all')
    def test_parse_is_public_valid(self, value):
        result = self.controller._parse_is_public(value)
        self.assertTrue(result in (True, False, None))

    def test_parse_is_public_invalid(self):
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._parse_is_public,
                          'fakefakefake')

    def test_share_types_delete(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/1')
        self.assertEqual(0, len(fake_notifier.NOTIFICATIONS))
        self.controller._delete(req, 1)
        self.assertEqual(1, len(fake_notifier.NOTIFICATIONS))

    def test_share_types_delete_not_found(self):
        self.assertEqual(0, len(fake_notifier.NOTIFICATIONS))
        req = fakes.HTTPRequest.blank('/v2/fake/types/777')
        self.assertRaises(webob.exc.HTTPNotFound, self.controller._delete,
                          req, '777')
        self.assertEqual(1, len(fake_notifier.NOTIFICATIONS))

    def test_share_types_with_volumes_destroy(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/1')
        self.assertEqual(0, len(fake_notifier.NOTIFICATIONS))
        self.controller._delete(req, 1)
        self.assertEqual(1, len(fake_notifier.NOTIFICATIONS))

    @ddt.data(make_create_body("share_type_1"),
              make_create_body(spec_driver_handles_share_servers="false"),
              make_create_body(spec_driver_handles_share_servers="true"),
              make_create_body(spec_driver_handles_share_servers="1"),
              make_create_body(spec_driver_handles_share_servers="0"),
              make_create_body(spec_driver_handles_share_servers="True"),
              make_create_body(spec_driver_handles_share_servers="False"),
              make_create_body(spec_driver_handles_share_servers="FalsE"))
    def test_create(self, body):
        req = fakes.HTTPRequest.blank('/v2/fake/types')
        self.assertEqual(0, len(fake_notifier.NOTIFICATIONS))
        res_dict = self.controller._create(req, body)
        self.assertEqual(1, len(fake_notifier.NOTIFICATIONS))
        self.assertEqual(2, len(res_dict))
        self.assertEqual('share_type_1', res_dict['share_type']['name'])
        self.assertEqual('share_type_1', res_dict['volume_type']['name'])

    @ddt.data(None,
              make_create_body(""),
              make_create_body("n" * 256),
              {'foo': {'a': 'b'}},
              {'share_type': 'string'},
              make_create_body(spec_driver_handles_share_servers=None),
              make_create_body(spec_driver_handles_share_servers=""),
              make_create_body(spec_driver_handles_share_servers=[]),
              )
    def test_create_invalid_request(self, body):
        req = fakes.HTTPRequest.blank('/v2/fake/types')
        self.assertEqual(0, len(fake_notifier.NOTIFICATIONS))
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._create, req, body)
        self.assertEqual(0, len(fake_notifier.NOTIFICATIONS))

    def assert_share_type_list_equal(self, expected, observed):
        self.assertEqual(len(expected), len(observed))
        expected = sorted(expected, key=lambda item: item['id'])
        observed = sorted(observed, key=lambda item: item['id'])
        for d1, d2 in zip(expected, observed):
            self.assertEqual(d1['id'], d2['id'])


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
    for k, v in SHARE_TYPES.items():
        if filters['is_public'] and _has_type_access(k, context.project_id):
            res.update({k: v})
            continue
        if v['is_public'] == filters['is_public']:
            res.update({k: v})
    return res


class FakeResponse(object):
    obj = {'share_type': {'id': '0'},
           'share_types': [{'id': '0'}, {'id': '2'}]}

    def attach(self, **kwargs):
        pass


class FakeRequest(object):
    environ = {"manila.context": context.get_admin_context()}

    def get_db_share_type(self, resource_id):
        return SHARE_TYPES[resource_id]


class ShareTypeAccessTest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = types.ShareTypesController()
        self.req = FakeRequest()
        self.context = self.req.environ['manila.context']
        self.mock_object(db, 'share_type_get', fake_share_type_get)
        self.mock_object(db, 'share_type_get_all', fake_share_type_get_all)

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
                          self.controller.share_type_access,
                          req, '1')

    def test_list_type_access_private(self):
        expected = {'share_type_access': [
            {'share_type_id': '2', 'project_id': PROJ2_UUID},
            {'share_type_id': '2', 'project_id': PROJ3_UUID},
        ]}

        result = self.controller.share_type_access(self.req, '2')

        self.assertEqual(expected, result)

    def test_list_with_no_context(self):
        req = fakes.HTTPRequest.blank('/v1/types/fake/types')

        def fake_authorize(context, target=None, action=None):
            raise exception.PolicyNotAuthorized(action='index')

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.share_type_access,
                          req, 'fake')

    def test_list_type_with_admin_default_proj1(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v1/fake/types', use_admin_context=True)
        req.environ['manila.context'].project_id = PROJ1_UUID

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_default_proj2(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}, {'id': '2'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types', use_admin_context=True)
        req.environ['manila.context'].project_id = PROJ2_UUID

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_ispublic_true(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=true',
                                      use_admin_context=True)

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_ispublic_false(self):
        expected = {'share_types': [{'id': '2'}, {'id': '3'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=false',
                                      use_admin_context=True)

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_ispublic_false_proj2(self):
        expected = {'share_types': [{'id': '2'}, {'id': '3'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=false',
                                      use_admin_context=True)
        req.environ['manila.context'].project_id = PROJ2_UUID

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_admin_ispublic_none(self):
        expected = {'share_types': [
            {'id': '0'}, {'id': '1'}, {'id': '2'}, {'id': '3'},
        ]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=all',
                                      use_admin_context=True)

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_no_admin_default(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types',
                                      use_admin_context=False)

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_no_admin_ispublic_true(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=true',
                                      use_admin_context=False)

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_no_admin_ispublic_false(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=false',
                                      use_admin_context=False)

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_list_type_with_no_admin_ispublic_none(self):
        expected = {'share_types': [{'id': '0'}, {'id': '1'}]}
        req = fakes.HTTPRequest.blank('/v2/fake/types?is_public=all',
                                      use_admin_context=False)

        result = self.controller.index(req)

        self.assertShareTypeListEqual(expected['share_types'],
                                      result['share_types'])

    def test_add_project_access(self):
        def stub_add_share_type_access(context, type_id, project_id):
            self.assertEqual('3', type_id, "type_id")
            self.assertEqual(PROJ2_UUID, project_id, "project_id")
        self.mock_object(db, 'share_type_access_add',
                         stub_add_share_type_access)
        body = {'addProjectAccess': {'project': PROJ2_UUID}}
        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=True)

        result = self.controller._add_project_access(req, '3', body)

        self.assertEqual(202, result.status_code)

    def test_add_project_access_with_no_admin_user(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=False)
        body = {'addProjectAccess': {'project': PROJ2_UUID}}

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller._add_project_access,
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
                          self.controller._add_project_access,
                          req, '3', body)

    def test_add_project_access_to_public_share_type(self):
        share_type_id = '3'
        body = {'addProjectAccess': {'project': PROJ2_UUID}}
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value={"is_public": True}))
        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=True)

        self.assertRaises(webob.exc.HTTPConflict,
                          self.controller._add_project_access,
                          req, share_type_id, body)

        share_types.get_share_type.assert_called_once_with(
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
                          self.controller._remove_project_access,
                          req, '3', body)

    def test_remove_project_access_with_no_admin_user(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=False)
        body = {'removeProjectAccess': {'project': PROJ2_UUID}}

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller._remove_project_access,
                          req, '2', body)

    def test_remove_project_access_from_public_share_type(self):
        share_type_id = '3'
        body = {'removeProjectAccess': {'project': PROJ2_UUID}}
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value={"is_public": True}))

        req = fakes.HTTPRequest.blank('/v2/fake/types/2/action',
                                      use_admin_context=True)

        self.assertRaises(webob.exc.HTTPConflict,
                          self.controller._remove_project_access,
                          req, share_type_id, body)
        share_types.get_share_type.assert_called_once_with(
            mock.ANY, share_type_id)

    def test_remove_project_access_by_nonexistent_share_type(self):
        self.mock_object(share_types, 'get_share_type',
                         return_share_types_get_share_type)
        body = {'removeProjectAccess': {'project': PROJ2_UUID}}
        req = fakes.HTTPRequest.blank('/v2/fake/types/777/action',
                                      use_admin_context=True)

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller._remove_project_access,
                          req, '777', body)
