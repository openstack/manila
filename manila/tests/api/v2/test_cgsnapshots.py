# Copyright 2015 Alex Meade
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

import copy
import datetime
import uuid

import ddt
import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
import six
import webob

from manila.api.openstack import wsgi
import manila.api.v2.cgsnapshots as cgs
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils

CONF = cfg.CONF


@ddt.ddt
class CGSnapshotApiTest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = cgs.CGSnapshotController()
        self.resource_name = self.controller.resource_name
        self.api_version = '2.4'
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.request = fakes.HTTPRequest.blank('/consistency-groups',
                                               version=self.api_version,
                                               experimental=True)
        self.context = self.request.environ['manila.context']
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')
        self.flags(rpc_backend='manila.openstack.common.rpc.impl_fake')

    def _get_fake_cgsnapshot(self, **values):
        snap = {
            'id': 'fake_id',
            'user_id': 'fakeuser',
            'project_id': 'fakeproject',
            'status': constants.STATUS_CREATING,
            'name': None,
            'description': None,
            'consistency_group_id': None,
            'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        }

        snap.update(**values)

        expected_snap = copy.deepcopy(snap)
        del expected_snap['user_id']
        expected_snap['links'] = mock.ANY
        return snap, expected_snap

    def _get_fake_simple_cgsnapshot(self, **values):
        snap = {
            'id': 'fake_id',
            'name': None,
        }

        snap.update(**values)
        expected_snap = copy.deepcopy(snap)
        expected_snap['links'] = mock.ANY
        return snap, expected_snap

    def _get_fake_cgsnapshot_member(self, **values):
        member = {
            'id': 'fake_id',
            'user_id': 'fakeuser',
            'project_id': 'fakeproject',
            'status': constants.STATUS_CREATING,
            'cgsnapshot_id': None,
            'share_proto': None,
            'share_type_id': None,
            'share_id': None,
            'size': None,
            'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        }

        member.update(**values)

        expected_member = copy.deepcopy(member)
        del expected_member['user_id']
        del expected_member['status']
        expected_member['share_protocol'] = member['share_proto']
        del expected_member['share_proto']
        return member, expected_member

    def test_create_invalid_body(self):
        body = {"not_cg_snapshot": {}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_no_consistency_group_id(self):
        body = {"cgnapshot": {}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create(self):
        fake_snap, expected_snap = self._get_fake_cgsnapshot()
        fake_id = six.text_type(uuid.uuid4())
        self.mock_object(self.controller.cg_api, 'create_cgsnapshot',
                         mock.Mock(return_value=fake_snap))

        body = {"cgsnapshot": {"consistency_group_id": fake_id}}

        res_dict = self.controller.create(self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')
        self.controller.cg_api.create_cgsnapshot.assert_called_once_with(
            self.context, consistency_group_id=fake_id)
        self.assertEqual(expected_snap, res_dict['cgsnapshot'])

    def test_create_cg_does_not_exist(self):
        fake_id = six.text_type(uuid.uuid4())
        self.mock_object(self.controller.cg_api, 'create_cgsnapshot',
                         mock.Mock(
                             side_effect=exception.ConsistencyGroupNotFound(
                                 consistency_group_id=six.text_type(
                                     uuid.uuid4())
                             )))

        body = {"cgsnapshot": {"consistency_group_id": fake_id}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_cg_does_not_a_uuid(self):
        self.mock_object(self.controller.cg_api, 'create_cgsnapshot',
                         mock.Mock(
                             side_effect=exception.ConsistencyGroupNotFound(
                                 consistency_group_id='not_a_uuid'
                             )))

        body = {"cgsnapshot": {"consistency_group_id": "not_a_uuid"}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_invalid_cg(self):
        fake_id = six.text_type(uuid.uuid4())
        self.mock_object(self.controller.cg_api, 'create_cgsnapshot',
                         mock.Mock(
                             side_effect=exception.InvalidConsistencyGroup(
                                 reason='bad_status'
                             )))

        body = {"cgsnapshot": {"consistency_group_id": fake_id}}
        self.assertRaises(webob.exc.HTTPConflict, self.controller.create,
                          self.request, body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_with_name(self):
        fake_name = 'fake_name'
        fake_snap, expected_snap = self._get_fake_cgsnapshot(name=fake_name)
        fake_id = six.text_type(uuid.uuid4())
        self.mock_object(self.controller.cg_api, 'create_cgsnapshot',
                         mock.Mock(return_value=fake_snap))

        body = {"cgsnapshot": {"consistency_group_id": fake_id,
                               "name": fake_name}}
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create_cgsnapshot.assert_called_once_with(
            self.context, consistency_group_id=fake_id, name=fake_name)
        self.assertEqual(expected_snap, res_dict['cgsnapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_with_description(self):
        fake_description = 'fake_description'
        fake_snap, expected_snap = self._get_fake_cgsnapshot(
            description=fake_description)
        fake_id = six.text_type(uuid.uuid4())
        self.mock_object(self.controller.cg_api, 'create_cgsnapshot',
                         mock.Mock(return_value=fake_snap))

        body = {"cgsnapshot": {"consistency_group_id": fake_id,
                               "description": fake_description}}
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create_cgsnapshot.assert_called_once_with(
            self.context, consistency_group_id=fake_id,
            description=fake_description)
        self.assertEqual(expected_snap, res_dict['cgsnapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_with_name_and_description(self):
        fake_name = 'fake_name'
        fake_description = 'fake_description'
        fake_id = six.text_type(uuid.uuid4())
        fake_snap, expected_snap = self._get_fake_cgsnapshot(
            description=fake_description, name=fake_name)
        self.mock_object(self.controller.cg_api, 'create_cgsnapshot',
                         mock.Mock(return_value=fake_snap))

        body = {"cgsnapshot": {"consistency_group_id": fake_id,
                               "description": fake_description,
                               "name": fake_name}}
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create_cgsnapshot.assert_called_once_with(
            self.context, consistency_group_id=fake_id, name=fake_name,
            description=fake_description)
        self.assertEqual(expected_snap, res_dict['cgsnapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_update_with_name_and_description(self):
        fake_name = 'fake_name'
        fake_description = 'fake_description'
        fake_id = six.text_type(uuid.uuid4())
        fake_snap, expected_snap = self._get_fake_cgsnapshot(
            description=fake_description, name=fake_name)
        self.mock_object(self.controller.cg_api, 'get_cgsnapshot',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.controller.cg_api, 'update_cgsnapshot',
                         mock.Mock(return_value=fake_snap))

        body = {"cgsnapshot": {"description": fake_description,
                               "name": fake_name}}
        res_dict = self.controller.update(self.request, fake_id, body)

        self.controller.cg_api.update_cgsnapshot.assert_called_once_with(
            self.context, fake_snap,
            dict(name=fake_name, description=fake_description))
        self.assertEqual(expected_snap, res_dict['cgsnapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_update_snapshot_not_found(self):
        body = {"cgsnapshot": {}}
        self.mock_object(self.controller.cg_api, 'get_cgsnapshot',
                         mock.Mock(side_effect=exception.NotFound))
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.update,
                          self.request, 'fake_id', body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_update_invalid_body(self):
        body = {"not_cgsnapshot": {}}
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update,
                          self.request, 'fake_id', body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_update_invalid_body_invalid_field(self):
        body = {"cgsnapshot": {"unknown_field": ""}}
        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.update,
                                self.request, 'fake_id', body)
        self.assertTrue('unknown_field' in six.text_type(exc))
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_update_invalid_body_readonly_field(self):
        body = {"cgsnapshot": {"created_at": []}}
        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.update,
                                self.request, 'fake_id', body)
        self.assertTrue('created_at' in six.text_type(exc))
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_list_index(self):
        fake_snap, expected_snap = self._get_fake_simple_cgsnapshot()
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshots',
                         mock.Mock(return_value=[fake_snap]))
        res_dict = self.controller.index(self.request)
        self.assertEqual([expected_snap], res_dict['cgsnapshots'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_list_index_no_cgs(self):
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshots',
                         mock.Mock(return_value=[]))
        res_dict = self.controller.index(self.request)
        self.assertEqual([], res_dict['cgsnapshots'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_list_index_with_limit(self):
        fake_snap, expected_snap = self._get_fake_simple_cgsnapshot()
        fake_snap2, expected_snap2 = self._get_fake_simple_cgsnapshot(
            id="fake_id2")
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshots',
                         mock.Mock(return_value=[fake_snap, fake_snap2]))
        req = fakes.HTTPRequest.blank('/cgsnapshots?limit=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req)

        self.assertEqual(1, len(res_dict['cgsnapshots']))
        self.assertEqual([expected_snap], res_dict['cgsnapshots'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_index_with_limit_and_offset(self):
        fake_snap, expected_snap = self._get_fake_simple_cgsnapshot()
        fake_snap2, expected_snap2 = self._get_fake_simple_cgsnapshot(
            id="fake_id2")
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshots',
                         mock.Mock(return_value=[fake_snap, fake_snap2]))
        req = fakes.HTTPRequest.blank('/cgsnapshots?limit=1&offset=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req)

        self.assertEqual(1, len(res_dict['cgsnapshots']))
        self.assertEqual([expected_snap2], res_dict['cgsnapshots'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_detail(self):
        fake_snap, expected_snap = self._get_fake_cgsnapshot()
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshots',
                         mock.Mock(return_value=[fake_snap]))
        res_dict = self.controller.detail(self.request)
        self.assertEqual([expected_snap], res_dict['cgsnapshots'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_list_detail_no_cgs(self):
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshots',
                         mock.Mock(return_value=[]))
        res_dict = self.controller.detail(self.request)
        self.assertEqual([], res_dict['cgsnapshots'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_list_detail_with_limit(self):
        fake_snap, expected_snap = self._get_fake_cgsnapshot()
        fake_snap2, expected_snap2 = self._get_fake_cgsnapshot(
            id="fake_id2")
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshots',
                         mock.Mock(return_value=[fake_snap, fake_snap2]))
        req = fakes.HTTPRequest.blank('/cgsnapshots?limit=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['cgsnapshots']))
        self.assertEqual([expected_snap], res_dict['cgsnapshots'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_detail_with_limit_and_offset(self):
        fake_snap, expected_snap = self._get_fake_cgsnapshot()
        fake_snap2, expected_snap2 = self._get_fake_cgsnapshot(
            id="fake_id2")
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshots',
                         mock.Mock(return_value=[fake_snap, fake_snap2]))
        req = fakes.HTTPRequest.blank('/cgsnapshots?limit=1&offset=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['cgsnapshots']))
        self.assertEqual([expected_snap2], res_dict['cgsnapshots'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_delete(self):
        fake_snap, expected_snap = self._get_fake_cgsnapshot()
        self.mock_object(self.controller.cg_api, 'get_cgsnapshot',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.controller.cg_api, 'delete_cgsnapshot')

        res = self.controller.delete(self.request, fake_snap['id'])

        self.assertEqual(202, res.status_code)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

    def test_delete_not_found(self):
        fake_snap, expected_snap = self._get_fake_cgsnapshot()
        self.mock_object(self.controller.cg_api, 'get_cgsnapshot',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.delete,
                          self.request, fake_snap['id'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

    def test_delete_in_conflicting_status(self):
        fake_snap, expected_snap = self._get_fake_cgsnapshot()
        self.mock_object(self.controller.cg_api, 'get_cgsnapshot',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.controller.cg_api, 'delete_cgsnapshot',
                         mock.Mock(
                             side_effect=exception.InvalidCGSnapshot(
                                 reason='blah')))

        self.assertRaises(webob.exc.HTTPConflict, self.controller.delete,
                          self.request, fake_snap['id'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

    def test_show(self):
        fake_snap, expected_snap = self._get_fake_cgsnapshot()
        self.mock_object(self.controller.cg_api, 'get_cgsnapshot',
                         mock.Mock(return_value=fake_snap))

        res_dict = self.controller.show(self.request, fake_snap['id'])

        self.assertEqual(expected_snap, res_dict['cgsnapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_cgsnapshot')

    def test_show_cg_not_found(self):
        fake_snap, expected_snap = self._get_fake_cgsnapshot()
        self.mock_object(self.controller.cg_api, 'get_cgsnapshot',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          self.request, fake_snap['id'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_cgsnapshot')

    def test_members_empty(self):
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshot_members',
                         mock.Mock(return_value=[]))

        res_dict = self.controller.members(self.request, 'fake_cg_id')

        self.assertEqual([], res_dict['cgsnapshot_members'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_cgsnapshot')

    def test_members(self):
        fake_member, expected_member = self._get_fake_cgsnapshot_member()
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshot_members',
                         mock.Mock(return_value=[fake_member]))

        res_dict = self.controller.members(self.request, 'fake_cg_id')

        self.assertEqual([expected_member], res_dict['cgsnapshot_members'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_cgsnapshot')

    def test_members_with_limit(self):
        fake_member, expected_member = self._get_fake_cgsnapshot_member()
        fake_member2, expected_member2 = self._get_fake_cgsnapshot_member(
            id="fake_id2")
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshot_members',
                         mock.Mock(return_value=[fake_member, fake_member2]))
        req = fakes.HTTPRequest.blank('/members?limit=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.members(req, 'fake_cg_id')

        self.assertEqual(1, len(res_dict['cgsnapshot_members']))
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_cgsnapshot')

    def test_members_with_limit_and_offset(self):
        fake_member, expected_member = self._get_fake_cgsnapshot_member()
        fake_member2, expected_member2 = self._get_fake_cgsnapshot_member(
            id="fake_id2")
        self.mock_object(self.controller.cg_api, 'get_all_cgsnapshot_members',
                         mock.Mock(return_value=[fake_member, fake_member2]))
        req = fakes.HTTPRequest.blank('/members?limit=1&offset=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.members(req, 'fake_cg_id')

        self.assertEqual(1, len(res_dict['cgsnapshot_members']))
        self.assertEqual([expected_member2], res_dict['cgsnapshot_members'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_cgsnapshot')

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _setup_cgsnapshot_data(self, cgsnapshot=None, version='2.7'):
        if cgsnapshot is None:
            cgsnapshot = db_utils.create_cgsnapshot(
                'fake_id', status=constants.STATUS_AVAILABLE)
        req = fakes.HTTPRequest.blank('/v2/fake/cgsnapshots/%s/action' %
                                      cgsnapshot['id'], version=version)
        req.headers[wsgi.API_VERSION_REQUEST_HEADER] = version
        req.headers[wsgi.EXPERIMENTAL_API_REQUEST_HEADER] = 'True'
        return cgsnapshot, req

    @ddt.data(*fakes.fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_cgsnapshot_force_delete_with_different_roles(self, role,
                                                          resp_code, version):
        cgsnap, req = self._setup_cgsnapshot_data()
        ctxt = self._get_context(role)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        if float(version) > 2.6:
            action_name = 'force_delete'
        else:
            action_name = 'os-force_delete'
        body = {action_name: {'status': constants.STATUS_ERROR}}
        req.body = six.b(jsonutils.dumps(body))
        req.headers['X-Openstack-Manila-Api-Version'] = version
        req.environ['manila.context'] = ctxt

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # Validate response
        self.assertEqual(resp_code, resp.status_int)

    @ddt.data(*fakes.fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_cgsnapshot_reset_status_with_different_roles(
            self, role, valid_code, valid_status, version):
        ctxt = self._get_context(role)
        cgsnap, req = self._setup_cgsnapshot_data(version=version)
        if float(version) > 2.6:
            action_name = 'reset_status'
        else:
            action_name = 'os-reset_status'
        body = {action_name: {'status': constants.STATUS_ERROR}}
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.body = six.b(jsonutils.dumps(body))
        req.headers['X-Openstack-Manila-Api-Version'] = version
        req.environ['manila.context'] = ctxt

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # Validate response code and model status
        self.assertEqual(valid_code, resp.status_int)

        if valid_code == 404:
            self.assertRaises(exception.NotFound,
                              db.cgsnapshot_get,
                              ctxt,
                              cgsnap['id'])
        else:
            actual_model = db.cgsnapshot_get(ctxt, cgsnap['id'])
            self.assertEqual(valid_status, actual_model['status'])
