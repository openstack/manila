# Copyright 2016 Alex Meade
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

import ddt
import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import six
import webob

from manila.api.openstack import wsgi
from manila.api.v2 import share_group_snapshots
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
class ShareGroupSnapshotAPITest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = share_group_snapshots.ShareGroupSnapshotController()
        self.resource_name = self.controller.resource_name
        self.api_version = '2.31'
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.request = fakes.HTTPRequest.blank(
            '/share-groups', version=self.api_version, experimental=True)
        self.context = self.request.environ['manila.context']
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')
        self.flags(rpc_backend='manila.openstack.common.rpc.impl_fake')

    def _get_fake_share_group_snapshot(self, **values):
        snap = {
            'id': 'fake_id',
            'user_id': 'fakeuser',
            'project_id': 'fakeproject',
            'status': constants.STATUS_CREATING,
            'name': None,
            'description': None,
            'share_group_id': None,
            'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
            'members': [],
        }

        snap.update(**values)

        expected_snap = copy.deepcopy(snap)
        del expected_snap['user_id']
        return snap, expected_snap

    def _get_fake_simple_share_group_snapshot(self, **values):
        snap = {
            'id': 'fake_id',
            'name': None,
        }

        snap.update(**values)
        expected_snap = copy.deepcopy(snap)
        return snap, expected_snap

    def _get_fake_share_group_snapshot_member(self, **values):
        member = {
            'id': 'fake_id',
            'user_id': 'fakeuser',
            'project_id': 'fakeproject',
            'status': constants.STATUS_CREATING,
            'share_group_snapshot_id': None,
            'share_proto': None,
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
        body = {"not_group_snapshot": {}}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_no_share_group_id(self):
        body = {"share_group_snapshot": {}}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create(self):
        fake_snap, expected_snap = self._get_fake_share_group_snapshot()
        fake_id = six.text_type(uuidutils.generate_uuid())
        body = {"share_group_snapshot": {"share_group_id": fake_id}}
        mock_create = self.mock_object(
            self.controller.share_group_api, 'create_share_group_snapshot',
            mock.Mock(return_value=fake_snap))

        res_dict = self.controller.create(self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')
        mock_create.assert_called_once_with(
            self.context, share_group_id=fake_id)
        res_dict['share_group_snapshot'].pop('links')

        self.assertEqual(expected_snap, res_dict['share_group_snapshot'])

    def test_create_group_does_not_exist(self):
        fake_id = six.text_type(uuidutils.generate_uuid())
        body = {"share_group_snapshot": {"share_group_id": fake_id}}
        self.mock_object(
            self.controller.share_group_api, 'create_share_group_snapshot',
            mock.Mock(side_effect=exception.ShareGroupNotFound(
                share_group_id=six.text_type(uuidutils.generate_uuid()))))

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_group_does_not_a_uuid(self):
        self.mock_object(
            self.controller.share_group_api, 'create_share_group_snapshot',
            mock.Mock(side_effect=exception.ShareGroupNotFound(
                share_group_id='not_a_uuid',
            )))
        body = {"share_group_snapshot": {"share_group_id": "not_a_uuid"}}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_invalid_share_group(self):
        fake_id = six.text_type(uuidutils.generate_uuid())
        body = {"share_group_snapshot": {"share_group_id": fake_id}}
        self.mock_object(
            self.controller.share_group_api, 'create_share_group_snapshot',
            mock.Mock(side_effect=exception.InvalidShareGroup(
                reason='bad_status')))

        self.assertRaises(
            webob.exc.HTTPConflict, self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_with_name(self):
        fake_name = 'fake_name'
        fake_snap, expected_snap = self._get_fake_share_group_snapshot(
            name=fake_name)
        fake_id = six.text_type(uuidutils.generate_uuid())
        mock_create = self.mock_object(
            self.controller.share_group_api, 'create_share_group_snapshot',
            mock.Mock(return_value=fake_snap))
        body = {
            "share_group_snapshot": {
                "share_group_id": fake_id,
                "name": fake_name,
            }
        }
        res_dict = self.controller.create(self.request, body)

        res_dict['share_group_snapshot'].pop('links')

        mock_create.assert_called_once_with(
            self.context, share_group_id=fake_id, name=fake_name)
        self.assertEqual(expected_snap, res_dict['share_group_snapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_with_description(self):
        fake_description = 'fake_description'
        fake_snap, expected_snap = self._get_fake_share_group_snapshot(
            description=fake_description)
        fake_id = six.text_type(uuidutils.generate_uuid())
        mock_create = self.mock_object(
            self.controller.share_group_api, 'create_share_group_snapshot',
            mock.Mock(return_value=fake_snap))

        body = {
            "share_group_snapshot": {
                "share_group_id": fake_id,
                "description": fake_description,
            }
        }
        res_dict = self.controller.create(self.request, body)

        res_dict['share_group_snapshot'].pop('links')

        mock_create.assert_called_once_with(
            self.context, share_group_id=fake_id, description=fake_description)
        self.assertEqual(expected_snap, res_dict['share_group_snapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_create_with_name_and_description(self):
        fake_name = 'fake_name'
        fake_description = 'fake_description'
        fake_id = six.text_type(uuidutils.generate_uuid())
        fake_snap, expected_snap = self._get_fake_share_group_snapshot(
            description=fake_description, name=fake_name)
        mock_create = self.mock_object(
            self.controller.share_group_api, 'create_share_group_snapshot',
            mock.Mock(return_value=fake_snap))

        body = {
            "share_group_snapshot": {
                "share_group_id": fake_id,
                "description": fake_description,
                "name": fake_name,
            }
        }
        res_dict = self.controller.create(self.request, body)

        res_dict['share_group_snapshot'].pop('links')

        mock_create.assert_called_once_with(
            self.context, share_group_id=fake_id, name=fake_name,
            description=fake_description)
        self.assertEqual(expected_snap, res_dict['share_group_snapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_update_with_name_and_description(self):
        fake_name = 'fake_name'
        fake_description = 'fake_description'
        fake_id = six.text_type(uuidutils.generate_uuid())
        fake_snap, expected_snap = self._get_fake_share_group_snapshot(
            description=fake_description, name=fake_name)
        self.mock_object(
            self.controller.share_group_api, 'get_share_group_snapshot',
            mock.Mock(return_value=fake_snap))
        mock_update = self.mock_object(
            self.controller.share_group_api, 'update_share_group_snapshot',
            mock.Mock(return_value=fake_snap))

        body = {
            "share_group_snapshot": {
                "description": fake_description,
                "name": fake_name,
            }
        }
        res_dict = self.controller.update(self.request, fake_id, body)

        res_dict['share_group_snapshot'].pop('links')

        mock_update.assert_called_once_with(
            self.context, fake_snap,
            {"name": fake_name, "description": fake_description})
        self.assertEqual(expected_snap, res_dict['share_group_snapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_update_snapshot_not_found(self):
        body = {"share_group_snapshot": {}}
        self.mock_object(
            self.controller.share_group_api, 'get_share_group_snapshot',
            mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.update, self.request, 'fake_id', body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_update_invalid_body(self):
        body = {"not_group_snapshot": {}}
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update,
                          self.request, 'fake_id', body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_update_invalid_body_invalid_field(self):
        body = {"share_group_snapshot": {"unknown_field": ""}}
        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.update,
                                self.request, 'fake_id', body)
        self.assertIn('unknown_field', six.text_type(exc))
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_update_invalid_body_readonly_field(self):
        body = {"share_group_snapshot": {"created_at": []}}
        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.update,
                                self.request, 'fake_id', body)
        self.assertIn('created_at', six.text_type(exc))
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_list_index(self):
        fake_snap, expected_snap = self._get_fake_simple_share_group_snapshot()
        self.mock_object(
            self.controller.share_group_api, 'get_all_share_group_snapshots',
            mock.Mock(return_value=[fake_snap]))

        res_dict = self.controller.index(self.request)

        res_dict['share_group_snapshots'][0].pop('links')

        self.assertEqual([expected_snap], res_dict['share_group_snapshots'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_list_index_no_share_groups(self):
        self.mock_object(
            self.controller.share_group_api, 'get_all_share_group_snapshots',
            mock.Mock(return_value=[]))

        res_dict = self.controller.index(self.request)

        self.assertEqual([], res_dict['share_group_snapshots'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_list_index_with_limit(self):
        fake_snap, expected_snap = self._get_fake_simple_share_group_snapshot()
        fake_snap2, expected_snap2 = (
            self._get_fake_simple_share_group_snapshot(
                id="fake_id2"))
        self.mock_object(
            self.controller.share_group_api, 'get_all_share_group_snapshots',
            mock.Mock(return_value=[fake_snap, fake_snap2]))
        req = fakes.HTTPRequest.blank('/share-group-snapshots?limit=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req)

        res_dict['share_group_snapshots'][0].pop('links')

        self.assertEqual(1, len(res_dict['share_group_snapshots']))
        self.assertEqual([expected_snap], res_dict['share_group_snapshots'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_index_with_limit_and_offset(self):
        fake_snap, expected_snap = self._get_fake_simple_share_group_snapshot()
        fake_snap2, expected_snap2 = (
            self._get_fake_simple_share_group_snapshot(id="fake_id2"))
        self.mock_object(
            self.controller.share_group_api, 'get_all_share_group_snapshots',
            mock.Mock(return_value=[fake_snap, fake_snap2]))
        req = fakes.HTTPRequest.blank(
            '/share-group-snapshots?limit=1&offset=1',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req)

        res_dict['share_group_snapshots'][0].pop('links')

        self.assertEqual(1, len(res_dict['share_group_snapshots']))
        self.assertEqual([expected_snap2], res_dict['share_group_snapshots'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_detail(self):
        fake_snap, expected_snap = self._get_fake_share_group_snapshot()
        self.mock_object(
            self.controller.share_group_api, 'get_all_share_group_snapshots',
            mock.Mock(return_value=[fake_snap]))

        res_dict = self.controller.detail(self.request)

        res_dict['share_group_snapshots'][0].pop('links')

        self.assertEqual(1, len(res_dict['share_group_snapshots']))
        self.assertEqual(expected_snap, res_dict['share_group_snapshots'][0])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_list_detail_no_share_groups(self):
        self.mock_object(
            self.controller.share_group_api, 'get_all_share_group_snapshots',
            mock.Mock(return_value=[]))
        res_dict = self.controller.detail(self.request)
        self.assertEqual([], res_dict['share_group_snapshots'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_list_detail_with_limit(self):
        fake_snap, expected_snap = self._get_fake_share_group_snapshot()
        fake_snap2, expected_snap2 = self._get_fake_share_group_snapshot(
            id="fake_id2")
        self.mock_object(
            self.controller.share_group_api, 'get_all_share_group_snapshots',
            mock.Mock(return_value=[fake_snap, fake_snap2]))
        req = fakes.HTTPRequest.blank('/share-group-snapshots?limit=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        res_dict['share_group_snapshots'][0].pop('links')

        self.assertEqual(1, len(res_dict['share_group_snapshots']))
        self.assertEqual([expected_snap], res_dict['share_group_snapshots'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_detail_with_limit_and_offset(self):
        fake_snap, expected_snap = self._get_fake_share_group_snapshot()
        fake_snap2, expected_snap2 = self._get_fake_share_group_snapshot(
            id="fake_id2")
        self.mock_object(
            self.controller.share_group_api, 'get_all_share_group_snapshots',
            mock.Mock(return_value=[fake_snap, fake_snap2]))
        req = fakes.HTTPRequest.blank(
            '/share-group-snapshots?limit=1&offset=1',
            version=self.api_version,
            experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        res_dict['share_group_snapshots'][0].pop('links')

        self.assertEqual(1, len(res_dict['share_group_snapshots']))
        self.assertEqual([expected_snap2], res_dict['share_group_snapshots'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_delete(self):
        fake_snap, expected_snap = self._get_fake_share_group_snapshot()
        self.mock_object(
            self.controller.share_group_api, 'get_share_group_snapshot',
            mock.Mock(return_value=fake_snap))
        self.mock_object(
            self.controller.share_group_api, 'delete_share_group_snapshot')

        res = self.controller.delete(self.request, fake_snap['id'])

        self.assertEqual(202, res.status_code)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

    def test_delete_not_found(self):
        fake_snap, expected_snap = self._get_fake_share_group_snapshot()
        self.mock_object(
            self.controller.share_group_api, 'get_share_group_snapshot',
            mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.delete, self.request, fake_snap['id'])

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

    def test_delete_in_conflicting_status(self):
        fake_snap, expected_snap = self._get_fake_share_group_snapshot()
        self.mock_object(
            self.controller.share_group_api, 'get_share_group_snapshot',
            mock.Mock(return_value=fake_snap))
        self.mock_object(
            self.controller.share_group_api, 'delete_share_group_snapshot',
            mock.Mock(side_effect=exception.InvalidShareGroupSnapshot(
                reason='blah')))

        self.assertRaises(
            webob.exc.HTTPConflict,
            self.controller.delete, self.request, fake_snap['id'])

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

    def test_show(self):
        fake_snap, expected_snap = self._get_fake_share_group_snapshot()
        self.mock_object(
            self.controller.share_group_api, 'get_share_group_snapshot',
            mock.Mock(return_value=fake_snap))

        res_dict = self.controller.show(self.request, fake_snap['id'])

        res_dict['share_group_snapshot'].pop('links')

        self.assertEqual(expected_snap, res_dict['share_group_snapshot'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get')

    def test_show_share_group_not_found(self):
        fake_snap, expected_snap = self._get_fake_share_group_snapshot()
        self.mock_object(
            self.controller.share_group_api, 'get_share_group_snapshot',
            mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.show, self.request, fake_snap['id'])

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get')

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _setup_share_group_snapshot_data(self, share_group_snapshot=None,
                                         version='2.31'):
        if share_group_snapshot is None:
            share_group_snapshot = db_utils.create_share_group_snapshot(
                'fake_id', status=constants.STATUS_AVAILABLE)

        path = ('/v2/fake/share-group-snapshots/%s/action' %
                share_group_snapshot['id'])
        req = fakes.HTTPRequest.blank(path, script_name=path, version=version)
        req.headers[wsgi.API_VERSION_REQUEST_HEADER] = version
        req.headers[wsgi.EXPERIMENTAL_API_REQUEST_HEADER] = 'True'
        return share_group_snapshot, req

    @ddt.data(*fakes.fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_share_group_snapshot_force_delete_with_different_roles(
            self, role,  resp_code, version):
        group_snap, req = self._setup_share_group_snapshot_data()
        ctxt = self._get_context(role)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        action_name = 'force_delete'
        body = {action_name: {'status': constants.STATUS_ERROR}}
        req.body = six.b(jsonutils.dumps(body))
        req.headers['X-Openstack-Manila-Api-Version'] = self.api_version
        req.environ['manila.context'] = ctxt

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # Validate response
        self.assertEqual(resp_code, resp.status_int)

    @ddt.data(*fakes.fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_share_group_snapshot_reset_status_with_different_roles(
            self, role, valid_code, valid_status, version):
        ctxt = self._get_context(role)
        group_snap, req = self._setup_share_group_snapshot_data()
        action_name = 'reset_status'
        body = {action_name: {'status': constants.STATUS_ERROR}}
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.body = six.b(jsonutils.dumps(body))
        req.headers['X-Openstack-Manila-Api-Version'] = self.api_version
        req.environ['manila.context'] = ctxt

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # Validate response code and model status
        self.assertEqual(valid_code, resp.status_int)

        if valid_code == 404:
            self.assertRaises(exception.NotFound,
                              db.share_group_snapshot_get,
                              ctxt,
                              group_snap['id'])
        else:
            actual_model = db.share_group_snapshot_get(ctxt, group_snap['id'])
            self.assertEqual(valid_status, actual_model['status'])
