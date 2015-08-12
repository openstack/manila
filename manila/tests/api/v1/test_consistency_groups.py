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

import mock
from oslo_config import cfg
import six
import webob

import manila.api.v1.consistency_groups as cgs
from manila.common import constants
import manila.consistency_group.api as cg_api
from manila import exception
from manila.share import share_types
from manila import test
from manila.tests.api import fakes


CONF = cfg.CONF


class CGApiTest(test.TestCase):
    """Share Api Test."""
    def setUp(self):
        super(CGApiTest, self).setUp()
        self.controller = cgs.CGController()
        self.fake_share_type = {'id': six.text_type(uuid.uuid4())}
        self.api_version = '1.5'
        self.request = fakes.HTTPRequest.blank('/consistency-groups',
                                               version=self.api_version,
                                               experimental=True)

    def _get_fake_cg(self, **values):
        cg = {
            'id': 'fake_id',
            'user_id': 'fakeuser',
            'project_id': 'fakeproject',
            'status': constants.STATUS_CREATING,
            'name': None,
            'description': None,
            'host': None,
            'source_cgsnapshot_id': None,
            'share_network_id': None,
            'share_server_id': None,
            'share_types': [],
            'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        }

        cg.update(**values)

        expected_cg = copy.deepcopy(cg)
        del expected_cg['user_id']
        del expected_cg['share_server_id']
        expected_cg['links'] = mock.ANY
        expected_cg['share_types'] = [st['share_type_id']
                                      for st in cg.get('share_types')]
        return cg, expected_cg

    def _get_fake_simple_cg(self, **values):
        cg = {
            'id': 'fake_id',
            'name': None,
        }

        cg.update(**values)
        expected_cg = copy.deepcopy(cg)
        expected_cg['links'] = mock.ANY
        return cg, expected_cg

    def test_cg_create(self):
        fake_cg, expected_cg = self._get_fake_cg()
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {}}
        context = self.request.environ['manila.context']
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create.assert_called_once_with(
            context, share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_create_invalid_cgsnapshot_state(self):
        fake_snap_id = six.text_type(uuid.uuid4())
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(side_effect=exception.InvalidCGSnapshot(
                             reason='bad status'
                         )))

        body = {"consistency_group": {"source_cgsnapshot_id": fake_snap_id}}
        self.assertRaises(webob.exc.HTTPConflict,
                          self.controller.create, self.request, body)

    def test_cg_create_no_default_share_type(self):
        fake_cg, expected_cg = self._get_fake_cg()
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=None))
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

    def test_cg_create_with_name(self):
        fake_name = 'fake_name'
        fake_cg, expected_cg = self._get_fake_cg(name=fake_name)
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {"name": fake_name}}
        context = self.request.environ['manila.context']
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create.assert_called_once_with(
            context, name=fake_name,
            share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_create_with_description(self):
        fake_description = 'fake_description'
        fake_cg, expected_cg = self._get_fake_cg(description=fake_description)
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {"description": fake_description}}
        context = self.request.environ['manila.context']
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create.assert_called_once_with(
            context, description=fake_description,
            share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_create_with_share_types(self):
        fake_share_types = [{"share_type_id": self.fake_share_type['id']}]
        fake_cg, expected_cg = self._get_fake_cg(share_types=fake_share_types)
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {
            "share_types": [self.fake_share_type['id']]}}
        context = self.request.environ['manila.context']
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create.assert_called_once_with(
            context, share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_create_with_source_cgsnapshot_id(self):
        fake_snap_id = six.text_type(uuid.uuid4())
        fake_cg, expected_cg = self._get_fake_cg(
            source_cgsnapshot_id=fake_snap_id)

        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {
                "source_cgsnapshot_id": fake_snap_id}}
        context = self.request.environ['manila.context']
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create.assert_called_once_with(
            context, source_cgsnapshot_id=fake_snap_id)
        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_create_with_share_network_id(self):
        fake_net_id = six.text_type(uuid.uuid4())
        fake_cg, expected_cg = self._get_fake_cg(
            share_network_id=fake_net_id)

        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {
                "share_network_id": fake_net_id}}
        context = self.request.environ['manila.context']
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create.assert_called_once_with(
            context, share_network_id=fake_net_id, share_type_ids=mock.ANY)
        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_create_no_default_share_type_with_cgsnapshot(self):
        fake_snap_id = six.text_type(uuid.uuid4())
        fake_cg, expected_cg = self._get_fake_cg()
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=None))
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {
                "source_cgsnapshot_id": fake_snap_id}}
        context = self.request.environ['manila.context']
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create.assert_called_once_with(
            context, source_cgsnapshot_id=fake_snap_id)
        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_create_with_name_and_description(self):
        fake_name = 'fake_name'
        fake_description = 'fake_description'
        fake_cg, expected_cg = self._get_fake_cg(name=fake_name,
                                                 description=fake_description)
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.cg_api, 'create',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {"name": fake_name,
                                      "description": fake_description}}
        context = self.request.environ['manila.context']
        res_dict = self.controller.create(self.request, body)

        self.controller.cg_api.create.assert_called_once_with(
            context, name=fake_name, description=fake_description,
            share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_create_invalid_body(self):
        body = {"not_consistency_group": {}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

    def test_cg_create_invalid_body_share_types_and_source_cgsnapshot(self):
        body = {"consistency_group": {"share_types": [],
                                      "source_cgsnapshot_id": ""}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

    def test_cg_create_source_cgsnapshot_not_in_available(self):
        fake_snap_id = six.text_type(uuid.uuid4())
        body = {"consistency_group": {"source_cgsnapshot_id": fake_snap_id}}
        self.mock_object(self.controller.cg_api, 'create', mock.Mock(
            side_effect=exception.InvalidCGSnapshot(reason='blah')))
        self.assertRaises(webob.exc.HTTPConflict, self.controller.create,
                          self.request, body)

    def test_cg_create_source_cgsnapshot_does_not_exist(self):
        fake_snap_id = six.text_type(uuid.uuid4())
        body = {"consistency_group": {"source_cgsnapshot_id": fake_snap_id}}
        self.mock_object(self.controller.cg_api, 'create', mock.Mock(
            side_effect=exception.CGSnapshotNotFound(
                cgsnapshot_id=fake_snap_id)))
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

    def test_cg_create_source_cgsnapshot_not_a_uuid(self):
        fake_snap_id = "Not a uuid"
        body = {"consistency_group": {"source_cgsnapshot_id": fake_snap_id}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

    def test_cg_create_share_network_id_not_a_uuid(self):
        fake_net_id = "Not a uuid"
        body = {"consistency_group": {"share_network_id": fake_net_id}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

    def test_cg_create_invalid_body_share_types_not_a_list(self):
        body = {"consistency_group": {"share_types": ""}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

    def test_cg_create_invalid_body_invalid_field(self):
        body = {"consistency_group": {"unknown_field": ""}}
        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.create,
                                self.request, body)
        self.assertTrue('unknown_field' in six.text_type(exc))

    def test_cg_create_with_invalid_share_types_field(self):
        body = {"consistency_group": {"share_types": 'iamastring'}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

    def test_cg_create_with_invalid_share_types_field_not_uuids(self):
        body = {"consistency_group": {"share_types": ['iamastring']}}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

    def test_cg_update_with_name_and_description(self):
        fake_name = 'fake_name'
        fake_description = 'fake_description'
        fake_cg, expected_cg = self._get_fake_cg(name=fake_name,
                                                 description=fake_description)
        self.mock_object(self.controller.cg_api, 'get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.controller.cg_api, 'update',
                         mock.Mock(return_value=fake_cg))

        body = {"consistency_group": {"name": fake_name,
                                      "description": fake_description}}
        context = self.request.environ['manila.context']
        res_dict = self.controller.update(self.request, fake_cg['id'], body)

        self.controller.cg_api.update.assert_called_once_with(
            context, fake_cg,
            {"name": fake_name, "description": fake_description})
        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_update_cg_not_found(self):
        body = {"consistency_group": {}}
        self.mock_object(self.controller.cg_api, 'get',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.update,
                          self.request, 'fake_id', body)

    def test_cg_update_invalid_body(self):
        body = {"not_consistency_group": {}}
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update,
                          self.request, 'fake_id', body)

    def test_cg_update_invalid_body_invalid_field(self):
        body = {"consistency_group": {"unknown_field": ""}}
        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.update,
                                self.request, 'fake_id', body)
        self.assertTrue('unknown_field' in six.text_type(exc))

    def test_cg_update_invalid_body_readonly_field(self):
        body = {"consistency_group": {"share_types": []}}
        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.update,
                                self.request, 'fake_id', body)
        self.assertTrue('share_types' in six.text_type(exc))

    def test_cg_list_index(self):
        fake_cg, expected_cg = self._get_fake_simple_cg()
        self.mock_object(cg_api.API, 'get_all',
                         mock.Mock(return_value=[fake_cg]))
        res_dict = self.controller.index(self.request)
        self.assertEqual([expected_cg], res_dict['consistency_groups'])

    def test_cg_list_index_no_cgs(self):
        self.mock_object(cg_api.API, 'get_all',
                         mock.Mock(return_value=[]))
        res_dict = self.controller.index(self.request)
        self.assertEqual([], res_dict['consistency_groups'])

    def test_cg_list_index_with_limit(self):
        fake_cg, expected_cg = self._get_fake_simple_cg()
        fake_cg2, expected_cg2 = self._get_fake_simple_cg(id="fake_id2")
        self.mock_object(cg_api.API, 'get_all',
                         mock.Mock(return_value=[fake_cg, fake_cg2]))
        req = fakes.HTTPRequest.blank('/consistency_groups?limit=1',
                                      version=self.api_version,
                                      experimental=True)
        res_dict = self.controller.index(req)
        self.assertEqual(1, len(res_dict['consistency_groups']))
        self.assertEqual([expected_cg], res_dict['consistency_groups'])

    def test_cg_list_index_with_limit_and_offset(self):
        fake_cg, expected_cg = self._get_fake_simple_cg()
        fake_cg2, expected_cg2 = self._get_fake_simple_cg(id="fake_id2")
        self.mock_object(cg_api.API, 'get_all',
                         mock.Mock(return_value=[fake_cg, fake_cg2]))
        req = fakes.HTTPRequest.blank('/consistency_groups?limit=1&offset=1',
                                      version=self.api_version,
                                      experimental=True)

        res_dict = self.controller.index(req)

        self.assertEqual(1, len(res_dict['consistency_groups']))
        self.assertEqual([expected_cg2], res_dict['consistency_groups'])

    def test_cg_list_detail(self):
        fake_cg, expected_cg = self._get_fake_cg()
        self.mock_object(cg_api.API, 'get_all',
                         mock.Mock(return_value=[fake_cg]))

        res_dict = self.controller.detail(self.request)

        self.assertEqual([expected_cg], res_dict['consistency_groups'])

    def test_cg_list_detail_no_cgs(self):
        self.mock_object(cg_api.API, 'get_all',
                         mock.Mock(return_value=[]))

        res_dict = self.controller.detail(self.request)

        self.assertEqual([], res_dict['consistency_groups'])

    def test_cg_list_detail_with_limit(self):
        fake_cg, expected_cg = self._get_fake_cg()
        fake_cg2, expected_cg2 = self._get_fake_cg(id="fake_id2")
        self.mock_object(cg_api.API, 'get_all',
                         mock.Mock(return_value=[fake_cg, fake_cg2]))
        req = fakes.HTTPRequest.blank('/consistency_groups?limit=1',
                                      version=self.api_version,
                                      experimental=True)

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['consistency_groups']))
        self.assertEqual([expected_cg], res_dict['consistency_groups'])

    def test_cg_list_detail_with_limit_and_offset(self):
        fake_cg, expected_cg = self._get_fake_cg()
        fake_cg2, expected_cg2 = self._get_fake_cg(id="fake_id2")
        self.mock_object(cg_api.API, 'get_all',
                         mock.Mock(return_value=[fake_cg, fake_cg2]))
        req = fakes.HTTPRequest.blank('/consistency_groups?limit=1&offset=1',
                                      version=self.api_version,
                                      experimental=True)

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['consistency_groups']))
        self.assertEqual([expected_cg2], res_dict['consistency_groups'])

    def test_cg_delete(self):
        fake_cg, expected_cg = self._get_fake_cg()
        self.mock_object(cg_api.API, 'get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(cg_api.API, 'delete')

        res = self.controller.delete(self.request, fake_cg['id'])

        self.assertEqual(202, res.status_code)

    def test_cg_delete_cg_not_found(self):
        fake_cg, expected_cg = self._get_fake_cg()
        self.mock_object(cg_api.API, 'get',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.delete,
                          self.request, fake_cg['id'])

    def test_cg_delete_in_conflicting_status(self):
        fake_cg, expected_cg = self._get_fake_cg()
        self.mock_object(cg_api.API, 'get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(cg_api.API, 'delete', mock.Mock(
            side_effect=exception.InvalidConsistencyGroup(reason='blah')))

        self.assertRaises(webob.exc.HTTPConflict, self.controller.delete,
                          self.request, fake_cg['id'])

    def test_cg_show(self):
        fake_cg, expected_cg = self._get_fake_cg()
        self.mock_object(cg_api.API, 'get',
                         mock.Mock(return_value=fake_cg))
        req = fakes.HTTPRequest.blank(
            '/consistency_groups/%s' % fake_cg['id'],
            version=self.api_version, experimental=True)

        res_dict = self.controller.show(req, fake_cg['id'])

        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_show_as_admin(self):
        fake_cg, expected_cg = self._get_fake_cg()
        expected_cg['share_server_id'] = None
        self.mock_object(cg_api.API, 'get',
                         mock.Mock(return_value=fake_cg))
        req = fakes.HTTPRequest.blank(
            '/consistency_groups/%s' % fake_cg['id'],
            version=self.api_version, experimental=True)
        admin_context = req.environ['manila.context'].elevated()
        req.environ['manila.context'] = admin_context

        res_dict = self.controller.show(req, fake_cg['id'])

        self.assertEqual(expected_cg, res_dict['consistency_group'])

    def test_cg_show_cg_not_found(self):
        fake_cg, expected_cg = self._get_fake_cg()
        self.mock_object(cg_api.API, 'get',
                         mock.Mock(side_effect=exception.NotFound))
        req = fakes.HTTPRequest.blank(
            '/consistency_groups/%s' % fake_cg['id'],
            version=self.api_version, experimental=True)

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          req, fake_cg['id'])
