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

import ddt
import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import six
import webob

from manila.api.openstack import wsgi
import manila.api.v2.share_groups as share_groups
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila import policy
from manila.share import share_types
from manila.share_group import api as share_group_api
from manila.share_group import share_group_types
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils


CONF = cfg.CONF


@ddt.ddt
class ShareGroupAPITest(test.TestCase):
    """Consistency Groups API Test suite."""

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = share_groups.ShareGroupController()
        self.resource_name = self.controller.resource_name
        self.fake_share_type = {'id': six.text_type(uuidutils.generate_uuid())}
        self.fake_share_group_type = {
            'id': six.text_type(uuidutils.generate_uuid())}
        self.api_version = '2.34'
        self.request = fakes.HTTPRequest.blank(
            '/share-groups', version=self.api_version, experimental=True)
        self.flags(rpc_backend='manila.openstack.common.rpc.impl_fake')
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.context = self.request.environ['manila.context']
        self.mock_object(share_group_types, 'get_default',
                         mock.Mock(return_value=self.fake_share_group_type))
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _setup_share_group_data(self, share_group=None, version='2.31'):
        if share_group is None:
            share_group = db_utils.create_share_group(
                status=constants.STATUS_AVAILABLE)
        path = '/v2/fake/share-groups/%s/action' % share_group['id']
        req = fakes.HTTPRequest.blank(path, script_name=path, version=version)
        req.headers[wsgi.API_VERSION_REQUEST_HEADER] = version
        req.headers[wsgi.EXPERIMENTAL_API_REQUEST_HEADER] = 'True'

        return share_group, req

    def _get_fake_share_group(self, ctxt=None, **values):
        if ctxt is None:
            ctxt = self.context

        share_group_db_dict = {
            'id': 'fake_id',
            'user_id': 'fakeuser',
            'project_id': 'fakeproject',
            'status': constants.STATUS_CREATING,
            'name': 'fake name',
            'description': 'fake description',
            'host': None,
            'availability_zone': None,
            'consistent_snapshot_support': None,
            'source_share_group_snapshot_id': None,
            'share_group_type_id': self.fake_share_group_type.get('id'),
            'share_network_id': uuidutils.generate_uuid(),
            'share_server_id': uuidutils.generate_uuid(),
            'share_types': [],
            'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        }

        share_group_db_dict.update(**values)

        expected_share_group = {
            'id': share_group_db_dict['id'],
            'project_id': share_group_db_dict['project_id'],
            'status': share_group_db_dict['status'],
            'name': share_group_db_dict['name'],
            'description': share_group_db_dict['description'],
            'host': share_group_db_dict['host'],
            'availability_zone': share_group_db_dict['availability_zone'],
            'consistent_snapshot_support': share_group_db_dict[
                'consistent_snapshot_support'],
            'source_share_group_snapshot_id': share_group_db_dict[
                'source_share_group_snapshot_id'],
            'share_group_type_id': share_group_db_dict['share_group_type_id'],
            'share_network_id': share_group_db_dict['share_network_id'],
            'share_server_id': share_group_db_dict['share_server_id'],
            'share_types': [st['share_type_id']
                            for st in share_group_db_dict.get('share_types')],
            'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
            'links': mock.ANY,
        }
        if not ctxt.is_admin:
            del expected_share_group['share_server_id']

        return share_group_db_dict, expected_share_group

    def _get_fake_simple_share_group(self, **values):
        share_group = {'id': 'fake_id', 'name': None}
        share_group.update(**values)
        expected_share_group = copy.deepcopy(share_group)
        expected_share_group['links'] = mock.ANY
        return share_group, expected_share_group

    def test_share_group_create(self):
        fake, expected = self._get_fake_share_group()
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake))
        body = {"share_group": {}}

        res_dict = self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context, share_group_type_id=self.fake_share_group_type['id'],
            share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_group_create_invalid_group_snapshot_state(self):
        fake_snap_id = six.text_type(uuidutils.generate_uuid())
        self.mock_object(
            self.controller.share_group_api, 'create',
            mock.Mock(side_effect=exception.InvalidShareGroupSnapshot(
                reason='bad status',
            )))
        body = {
            "share_group": {
                "source_share_group_snapshot_id": fake_snap_id
            }
        }

        self.assertRaises(webob.exc.HTTPConflict,
                          self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_no_default_share_type(self):
        fake_group, expected_group = self._get_fake_share_group()
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=None))
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake_group))
        body = {"share_group": {}}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_no_default_group_type(self):
        fake_group, expected_group = self._get_fake_share_group()
        self.mock_object(
            share_group_types, 'get_default', mock.Mock(return_value=None))
        self.mock_object(
            self.controller.share_group_api, 'create',
            mock.Mock(return_value=fake_group))
        body = {"share_group": {}}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_group_type_specified(self):
        fake_share_group, expected_group = self._get_fake_share_group()
        self.mock_object(
            share_group_types, 'get_default', mock.Mock(return_value=None))
        self.mock_object(
            self.controller.share_group_api, 'create',
            mock.Mock(return_value=fake_share_group))
        body = {
            "share_group": {
                "share_group_type_id": self.fake_share_group_type.get('id'),
            }
        }

        self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context,
            share_group_type_id=self.fake_share_group_type['id'],
            share_type_ids=[self.fake_share_type['id']])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_invalid_group_type_specified(self):
        fake_share_group, expected_share_group = self._get_fake_share_group()
        self.mock_object(
            share_group_types, 'get_default', mock.Mock(return_value=None))
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake_share_group))
        body = {"share_group": {"group_type_id": "invalid"}}

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_az(self):
        fake_az_name = 'fake_az_name'
        fake_az_id = 'fake_az_id'
        fake_share_group, expected_share_group = self._get_fake_share_group(
            availability_zone_id=fake_az_id)
        self.mock_object(
            self.controller.share_group_api, 'create',
            mock.Mock(return_value=fake_share_group))
        self.mock_object(
            share_groups.db, 'availability_zone_get',
            mock.Mock(return_value=type(
                'FakeAZ', (object, ), {
                    'id': fake_az_id,
                    'name': fake_az_name,
                })))

        body = {"share_group": {"availability_zone": fake_az_name}}

        res_dict = self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context, availability_zone_id=fake_az_id,
            share_group_type_id=self.fake_share_group_type['id'],
            share_type_ids=[self.fake_share_type['id']])
        share_groups.db.availability_zone_get.assert_called_once_with(
            self.context, fake_az_name)
        self.assertEqual(expected_share_group, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_az_and_source_share_group_snapshot(self):
        fake_az_name = 'fake_az_name'
        fake_az_id = 'fake_az_id'
        fake_share_group, expected_share_group = self._get_fake_share_group(
            availability_zone_id=fake_az_id)
        self.mock_object(
            self.controller.share_group_api, 'create',
            mock.Mock(return_value=fake_share_group))
        self.mock_object(
            share_groups.db, 'availability_zone_get',
            mock.Mock(return_value=type(
                'FakeAZ', (object, ), {
                    'id': fake_az_id,
                    'name': fake_az_name,
                })))

        body = {"share_group": {
            "availability_zone": fake_az_name,
            "source_share_group_snapshot_id": 'fake_sgs_id',
        }}

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.create,
            self.request, body)

        self.controller.share_group_api.create.assert_not_called()
        share_groups.db.availability_zone_get.assert_not_called()
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_nonexistent_az(self):
        fake_az_name = 'fake_az_name'
        fake_az_id = 'fake_az_id'
        fake_share_group, expected_share_group = self._get_fake_share_group(
            availability_zone_id=fake_az_id)
        self.mock_object(
            self.controller.share_group_api, 'create',
            mock.Mock(return_value=fake_share_group))
        self.mock_object(
            share_groups.db, 'availability_zone_get',
            mock.Mock(
                side_effect=exception.AvailabilityZoneNotFound(id=fake_az_id)))

        body = {"share_group": {"availability_zone": fake_az_name}}

        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.create, self.request, body)

        self.assertEqual(0, self.controller.share_group_api.create.call_count)
        share_groups.db.availability_zone_get.assert_called_once_with(
            self.context, fake_az_name)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_name(self):
        fake_name = 'fake_name'
        fake_share_group, expected_share_group = self._get_fake_share_group(
            name=fake_name)
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake_share_group))
        body = {"share_group": {"name": fake_name}}

        res_dict = self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context, name=fake_name,
            share_group_type_id=self.fake_share_group_type['id'],
            share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected_share_group, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_description(self):
        fake_description = 'fake_description'
        fake_share_group, expected_share_group = self._get_fake_share_group(
            description=fake_description)
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake_share_group))
        body = {"share_group": {"description": fake_description}}

        res_dict = self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context, description=fake_description,
            share_group_type_id=self.fake_share_group_type['id'],
            share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected_share_group, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_share_types(self):
        fake_share_types = [{"share_type_id": self.fake_share_type['id']}]
        fake_group, expected_group = self._get_fake_share_group(
            share_types=fake_share_types)
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake_group))
        body = {
            "share_group": {
                "share_types": [self.fake_share_type['id']]
            }
        }

        res_dict = self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context, share_group_type_id=self.fake_share_group_type['id'],
            share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected_group, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_sg_create_with_source_sg_snapshot_id_and_share_network(self):
        fake_snap_id = six.text_type(uuidutils.generate_uuid())
        fake_net_id = six.text_type(uuidutils.generate_uuid())
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        mock_api_call = self.mock_object(
            self.controller.share_group_api, 'create')
        body = {
            "share_group": {
                "source_share_group_snapshot_id": fake_snap_id,
                "share_network_id": fake_net_id,
            }
        }

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create,
                          self.request, body)

        self.assertFalse(mock_api_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_source_sg_snapshot_id(self):
        fake_snap_id = six.text_type(uuidutils.generate_uuid())
        fake_share_group, expected_group = self._get_fake_share_group(
            source_share_group_snapshot_id=fake_snap_id)
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake_share_group))

        body = {
            "share_group": {
                "source_share_group_snapshot_id": fake_snap_id,
            }
        }

        res_dict = self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context, share_group_type_id=self.fake_share_group_type['id'],
            source_share_group_snapshot_id=fake_snap_id)
        self.assertEqual(expected_group, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_share_network_id(self):
        fake_net_id = six.text_type(uuidutils.generate_uuid())
        fake_group, expected_group = self._get_fake_share_group(
            share_network_id=fake_net_id)

        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake_group))
        body = {
            "share_group": {
                "share_network_id": fake_net_id,
            }
        }

        res_dict = self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context, share_network_id=fake_net_id,
            share_group_type_id=self.fake_share_group_type['id'],
            share_type_ids=mock.ANY)
        self.assertEqual(expected_group, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_sg_create_no_default_share_type_with_share_group_snapshot(self):
        fake_snap_id = six.text_type(uuidutils.generate_uuid())
        fake, expected = self._get_fake_share_group()
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=None))
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake))
        body = {
            "share_group": {
                "source_share_group_snapshot_id": fake_snap_id,
            }
        }

        res_dict = self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context, share_group_type_id=self.fake_share_group_type['id'],
            source_share_group_snapshot_id=fake_snap_id)
        self.assertEqual(expected, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_name_and_description(self):
        fake_name = 'fake_name'
        fake_description = 'fake_description'
        fake_group, expected_group = self._get_fake_share_group(
            name=fake_name, description=fake_description)
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(return_value=self.fake_share_type))
        self.mock_object(self.controller.share_group_api, 'create',
                         mock.Mock(return_value=fake_group))
        body = {
            "share_group": {
                "name": fake_name,
                "description": fake_description
            }
        }

        res_dict = self.controller.create(self.request, body)

        self.controller.share_group_api.create.assert_called_once_with(
            self.context, name=fake_name, description=fake_description,
            share_group_type_id=self.fake_share_group_type['id'],
            share_type_ids=[self.fake_share_type['id']])
        self.assertEqual(expected_group, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_invalid_body(self):
        body = {"not_group": {}}

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_group_create_invalid_body_share_types_and_source_group_snapshot(
            self):
        body = {
            "share_group": {
                "share_types": [],
                "source_share_group_snapshot_id": "",
            }
        }
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_source_group_snapshot_not_in_available(self):
        fake_snap_id = six.text_type(uuidutils.generate_uuid())
        body = {
            "share_group": {
                "source_share_group_snapshot_id": fake_snap_id,
            }
        }
        self.mock_object(self.controller.share_group_api, 'create', mock.Mock(
            side_effect=exception.InvalidShareGroupSnapshot(reason='blah')))

        self.assertRaises(
            webob.exc.HTTPConflict, self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_source_group_snapshot_does_not_exist(self):
        fake_snap_id = six.text_type(uuidutils.generate_uuid())
        body = {
            "share_group": {"source_share_group_snapshot_id": fake_snap_id}
        }
        self.mock_object(
            self.controller.share_group_api, 'create',
            mock.Mock(side_effect=exception.ShareGroupSnapshotNotFound(
                share_group_snapshot_id=fake_snap_id)))

        self.assertRaises(
            webob.exc.HTTPBadRequest,
            self.controller.create, self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_source_group_snapshot_not_a_uuid(self):
        fake_snap_id = "Not a uuid"
        body = {
            "share_group": {
                "source_share_group_snapshot_id": fake_snap_id,
            }
        }

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_share_network_id_not_a_uuid(self):
        fake_net_id = "Not a uuid"
        body = {"share_group": {"share_network_id": fake_net_id}}

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_invalid_body_share_types_not_a_list(self):
        body = {"share_group": {"share_types": ""}}

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_invalid_body_invalid_field(self):
        body = {"share_group": {"unknown_field": ""}}

        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.create,
                                self.request, body)

        self.assertIn('unknown_field', six.text_type(exc))
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_invalid_share_types_field(self):
        body = {"share_group": {"share_types": 'iamastring'}}

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_create_with_invalid_share_types_field_not_uuids(self):
        body = {"share_group": {"share_types": ['iamastring']}}

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.create,
                          self.request, body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'create')

    def test_share_group_update_with_name_and_description(self):
        fake_name = 'fake_name'
        fake_description = 'fake_description'
        fake_group, expected_group = self._get_fake_share_group(
            name=fake_name, description=fake_description)
        self.mock_object(self.controller.share_group_api, 'get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.controller.share_group_api, 'update',
                         mock.Mock(return_value=fake_group))
        body = {
            "share_group": {
                "name": fake_name,
                "description": fake_description,
            }
        }
        context = self.request.environ['manila.context']

        res_dict = self.controller.update(self.request, fake_group['id'], body)

        self.controller.share_group_api.update.assert_called_once_with(
            context, fake_group,
            {"name": fake_name, "description": fake_description})
        self.assertEqual(expected_group, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_share_group_update_group_not_found(self):
        body = {"share_group": {}}
        self.mock_object(self.controller.share_group_api, 'get',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.update,
                          self.request, 'fake_id', body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_share_group_update_invalid_body(self):
        body = {"not_group": {}}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update,
                          self.request, 'fake_id', body)

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_share_group_update_invalid_body_invalid_field(self):
        body = {"share_group": {"unknown_field": ""}}

        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.update,
                                self.request, 'fake_id', body)

        self.assertIn('unknown_field', six.text_type(exc))
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_share_group_update_invalid_body_readonly_field(self):
        body = {"share_group": {"share_types": []}}

        exc = self.assertRaises(webob.exc.HTTPBadRequest,
                                self.controller.update,
                                self.request, 'fake_id', body)

        self.assertIn('share_types', six.text_type(exc))
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'update')

    def test_share_group_list_index(self):
        fake, expected = self._get_fake_simple_share_group()
        self.mock_object(
            share_group_api.API, 'get_all', mock.Mock(return_value=[fake]))

        res_dict = self.controller.index(self.request)

        self.assertEqual([expected], res_dict['share_groups'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_share_group_list_index_no_groups(self):
        self.mock_object(
            share_group_api.API, 'get_all', mock.Mock(return_value=[]))

        res_dict = self.controller.index(self.request)

        self.assertEqual([], res_dict['share_groups'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_share_group_list_index_with_limit(self):
        fake, expected = self._get_fake_simple_share_group()
        fake2, expected2 = self._get_fake_simple_share_group(id="fake_id2")
        self.mock_object(
            share_group_api.API, 'get_all',
            mock.Mock(return_value=[fake, fake2]))
        req = fakes.HTTPRequest.blank(
            '/share-groups?limit=1', version=self.api_version,
            experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req)

        self.assertEqual(1, len(res_dict['share_groups']))
        self.assertEqual([expected], res_dict['share_groups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_share_group_list_index_with_limit_and_offset(self):
        fake, expected = self._get_fake_simple_share_group()
        fake2, expected2 = self._get_fake_simple_share_group(
            id="fake_id2")
        self.mock_object(share_group_api.API, 'get_all',
                         mock.Mock(return_value=[fake, fake2]))
        req = fakes.HTTPRequest.blank(
            '/share-groups?limit=1&offset=1', version=self.api_version,
            experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req)

        self.assertEqual(1, len(res_dict['share_groups']))
        self.assertEqual([expected2], res_dict['share_groups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_share_group_list_index_with_like_filter(self):
        fake, expected = self._get_fake_simple_share_group(
            name='fake_1', description='fake_ds_1')
        fake2, expected2 = self._get_fake_simple_share_group(
            name='fake_2', description='fake_ds_2')
        self.mock_object(share_group_api.API, 'get_all',
                         mock.Mock(return_value=[fake, fake2]))
        req = fakes.HTTPRequest.blank(
            '/share-groups?name~=fake&description~=fake',
            version='2.36',
            experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req)

        expected.pop('description')
        expected2.pop('description')
        self.assertEqual(2, len(res_dict['share_groups']))
        self.assertEqual([expected, expected2], res_dict['share_groups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_share_group_list_detail(self):
        fake, expected = self._get_fake_share_group()
        self.mock_object(
            share_group_api.API, 'get_all', mock.Mock(return_value=[fake]))

        res_dict = self.controller.detail(self.request)

        self.assertEqual([expected], res_dict['share_groups'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_share_group_list_detail_no_groups(self):
        self.mock_object(
            share_group_api.API, 'get_all', mock.Mock(return_value=[]))

        res_dict = self.controller.detail(self.request)

        self.assertEqual([], res_dict['share_groups'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'get_all')

    def test_share_group_list_detail_with_limit(self):
        req = fakes.HTTPRequest.blank('/share-groups?limit=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']
        fake_group, expected_group = self._get_fake_share_group(
            ctxt=req_context)
        fake_group2, expected_group2 = self._get_fake_share_group(
            ctxt=req_context, id="fake_id2")
        self.mock_object(share_group_api.API, 'get_all',
                         mock.Mock(return_value=[fake_group, fake_group2]))

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_groups']))
        self.assertEqual([expected_group], res_dict['share_groups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_share_group_list_detail_with_limit_and_offset(self):
        req = fakes.HTTPRequest.blank('/share-groups?limit=1&offset=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']
        fake_group, expected_group = self._get_fake_share_group(
            ctxt=req_context)
        fake_group2, expected_group2 = self._get_fake_share_group(
            id="fake_id2", ctxt=req_context)
        self.mock_object(share_group_api.API, 'get_all',
                         mock.Mock(return_value=[fake_group, fake_group2]))

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_groups']))
        self.assertEqual([expected_group2], res_dict['share_groups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_share_group_delete(self):
        fake_group, expected_group = self._get_fake_share_group()
        self.mock_object(share_group_api.API, 'get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(share_group_api.API, 'delete')

        res = self.controller.delete(self.request, fake_group['id'])

        self.assertEqual(202, res.status_code)
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

    def test_share_group_delete_group_not_found(self):
        fake_group, expected_group = self._get_fake_share_group()
        self.mock_object(share_group_api.API, 'get',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.delete,
                          self.request, fake_group['id'])
        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

    def test_share_group_delete_in_conflicting_status(self):
        fake, expected = self._get_fake_share_group()
        self.mock_object(
            share_group_api.API, 'get', mock.Mock(return_value=fake))
        self.mock_object(share_group_api.API, 'delete', mock.Mock(
            side_effect=exception.InvalidShareGroup(reason='blah')))

        self.assertRaises(
            webob.exc.HTTPConflict,
            self.controller.delete, self.request, fake['id'])

        self.mock_policy_check.assert_called_once_with(
            self.context, self.resource_name, 'delete')

    def test_share_group_show(self):
        fake, expected = self._get_fake_share_group()
        self.mock_object(
            share_group_api.API, 'get', mock.Mock(return_value=fake))
        req = fakes.HTTPRequest.blank(
            '/share-groupss/%s' % fake['id'], version=self.api_version,
            experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.show(req, fake['id'])

        self.assertEqual(expected, res_dict['share_group'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get')

    def test_share_group_show_as_admin(self):
        req = fakes.HTTPRequest.blank(
            '/share-groupss/my_group_id',
            version=self.api_version, experimental=True)
        admin_context = req.environ['manila.context'].elevated()
        req.environ['manila.context'] = admin_context
        fake_group, expected_group = self._get_fake_share_group(
            ctxt=admin_context, id='my_group_id')
        self.mock_object(share_group_api.API, 'get',
                         mock.Mock(return_value=fake_group))

        res_dict = self.controller.show(req, fake_group['id'])

        self.assertEqual(expected_group, res_dict['share_group'])
        self.assertIsNotNone(res_dict['share_group']['share_server_id'])
        self.mock_policy_check.assert_called_once_with(
            admin_context, self.resource_name, 'get')

    def test_share_group_show_group_not_found(self):
        req = fakes.HTTPRequest.blank(
            '/share-groupss/myfakegroup',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']
        fake, expected = self._get_fake_share_group(
            ctxt=req_context, id='myfakegroup')
        self.mock_object(share_group_api.API, 'get',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(
            webob.exc.HTTPNotFound, self.controller.show, req, fake['id'])

        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get')

    @ddt.data(*fakes.fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_share_groups_reset_status_with_different_roles(
            self, role, valid_code, valid_status, version):
        ctxt = self._get_context(role)
        share_group, req = self._setup_share_group_data()

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

        # validate response code and model status
        self.assertEqual(valid_code, resp.status_int)

        if valid_code == 404:
            self.assertRaises(
                exception.NotFound,
                db.share_group_get, ctxt, share_group['id'])
        else:
            actual_model = db.share_group_get(ctxt, share_group['id'])
            self.assertEqual(valid_status, actual_model['status'])

    @ddt.data(*fakes.fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_share_group_force_delete_with_different_roles(self, role,
                                                           resp_code, version):
        ctxt = self._get_context(role)
        share_group, req = self._setup_share_group_data()
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        action_name = 'force_delete'
        body = {action_name: {}}
        req.body = six.b(jsonutils.dumps(body))
        req.headers['X-Openstack-Manila-Api-Version'] = self.api_version
        req.environ['manila.context'] = ctxt

        with mock.patch.object(
                policy, 'check_policy', fakes.mock_fake_admin_check):
            resp = req.get_response(fakes.app())

        # validate response
        self.assertEqual(resp_code, resp.status_int)
