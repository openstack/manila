# Copyright 2014 OpenStack Foundation
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

import mock
from webob import exc

from manila.api.v1 import share_servers
from manila.common import constants
from manila import context
from manila.db import api as db_api
from manila import exception
from manila import policy
from manila import test


fake_share_server_list = {
    'share_servers': [
        {
            'status': constants.STATUS_ACTIVE,
            'updated_at': None,
            'host': 'fake_host',
            'share_network_id': 'fake_sn_id',
            'share_network_name': 'fake_sn_name',
            'project_id': 'fake_project_id',
            'id': 'fake_server_id',
        },
        {
            'status': constants.STATUS_ERROR,
            'updated_at': None,
            'host': 'fake_host_2',
            'share_network_id': 'fake_sn_id_2',
            'share_network_name': 'fake_sn_id_2',
            'project_id': 'fake_project_id_2',
            'id': 'fake_server_id_2',
        },
    ]
}


fake_share_server_get_result = {
    'share_server': {
        'status': constants.STATUS_ACTIVE,
        'created_at': None,
        'updated_at': None,
        'host': 'fake_host',
        'share_network_name': 'fake_sn_name',
        'share_network_id': 'fake_sn_id',
        'project_id': 'fake_project_id',
        'id': 'fake_server_id',
        'backend_details': {
            'fake_key_1': 'fake_value_1',
            'fake_key_2': 'fake_value_2',
        }
    }
}

share_server_backend_details = {
    'fake_key_1': 'fake_value_1',
    'fake_key_2': 'fake_value_2',
}

fake_share_server_backend_details_get_result = {
    'details': share_server_backend_details
}


CONTEXT = context.get_admin_context()


class FakeShareServer(object):

    def __init__(self, *args, **kwargs):
        super(FakeShareServer, self).__init__()
        self.id = kwargs.get('id', 'fake_server_id')
        if 'created_at' in kwargs:
            self.created_at = kwargs.get('created_at', None)
        self.updated_at = kwargs.get('updated_at', None)
        self.host = kwargs.get('host', 'fake_host')
        self.share_network = kwargs.get('share_network', {
            'name': 'fake_sn_name', 'id': 'fake_sn_id',
            'project_id': 'fake_project_id'})
        self.share_network_id = kwargs.get('share_network_id',
                                           self.share_network['id'])
        self.status = kwargs.get('status', constants.STATUS_ACTIVE)
        self.project_id = self.share_network['project_id']
        self.backend_details = share_server_backend_details

    def __getitem__(self, item):
        return getattr(self, item)


def fake_share_server_get_all():
    fake_share_servers = [
        FakeShareServer(),
        FakeShareServer(id='fake_server_id_2',
                        host='fake_host_2',
                        share_network={
                            'name': None,
                            'id': 'fake_sn_id_2',
                            'project_id': 'fake_project_id_2'},
                        status=constants.STATUS_ERROR)
    ]
    return fake_share_servers


def fake_share_server_get():
    return FakeShareServer(created_at=None)


class FakeRequestAdmin(object):
    environ = {"manila.context": CONTEXT}
    GET = {}


class FakeRequestWithHost(FakeRequestAdmin):
    GET = {'host': fake_share_server_list['share_servers'][0]['host']}


class FakeRequestWithStatus(FakeRequestAdmin):
    GET = {'status': constants.STATUS_ERROR}


class FakeRequestWithProjectId(FakeRequestAdmin):
    GET = {'project_id': fake_share_server_get_all()[0].project_id}


class FakeRequestWithShareNetworkName(FakeRequestAdmin):
    GET = {
        'share_network': fake_share_server_get_all()[0].share_network['name'],
    }


class FakeRequestWithShareNetworkId(FakeRequestAdmin):
    GET = {
        'share_network': fake_share_server_get_all()[0].share_network['id'],
    }


class FakeRequestWithFakeFilter(FakeRequestAdmin):
    GET = {'fake_key': 'fake_value'}


class ShareServerAPITest(test.TestCase):

    def setUp(self):
        super(ShareServerAPITest, self).setUp()
        self.controller = share_servers.ShareServerController()
        self.resource_name = self.controller.resource_name
        self.mock_object(policy, 'check_policy',
                         mock.Mock(return_value=True))
        self.mock_object(db_api, 'share_server_get_all',
                         mock.Mock(return_value=fake_share_server_get_all()))

    def test_index_no_filters(self):
        result = self.controller.index(FakeRequestAdmin)
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(CONTEXT)
        self.assertEqual(fake_share_server_list, result)

    def test_index_host_filter(self):
        result = self.controller.index(FakeRequestWithHost)
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(CONTEXT)
        self.assertEqual([fake_share_server_list['share_servers'][0]],
                         result['share_servers'])

    def test_index_status_filter(self):
        result = self.controller.index(FakeRequestWithStatus)
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(CONTEXT)
        self.assertEqual([fake_share_server_list['share_servers'][1]],
                         result['share_servers'])

    def test_index_project_id_filter(self):
        result = self.controller.index(FakeRequestWithProjectId)
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(CONTEXT)
        self.assertEqual([fake_share_server_list['share_servers'][0]],
                         result['share_servers'])

    def test_index_share_network_filter_by_name(self):
        result = self.controller.index(FakeRequestWithShareNetworkName)
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(CONTEXT)
        self.assertEqual([fake_share_server_list['share_servers'][0]],
                         result['share_servers'])

    def test_index_share_network_filter_by_id(self):
        result = self.controller.index(FakeRequestWithShareNetworkId)
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(CONTEXT)
        self.assertEqual([fake_share_server_list['share_servers'][0]],
                         result['share_servers'])

    def test_index_fake_filter(self):
        result = self.controller.index(FakeRequestWithFakeFilter)
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(CONTEXT)
        self.assertEqual(0, len(result['share_servers']))

    def test_show(self):
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=fake_share_server_get()))
        result = self.controller.show(
            FakeRequestAdmin,
            fake_share_server_get_result['share_server']['id'])
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'show')
        db_api.share_server_get.assert_called_once_with(
            CONTEXT, fake_share_server_get_result['share_server']['id'])
        self.assertEqual(fake_share_server_get_result['share_server'],
                         result['share_server'])

    def test_details(self):
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=fake_share_server_get()))
        result = self.controller.details(
            FakeRequestAdmin,
            fake_share_server_get_result['share_server']['id'])
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'details')
        db_api.share_server_get.assert_called_once_with(
            CONTEXT, fake_share_server_get_result['share_server']['id'])
        self.assertEqual(fake_share_server_backend_details_get_result,
                         result)

    def test_delete_active_server(self):
        share_server = FakeShareServer(status=constants.STATUS_ACTIVE)
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.controller.share_api, 'delete_share_server')
        self.controller.delete(
            FakeRequestAdmin,
            fake_share_server_get_result['share_server']['id'])
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'delete')
        db_api.share_server_get.assert_called_once_with(
            CONTEXT, fake_share_server_get_result['share_server']['id'])
        self.controller.share_api.delete_share_server.assert_called_once_with(
            CONTEXT, share_server)

    def test_delete_error_server(self):
        share_server = FakeShareServer(status=constants.STATUS_ERROR)
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.controller.share_api, 'delete_share_server')
        self.controller.delete(
            FakeRequestAdmin,
            fake_share_server_get_result['share_server']['id'])
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'delete')
        db_api.share_server_get.assert_called_once_with(
            CONTEXT, fake_share_server_get_result['share_server']['id'])
        self.controller.share_api.delete_share_server.assert_called_once_with(
            CONTEXT, share_server)

    def test_delete_used_server(self):
        share_server_id = fake_share_server_get_result['share_server']['id']

        def raise_not_share_server_in_use(*args, **kwargs):
            raise exception.ShareServerInUse(share_server_id=share_server_id)

        share_server = fake_share_server_get()
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.controller.share_api, 'delete_share_server',
                         mock.Mock(side_effect=raise_not_share_server_in_use))
        self.assertRaises(exc.HTTPConflict,
                          self.controller.delete,
                          FakeRequestAdmin,
                          share_server_id)
        db_api.share_server_get.assert_called_once_with(CONTEXT,
                                                        share_server_id)
        self.controller.share_api.delete_share_server.assert_called_once_with(
            CONTEXT, share_server)

    def test_delete_not_found(self):
        share_server_id = fake_share_server_get_result['share_server']['id']

        def raise_not_found(*args, **kwargs):
            raise exception.ShareServerNotFound(
                share_server_id=share_server_id)

        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(side_effect=raise_not_found))
        self.assertRaises(exc.HTTPNotFound,
                          self.controller.delete,
                          FakeRequestAdmin,
                          share_server_id)
        db_api.share_server_get.assert_called_once_with(
            CONTEXT, share_server_id)
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'delete')

    def test_delete_creating_server(self):
        share_server = FakeShareServer(status=constants.STATUS_CREATING)
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.assertRaises(exc.HTTPForbidden,
                          self.controller.delete,
                          FakeRequestAdmin,
                          share_server['id'])
        policy.check_policy.assert_called_once_with(
            CONTEXT,
            self.resource_name, 'delete')

    def test_delete_deleting_server(self):
        share_server = FakeShareServer(status=constants.STATUS_DELETING)
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.assertRaises(exc.HTTPForbidden,
                          self.controller.delete,
                          FakeRequestAdmin,
                          share_server['id'])
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'delete')
