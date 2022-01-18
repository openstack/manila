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

from unittest import mock

import copy
import ddt
from webob import exc

from manila.api.openstack import api_version_request as api_version
from manila.api.v1 import share_servers
from manila.common import constants
from manila import context
from manila.db import api as db_api
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes

fake_share_server_list = {
    'share_servers': [
        {
            'status': constants.STATUS_ACTIVE,
            'updated_at': None,
            'host': 'fake_host',
            'share_network_name': 'fake_sn_name',
            'share_network_id': 'fake_sn_id',
            'share_network_subnet_ids': ['fake_sns_id'],
            'project_id': 'fake_project_id',
            'id': 'fake_server_id',
            'is_auto_deletable': False,
            'task_state': None,
            'source_share_server_id': None,
            'identifier': 'fake_id',
            'security_service_update_support': False,
            'network_allocation_update_support': False
        },
        {
            'status': constants.STATUS_ERROR,
            'updated_at': None,
            'host': 'fake_host_2',
            'share_network_name': 'fake_sn_id_2',
            'share_network_id': 'fake_sn_id_2',
            'share_network_subnet_ids': ['fake_sns_id_2'],
            'project_id': 'fake_project_id_2',
            'id': 'fake_server_id_2',
            'is_auto_deletable': True,
            'task_state': None,
            'source_share_server_id': None,
            'identifier': 'fake_id_2',
            'security_service_update_support': False,
            'network_allocation_update_support': False

        },
    ]
}

fake_share_network_get_list = {
    'share_networks': [
        {
            'name': 'fake_sn_name',
            'id': 'fake_sn_id',
            'project_id': 'fake_project_id',
        },
        {
            'name': None,
            'id': 'fake_sn_id_2',
            'project_id': 'fake_project_id_2',
        }
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
        'share_network_subnet_ids': ['fake_sns_id'],
        'project_id': 'fake_project_id',
        'id': 'fake_server_id',
        'backend_details': {
            'fake_key_1': 'fake_value_1',
            'fake_key_2': 'fake_value_2',
        },
        'is_auto_deletable': False,
        'task_state': None,
        'source_share_server_id': None,
        'identifier': 'fake_id',
        'security_service_update_support': False,
        'network_allocation_update_support': False
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
        self.share_network_subnets = kwargs.get('share_network_subnets', [{
            'id': 'fake_sns_id', 'share_network_id': 'fake_sn_id'}])
        self.share_network_subnet_ids = kwargs.get(
            'share_network_subnet_ids',
            [sn['id'] for sn in self.share_network_subnets])
        self.status = kwargs.get('status', constants.STATUS_ACTIVE)
        self.project_id = 'fake_project_id'
        self.identifier = kwargs.get('identifier', 'fake_id')
        self.is_auto_deletable = kwargs.get('is_auto_deletable', False)
        self.task_state = kwargs.get('task_state')
        self.source_share_server_id = kwargs.get('source_share_server_id')
        self.backend_details = share_server_backend_details
        self.security_service_update_support = kwargs.get(
            'security_service_update_support', False)
        self.network_allocation_update_support = kwargs.get(
            'network_allocation_update_support', False)
        self.share_network_id = kwargs.get('share_network_id', 'fake_sn_id')

    def __getitem__(self, item):
        return getattr(self, item)


def fake_share_server_get_all():
    fake_share_servers = [
        FakeShareServer(),
        FakeShareServer(id='fake_server_id_2',
                        host='fake_host_2',
                        share_network_subnets=[{
                            'id': 'fake_sns_id_2',
                            'share_network_id': 'fake_sn_id_2',
                            }],
                        share_network_id='fake_sn_id_2',
                        identifier='fake_id_2',
                        task_state=None,
                        is_auto_deletable=True,
                        status=constants.STATUS_ERROR,
                        security_service_update_support=False,
                        network_allocation_update_support=False),
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


class FakeRequestWithShareNetworkSubnetId(FakeRequestAdmin):
    GET = {
        'share_network_subnet_id':
            fake_share_server_get_all()[0].share_network_subnet_ids,
    }


class FakeRequestWithFakeFilter(FakeRequestAdmin):
    GET = {'fake_key': 'fake_value'}


@ddt.ddt
class ShareServerAPITest(test.TestCase):

    def setUp(self):
        super(ShareServerAPITest, self).setUp()
        self.controller = share_servers.ShareServerController()
        self.resource_name = self.controller.resource_name
        self.mock_object(policy, 'check_policy',
                         mock.Mock(return_value=True))
        self.mock_object(db_api, 'share_server_get_all',
                         mock.Mock(return_value=fake_share_server_get_all()))

    def _prepare_request(self, url, use_admin_context,
                         version=api_version._MAX_API_VERSION):
        request = fakes.HTTPRequest.blank(url,
                                          use_admin_context=use_admin_context,
                                          version=version)
        ctxt = request.environ['manila.context']
        return request, ctxt

    def test_index_no_filters(self):
        request, ctxt = self._prepare_request(url='/v2/share-servers/',
                                              use_admin_context=True)
        self.mock_object(db_api, 'share_network_get', mock.Mock(
            side_effect=[fake_share_network_get_list['share_networks'][0],
                         fake_share_network_get_list['share_networks'][1]]))
        result = self.controller.index(request)
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(ctxt)
        self.assertEqual(fake_share_server_list, result)

    def test_index_host_filter(self):
        request, ctxt = self._prepare_request(
            url='/index?host=%s'
                % fake_share_server_list['share_servers'][0]['host'],
            use_admin_context=True)
        self.mock_object(db_api, 'share_network_get', mock.Mock(
            side_effect=[fake_share_network_get_list['share_networks'][0],
                         fake_share_network_get_list['share_networks'][1]]))
        result = self.controller.index(request)
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(ctxt)
        self.assertEqual([fake_share_server_list['share_servers'][0]],
                         result['share_servers'])

    def test_index_status_filter(self):
        request, ctxt = self._prepare_request(url='/index?status=%s' %
                                                  constants.STATUS_ERROR,
                                              use_admin_context=True)
        self.mock_object(db_api, 'share_network_get', mock.Mock(
            side_effect=[fake_share_network_get_list['share_networks'][0],
                         fake_share_network_get_list['share_networks'][1]]))
        result = self.controller.index(request)
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(ctxt)
        self.assertEqual([fake_share_server_list['share_servers'][1]],
                         result['share_servers'])

    def test_index_project_id_filter(self):
        request, ctxt = self._prepare_request(
            url='/index?project_id=%s'
                % fake_share_server_get_all()[0].project_id,
            use_admin_context=True)
        self.mock_object(db_api, 'share_network_get', mock.Mock(
            side_effect=[fake_share_network_get_list['share_networks'][0],
                         fake_share_network_get_list['share_networks'][1]]))
        result = self.controller.index(request)
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(ctxt)

        self.assertEqual([fake_share_server_list['share_servers'][0]],
                         result['share_servers'])

    def test_index_share_network_filter_by_name(self):
        request, ctxt = self._prepare_request(
            url='/index?host=%s'
                % fake_share_server_list['share_servers'][0]['host'],
            use_admin_context=True)
        self.mock_object(db_api, 'share_network_get', mock.Mock(
            side_effect=[fake_share_network_get_list['share_networks'][0],
                         fake_share_network_get_list['share_networks'][1]]))
        result = self.controller.index(request)
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(ctxt)
        self.assertEqual([fake_share_server_list['share_servers'][0]],
                         result['share_servers'])

    def test_index_share_network_filter_by_id(self):
        request, ctxt = self._prepare_request(
            url='/index?share_network=%s'
                % fake_share_network_get_list['share_networks'][0]['id'],
            use_admin_context=True)
        self.mock_object(db_api, 'share_network_get', mock.Mock(
            side_effect=[fake_share_network_get_list['share_networks'][0],
                         fake_share_network_get_list['share_networks'][1]]))
        result = self.controller.index(request)
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(ctxt)
        self.assertEqual([fake_share_server_list['share_servers'][0]],
                         result['share_servers'])

    def test_index_fake_filter(self):
        request, ctxt = self._prepare_request(url='/index?fake_key=fake_value',
                                              use_admin_context=True)
        self.mock_object(db_api, 'share_network_get', mock.Mock(
            side_effect=[fake_share_network_get_list['share_networks'][0],
                         fake_share_network_get_list['share_networks'][1]]))
        result = self.controller.index(request)
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'index')
        db_api.share_server_get_all.assert_called_once_with(ctxt)
        self.assertEqual(0, len(result['share_servers']))

    def test_index_share_network_not_found(self):
        request, ctxt = self._prepare_request(
            url='/index?identifier=%s'
                % fake_share_server_get_all()[0].identifier,
            use_admin_context=True)
        self.mock_object(
            db_api, 'share_network_get',
            mock.Mock(side_effect=exception.ShareNetworkNotFound(
                share_network_id='fake')))

        result = self.controller.index(request)
        db_api.share_server_get_all.assert_called_once_with(ctxt)
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'index')
        exp_share_server = fake_share_server_list['share_servers'][0].copy()
        exp_share_server['project_id'] = ''
        exp_share_server['share_network_name'] = ''
        self.assertEqual([exp_share_server],
                         result['share_servers'])

    def test_index_share_network_not_found_filter_project(self):
        request, ctxt = self._prepare_request(
            url='/index?project_id=%s'
                % fake_share_server_get_all()[0].project_id,
            use_admin_context=True)
        self.mock_object(
            db_api, 'share_network_get',
            mock.Mock(side_effect=exception.ShareNetworkNotFound(
                share_network_id='fake')))

        result = self.controller.index(request)
        db_api.share_server_get_all.assert_called_once_with(ctxt)
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'index')
        self.assertEqual(0, len(result['share_servers']))

    @ddt.data({'version': '2.70', 'share_network_name': ''},
              {'version': '2.70', 'share_network_name': 'fake_sn_name'},
              {'version': '2.68', 'share_network_name': 'fake_sn_name'})
    @ddt.unpack
    def test_show(self, version, share_network_name):
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=fake_share_server_get()))
        request, ctxt = self._prepare_request('/show', use_admin_context=True,
                                              version=version)

        share_network = copy.deepcopy(
            fake_share_network_get_list['share_networks'][0])
        share_server = copy.deepcopy(
            fake_share_server_get_result['share_server'])

        if version == '2.68':
            share_server['share_network_subnet_id'] = \
                share_server['share_network_subnet_ids'][0]
            share_server.pop('share_network_subnet_ids')
            share_server.pop('network_allocation_update_support')

        share_network['name'] = share_network_name
        if share_network['name']:
            share_server['share_network_name'] = share_network['name']
        else:
            share_server['share_network_name'] = share_network['id']

        self.mock_object(db_api, 'share_network_get', mock.Mock(
            return_value=share_network))
        result = self.controller.show(
            request,
            share_server['id'])
        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'show')
        db_api.share_server_get.assert_called_once_with(
            ctxt, share_server['id'])
        self.assertEqual(share_server,
                         result['share_server'])

    @ddt.data(
        {'share_server_side_effect': exception.ShareServerNotFound(
            share_server_id="foo"),
            'share_net_side_effect': mock.Mock()},
        {'share_server_side_effect': mock.Mock(
            return_value=fake_share_server_get()),
            'share_net_side_effect': exception.ShareNetworkNotFound(
                share_network_id="foo")})
    @ddt.unpack
    def test_show_server_not_found(self, share_server_side_effect,
                                   share_net_side_effect):
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(side_effect=share_server_side_effect))
        request, ctxt = self._prepare_request('/show', use_admin_context=True)
        self.mock_object(db_api, 'share_network_get', mock.Mock(
            side_effect=share_net_side_effect))
        self.assertRaises(
            exc.HTTPNotFound, self.controller.show, request,
            fake_share_server_get_result['share_server']['id'])

        policy.check_policy.assert_called_once_with(
            ctxt, self.resource_name, 'show')
        db_api.share_server_get.assert_called_once_with(
            ctxt, fake_share_server_get_result['share_server']['id'])
        if isinstance(share_net_side_effect, exception.ShareNetworkNotFound):
            exp_share_net_id = (fake_share_server_get()
                                .share_network_subnets[0]['share_network_id'])
            db_api.share_network_get.assert_called_once_with(
                ctxt, exp_share_net_id)

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

    def test_details_share_server_not_found(self):
        share_server_id = 'fake'
        self.mock_object(
            db_api, 'share_server_get',
            mock.Mock(side_effect=exception.ShareServerNotFound(
                share_server_id=share_server_id)))
        self.assertRaises(exc.HTTPNotFound,
                          self.controller.details,
                          FakeRequestAdmin,
                          share_server_id)
        policy.check_policy.assert_called_once_with(
            CONTEXT, self.resource_name, 'details')
        db_api.share_server_get.assert_called_once_with(
            CONTEXT, share_server_id)

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
