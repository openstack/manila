# Copyright 2014 NetApp
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
from unittest import mock
from urllib import parse

import ddt
from oslo_db import exception as db_exception
from oslo_utils import timeutils
from webob import exc as webob_exc

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.v2 import share_networks
from manila.db import api as db_api
from manila import exception
from manila import quota
from manila.share import api as share_api
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils


fake_share_network_subnet = {
    'id': 'fake subnet id',
    'neutron_net_id': 'fake net id',
    'neutron_subnet_id': 'fake subnet id',
    'network_type': 'vlan',
    'segmentation_id': 1000,
    'cidr': '10.0.0.0/24',
    'ip_version': 4,
    'share_network_id': 'fake network id',
    'availability_zone_id': None,
    'share_servers': [],
    'availability_zone': []
}

fake_share_network = {
    'id': 'fake network id',
    'project_id': 'fake project',
    'created_at': timeutils.parse_strtime('2002-02-02', fmt="%Y-%m-%d"),
    'updated_at': None,
    'name': 'fake name',
    'description': 'fake description',
    'security_services': [],
    'share_network_subnets': [],
    'security_service_update_support': True,
    'status': 'active'
}


fake_share_network_shortened = {
    'id': 'fake network id',
    'name': 'fake name',
}

fake_share_network_with_ss = {
    'id': 'sn-id',
    'project_id': 'fake',
    'created_at': timeutils.parse_strtime('2001-01-01', fmt="%Y-%m-%d"),
    'updated_at': None,
    'name': 'test-sn',
    'description': 'fake description',
    'share_network_subnets': [],
    'security_services': [{'id': 'fake-ss-id'}]
}

fake_sn_with_ss_shortened = {
    'id': 'sn-id',
    'name': 'test-sn',
}

ADD_UPDATE_SEC_SERVICE_VERSION = '2.63'

QUOTAS = quota.QUOTAS


@ddt.ddt
class ShareNetworkAPITest(test.TestCase):

    def setUp(self):
        super(ShareNetworkAPITest, self).setUp()
        self.controller = share_networks.ShareNetworkController()
        self.req = fakes.HTTPRequest.blank('/share-networks')
        self.body = {share_networks.RESOURCE_NAME: {'name': 'fake name'}}
        self.context = self.req.environ['manila.context']
        self.share_api = share_api.API()

    def _check_share_network_view_shortened(self, view, share_nw):
        self.assertEqual(share_nw['id'], view['id'])
        self.assertEqual(share_nw['name'], view['name'])

    def _check_share_network_view(self, view, share_nw):
        self.assertEqual(share_nw['id'], view['id'])
        self.assertEqual(share_nw['project_id'], view['project_id'])
        self.assertEqual(share_nw['created_at'], view['created_at'])
        self.assertEqual(share_nw['updated_at'], view['updated_at'])
        self.assertEqual(share_nw['name'], view['name'])
        self.assertEqual(share_nw['description'], view['description'])
        self.assertNotIn('shares', view)
        self.assertNotIn('network_allocations', view)
        self.assertNotIn('security_services', view)

    def _setup_body_for_create_test(self, data):
        data.update({'user_id': 'fake_user_id'})
        body = {share_networks.RESOURCE_NAME: data}
        return body

    @ddt.data(
        {'neutron_net_id': 'fake', 'neutron_subnet_id': 'fake'})
    def test_create_valid_cases(self, data):
        body = self._setup_body_for_create_test(data)
        result = self.controller.create(self.req, body)
        data.pop('user_id', None)
        for k, v in data.items():
            self.assertIn(data[k], result['share_network'][k])

    @ddt.data(
        {'neutron_net_id': 'fake', 'neutron_subnet_id': 'fake',
         'availability_zone': 'fake'})
    def test_create_valid_cases_upper_2_50(self, data):
        req = fakes.HTTPRequest.blank('/share-networks', version="2.51")
        context = req.environ['manila.context']
        body = self._setup_body_for_create_test(data)
        fake_az = {
            'name': 'fake',
            'id': 'fake_id'
        }
        self.mock_object(db_api, 'availability_zone_get',
                         mock.Mock(return_value=fake_az))

        result = self.controller.create(req, body)
        result_subnet = result['share_network']['share_network_subnets'][0]
        data.pop('user_id', None)
        data.pop('project_id', None)
        data.pop('availability_zone_id', None)
        data.pop('id', None)
        data['availability_zone'] = result_subnet['availability_zone']

        for k, v in data.items():
            self.assertIn(k, result_subnet.keys())

        db_api.availability_zone_get.assert_called_once_with(
            context, fake_az['name']
        )

    @ddt.data(
        {'nova_net_id': 'foo', 'neutron_net_id': 'bar'},
        {'nova_net_id': 'foo', 'neutron_subnet_id': 'quuz'},
        {'nova_net_id': 'foo', 'neutron_net_id': 'bar',
         'neutron_subnet_id': 'quuz'},
        {'nova_net_id': 'fake_nova_net_id'},
        {'neutron_net_id': 'bar'},
        {'neutron_subnet_id': 'quuz'})
    def test_create_invalid_cases(self, data):
        data.update({'user_id': 'fake_user_id'})
        body = {share_networks.RESOURCE_NAME: data}
        self.assertRaises(
            webob_exc.HTTPBadRequest, self.controller.create, self.req, body)

    @ddt.data(
        {'name': 'new fake name'},
        {'description': 'new fake description'},
        {'name': 'new fake name', 'description': 'new fake description'})
    def test_update_valid_cases(self, data):
        body = {share_networks.RESOURCE_NAME: {'user_id': 'fake_user'}}
        created = self.controller.create(self.req, body)

        body = {share_networks.RESOURCE_NAME: data}
        result = self.controller.update(
            self.req, created['share_network']['id'], body)

        for k, v in data.items():
            self.assertIn(data[k], result['share_network'][k])

        self._check_share_network_view(
            result[share_networks.RESOURCE_NAME],
            result['share_network'])

    @ddt.data(
        {'nova_net_id': 'foo', 'neutron_net_id': 'bar'},
        {'nova_net_id': 'foo', 'neutron_subnet_id': 'quuz'},
        {'nova_net_id': 'foo', 'neutron_net_id': 'bar',
         'neutron_subnet_id': 'quuz'},
        {'nova_net_id': 'fake_nova_net_id'},
    )
    def test_update_invalid_cases(self, data):
        body = {share_networks.RESOURCE_NAME: {'user_id': 'fake_user'}}
        created = self.controller.create(self.req, body)
        body = {share_networks.RESOURCE_NAME: data}
        self.assertRaises(
            webob_exc.HTTPBadRequest,
            self.controller.update,
            self.req, created['share_network']['id'], body)

    @ddt.data(
        ({'share_network_subnets': [
            {'share_network_id': fake_share_network['id']}]}, True),
        ({'share_network_subnets': []}, False))
    @ddt.unpack
    def test__subnet_has_search_opt(self, network, has_search_opt):
        search_opts = {
            'share_network_id': fake_share_network['id']
        }

        result = None

        for key, value in search_opts.items():
            result = self.controller._subnet_has_search_opt(
                key, value, network)

        self.assertEqual(has_search_opt, result)

    def test_create_nominal(self):
        self.mock_object(db_api, 'share_network_subnet_create')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=fake_share_network))
        self.mock_object(common, 'check_net_id_and_subnet_id')
        with mock.patch.object(db_api,
                               'share_network_create',
                               mock.Mock(return_value=fake_share_network)):

            result = self.controller.create(self.req, self.body)

            db_api.share_network_create.assert_called_once_with(
                self.req.environ['manila.context'],
                self.body[share_networks.RESOURCE_NAME])

            self._check_share_network_view(
                result[share_networks.RESOURCE_NAME],
                fake_share_network)

    def test_create_db_api_exception(self):
        with mock.patch.object(db_api,
                               'share_network_create',
                               mock.Mock(side_effect=db_exception.DBError)):
            self.assertRaises(webob_exc.HTTPInternalServerError,
                              self.controller.create,
                              self.req,
                              self.body)

    def test_create_wrong_body(self):
        body = None
        self.assertRaises(webob_exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          self.req,
                          body)

    @ddt.data(
        {'availability_zone': 'fake-zone'})
    def test_create_az_not_found(self, data):
        req = fakes.HTTPRequest.blank('/share-networks', version="2.51")

        self.mock_object(
            db_api, 'availability_zone_get',
            mock.Mock(
                side_effect=exception.AvailabilityZoneNotFound(id='fake')))

        body = {share_networks.RESOURCE_NAME: data}

        self.assertRaises(webob_exc.HTTPBadRequest,
                          self.controller.create,
                          req,
                          body)

    def test_create_error_on_network_creation(self):
        self.mock_object(share_networks.QUOTAS, 'reserve',
                         mock.Mock(return_value='fake_reservation'))
        self.mock_object(share_networks.QUOTAS, 'rollback')
        self.mock_object(db_api, 'share_network_create',
                         mock.Mock(side_effect=db_exception.DBError()))

        self.assertRaises(webob_exc.HTTPInternalServerError,
                          self.controller.create,
                          self.req,
                          self.body)
        self.assertTrue(share_networks.QUOTAS.rollback.called)

    def test_create_error_on_subnet_creation(self):
        data = {
            'neutron_net_id': 'fake',
            'neutron_subnet_id': 'fake',
            'id': fake_share_network['id']
        }
        subnet_data = copy.deepcopy(data)
        self.mock_object(share_networks.QUOTAS, 'reserve',
                         mock.Mock(return_value='fake_reservation'))
        self.mock_object(share_networks.QUOTAS, 'rollback')
        self.mock_object(db_api, 'share_network_create',
                         mock.Mock(return_value=fake_share_network))
        self.mock_object(db_api, 'share_network_subnet_create',
                         mock.Mock(side_effect=db_exception.DBError()))
        self.mock_object(db_api, 'share_network_delete')
        body = {share_networks.RESOURCE_NAME: data}

        self.assertRaises(webob_exc.HTTPInternalServerError,
                          self.controller.create,
                          self.req,
                          body)

        db_api.share_network_create.assert_called_once_with(self.context, data)
        subnet_data['share_network_id'] = data['id']
        subnet_data.pop('id')
        db_api.share_network_subnet_create.assert_called_once_with(
            self.context, subnet_data)
        db_api.share_network_delete.assert_called_once_with(
            self.context, fake_share_network['id'])
        self.assertTrue(share_networks.QUOTAS.rollback.called)

    def test_delete_nominal(self):
        share_nw = fake_share_network.copy()
        subnet = fake_share_network_subnet.copy()
        subnet['share_servers'] = ['foo', 'bar']
        share_nw['share_network_subnets'] = [subnet]
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'share_instances_get_all_by_share_network',
                         mock.Mock(return_value=[]))
        self.mock_object(self.controller.share_rpcapi, 'delete_share_server')
        self.mock_object(self.controller,
                         '_all_share_servers_are_auto_deletable',
                         mock.Mock(return_value=True))
        self.mock_object(db_api, 'share_network_delete')

        self.controller.delete(self.req, share_nw['id'])

        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])
        (db_api.share_instances_get_all_by_share_network.
            assert_called_once_with(self.req.environ['manila.context'],
                                    share_nw['id']))
        self.controller.share_rpcapi.delete_share_server.assert_has_calls([
            mock.call(self.req.environ['manila.context'], 'foo'),
            mock.call(self.req.environ['manila.context'], 'bar')])
        db_api.share_network_delete.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])

    def test_delete_not_found(self):
        share_nw = 'fake network id'
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(side_effect=exception.ShareNetworkNotFound(
                             share_network_id=share_nw)))

        self.assertRaises(webob_exc.HTTPNotFound,
                          self.controller.delete,
                          self.req,
                          share_nw)

    def test_quota_delete_reservation_failed(self):
        share_nw = fake_share_network.copy()
        subnet = fake_share_network_subnet.copy()
        subnet['share_servers'] = ['foo', 'bar']
        share_nw['share_network_subnets'] = [subnet]
        share_nw['user_id'] = 'fake_user_id'

        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'share_instances_get_all_by_share_network',
                         mock.Mock(return_value=[]))
        self.mock_object(self.controller,
                         '_all_share_servers_are_auto_deletable',
                         mock.Mock(return_value=True))
        self.mock_object(self.controller.share_rpcapi, 'delete_share_server')
        self.mock_object(db_api, 'share_network_delete')
        self.mock_object(share_networks.QUOTAS, 'reserve',
                         mock.Mock(side_effect=Exception))
        self.mock_object(share_networks.QUOTAS, 'commit')

        self.controller.delete(self.req, share_nw['id'])

        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])

        (db_api.share_instances_get_all_by_share_network.
            assert_called_once_with(self.req.environ['manila.context'],
                                    share_nw['id']))

        self.controller.share_rpcapi.delete_share_server.assert_has_calls([
            mock.call(self.req.environ['manila.context'], 'foo'),
            mock.call(self.req.environ['manila.context'], 'bar')])
        db_api.share_network_delete.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])
        share_networks.QUOTAS.reserve.assert_called_once_with(
            self.req.environ['manila.context'],
            project_id=share_nw['project_id'],
            share_networks=-1,
            user_id=share_nw['user_id']
        )
        self.assertFalse(share_networks.QUOTAS.commit.called)

    def test_delete_in_use_by_share(self):
        share_nw = fake_share_network.copy()
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'share_instances_get_all_by_share_network',
                         mock.Mock(return_value=['foo', 'bar']))

        self.assertRaises(webob_exc.HTTPConflict,
                          self.controller.delete,
                          self.req,
                          share_nw['id'])

        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])
        (db_api.share_instances_get_all_by_share_network.
            assert_called_once_with(self.req.environ['manila.context'],
                                    share_nw['id']))

    def test_delete_in_use_by_share_group(self):
        share_nw = fake_share_network.copy()
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'count_share_groups_in_share_network',
                         mock.Mock(return_value=2))

        self.assertRaises(webob_exc.HTTPConflict,
                          self.controller.delete,
                          self.req,
                          share_nw['id'])

        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])

    def test_delete_contains_is_auto_deletable_false_servers(self):
        share_nw = fake_share_network.copy()
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'count_share_groups_in_share_network')
        self.mock_object(share_networks.ShareNetworkController,
                         '_all_share_servers_are_auto_deletable',
                         mock.Mock(return_value=False))

        self.assertRaises(webob_exc.HTTPConflict,
                          self.controller.delete,
                          self.req,
                          share_nw['id'])

        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])

    def test_delete_contains_more_than_one_subnet(self):
        share_nw = fake_share_network.copy()
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'share_instances_get_all_by_share_network',
                         mock.Mock(return_value=None))
        self.mock_object(db_api, 'count_share_groups_in_share_network',
                         mock.Mock(return_value=None))
        self.mock_object(self.controller, '_share_network_contains_subnets',
                         mock.Mock(return_value=True))

        self.assertRaises(webob_exc.HTTPConflict,
                          self.controller.delete,
                          self.req,
                          share_nw['id'])

        db_api.share_network_get.assert_called_once_with(
            self.context, share_nw['id'])
        (db_api.share_instances_get_all_by_share_network
            .assert_called_once_with(self.context, share_nw['id']))
        db_api.count_share_groups_in_share_network.assert_called_once_with(
            self.context, share_nw['id']
        )
        (self.controller._share_network_contains_subnets
            .assert_called_once_with(share_nw))

    def test_delete_subnet_contains_share_server(self):
        share_nw = fake_share_network.copy()
        share_nw['share_network_subnets'].append({
            'id': 'fake_sns_id',
            'share_servers': [{'id': 'fake_share_server_id'}]
        })
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'count_share_groups_in_share_network',
                         mock.Mock(return_value=0))
        self.mock_object(self.controller, '_share_network_contains_subnets',
                         mock.Mock(return_value=False))
        self.mock_object(
            self.controller, '_all_share_servers_are_auto_deletable',
            mock.Mock(return_value=False))

        self.assertRaises(webob_exc.HTTPConflict,
                          self.controller.delete,
                          self.req,
                          share_nw['id'])

    @ddt.data(
        ({'share_servers': [{'is_auto_deletable': True},
                            {'is_auto_deletable': True}]}, True),
        ({'share_servers': [{'is_auto_deletable': True},
                            {'is_auto_deletable': False}]}, False),
    )
    @ddt.unpack
    def test__share_servers_are_auto_deletable(self, fake_share_network,
                                               expected_result):
        self.assertEqual(
            expected_result,
            self.controller._all_share_servers_are_auto_deletable(
                fake_share_network))

    @ddt.data(
        ({'share_network_subnets': [{'share_servers': [{}, {}]}]}, True),
        ({'share_network_subnets': [{'share_servers': []}]}, False),
    )
    @ddt.unpack
    def test__share_network_subnets_contain_share_servers(self, share_network,
                                                          expected_result):
        self.assertEqual(
            expected_result,
            self.controller._share_network_subnets_contain_share_servers(
                share_network))

    def test_show_nominal(self):
        share_nw = 'fake network id'
        with mock.patch.object(db_api,
                               'share_network_get',
                               mock.Mock(return_value=fake_share_network)):
            result = self.controller.show(self.req, share_nw)

            db_api.share_network_get.assert_called_once_with(
                self.req.environ['manila.context'],
                share_nw)

            self._check_share_network_view(
                result[share_networks.RESOURCE_NAME],
                fake_share_network)

    def test_show_not_found(self):
        share_nw = 'fake network id'
        test_exception = exception.ShareNetworkNotFound(
            share_network_id=share_nw)
        with mock.patch.object(db_api,
                               'share_network_get',
                               mock.Mock(side_effect=test_exception)):
            self.assertRaises(webob_exc.HTTPNotFound,
                              self.controller.show,
                              self.req,
                              share_nw)

    def test_index_no_filters(self):
        networks = [fake_share_network]
        with mock.patch.object(db_api,
                               'share_network_get_all_by_filter',
                               mock.Mock(return_value=networks)):

            result = self.controller.index(self.req)

            db_api.share_network_get_all_by_filter.assert_called_once_with(
                self.context, filters={})

            self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
            self._check_share_network_view_shortened(
                result[share_networks.RESOURCES_NAME][0],
                fake_share_network_shortened)

    def test_index_detailed(self):
        networks = [fake_share_network]
        with mock.patch.object(db_api,
                               'share_network_get_all_by_filter',
                               mock.Mock(return_value=networks)):

            result = self.controller.detail(self.req)

            db_api.share_network_get_all_by_filter.assert_called_once_with(
                self.context, filters={})

            self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
            self._check_share_network_view(
                result[share_networks.RESOURCES_NAME][0],
                fake_share_network)

    @mock.patch.object(db_api, 'share_network_get_all_by_filter',
                       mock.Mock())
    def test_index_filter_by_security_service(self):
        db_api.share_network_get_all_by_filter.return_value = [
            fake_share_network_with_ss]
        req = fakes.HTTPRequest.blank(
            '/share_networks?security_service_id=fake-ss-id')
        result = self.controller.index(req)
        filters = {'security_service_id': 'fake-ss-id'}
        (db_api.share_network_get_all_by_filter.
            assert_called_once_with(req.environ['manila.context'],
                                    filters=filters))
        self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
        self._check_share_network_view_shortened(
            result[share_networks.RESOURCES_NAME][0],
            fake_sn_with_ss_shortened)

    @mock.patch.object(db_api, 'share_network_get_all_by_filter', mock.Mock())
    def test_index_all_tenants_non_admin_context(self):
        req = fakes.HTTPRequest.blank(
            '/share_networks?all_tenants=1')
        fake_context = req.environ['manila.context']
        db_api.share_network_get_all_by_filter.return_value = []
        self.controller.index(req)
        db_api.share_network_get_all_by_filter.assert_called_with(
            fake_context, filters={})

    @mock.patch.object(db_api, 'share_network_get_all_by_filter', mock.Mock())
    def test_index_all_tenants_admin_context(self):
        db_api.share_network_get_all_by_filter.return_value = [
            fake_share_network]
        req = fakes.HTTPRequest.blank(
            '/share_networks?all_tenants=1',
            use_admin_context=True)
        result = self.controller.index(req)
        db_api.share_network_get_all_by_filter.assert_called_once_with(
            req.environ['manila.context'], filters={})
        self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
        self._check_share_network_view_shortened(
            result[share_networks.RESOURCES_NAME][0],
            fake_share_network_shortened)

    @mock.patch.object(db_api, 'share_network_get_all', mock.Mock())
    def test_index_all_tenants_with_invaild_value(self):
        req = fakes.HTTPRequest.blank(
            '/share_networks?all_tenants=wonk',
            use_admin_context=True)

        self.assertRaises(exception.InvalidInput, self.controller.index, req)

    @mock.patch.object(db_api, 'share_network_get_all_by_filter', mock.Mock())
    def test_index_all_tenants_with_value_zero(self):
        db_api.share_network_get_all_by_filter.return_value = [
            fake_share_network]
        req = fakes.HTTPRequest.blank(
            '/share_networks?all_tenants=0',
            use_admin_context=True)

        result = self.controller.index(req)

        self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
        self._check_share_network_view_shortened(
            result[share_networks.RESOURCES_NAME][0],
            fake_share_network_shortened)
        filters = {'project_id': 'fake'}
        db_api.share_network_get_all_by_filter.assert_called_once_with(
            req.environ['manila.context'], filters=filters)

    @mock.patch.object(db_api, 'share_network_get_all_by_filter', mock.Mock())
    def test_index_filter_by_project_id_non_admin_context(self):
        req = fakes.HTTPRequest.blank(
            '/share_networks?project_id=fake project')
        fake_context = req.environ['manila.context']
        db_api.share_network_get_all_by_filter.return_value = []
        self.controller.index(req)
        db_api.share_network_get_all_by_filter.assert_called_with(
            fake_context, filters={})

    @mock.patch.object(db_api, 'share_network_get_all_by_filter', mock.Mock())
    def test_index_filter_by_project_id_admin_context(self):
        db_api.share_network_get_all_by_filter.return_value = [
            fake_share_network_with_ss
        ]
        req = fakes.HTTPRequest.blank(
            '/share_networks?project_id=fake',
            use_admin_context=True)
        result = self.controller.index(req)
        filters = {'project_id': 'fake'}
        db_api.share_network_get_all_by_filter.assert_called_once_with(
            req.environ['manila.context'], filters=filters)
        self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
        self._check_share_network_view_shortened(
            result[share_networks.RESOURCES_NAME][0],
            fake_sn_with_ss_shortened)

    @mock.patch.object(db_api, 'share_network_get_all_by_filter',
                       mock.Mock())
    def test_index_filter_by_ss_and_project_id_admin_context(self):
        db_api.share_network_get_all_by_filter.return_value = [
            fake_share_network_with_ss
        ]
        req = fakes.HTTPRequest.blank(
            '/share_networks?security_service_id=fake-ss-id&project_id=fake',
            use_admin_context=True)
        result = self.controller.index(req)
        filters = {'project_id': 'fake',
                   'security_service_id': 'fake-ss-id'}
        db_api.share_network_get_all_by_filter.assert_called_once_with(
            req.environ['manila.context'], filters=filters)
        self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
        self._check_share_network_view_shortened(
            result[share_networks.RESOURCES_NAME][0],
            fake_sn_with_ss_shortened)

    @ddt.data(('name=fo', 0), ('description=d', 0),
              ('name=foo&description=d', 0),
              ('name=foo', 1), ('description=ds', 1),
              ('name~=foo&description~=ds', 2),
              ('name=foo&description~=ds', 1),
              ('name~=foo&description=ds', 1))
    @ddt.unpack
    @mock.patch.object(db_api, 'share_network_get_all_by_filter',
                       mock.Mock())
    def test_index_filter_by_name_and_description(
            self, filter, share_network_number):
        fake_objs = [{'name': 'fo2', 'description': 'd2', 'id': 'fake1'},
                     {'name': 'foo', 'description': 'ds', 'id': 'fake2'},
                     {'name': 'foo1', 'description': 'ds1', 'id': 'fake3'}]
        db_api.share_network_get_all_by_filter.return_value = fake_objs
        req = fakes.HTTPRequest.blank(
            '/share_networks?' + filter,
            use_admin_context=True, version='2.36')
        result = self.controller.index(req)
        filters = {'project_id': self.context.project_id}
        db_api.share_network_get_all_by_filter.assert_called_with(
            req.environ['manila.context'], filters=filters)
        self.assertEqual(share_network_number,
                         len(result[share_networks.RESOURCES_NAME]))
        if share_network_number > 0:
            self._check_share_network_view_shortened(
                result[share_networks.RESOURCES_NAME][0], fake_objs[1])
        if share_network_number > 1:
            self._check_share_network_view_shortened(
                result[share_networks.RESOURCES_NAME][1], fake_objs[2])

    @mock.patch.object(db_api, 'share_network_get_all_by_filter',
                       mock.Mock())
    def test_index_all_filter_opts(self):
        valid_filter_opts = {
            'created_before': '2001-02-02',
            'created_since': '1999-01-01',
            'name': 'test-sn'
        }
        db_api.share_network_get_all_by_filter.return_value = [
            fake_share_network_with_ss]

        query_string = '/share-networks?' + parse.urlencode(sorted(
            [(k, v) for (k, v) in list(valid_filter_opts.items())]))
        for use_admin_context in [True, False]:
            req = fakes.HTTPRequest.blank(query_string,
                                          use_admin_context=use_admin_context)
            result = self.controller.index(req)
            parsed_created_before = timeutils.parse_strtime(
                valid_filter_opts['created_before'], fmt="%Y-%m-%d")
            parsed_created_since = timeutils.parse_strtime(
                valid_filter_opts['created_since'], fmt="%Y-%m-%d")
            filters = {'created_before': parsed_created_before,
                       'created_since': parsed_created_since}
            if use_admin_context:
                filters['project_id'] = 'fake'
            db_api.share_network_get_all_by_filter.assert_called_with(
                req.environ['manila.context'], filters=filters)
            self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
            self._check_share_network_view_shortened(
                result[share_networks.RESOURCES_NAME][0],
                fake_sn_with_ss_shortened)

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    def test_update_nominal(self):
        share_nw = 'fake network id'
        db_api.share_network_get.return_value = fake_share_network

        body = {share_networks.RESOURCE_NAME: {'name': 'new name'}}

        with mock.patch.object(db_api,
                               'share_network_update',
                               mock.Mock(return_value=fake_share_network)):
            result = self.controller.update(self.req, share_nw, body)

            db_api.share_network_update.assert_called_once_with(
                self.req.environ['manila.context'],
                share_nw,
                body[share_networks.RESOURCE_NAME])

            self._check_share_network_view(
                result[share_networks.RESOURCE_NAME],
                fake_share_network)

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    def test_update_not_found(self):
        share_nw = 'fake network id'
        db_api.share_network_get.side_effect = exception.ShareNetworkNotFound(
            share_network_id=share_nw)

        self.assertRaises(webob_exc.HTTPNotFound,
                          self.controller.update,
                          self.req,
                          share_nw,
                          self.body)

    def test_update_invalid_body(self):
        self.assertRaises(webob_exc.HTTPUnprocessableEntity,
                          self.controller.update,
                          self.req,
                          'fake_sn_id',
                          None)

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    def test_update_invalid_key_in_use(self):
        share_nw = fake_share_network.copy()
        subnet = fake_share_network_subnet.copy()
        subnet['share_servers'] = [{'id': 1}]
        share_nw['share_network_subnets'] = [subnet]

        db_api.share_network_get.return_value = share_nw
        body = {
            share_networks.RESOURCE_NAME: {
                'name': 'new name',
                'user_id': 'new id',
            },
        }
        self.assertRaises(webob_exc.HTTPForbidden,
                          self.controller.update,
                          self.req,
                          share_nw['id'],
                          body)

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    @mock.patch.object(db_api, 'share_network_update', mock.Mock())
    def test_update_valid_keys_in_use(self):
        share_nw = fake_share_network.copy()
        subnet = fake_share_network_subnet.copy()
        subnet['share_servers'] = [{'id': 1}]
        share_nw['share_network_subnets'] = [subnet]
        updated_share_nw = share_nw.copy()
        updated_share_nw['name'] = 'new name'
        updated_share_nw['description'] = 'new description'

        db_api.share_network_get.return_value = share_nw
        db_api.share_network_update.return_value = updated_share_nw
        body = {
            share_networks.RESOURCE_NAME: {
                'name': updated_share_nw['name'],
                'description': updated_share_nw['description'],
            },
        }
        self.controller.update(self.req, share_nw['id'], body)
        db_api.share_network_get.assert_called_once_with(self.context,
                                                         share_nw['id'])
        db_api.share_network_update.assert_called_once_with(
            self.context, share_nw['id'], body['share_network'])

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    def test_update_db_api_exception(self):
        share_nw = 'fake network id'
        db_api.share_network_get.return_value = fake_share_network

        self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers',
            mock.Mock(return_value=False))
        self.mock_object(db_api, 'share_network_subnet_get_default_subnets',
                         mock.Mock(return_value=[fake_share_network_subnet]))
        self.mock_object(db_api, 'share_network_subnet_update')

        body = {share_networks.RESOURCE_NAME: {'neutron_subnet_id':
                                               'new subnet'}}

        with mock.patch.object(db_api,
                               'share_network_update',
                               mock.Mock(side_effect=db_exception.DBError)):
            self.assertRaises(webob_exc.HTTPBadRequest,
                              self.controller.update,
                              self.req,
                              share_nw,
                              body)
        (db_api.share_network_subnet_get_default_subnets.
         assert_called_once_with(self.context, share_nw))
        db_api.share_network_subnet_update.assert_called_once_with(
            self.context, fake_share_network_subnet['id'],
            body['share_network'])

    @ddt.data((webob_exc.HTTPBadRequest, 1, None,
               'new subnet'),
              (webob_exc.HTTPBadRequest, 2, None,
               'new subnet'),
              (webob_exc.HTTPBadRequest, None, 'neutron net', None))
    @ddt.unpack
    def test_update_default_subnet_errors(self, exception_to_raise,
                                          get_default_subnet_return_length,
                                          neutron_net_id, neutron_subnet_id):
        share_nw = 'fake network id'
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=fake_share_network))
        self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers',
            mock.Mock(return_value=False))
        self.mock_object(db_api, 'share_network_subnet_get_default_subnets',
                         mock.Mock(return_value=None))

        if get_default_subnet_return_length:
            fake_subnet = copy.deepcopy(fake_share_network_subnet)
            fake_subnet['neutron_net_id'] = None
            fake_subnet['neutron_subnet_id'] = None

            if get_default_subnet_return_length == 1:
                (db_api.share_network_subnet_get_default_subnets.
                 return_value) = [fake_subnet]
            elif get_default_subnet_return_length == 2:
                (db_api.share_network_subnet_get_default_subnets.
                 return_value) = [fake_subnet, fake_subnet]

        body = {
            share_networks.RESOURCE_NAME: {
                'neutron_net_id': neutron_net_id,
                'neutron_subnet_id': neutron_subnet_id
            }
        }

        self.assertRaises(exception_to_raise,
                          self.controller.update,
                          self.req,
                          share_nw,
                          body)

        (db_api.share_network_subnet_get_default_subnets.
         assert_called_once_with(self.context, share_nw))

    @ddt.data(*set(("1.0", "2.25", "2.26", api_version._MAX_API_VERSION)))
    def test_add_security_service(self, microversion):
        share_network_id = 'fake network id'
        security_service_id = 'fake ss id'
        self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers')

        body = {'add_security_service': {'security_service_id':
                                         security_service_id}}

        req = fakes.HTTPRequest.blank('/share-networks', version=microversion)
        with mock.patch.object(self.controller, 'add_security_service',
                               mock.Mock()):
            self.controller.add_security_service(req, share_network_id, body)
            self.controller.add_security_service.assert_called_once_with(
                req, share_network_id, body)

    def _setup_add_sec_services_with_servers_tests(
            self, share_network, security_service, network_is_active=True,
            version=ADD_UPDATE_SEC_SERVICE_VERSION,
            share_api_update_services_action=mock.Mock()):
        self.mock_object(
            db_api, 'share_network_get', mock.Mock(return_value=share_network))
        self.mock_object(
            db_api, 'security_service_get',
            mock.Mock(return_value=security_service))
        self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers',
            mock.Mock(return_value=True))
        self.mock_object(
            self.controller.share_api, 'update_share_network_security_service',
            share_api_update_services_action)
        self.mock_object(
            common, 'check_share_network_is_active',
            mock.Mock(return_value=network_is_active))
        self.mock_object(db_api, 'share_network_add_security_service')
        self.mock_object(self.controller._view_builder, 'build_share_network')

        body = {
            'add_security_service': {
                'security_service_id': security_service['id']
            }
        }
        req = fakes.HTTPRequest.blank(
            '/add_security_service', version=version, use_admin_context=True)
        context = req.environ['manila.context']

        return req, context, body

    def test_add_security_service_with_servers(self):
        security_service = db_utils.create_security_service()
        security_service_id = security_service['id']
        share_network = db_utils.create_share_network()
        share_network_id = share_network['id']
        req, context, body = self._setup_add_sec_services_with_servers_tests(
            share_network, security_service)

        self.controller.add_security_service(req, share_network_id, body)

        db_api.security_service_get.assert_called_once_with(
            context, security_service_id)
        (self.controller._share_network_subnets_contain_share_servers.
         assert_called_once_with(share_network))
        db_api.share_network_get.assert_called_once_with(
            context, share_network_id)
        (self.controller.share_api.update_share_network_security_service.
         assert_called_once_with(context, share_network, security_service))

    def test_add_security_service_with_server_invalid_version(self):
        security_service = db_utils.create_security_service()
        security_service_id = security_service['id']
        share_network = db_utils.create_share_network()
        share_network_id = share_network['id']
        req, context, body = self._setup_add_sec_services_with_servers_tests(
            share_network, security_service, version='2.59')

        self.assertRaises(
            webob_exc.HTTPForbidden,
            self.controller.add_security_service,
            req, share_network_id, body
        )

        db_api.security_service_get.assert_called_once_with(
            context, security_service_id)
        (self.controller._share_network_subnets_contain_share_servers.
         assert_called_once_with(share_network))
        db_api.share_network_get.assert_called_once_with(
            context, share_network_id)

    @ddt.data(
        (exception.ServiceIsDown(message='fake'), webob_exc.HTTPConflict),
        (exception.InvalidShareNetwork(message='fake'),
         webob_exc.HTTPBadRequest)
    )
    @ddt.unpack
    def test_add_security_service_with_server_update_failed(
            self, side_effect, exception_to_raise):
        security_service = db_utils.create_security_service()
        security_service_id = security_service['id']
        share_network_id = fake_share_network['id']
        fake_share_network['security_service_update_support'] = True
        action = mock.Mock(side_effect=side_effect)

        req, context, body = self._setup_add_sec_services_with_servers_tests(
            fake_share_network, security_service,
            share_api_update_services_action=action)

        self.assertRaises(
            exception_to_raise,
            self.controller.add_security_service,
            req, share_network_id, body
        )

        db_api.security_service_get.assert_called_once_with(
            context, security_service_id)
        db_api.share_network_get.assert_called_once_with(
            context, share_network_id)
        (self.controller.share_api.update_share_network_security_service.
         assert_called_once_with(context, fake_share_network,
                                 security_service))

    @ddt.data(
        (exception.NotFound(message='fake'), webob_exc.HTTPNotFound),
        (exception.ShareNetworkSecurityServiceAssociationError(message='fake'),
         webob_exc.HTTPBadRequest))
    @ddt.unpack
    def test_action_add_security_service_conflict(self, captured_exception,
                                                  expected_raised_exception):
        share_network = fake_share_network.copy()
        share_network['security_services'] = [{'id': 'security_service_1',
                                               'type': 'ldap'}]
        security_service = {'id': ' security_service_2',
                            'type': 'ldap'}
        body = {'add_security_service': {'security_service_id':
                                         security_service['id']}}
        request = fakes.HTTPRequest.blank(
            '/share-networks', use_admin_context=True)
        self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers',
            mock.Mock(return_value=False))
        update_sec_serv_mock = self.mock_object(
            self.controller.share_api, 'update_share_network_security_service')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(db_api, 'security_service_get',
                         mock.Mock(return_value=security_service))
        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(
            db_api, 'share_network_add_security_service',
            mock.Mock(side_effect=captured_exception))

        db_api.security_service_get.return_value = security_service
        db_api.share_network_get.return_value = share_network
        self.assertRaises(expected_raised_exception,
                          self.controller.add_security_service,
                          request,
                          share_network['id'],
                          body)

        db_api.share_network_get.assert_called_once_with(
            request.environ['manila.context'], share_network['id'])
        db_api.security_service_get.assert_called_once_with(
            request.environ['manila.context'], security_service['id'])
        share_networks.policy.check_policy.assert_called_once_with(
            request.environ['manila.context'],
            share_networks.RESOURCE_NAME,
            'add_security_service', target_obj=share_network)
        update_sec_serv_mock.assert_called_once_with(
            request.environ['manila.context'], share_network,
            security_service)

    def _setup_update_sec_services_with_servers_tests(
            self, share_network, security_services,
            version=ADD_UPDATE_SEC_SERVICE_VERSION,
            share_api_update_services_action=mock.Mock()):

        self.mock_object(
            db_api, 'share_network_get', mock.Mock(return_value=share_network))
        self.mock_object(
            db_api, 'security_service_get',
            mock.Mock(side_effect=security_services))
        self.mock_object(
            self.controller.share_api, 'update_share_network_security_service',
            share_api_update_services_action)
        self.mock_object(self.controller._view_builder, 'build_share_network')
        self.mock_object(db_api, 'share_network_update_security_service')

        body = {
            'update_security_service': {
                'current_service_id': security_services[0]['id'],
                'new_service_id': security_services[1]['id']
            }
        }
        req = fakes.HTTPRequest.blank(
            '/add_security_service', version=version, use_admin_context=True)
        context = req.environ['manila.context']

        return req, context, body

    def test_update_security_service_service_not_found(self):
        security_services = [
            db_utils.create_security_service() for i in range(2)]
        share_network = copy.deepcopy(fake_share_network)
        share_network['security_service_update_support'] = True

        req, context, body = (
            self._setup_update_sec_services_with_servers_tests(
                share_network, security_services))

        db_api.security_service_get.side_effect = exception.NotFound('fake')

        self.assertRaises(
            webob_exc.HTTPBadRequest,
            self.controller.update_security_service,
            req, share_network['id'], body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        db_api.security_service_get.assert_has_calls(
            [mock.call(context, security_services[0]['id'])]
        )

    @ddt.data(
        (exception.ServiceIsDown(message='fake'), webob_exc.HTTPConflict),
        (exception.InvalidShareNetwork(message='fake'),
         webob_exc.HTTPBadRequest))
    @ddt.unpack
    def test_update_security_service_share_api_failure(self, side_effect, exc):
        security_services = [
            db_utils.create_security_service() for i in range(2)]
        share_network = copy.deepcopy(fake_share_network)
        share_network['security_service_update_support'] = True

        req, context, body = (
            self._setup_update_sec_services_with_servers_tests(
                share_network, security_services,
                share_api_update_services_action=mock.Mock(
                    side_effect=side_effect)))

        self.assertRaises(
            exc,
            self.controller.update_security_service,
            req, share_network['id'], body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        db_api.security_service_get.assert_has_calls(
            [mock.call(context, security_services[0]['id']),
             mock.call(context, security_services[1]['id'])]
        )

    def test_update_security_service(self):
        security_services = [
            db_utils.create_security_service() for i in range(2)]
        share_network = copy.copy(fake_share_network)
        share_network['security_service_update_support'] = True

        req, context, body = (
            self._setup_update_sec_services_with_servers_tests(
                share_network, security_services))

        self.controller.update_security_service(
            req, share_network['id'], body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        db_api.security_service_get.assert_has_calls(
            [mock.call(context, security_services[0]['id']),
             mock.call(context, security_services[1]['id'])]
        )
        (self.controller.share_api.update_share_network_security_service.
            assert_called_once_with(
                context, share_network, security_services[1],
                current_security_service=security_services[0]))
        db_api.share_network_update_security_service.assert_called_once_with(
            context, share_network['id'], security_services[0]['id'],
            security_services[1]['id'])

    @ddt.data(*set(("1.0", "2.25", "2.26", api_version._MAX_API_VERSION)))
    def test_action_remove_security_service(self, microversion):
        share_network_id = 'fake network id'
        security_service_id = 'fake ss id'
        self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers')
        body = {'remove_security_service': {'security_service_id':
                                            security_service_id}}

        req = fakes.HTTPRequest.blank('/share-networks', version=microversion)
        with mock.patch.object(self.controller, 'remove_security_service',
                               mock.Mock()):
            self.controller.remove_security_service(
                req, share_network_id, body)
            self.controller.remove_security_service.assert_called_once_with(
                req, share_network_id, body)

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    @mock.patch.object(share_networks.policy, 'check_policy', mock.Mock())
    def test_action_remove_security_service_forbidden(self):
        share_network = fake_share_network.copy()
        subnet = fake_share_network_subnet.copy()
        subnet['share_servers'] = ['foo']
        share_network['share_network_subnets'] = [subnet]
        db_api.share_network_get.return_value = share_network
        self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers',
            mock.Mock(return_value=True))
        body = {
            'remove_security_service': {
                'security_service_id': 'fake id',
            },
        }
        self.assertRaises(webob_exc.HTTPForbidden,
                          self.controller.remove_security_service,
                          self.req,
                          share_network['id'],
                          body)
        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_network['id'])
        share_networks.policy.check_policy.assert_called_once_with(
            self.req.environ['manila.context'],
            share_networks.RESOURCE_NAME,
            'remove_security_service', target_obj=share_network)

    @mock.patch.object(share_networks.policy, 'check_policy', mock.Mock())
    def test_action_remove_security_service_share_no_share_servers(self):
        share_network = fake_share_network.copy()
        subnet = fake_share_network_subnet.copy()
        share_network['share_network_subnets'] = [subnet]
        mock_share_net_get = self.mock_object(
            db_api, 'share_network_get', mock.Mock(return_value=share_network))
        mock_contains_servers = self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers',
            mock.Mock(return_value=False))
        mock_api_remove = self.mock_object(
            db_api, 'share_network_remove_security_service',
            mock.Mock(return_value=share_network))
        mock_view = self.mock_object(
            self.controller._view_builder, 'build_share_network',
            mock.Mock(return_value='fake_view'))
        body = {
            'remove_security_service': {
                'security_service_id': 'fake_ss_id',
            },
        }

        view = self.controller.remove_security_service(
            self.req, share_network['id'], body)

        self.assertEqual('fake_view', view)
        mock_share_net_get.assert_called_once_with(
            self.req.environ['manila.context'], share_network['id'])
        share_networks.policy.check_policy.assert_called_once_with(
            self.req.environ['manila.context'],
            share_networks.RESOURCE_NAME,
            'remove_security_service', target_obj=share_network)
        mock_contains_servers.assert_called_once_with(share_network)
        mock_api_remove.assert_called_once_with(
            self.req.environ['manila.context'], share_network['id'],
            'fake_ss_id')
        mock_view.assert_called_once_with(self.req, share_network)

    @ddt.data(
        (KeyError, webob_exc.HTTPBadRequest),
        (exception.NotFound(message='fake'), webob_exc.HTTPNotFound),
        (exception.ShareNetworkSecurityServiceDissociationError(
            message='fake'), webob_exc.HTTPBadRequest))
    @ddt.unpack
    def test_action_remove_security_service_share_api_exception(self, api_exp,
                                                                expect_exp):
        share_network = fake_share_network.copy()
        subnet = fake_share_network_subnet.copy()
        share_network['share_network_subnets'] = [subnet]
        mock_policy = self.mock_object(
            share_networks.policy, 'check_policy', mock.Mock())
        mock_share_net_get = self.mock_object(
            db_api, 'share_network_get',
            mock.Mock(return_value=share_network))
        mock_contains_servers = self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers',
            mock.Mock(return_value=False))
        mock_api_remove = self.mock_object(
            db_api, 'share_network_remove_security_service',
            mock.Mock(side_effect=api_exp))
        body = {
            'remove_security_service': {
                'security_service_id': 'fake_ss_id',
            },
        }

        self.assertRaises(expect_exp,
                          self.controller.remove_security_service,
                          self.req,
                          share_network['id'],
                          body)

        mock_share_net_get.assert_called_once_with(
            self.req.environ['manila.context'], share_network['id'])
        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_network['id'])
        mock_policy.assert_called_once_with(
            self.req.environ['manila.context'],
            share_networks.RESOURCE_NAME,
            'remove_security_service', target_obj=share_network)
        mock_contains_servers.assert_called_once_with(share_network)
        mock_api_remove.assert_called_once_with(
            self.req.environ['manila.context'], share_network['id'],
            'fake_ss_id')

    @ddt.data('add_security_service', 'remove_security_service')
    def test_action_security_service_contains_share_servers(self, action):
        share_network = fake_share_network.copy()
        security_service = {'id': ' security_service_2',
                            'type': 'ldap'}
        method_to_call = (
            self.controller.add_security_service
            if action == 'add_security_service'
            else self.controller.remove_security_service)
        body = {
            action: {
                'security_service_id': security_service['id']
            }
        }
        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(db_api, 'security_service_get',
                         mock.Mock(return_value=security_service))
        self.mock_object(
            self.controller, '_share_network_subnets_contain_share_servers',
            mock.Mock(return_value=True))

        self.assertRaises(webob_exc.HTTPForbidden,
                          method_to_call,
                          self.req,
                          share_network['id'],
                          body)
        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_network['id'])
        share_networks.policy.check_policy.assert_called_once_with(
            self.req.environ['manila.context'],
            share_networks.RESOURCE_NAME, action, target_obj=share_network)

    def _setup_data_for_update_tests(self, is_check=False):
        security_services = [
            db_utils.create_security_service() for i in range(2)]
        share_network = db_utils.create_share_network()
        action = ('update_security_service_check' if is_check
                  else 'update_security_service')
        body = {
            action: {
                'current_service_id': security_services[0]['id'],
                'new_service_id': security_services[1]['id'],
            }
        }
        if is_check:
            body[action]['reset_operation'] = False
        request = fakes.HTTPRequest.blank(
            '/v2/fake/share-networks/%s/action' % share_network['id'],
            use_admin_context=True, version='2.63')
        return security_services, share_network, body, request

    def test_check_update_security_service_not_found(self):
        security_services, share_network, body, request = (
            self._setup_data_for_update_tests(is_check=True))

        context = request.environ['manila.context']

        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(db_api, 'security_service_get',
                         mock.Mock(side_effect=exception.NotFound()))

        self.assertRaises(
            webob_exc.HTTPBadRequest,
            self.controller.check_update_security_service,
            request,
            share_network['id'],
            body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id']
        )
        db_api.security_service_get.assert_called_once_with(
            context, security_services[0]['id'])

    def test_check_update_security_service(self):
        security_services, share_network, body, request = (
            self._setup_data_for_update_tests(is_check=True))
        context = request.environ['manila.context']
        share_api_return = {'fake_key': 'fake_value'}

        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(
            db_api, 'security_service_get',
            mock.Mock(
                side_effect=[security_services[0], security_services[1]]))
        self.mock_object(
            self.controller.share_api,
            'check_share_network_security_service_update',
            mock.Mock(return_vale=share_api_return))
        self.mock_object(
            self.controller._view_builder,
            'build_security_service_update_check')

        self.controller.check_update_security_service(
            request, share_network['id'], body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        db_api.security_service_get.assert_has_calls(
            [mock.call(context, security_services[0]['id']),
             mock.call(context, security_services[1]['id'])])
        (self.controller.share_api.check_share_network_security_service_update.
            assert_called_once_with(
                context, share_network, security_services[1],
                current_security_service=security_services[0],
                reset_operation=False))

    @ddt.data(
        (exception.ServiceIsDown(message='fake'), webob_exc.HTTPConflict),
        (exception.InvalidShareNetwork(message='fake'),
         webob_exc.HTTPBadRequest),
        (exception.InvalidSecurityService(message='fake'),
         webob_exc.HTTPConflict))
    @ddt.unpack
    def test_check_update_security_service_share_api_failed(
            self, captured_exception, exception_to_be_raised):
        security_services, share_network, body, request = (
            self._setup_data_for_update_tests(is_check=True))
        context = request.environ['manila.context']

        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(
            db_api, 'security_service_get',
            mock.Mock(
                side_effect=[security_services[0], security_services[1]]))
        self.mock_object(
            self.controller.share_api,
            'check_share_network_security_service_update',
            mock.Mock(side_effect=captured_exception))

        self.assertRaises(
            exception_to_be_raised,
            self.controller.check_update_security_service,
            request,
            share_network['id'],
            body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        db_api.security_service_get.assert_has_calls(
            [mock.call(context, security_services[0]['id']),
             mock.call(context, security_services[1]['id'])])
        (self.controller.share_api.check_share_network_security_service_update.
            assert_called_once_with(
                context, share_network, security_services[1],
                current_security_service=security_services[0],
                reset_operation=False))

    def _setup_data_for_check_add_tests(self):
        security_service = db_utils.create_security_service()
        share_network = db_utils.create_share_network()
        body = {
            'add_security_service_check': {
                'reset_operation': False,
                'security_service_id': security_service['id'],
            }
        }
        request = fakes.HTTPRequest.blank(
            '/share-networks', use_admin_context=True, version='2.63')
        return security_service, share_network, body, request

    def test_check_add_security_service_not_found(self):
        security_service, share_network, body, request = (
            self._setup_data_for_check_add_tests())

        context = request.environ['manila.context']

        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(db_api, 'security_service_get',
                         mock.Mock(side_effect=exception.NotFound()))

        self.assertRaises(
            webob_exc.HTTPBadRequest,
            self.controller.check_add_security_service,
            request,
            share_network['id'],
            body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id']
        )
        db_api.security_service_get.assert_called_once_with(
            context, security_service['id'], project_only=True)

    def test_check_add_security_service(self):
        security_service, share_network, body, request = (
            self._setup_data_for_check_add_tests())
        context = request.environ['manila.context']
        share_api_return = {'fake_key': 'fake_value'}

        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(
            db_api, 'security_service_get',
            mock.Mock(return_value=security_service))
        self.mock_object(
            self.controller.share_api,
            'check_share_network_security_service_update',
            mock.Mock(return_vale=share_api_return))
        self.mock_object(
            self.controller._view_builder,
            'build_security_service_update_check')

        self.controller.check_add_security_service(
            request, share_network['id'], body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        db_api.security_service_get.assert_called_once_with(
            context, security_service['id'], project_only=True)
        (self.controller.share_api.check_share_network_security_service_update.
            assert_called_once_with(
                context, share_network, security_service,
                reset_operation=False))

    @ddt.data(
        (exception.ServiceIsDown(message='fake'), webob_exc.HTTPConflict),
        (exception.InvalidShareNetwork(message='fake'),
         webob_exc.HTTPBadRequest),
        (exception.InvalidSecurityService(message='fake'),
         webob_exc.HTTPConflict))
    @ddt.unpack
    def test_check_add_security_service_share_api_failed(
            self, captured_exception, exception_to_be_raised):
        security_service, share_network, body, request = (
            self._setup_data_for_check_add_tests())
        context = request.environ['manila.context']

        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(
            db_api, 'security_service_get',
            mock.Mock(return_value=security_service))
        self.mock_object(
            self.controller.share_api,
            'check_share_network_security_service_update',
            mock.Mock(side_effect=captured_exception))

        self.assertRaises(
            exception_to_be_raised,
            self.controller.check_add_security_service,
            request,
            share_network['id'],
            body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        db_api.security_service_get.assert_called_once_with(
            context, security_service['id'], project_only=True)
        (self.controller.share_api.check_share_network_security_service_update.
            assert_called_once_with(
                context, share_network, security_service,
                reset_operation=False))

    @ddt.data(
        (exception.NotFound(message='fake'),
         webob_exc.HTTPBadRequest))
    @ddt.unpack
    def test_check_add_security_service_failed_project_id(
            self, captured_exception, exception_to_be_raised):
        security_service, share_network, body, request = (
            self._setup_data_for_check_add_tests())
        share_network = fake_share_network
        context = request.environ['manila.context']
        share_api_return = {'fake_key': 'fake_value'}

        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(
            db_api, 'security_service_get',
            mock.Mock(side_effect=captured_exception))
        self.mock_object(
            self.controller.share_api,
            'check_share_network_security_service_update',
            mock.Mock(return_vale=share_api_return))
        self.mock_object(
            self.controller._view_builder,
            'build_security_service_update_check')

        self.assertRaises(
            exception_to_be_raised,
            self.controller.check_add_security_service,
            request,
            share_network['id'],
            body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        db_api.security_service_get.assert_called_once_with(
            context, security_service['id'], project_only=True)

    @ddt.data(
        (exception.ServiceIsDown(message='fake'), webob_exc.HTTPConflict),
        (exception.InvalidShareNetwork(message='fake'),
         webob_exc.HTTPBadRequest),
        (exception.InvalidSecurityService(message='fake'),
         webob_exc.HTTPConflict))
    @ddt.unpack
    def test_update_security_service_share_api_failed(
            self, captured_exception, exception_to_be_raised):
        security_services, share_network, body, request = (
            self._setup_data_for_update_tests())
        context = request.environ['manila.context']

        self.mock_object(share_networks.policy, 'check_policy')
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(
            db_api, 'security_service_get',
            mock.Mock(
                side_effect=[security_services[0], security_services[1]]))
        self.mock_object(
            self.controller.share_api,
            'update_share_network_security_service',
            mock.Mock(side_effect=captured_exception))

        self.assertRaises(exception_to_be_raised,
                          self.controller.update_security_service,
                          request,
                          share_network['id'],
                          body)

        db_api.share_network_get.assert_called_once_with(
            context, share_network['id'])
        db_api.security_service_get.assert_has_calls(
            [mock.call(context, security_services[0]['id']),
             mock.call(context, security_services[1]['id'])])
        (self.controller.share_api.update_share_network_security_service.
            assert_called_once_with(
                context, share_network, security_services[1],
                current_security_service=security_services[0]))

    def test_reset_status(self):
        share_network = db_utils.create_share_network()
        request = fakes.HTTPRequest.blank(
            '/v2/fake/share-networks/%s/action' % share_network['id'],
            use_admin_context=True, version='2.63')
        self.mock_object(db_api, 'share_network_update')

        status = {'status': 'active'}
        body = {'reset_status': status}

        response = self.controller.reset_status(request,
                                                share_network['id'], body)

        self.assertEqual(202, response.status_int)
        db_api.share_network_update.assert_called_once_with(
            request.environ['manila.context'],
            share_network['id'], {'status': 'active'})

    @ddt.data([], ['fake_server'])
    def test_share_network_subnet_create_check(self, servers):
        body = {
            'share_network_subnet_create_check': {
                'reset_operation': False,
                'availability_zone': 'fake_az',
            }
        }
        request = fakes.HTTPRequest.blank(
            '/share-networks', use_admin_context=True, version='2.70')
        context = request.environ['manila.context']

        share_net = 'fake_net'
        subnet = {'share_servers': servers}
        existing_subnets = [subnet]
        mock_validate_subnet = self.mock_object(
            common, 'validate_subnet_create',
            mock.Mock(return_value=(share_net, existing_subnets)))
        share_api_return = {
            'compatible': not bool(servers),
            'hosts_check_result': {}
        }
        mock_check_update = self.mock_object(
            self.controller.share_api,
            'check_update_share_server_network_allocations',
            mock.Mock(return_value=share_api_return))
        subnet_view = 'fake_subnet'
        mock_view = self.mock_object(
            self.controller._view_builder,
            'build_share_network_subnet_create_check',
            mock.Mock(return_value=subnet_view))

        net_id = 'fake_net_id'
        response = self.controller.share_network_subnet_create_check(
            request, net_id, body)

        self.assertEqual(subnet_view, response)
        data = body['share_network_subnet_create_check']
        mock_validate_subnet.assert_called_once_with(
            context, net_id, data, True)
        if servers:
            data['share_servers'] = servers
            mock_check_update.assert_called_once_with(
                context, share_net, data, False)
        else:
            mock_check_update.assert_not_called()
        mock_view.assert_called_once_with(request, share_api_return)

    @ddt.data(
        (exception.ServiceIsDown(message='fake'),
         webob_exc.HTTPInternalServerError),
        (exception.InvalidShareNetwork(message='fake'),
         webob_exc.HTTPBadRequest))
    @ddt.unpack
    def test_share_network_subnet_create_check_api_failed(
            self, captured_exception, exception_to_be_raised):
        body = {
            'share_network_subnet_create_check': {
                'reset_operation': False,
                'availability_zone': 'fake_az',
            }
        }
        request = fakes.HTTPRequest.blank(
            '/share-networks', use_admin_context=True, version='2.70')
        share_net = 'fake_net'
        subnet = {'share_servers': 'fake_server'}
        existing_subnets = [subnet]
        self.mock_object(
            common, 'validate_subnet_create',
            mock.Mock(return_value=(share_net, existing_subnets)))
        self.mock_object(
            self.controller.share_api,
            'check_update_share_server_network_allocations',
            mock.Mock(side_effect=captured_exception))

        self.assertRaises(exception_to_be_raised,
                          self.controller.share_network_subnet_create_check,
                          request, 'fake_net_id', body)
