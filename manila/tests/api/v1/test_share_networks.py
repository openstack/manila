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

import ddt
import mock
from oslo_db import exception as db_exception
from oslo_utils import timeutils
from six.moves.urllib import parse
from webob import exc as webob_exc

from manila.api.v1 import share_networks
from manila.db import api as db_api
from manila import exception
from manila import quota
from manila import test
from manila.tests.api import fakes


fake_share_network = {
    'id': 'fake network id',
    'project_id': 'fake project',
    'created_at': timeutils.parse_strtime('2002-02-02', fmt="%Y-%m-%d"),
    'updated_at': None,
    'neutron_net_id': 'fake net id',
    'neutron_subnet_id': 'fake subnet id',
    'network_type': 'vlan',
    'segmentation_id': 1000,
    'cidr': '10.0.0.0/24',
    'ip_version': 4,
    'name': 'fake name',
    'description': 'fake description',
    'share_servers': [],
    'security_services': []
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
    'neutron_net_id': '1111',
    'neutron_subnet_id': '2222',
    'network_type': 'local',
    'segmentation_id': 2000,
    'cidr': '8.0.0.0/12',
    'ip_version': 6,
    'name': 'test-sn',
    'description': 'fake description',
    'share_servers': [],
    'security_services': [{'id': 'fake-ss-id'}]
}

fake_sn_with_ss_shortened = {
    'id': 'sn-id',
    'name': 'test-sn',
}

QUOTAS = quota.QUOTAS


@ddt.ddt
class ShareNetworkAPITest(test.TestCase):

    def setUp(self):
        super(ShareNetworkAPITest, self).setUp()
        self.controller = share_networks.ShareNetworkController()
        self.req = fakes.HTTPRequest.blank('/share-networks')
        self.body = {share_networks.RESOURCE_NAME: {'name': 'fake name'}}
        self.context = self.req.environ['manila.context']

    def _check_share_network_view_shortened(self, view, share_nw):
        self.assertEqual(share_nw['id'], view['id'])
        self.assertEqual(share_nw['name'], view['name'])

    def _check_share_network_view(self, view, share_nw):
        self.assertEqual(share_nw['id'], view['id'])
        self.assertEqual(share_nw['project_id'], view['project_id'])
        self.assertEqual(share_nw['created_at'], view['created_at'])
        self.assertEqual(share_nw['updated_at'], view['updated_at'])
        self.assertEqual(share_nw['neutron_net_id'],
                         view['neutron_net_id'])
        self.assertEqual(share_nw['neutron_subnet_id'],
                         view['neutron_subnet_id'])
        self.assertEqual(share_nw['network_type'], view['network_type'])
        self.assertEqual(share_nw['segmentation_id'],
                         view['segmentation_id'])
        self.assertEqual(share_nw['cidr'], view['cidr'])
        self.assertEqual(share_nw['ip_version'], view['ip_version'])
        self.assertEqual(share_nw['name'], view['name'])
        self.assertEqual(share_nw['description'], view['description'])

        self.assertEqual(share_nw['created_at'], view['created_at'])
        self.assertEqual(share_nw['updated_at'], view['updated_at'])
        self.assertFalse('shares' in view)
        self.assertFalse('network_allocations' in view)
        self.assertFalse('security_services' in view)

    @ddt.data(
        {'nova_net_id': 'fake_nova_net_id'},
        {'neutron_net_id': 'fake_neutron_net_id'},
        {'neutron_subnet_id': 'fake_neutron_subnet_id'},
        {'neutron_net_id': 'fake', 'neutron_subnet_id': 'fake'})
    def test_create_valid_cases(self, data):
        data.update({'user_id': 'fake_user_id'})
        body = {share_networks.RESOURCE_NAME: data}
        result = self.controller.create(self.req, body)
        data.pop('user_id', None)
        for k, v in data.items():
            self.assertIn(data[k], result['share_network'][k])

    @ddt.data(
        {'nova_net_id': 'foo', 'neutron_net_id': 'bar'},
        {'nova_net_id': 'foo', 'neutron_subnet_id': 'quuz'},
        {'nova_net_id': 'foo', 'neutron_net_id': 'bar',
         'neutron_subnet_id': 'quuz'})
    def test_create_invalid_cases(self, data):
        data.update({'user_id': 'fake_user_id'})
        body = {share_networks.RESOURCE_NAME: data}
        self.assertRaises(
            webob_exc.HTTPBadRequest, self.controller.create, self.req, body)

    @ddt.data(
        {'nova_net_id': 'fake_nova_net_id'},
        {'neutron_net_id': 'fake_neutron_net_id'},
        {'neutron_subnet_id': 'fake_neutron_subnet_id'},
        {'neutron_net_id': 'fake', 'neutron_subnet_id': 'fake'})
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
         'neutron_subnet_id': 'quuz'})
    def test_update_invalid_cases(self, data):
        body = {share_networks.RESOURCE_NAME: {'user_id': 'fake_user'}}
        created = self.controller.create(self.req, body)
        body = {share_networks.RESOURCE_NAME: data}
        self.assertRaises(
            webob_exc.HTTPBadRequest,
            self.controller.update,
            self.req, created['share_network']['id'], body)

    def test_create_nominal(self):
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
            self.assertRaises(webob_exc.HTTPBadRequest,
                              self.controller.create,
                              self.req,
                              self.body)

    def test_create_wrong_body(self):
        body = None
        self.assertRaises(webob_exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          self.req,
                          body)

    def test_delete_nominal(self):
        share_nw = fake_share_network.copy()
        share_nw['share_servers'] = ['foo', 'bar']
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'share_instances_get_all_by_share_network',
                         mock.Mock(return_value=[]))
        self.mock_object(self.controller.share_rpcapi, 'delete_share_server')
        self.mock_object(db_api, 'share_network_delete')

        self.controller.delete(self.req, share_nw['id'])

        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])
        db_api.share_instances_get_all_by_share_network.\
            assert_called_once_with(self.req.environ['manila.context'],
                                    share_nw['id'])
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
        share_nw['share_servers'] = ['foo', 'bar']
        share_nw['user_id'] = 'fake_user_id'

        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'share_instances_get_all_by_share_network',
                         mock.Mock(return_value=[]))
        self.mock_object(self.controller.share_rpcapi, 'delete_share_server')
        self.mock_object(db_api, 'share_network_delete')
        self.mock_object(share_networks.QUOTAS, 'reserve',
                         mock.Mock(side_effect=Exception))
        self.mock_object(share_networks.QUOTAS, 'commit')

        self.controller.delete(self.req, share_nw['id'])

        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])

        db_api.share_instances_get_all_by_share_network.\
            assert_called_once_with(self.req.environ['manila.context'],
                                    share_nw['id'])

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
        db_api.share_instances_get_all_by_share_network.\
            assert_called_once_with(self.req.environ['manila.context'],
                                    share_nw['id'])

    def test_delete_in_use_by_consistency_group(self):
        share_nw = fake_share_network.copy()
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_nw))
        self.mock_object(db_api, 'count_consistency_groups_in_share_network',
                         mock.Mock(return_value=2))

        self.assertRaises(webob_exc.HTTPConflict,
                          self.controller.delete,
                          self.req,
                          share_nw['id'])

        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_nw['id'])

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
                               'share_network_get_all_by_project',
                               mock.Mock(return_value=networks)):

            result = self.controller.index(self.req)

            db_api.share_network_get_all_by_project.assert_called_once_with(
                self.context,
                self.context.project_id)

            self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
            self._check_share_network_view_shortened(
                result[share_networks.RESOURCES_NAME][0],
                fake_share_network_shortened)

    def test_index_detailed(self):
        networks = [fake_share_network]
        with mock.patch.object(db_api,
                               'share_network_get_all_by_project',
                               mock.Mock(return_value=networks)):

            result = self.controller.detail(self.req)

            db_api.share_network_get_all_by_project.assert_called_once_with(
                self.context,
                self.context.project_id)

            self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
            self._check_share_network_view(
                result[share_networks.RESOURCES_NAME][0],
                fake_share_network)

    @mock.patch.object(db_api, 'share_network_get_all_by_security_service',
                       mock.Mock())
    def test_index_filter_by_security_service(self):
        db_api.share_network_get_all_by_security_service.return_value = [
            fake_share_network_with_ss]
        req = fakes.HTTPRequest.blank(
            '/share_networks?security_service_id=fake-ss-id')
        result = self.controller.index(req)
        db_api.share_network_get_all_by_security_service.\
            assert_called_once_with(req.environ['manila.context'],
                                    'fake-ss-id')
        self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
        self._check_share_network_view_shortened(
            result[share_networks.RESOURCES_NAME][0],
            fake_sn_with_ss_shortened)

    @mock.patch.object(db_api, 'share_network_get_all', mock.Mock())
    def test_index_all_tenants_non_admin_context(self):
        req = fakes.HTTPRequest.blank(
            '/share_networks?all_tenants=1')
        self.assertRaises(exception.PolicyNotAuthorized, self.controller.index,
                          req)
        self.assertFalse(db_api.share_network_get_all.called)

    @mock.patch.object(db_api, 'share_network_get_all', mock.Mock())
    def test_index_all_tenants_admin_context(self):
        db_api.share_network_get_all.return_value = [fake_share_network]
        req = fakes.HTTPRequest.blank(
            '/share_networks?all_tenants=1',
            use_admin_context=True)
        result = self.controller.index(req)
        db_api.share_network_get_all.assert_called_once_with(
            req.environ['manila.context'])
        self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
        self._check_share_network_view_shortened(
            result[share_networks.RESOURCES_NAME][0],
            fake_share_network_shortened)

    @mock.patch.object(db_api, 'share_network_get_all_by_project', mock.Mock())
    def test_index_filter_by_project_id_non_admin_context(self):
        req = fakes.HTTPRequest.blank(
            '/share_networks?project_id=fake project')
        self.assertRaises(exception.PolicyNotAuthorized, self.controller.index,
                          req)
        self.assertFalse(db_api.share_network_get_all_by_project.called)

    @mock.patch.object(db_api, 'share_network_get_all_by_project', mock.Mock())
    def test_index_filter_by_project_id_admin_context(self):
        db_api.share_network_get_all_by_project.return_value = [
            fake_share_network,
            fake_share_network_with_ss,
        ]
        req = fakes.HTTPRequest.blank(
            '/share_networks?project_id=fake',
            use_admin_context=True)
        result = self.controller.index(req)
        db_api.share_network_get_all_by_project.assert_called_once_with(
            req.environ['manila.context'], 'fake')
        self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
        self._check_share_network_view_shortened(
            result[share_networks.RESOURCES_NAME][0],
            fake_sn_with_ss_shortened)

    @mock.patch.object(db_api, 'share_network_get_all_by_security_service',
                       mock.Mock())
    def test_index_filter_by_ss_and_project_id_admin_context(self):
        db_api.share_network_get_all_by_security_service.return_value = [
            fake_share_network,
            fake_share_network_with_ss,
        ]
        req = fakes.HTTPRequest.blank(
            '/share_networks?security_service_id=fake-ss-id&project_id=fake',
            use_admin_context=True)
        result = self.controller.index(req)
        db_api.share_network_get_all_by_security_service.\
            assert_called_once_with(req.environ['manila.context'],
                                    'fake-ss-id')
        self.assertEqual(1, len(result[share_networks.RESOURCES_NAME]))
        self._check_share_network_view_shortened(
            result[share_networks.RESOURCES_NAME][0],
            fake_sn_with_ss_shortened)

    @mock.patch.object(db_api, 'share_network_get_all_by_project',
                       mock.Mock())
    def test_index_all_filter_opts(self):
        valid_filter_opts = {
            'created_before': '2001-02-02',
            'created_since': '1999-01-01',
            'neutron_net_id': '1111',
            'neutron_subnet_id': '2222',
            'network_type': 'local',
            'segmentation_id': 2000,
            'cidr': '8.0.0.0/12',
            'ip_version': 6,
            'name': 'test-sn'
        }
        db_api.share_network_get_all_by_project.return_value = [
            fake_share_network,
            fake_share_network_with_ss]

        query_string = '/share-networks?' + parse.urlencode(sorted(
            [(k, v) for (k, v) in list(valid_filter_opts.items())]))
        for use_admin_context in [True, False]:
            req = fakes.HTTPRequest.blank(query_string,
                                          use_admin_context=use_admin_context)
            result = self.controller.index(req)
            db_api.share_network_get_all_by_project.assert_called_with(
                req.environ['manila.context'],
                'fake')
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

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    def test_update_invalid_key_in_use(self):
        share_nw = fake_share_network.copy()
        share_nw['share_servers'] = [{'id': 1}]

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
        share_nw['share_servers'] = [{'id': 1}]
        updated_share_nw = share_nw.copy()
        updated_share_nw['name'] = 'new name'
        updated_share_nw['description'] = 'new description'

        db_api.share_network_get.return_value = share_nw
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

    def test_action_add_security_service(self):
        share_network_id = 'fake network id'
        security_service_id = 'fake ss id'
        body = {'add_security_service': {'security_service_id':
                                         security_service_id}}

        with mock.patch.object(self.controller, '_add_security_service',
                               mock.Mock()):
            self.controller.action(self.req, share_network_id, body)
            self.controller._add_security_service.assert_called_once_with(
                self.req, share_network_id, body['add_security_service'])

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    @mock.patch.object(db_api, 'security_service_get', mock.Mock())
    def test_action_add_security_service_conflict(self):
        share_network = fake_share_network.copy()
        share_network['security_services'] = [{'id': 'security_service_1',
                                               'type': 'ldap'}]
        security_service = {'id': ' security_service_2',
                            'type': 'ldap'}
        body = {'add_security_service': {'security_service_id':
                                         security_service['id']}}

        db_api.security_service_get.return_value = security_service
        db_api.share_network_get.return_value = share_network
        with mock.patch.object(share_networks.policy, 'check_policy',
                               mock.Mock()):
            self.assertRaises(webob_exc.HTTPConflict,
                              self.controller.action,
                              self.req,
                              share_network['id'],
                              body)
            db_api.share_network_get.assert_called_once_with(
                self.req.environ['manila.context'], share_network['id'])
            db_api.security_service_get.assert_called_once_with(
                self.req.environ['manila.context'], security_service['id'])
            share_networks.policy.check_policy.assert_called_once_with(
                self.req.environ['manila.context'],
                share_networks.RESOURCE_NAME,
                'add_security_service',
            )

    def test_action_remove_security_service(self):
        share_network_id = 'fake network id'
        security_service_id = 'fake ss id'
        body = {'remove_security_service': {'security_service_id':
                                            security_service_id}}

        with mock.patch.object(self.controller, '_remove_security_service',
                               mock.Mock()):
            self.controller.action(self.req, share_network_id, body)
            self.controller._remove_security_service.assert_called_once_with(
                self.req, share_network_id, body['remove_security_service'])

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    @mock.patch.object(share_networks.policy, 'check_policy', mock.Mock())
    def test_action_remove_security_service_forbidden(self):
        share_network = fake_share_network.copy()
        share_network['share_servers'] = 'fake share server'
        db_api.share_network_get.return_value = share_network
        body = {
            'remove_security_service': {
                'security_service_id': 'fake id',
            },
        }
        self.assertRaises(webob_exc.HTTPForbidden,
                          self.controller.action,
                          self.req,
                          share_network['id'],
                          body)
        db_api.share_network_get.assert_called_once_with(
            self.req.environ['manila.context'], share_network['id'])
        share_networks.policy.check_policy.assert_called_once_with(
            self.req.environ['manila.context'],
            share_networks.RESOURCE_NAME,
            'remove_security_service')

    def test_action_bad_request(self):
        share_network_id = 'fake network id'
        body = {'bad_action': {}}

        self.assertRaises(webob_exc.HTTPBadRequest,
                          self.controller.action,
                          self.req,
                          share_network_id,
                          body)
