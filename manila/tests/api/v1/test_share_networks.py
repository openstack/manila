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

import mock
from webob import exc as webob_exc

from manila.api.v1 import share_networks
from manila.common import constants
from manila.db import api as db_api
from manila import exception
from manila import policy
from manila import quota
from manila import test
from manila.tests.api import fakes


fake_share_network = {
    'id': 'fake network id',
    'project_id': 'fake project',
    'created_at': None,
    'updated_at': None,
    'neutron_net_id': 'fake net id',
    'neutron_subnet_id': 'fake subnet id',
    'network_type': 'vlan',
    'segmentation_id': 1000,
    'cidr': '10.0.0.0/24',
    'ip_version': 4,
    'name': 'fake name',
    'description': 'fake description',
    'status': constants.STATUS_INACTIVE,
    'share_servers': [],
    'security_services': []
}
fake_share_network_shortened = {
    'id': 'fake network id',
    'name': 'fake name',
    'status': constants.STATUS_INACTIVE,
}

QUOTAS = quota.QUOTAS


class ShareNetworkAPITest(test.TestCase):

    def setUp(self):
        super(ShareNetworkAPITest, self).setUp()
        self.controller = share_networks.ShareNetworkController()
        self.req = fakes.HTTPRequest.blank('/share-networks')
        self.body = {share_networks.RESOURCE_NAME: {'name': 'fake name'}}
        self.context = self.req.environ['manila.context']

    def _check_share_network_view_shortened(self, view, share_nw):
        self.assertEqual(view['id'], share_nw['id'])
        self.assertEqual(view['name'], share_nw['name'])
        self.assertEqual(view['status'], share_nw['status'])

    def _check_share_network_view(self, view, share_nw):
        self.assertEqual(view['id'], share_nw['id'])
        self.assertEqual(view['project_id'], share_nw['project_id'])
        self.assertEqual(view['created_at'], share_nw['created_at'])
        self.assertEqual(view['updated_at'], share_nw['updated_at'])
        self.assertEqual(view['neutron_net_id'],
                         share_nw['neutron_net_id'])
        self.assertEqual(view['neutron_subnet_id'],
                         share_nw['neutron_subnet_id'])
        self.assertEqual(view['network_type'], share_nw['network_type'])
        self.assertEqual(view['segmentation_id'],
                         share_nw['segmentation_id'])
        self.assertEqual(view['cidr'], share_nw['cidr'])
        self.assertEqual(view['ip_version'], share_nw['ip_version'])
        self.assertEqual(view['name'], share_nw['name'])
        self.assertEqual(view['description'], share_nw['description'])
        self.assertEqual(view['status'], share_nw['status'])

        self.assertEqual(view['created_at'], None)
        self.assertEqual(view['updated_at'], None)
        self.assertFalse('shares' in view)
        self.assertFalse('network_allocations' in view)
        self.assertFalse('security_services' in view)

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
                               mock.Mock(side_effect=exception.DBError)):
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

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    def test_delete_nominal(self):
        share_nw = fake_share_network.copy()
        share_nw['share_servers'] = []
        db_api.share_network_get.return_value = share_nw

        with mock.patch.object(db_api, 'share_network_delete'):
            self.controller.delete(self.req, share_nw)
            db_api.share_network_delete.assert_called_once_with(
                self.req.environ['manila.context'],
                share_nw)

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    def test_delete_not_found(self):
        share_nw = 'fake network id'
        db_api.share_network_get.side_effect = exception.ShareNetworkNotFound(
                                                    share_network_id=share_nw)

        self.assertRaises(webob_exc.HTTPNotFound,
                          self.controller.delete,
                          self.req,
                          share_nw)

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    def test_delete_in_use(self):
        share_nw = fake_share_network.copy()
        share_servers = [{'id': 1}]
        share_nw['share_servers'] = share_servers

        db_api.share_network_get.return_value = share_nw

        self.assertRaises(webob_exc.HTTPForbidden,
                          self.controller.delete,
                          self.req,
                          share_nw['id'])

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

            self.assertEqual(len(result[share_networks.RESOURCES_NAME]), 1)
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

            self.assertEqual(len(result[share_networks.RESOURCES_NAME]), 1)
            self._check_share_network_view(
                result[share_networks.RESOURCES_NAME][0],
                fake_share_network)

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
    def test_update_in_use(self):
        share_nw = fake_share_network.copy()
        share_nw['share_servers'] = [{'id': 1}]

        db_api.share_network_get.return_value = share_nw

        self.assertRaises(webob_exc.HTTPForbidden,
                          self.controller.update,
                          self.req,
                          share_nw['id'],
                          self.body)

    @mock.patch.object(db_api, 'share_network_get', mock.Mock())
    def test_update_db_api_exception(self):
        share_nw = 'fake network id'
        db_api.share_network_get.return_value = fake_share_network

        body = {share_networks.RESOURCE_NAME: {'neutron_subnet_id':
                                               'new subnet'}}

        with mock.patch.object(db_api,
                               'share_network_update',
                               mock.Mock(side_effect=exception.DBError)):
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

    def test_action_bad_request(self):
        share_network_id = 'fake network id'
        body = {'bad_action': {}}

        self.assertRaises(webob_exc.HTTPBadRequest,
                          self.controller.action,
                          self.req,
                          share_network_id,
                          body)
