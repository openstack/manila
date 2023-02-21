# Copyright 2019 NetApp, Inc.
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

import ddt
from oslo_db import exception as db_exception

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.v2 import share_network_subnets
from manila.db import api as db_api
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils
from webob import exc

fake_az = {
    'id': 'ae525e12-07e8-4ddc-a2fd-4a89ad4a65ff',
    'name': 'fake_az_name'
}

fake_default_subnet = {
    'neutron_net_id': 'fake_nn_id',
    'neutron_subnet_id': 'fake_nsn_id',
    'availability_zone_id': None
}

fake_subnet_with_az = {
    'neutron_net_id': 'fake_nn_id',
    'neutron_subnet_id': 'fake_nsn_id',
    'availability_zone_id': 'fake_az_id'
}


@ddt.ddt
class ShareNetworkSubnetControllerTest(test.TestCase):
    """Share network subnet api test"""

    def setUp(self):
        super(ShareNetworkSubnetControllerTest, self).setUp()
        self.controller = share_network_subnets.ShareNetworkSubnetController()
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.resource_name = self.controller.resource_name
        self.mock_az_get = self.mock_object(db_api, 'availability_zone_get',
                                            mock.Mock(return_value=fake_az))
        self.share_network = db_utils.create_share_network(
            name='fake_network', id='fake_sn_id')
        self.subnet_metadata = {'fake_key': 'fake_value'}
        self.subnet = db_utils.create_share_network_subnet(
            share_network_id=self.share_network['id'],
            metadata=self.subnet_metadata)
        self.share_server = db_utils.create_share_server(
            share_network_subnets=[self.subnet])
        self.share = db_utils.create_share()

    def test_share_network_subnet_delete(self):
        req = fakes.HTTPRequest.blank('/subnets/%s' % self.subnet['id'],
                                      version="2.51")
        context = req.environ['manila.context']
        self.subnet['share_servers'] = [self.share_server]

        mock_sns_get = self.mock_object(
            db_api, 'share_network_subnet_get',
            mock.Mock(return_value=self.subnet))
        mock_all_get_all_shares_by_ss = self.mock_object(
            db_api, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=[]))
        mock_all_ss_are_auto_deletable = self.mock_object(
            self.controller, '_all_share_servers_are_auto_deletable',
            mock.Mock(return_value=True))
        mock_delete_share_server = self.mock_object(
            self.controller.share_rpcapi, 'delete_share_server')
        mock_subnet_delete = self.mock_object(db_api,
                                              'share_network_subnet_delete')

        result = self.controller.delete(req, self.share_network['id'],
                                        self.subnet['id'])

        self.assertEqual(202, result.status_int)
        mock_sns_get.assert_called_once_with(
            context, self.subnet['id'])
        mock_all_get_all_shares_by_ss.assert_called_once_with(
            context, self.subnet['share_servers'][0].id
        )
        mock_all_ss_are_auto_deletable.assert_called_once_with(
            self.subnet)
        mock_delete_share_server.assert_called_once_with(
            context, self.subnet['share_servers'][0])
        mock_subnet_delete.assert_called_once_with(
            context, self.subnet['id'])
        policy.check_policy.assert_called_once_with(
            context, self.resource_name, 'delete')

    def test_share_network_subnet_delete_network_not_found(self):
        req = fakes.HTTPRequest.blank('/subnets/%s' % self.subnet['id'],
                                      version="2.51")
        context = req.environ['manila.context']

        mock_sn_get = self.mock_object(
            db_api, 'share_network_get',
            mock.Mock(side_effect=exception.ShareNetworkNotFound(
                share_network_id=self.share_network['id']
            )))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.delete,
                          req,
                          self.share_network['id'],
                          self.subnet['id'])
        mock_sn_get.assert_called_once_with(
            context, self.share_network['id'])
        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'delete')

    def test_share_network_subnet_delete_subnet_not_found(self):
        req = fakes.HTTPRequest.blank('/subnets/%s' % self.subnet['id'],
                                      version="2.51")
        context = req.environ['manila.context']

        mock_sns_get = self.mock_object(
            db_api, 'share_network_subnet_get',
            mock.Mock(side_effect=exception.ShareNetworkSubnetNotFound(
                share_network_subnet_id=self.subnet['id']
            )))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.delete,
                          req,
                          self.share_network['id'],
                          self.subnet['id'])
        mock_sns_get.assert_called_once_with(
            context, self.subnet['id'])
        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'delete')

    def test_delete_subnet_with_share_servers_fail(self):
        req = fakes.HTTPRequest.blank('/subnets/%s' % self.subnet['id'],
                                      version="2.51")
        context = req.environ['manila.context']
        self.subnet['share_servers'] = [self.share_server]

        mock_sns_get = self.mock_object(
            db_api, 'share_network_subnet_get',
            mock.Mock(return_value=self.subnet))
        mock_all_get_all_shares_by_ss = self.mock_object(
            db_api, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=[]))
        mock_all_ss_are_auto_deletable = self.mock_object(
            self.controller, '_all_share_servers_are_auto_deletable',
            mock.Mock(return_value=False))

        self.assertRaises(exc.HTTPConflict,
                          self.controller.delete,
                          req,
                          self.share_network['id'],
                          self.subnet['id'])

        mock_sns_get.assert_called_once_with(
            context, self.subnet['id'])
        mock_all_get_all_shares_by_ss.assert_called_once_with(
            context, self.subnet['share_servers'][0].id
        )
        mock_all_ss_are_auto_deletable.assert_called_once_with(
            self.subnet
        )
        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'delete')

    def test_delete_subnet_with_shares_fail(self):
        req = fakes.HTTPRequest.blank('/subnets/%s' % self.subnet['id'],
                                      version="2.51")
        context = req.environ['manila.context']
        self.subnet['share_servers'] = [self.share_server]

        mock_network_get = self.mock_object(
            db_api, 'share_network_get')
        mock_sns_get = self.mock_object(
            db_api, 'share_network_subnet_get',
            mock.Mock(return_value=self.subnet))
        mock_all_get_all_shares_by_ss = self.mock_object(
            db_api, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=[self.share]))

        self.assertRaises(exc.HTTPConflict,
                          self.controller.delete,
                          req,
                          self.share_network['id'],
                          self.subnet['id'])

        mock_network_get.assert_called_once_with(
            context, self.share_network['id'])
        mock_sns_get.assert_called_once_with(
            context, self.subnet['id'])
        mock_all_get_all_shares_by_ss.assert_called_once_with(
            context, self.subnet['share_servers'][0].id
        )
        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'delete')

    def _setup_create_test_request_body(self, metadata=False):
        body = {
            'share_network_id': self.share_network['id'],
            'availability_zone': fake_az['name'],
            'neutron_net_id': 'fake_nn_id',
            'neutron_subnet_id': 'fake_nsn_id'
        }
        if metadata:
            body['metadata'] = self.subnet_metadata
        return body

    @ddt.data({'version': "2.51", 'has_share_servers': False},
              {'version': "2.70", 'has_share_servers': False},
              {'version': "2.70", 'has_share_servers': True},
              {'version': "2.78", 'has_share_servers': False})
    @ddt.unpack
    def test_subnet_create(self, version, has_share_servers):
        req = fakes.HTTPRequest.blank('/subnets', version=version)
        multiple_subnet_support = (req.api_version_request >=
                                   api_version.APIVersionRequest("2.70"))
        metadata_support = (req.api_version_request >=
                            api_version.APIVersionRequest("2.78"))

        context = req.environ['manila.context']
        body = {
            'share-network-subnet': self._setup_create_test_request_body(
                metadata=metadata_support)
        }

        sn_id = body['share-network-subnet']['share_network_id']
        expected_subnet = copy.deepcopy(self.subnet)
        if has_share_servers:
            expected_subnet['share_servers'] = [self.share_server]

        mock_validate_subnet_create = self.mock_object(
            common, 'validate_subnet_create',
            mock.Mock(return_value=(self.share_network, [expected_subnet])))
        mock_subnet_create = self.mock_object(
            db_api, 'share_network_subnet_create',
            mock.Mock(return_value=expected_subnet))
        mock_update_net_allocations = self.mock_object(
            self.controller.share_api,
            'update_share_server_network_allocations',
            mock.Mock(return_value=expected_subnet))
        mock_share_network_subnet_get = self.mock_object(
            db_api, 'share_network_subnet_get',
            mock.Mock(return_value=expected_subnet))
        mock_check_metadata_properties = self.mock_object(
            common, 'check_metadata_properties')

        fake_data = body['share-network-subnet']
        fake_data['share_network_id'] = self.share_network['id']
        res = self.controller.create(
            req, body['share-network-subnet']['share_network_id'], body)

        view_subnet = {
            'id': expected_subnet.get('id'),
            'availability_zone': expected_subnet.get('availability_zone'),
            'share_network_id': expected_subnet.get('share_network_id'),
            'share_network_name': expected_subnet['share_network_name'],
            'created_at': expected_subnet.get('created_at'),
            'segmentation_id': expected_subnet.get('segmentation_id'),
            'neutron_subnet_id': expected_subnet.get('neutron_subnet_id'),
            'updated_at': expected_subnet.get('updated_at'),
            'neutron_net_id': expected_subnet.get('neutron_net_id'),
            'ip_version': expected_subnet.get('ip_version'),
            'cidr': expected_subnet.get('cidr'),
            'network_type': expected_subnet.get('network_type'),
            'mtu': expected_subnet.get('mtu'),
            'gateway': expected_subnet.get('gateway')
        }
        if metadata_support:
            view_subnet['metadata'] = self.subnet_metadata
        self.assertEqual(view_subnet, res['share_network_subnet'])
        mock_share_network_subnet_get.assert_called_once_with(
            context, expected_subnet['id'])
        mock_validate_subnet_create.assert_called_once_with(
            context, sn_id, fake_data, multiple_subnet_support)
        if has_share_servers:
            fake_data['share_servers'] = [self.share_server]
            mock_update_net_allocations.assert_called_once_with(
                context, self.share_network, fake_data)
        else:
            mock_subnet_create.assert_called_once_with(
                context, fake_data)
        self.assertEqual(metadata_support,
                         mock_check_metadata_properties.called)

    @ddt.data({'exception1': exception.ServiceIsDown(service='fake_srv'),
               'exc_raise': exc.HTTPInternalServerError},
              {'exception1': exception.InvalidShareNetwork(
                  reason='fake_reason'),
               'exc_raise': exc.HTTPBadRequest},
              {'exception1': db_exception.DBError(),
               'exc_raise': exc.HTTPInternalServerError})
    @ddt.unpack
    def test_subnet_create_fail_update_network_allocation(self, exception1,
                                                          exc_raise):
        req = fakes.HTTPRequest.blank('/subnets', version="2.70")
        multiple_subnet_support = (req.api_version_request >=
                                   api_version.APIVersionRequest("2.70"))
        context = req.environ['manila.context']
        body = {
            'share-network-subnet': self._setup_create_test_request_body()
        }
        sn_id = body['share-network-subnet']['share_network_id']

        expected_subnet = copy.deepcopy(self.subnet)
        expected_subnet['share_servers'] = [self.share_server]

        mock_validate_subnet_create = self.mock_object(
            common, 'validate_subnet_create',
            mock.Mock(return_value=(self.share_network, [expected_subnet])))
        mock_update_net_allocations = self.mock_object(
            self.controller.share_api,
            'update_share_server_network_allocations',
            mock.Mock(side_effect=exception1))

        fake_data = body['share-network-subnet']
        fake_data['share_network_id'] = self.share_network['id']
        fake_data['share_servers'] = [self.share_server]

        self.assertRaises(exc_raise,
                          self.controller.create,
                          req,
                          body['share-network-subnet']['share_network_id'],
                          body)

        mock_validate_subnet_create.assert_called_once_with(
            context, sn_id, fake_data, multiple_subnet_support)
        mock_update_net_allocations.assert_called_once_with(
            context, self.share_network, fake_data)

    def test_subnet_create_invalid_body(self):
        fake_sn_id = 'fake_id'
        req = fakes.HTTPRequest.blank('/subnets', version="2.51")
        body = {}
        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.create,
                          req,
                          fake_sn_id,
                          body)

    @ddt.data("2.51", "2.70")
    def test_subnet_create_subnet_db_error(self, version):
        req = fakes.HTTPRequest.blank('/subnets', version=version)
        body = {
            'share-network-subnet': self._setup_create_test_request_body()
        }
        expected_subnet = copy.deepcopy(self.subnet)
        self.mock_object(
            common, 'validate_subnet_create',
            mock.Mock(return_value=(self.share_network, [expected_subnet])))
        self.mock_object(
            db_api, 'share_network_subnet_create',
            mock.Mock(side_effect=db_exception.DBError()))

        self.assertRaises(exc.HTTPInternalServerError,
                          self.controller.create,
                          req,
                          'fake_sn_id',
                          body)

    def test_show_subnet(self):
        subnet = db_utils.create_share_network_subnet(
            id='fake_sns_2', share_network_id=self.share_network['id'])
        expected_result = {
            'share_network_subnet': {
                "created_at": subnet['created_at'],
                "id": subnet['id'],
                "share_network_id": subnet['share_network_id'],
                "share_network_name": self.share_network['name'],
                "availability_zone": subnet['availability_zone'],
                "segmentation_id": subnet['segmentation_id'],
                "neutron_subnet_id": subnet['neutron_subnet_id'],
                "updated_at": subnet['updated_at'],
                "neutron_net_id": subnet['neutron_net_id'],
                "ip_version": subnet['ip_version'],
                "cidr": subnet['cidr'],
                "network_type": subnet['network_type'],
                "gateway": subnet['gateway'],
                "mtu": subnet['mtu'],
            }
        }
        req = fakes.HTTPRequest.blank('/subnets/%s' % subnet['id'],
                                      version="2.51")
        context = req.environ['manila.context']
        mock_sn_get = self.mock_object(
            db_api, 'share_network_get', mock.Mock(
                return_value=self.share_network))
        mock_sns_get = self.mock_object(
            db_api, 'share_network_subnet_get', mock.Mock(
                return_value=subnet))

        result = self.controller.show(req, self.share_network['id'],
                                      subnet['id'])

        self.assertEqual(expected_result, result)
        mock_sn_get.assert_called_once_with(context, self.share_network['id'])
        mock_sns_get.assert_called_once_with(context, subnet['id'])

    @ddt.data(
        (mock.Mock(side_effect=exception.ShareNetworkNotFound(
            share_network_id='fake_net_id')), None),
        (mock.Mock(), mock.Mock(
            side_effect=exception.ShareNetworkSubnetNotFound(
                share_network_subnet_id='fake_subnet_id'))))
    @ddt.unpack
    def test_show_subnet_not_found(self, sn_get_side_effect,
                                   sns_get_side_effect):
        req = fakes.HTTPRequest.blank('/subnets/%s' % self.subnet['id'],
                                      version="2.51")
        context = req.environ['manila.context']

        mock_sn_get = self.mock_object(
            db_api, 'share_network_get', sn_get_side_effect)
        mock_sns_get = self.mock_object(
            db_api, 'share_network_subnet_get', sns_get_side_effect)

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.show,
                          req,
                          self.share_network['id'],
                          self.subnet['id'])
        mock_sn_get.assert_called_once_with(context, self.share_network['id'])
        if sns_get_side_effect:
            mock_sns_get.assert_called_once_with(context, self.subnet['id'])

    def test_list_subnet(self):
        share_network_id = 'fake_id'
        subnet = db_utils.create_share_network_subnet(
            share_network_id=share_network_id, id='fake_id')
        fake_sn = db_utils.create_share_network(id=share_network_id)
        expected_result = {
            'share_network_subnets': [{
                "created_at": subnet['created_at'],
                "id": subnet['id'],
                "share_network_id": subnet['id'],
                "share_network_name": fake_sn["name"],
                "availability_zone": subnet['availability_zone'],
                "segmentation_id": subnet['segmentation_id'],
                "neutron_subnet_id": subnet['neutron_subnet_id'],
                "updated_at": subnet['updated_at'],
                "neutron_net_id": subnet['neutron_net_id'],
                "ip_version": subnet['ip_version'],
                "cidr": subnet['cidr'],
                "network_type": subnet['network_type'],
                "gateway": subnet['gateway'],
                "mtu": subnet['mtu'],
            }]
        }

        req = fakes.HTTPRequest.blank('/subnets/', version="2.51")
        context = req.environ['manila.context']
        mock_sn_get = self.mock_object(
            db_api, 'share_network_get', mock.Mock(
                return_value=fake_sn))

        result = self.controller.index(req, self.share_network['id'])

        self.assertEqual(expected_result, result)
        mock_sn_get.assert_called_once_with(context, self.share_network['id'])

    def test_list_subnet_share_network_not_found(self):
        req = fakes.HTTPRequest.blank('/subnets/', version="2.51")
        context = req.environ['manila.context']

        mock_sn_get = self.mock_object(
            db_api, 'share_network_get', mock.Mock(
                side_effect=exception.ShareNetworkNotFound(
                    share_network_id=self.share_network['id'])))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.index,
                          req,
                          self.share_network['id'])
        mock_sn_get.assert_called_once_with(context, self.share_network['id'])

    def test_index_metadata(self):
        req = fakes.HTTPRequest.blank('/subnets/', version="2.78")
        mock_index = self.mock_object(
            self.controller, '_index_metadata',
            mock.Mock(return_value='fake_metadata'))

        result = self.controller.index_metadata(req, self.share_network['id'],
                                                self.subnet['id'])

        self.assertEqual('fake_metadata', result)
        mock_index.assert_called_once_with(req, self.subnet['id'],
                                           parent_id=self.share_network['id'])

    def test_create_metadata(self):
        req = fakes.HTTPRequest.blank('/subnets/', version="2.78")
        mock_index = self.mock_object(
            self.controller, '_create_metadata',
            mock.Mock(return_value='fake_metadata'))

        body = 'fake_metadata_body'
        result = self.controller.create_metadata(req, self.share_network['id'],
                                                 self.subnet['id'], body)

        self.assertEqual('fake_metadata', result)
        mock_index.assert_called_once_with(req, self.subnet['id'], body,
                                           parent_id=self.share_network['id'])

    def test_update_all_metadata(self):
        req = fakes.HTTPRequest.blank('/subnets/', version="2.78")
        mock_index = self.mock_object(
            self.controller, '_update_all_metadata',
            mock.Mock(return_value='fake_metadata'))

        body = 'fake_metadata_body'
        result = self.controller.update_all_metadata(
            req, self.share_network['id'], self.subnet['id'], body)

        self.assertEqual('fake_metadata', result)
        mock_index.assert_called_once_with(req, self.subnet['id'], body,
                                           parent_id=self.share_network['id'])

    def test_update_metadata_item(self):
        req = fakes.HTTPRequest.blank('/subnets/', version="2.78")
        mock_index = self.mock_object(
            self.controller, '_update_metadata_item',
            mock.Mock(return_value='fake_metadata'))

        body = 'fake_metadata_body'
        key = 'fake_key'
        result = self.controller.update_metadata_item(
            req, self.share_network['id'], self.subnet['id'], body, key)

        self.assertEqual('fake_metadata', result)
        mock_index.assert_called_once_with(req, self.subnet['id'], body, key,
                                           parent_id=self.share_network['id'])

    def test_show_metadata(self):
        req = fakes.HTTPRequest.blank('/subnets/', version="2.78")
        mock_index = self.mock_object(
            self.controller, '_show_metadata',
            mock.Mock(return_value='fake_metadata'))

        key = 'fake_key'
        result = self.controller.show_metadata(
            req, self.share_network['id'], self.subnet['id'], key)

        self.assertEqual('fake_metadata', result)
        mock_index.assert_called_once_with(req, self.subnet['id'], key,
                                           parent_id=self.share_network['id'])

    def test_delete_metadata(self):
        req = fakes.HTTPRequest.blank('/subnets/', version="2.78")
        mock_index = self.mock_object(
            self.controller, '_delete_metadata',
            mock.Mock(return_value='fake_metadata'))

        key = 'fake_key'
        result = self.controller.delete_metadata(
            req, self.share_network['id'], self.subnet['id'], key)

        self.assertEqual('fake_metadata', result)
        mock_index.assert_called_once_with(req, self.subnet['id'], key,
                                           parent_id=self.share_network['id'])
