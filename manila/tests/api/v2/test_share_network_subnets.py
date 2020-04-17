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
        self.share_server = db_utils.create_share_server(
            share_network_subnet_id='fake_sns_id')
        self.subnet = db_utils.create_share_network_subnet(
            share_network_id=self.share_network['id'])
        self.share = db_utils.create_share()

    def test_share_network_subnet_delete(self):
        req = fakes.HTTPRequest.blank('/subnets/%s' % self.subnet['id'],
                                      version="2.51")
        context = req.environ['manila.context']

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

        mock_sns_get.assert_called_once_with(
            context, self.subnet['id'])
        mock_all_get_all_shares_by_ss.assert_called_once_with(
            context, self.subnet['share_servers'][0].id
        )
        self.mock_policy_check.assert_called_once_with(
            context, self.resource_name, 'delete')

    @ddt.data((None, fake_default_subnet, None),
              (fake_az, None, fake_subnet_with_az))
    @ddt.unpack
    def test__validate_subnet(self, az, default_subnet, subnet_az):
        req = fakes.HTTPRequest.blank('/subnets', version='2.51')
        context = req.environ['manila.context']

        mock_get_default_sns = self.mock_object(
            db_api, 'share_network_subnet_get_default_subnet',
            mock.Mock(return_value=default_subnet))
        mock_get_subnet_by_az = self.mock_object(
            db_api, 'share_network_subnet_get_by_availability_zone_id',
            mock.Mock(return_value=subnet_az))

        self.assertRaises(exc.HTTPConflict,
                          self.controller._validate_subnet,
                          context,
                          self.share_network['id'],
                          az)
        if az:
            mock_get_subnet_by_az.assert_called_once_with(
                context, self.share_network['id'], az['id'])
            mock_get_default_sns.assert_not_called()
        else:
            mock_get_default_sns.assert_called_once_with(
                context, self.share_network['id'])
            mock_get_subnet_by_az.assert_not_called()

    def _setup_create_test_request_body(self):
        body = {
            'share_network_id': self.share_network['id'],
            'availability_zone': fake_az['name'],
            'neutron_net_id': 'fake_nn_id',
            'neutron_subnet_id': 'fake_nsn_id'
        }
        return body

    def test_subnet_create(self):
        req = fakes.HTTPRequest.blank('/subnets', version="2.51")
        context = req.environ['manila.context']
        body = {
            'share-network-subnet': self._setup_create_test_request_body()
        }
        sn_id = body['share-network-subnet']['share_network_id']

        expected_result = copy.deepcopy(body)
        expected_result['share-network-subnet']['id'] = self.subnet['id']
        mock_check_net_and_subnet_id = self.mock_object(
            common, 'check_net_id_and_subnet_id')
        mock_validate_subnet = self.mock_object(
            self.controller, '_validate_subnet')
        mock_subnet_create = self.mock_object(
            db_api, 'share_network_subnet_create',
            mock.Mock(return_value=self.subnet))

        self.controller.create(
            req, body['share-network-subnet']['share_network_id'], body)

        mock_check_net_and_subnet_id.assert_called_once_with(
            body['share-network-subnet'])
        mock_validate_subnet.assert_called_once_with(
            context, sn_id, az=fake_az)
        mock_subnet_create.assert_called_once_with(
            context, body['share-network-subnet'])

    def test_subnet_create_share_network_not_found(self):
        fake_sn_id = 'fake_id'
        req = fakes.HTTPRequest.blank('/subnets', version="2.51")
        context = req.environ['manila.context']
        body = {
            'share-network-subnet': self._setup_create_test_request_body()
        }
        mock_sn_get = self.mock_object(
            db_api, 'share_network_get',
            mock.Mock(side_effect=exception.ShareNetworkNotFound(
                share_network_id=fake_sn_id)))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.create,
                          req,
                          fake_sn_id,
                          body)
        mock_sn_get.assert_called_once_with(context, fake_sn_id)

    def test_subnet_create_az_not_found(self):
        fake_sn_id = 'fake_id'
        req = fakes.HTTPRequest.blank('/subnets', version="2.51")
        context = req.environ['manila.context']
        body = {
            'share-network-subnet': self._setup_create_test_request_body()
        }
        mock_sn_get = self.mock_object(db_api, 'share_network_get')
        mock_az_get = self.mock_object(
            db_api, 'availability_zone_get',
            mock.Mock(side_effect=exception.AvailabilityZoneNotFound(id='')))

        expected_az = body['share-network-subnet']['availability_zone']

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.create,
                          req,
                          fake_sn_id,
                          body)
        mock_sn_get.assert_called_once_with(context, fake_sn_id)
        mock_az_get.assert_called_once_with(
            context, expected_az)

    def test_subnet_create_subnet_default_or_same_az_exists(self):
        fake_sn_id = 'fake_id'
        req = fakes.HTTPRequest.blank('/subnets', version="2.51")
        context = req.environ['manila.context']
        body = {
            'share-network-subnet': self._setup_create_test_request_body()
        }
        mock_sn_get = self.mock_object(db_api, 'share_network_get')
        mock__validate_subnet = self.mock_object(
            self.controller, '_validate_subnet',
            mock.Mock(side_effect=exc.HTTPConflict(''))
        )
        expected_az = body['share-network-subnet']['availability_zone']

        self.assertRaises(exc.HTTPConflict,
                          self.controller.create,
                          req,
                          fake_sn_id,
                          body)
        mock_sn_get.assert_called_once_with(context, fake_sn_id)
        self.mock_az_get.assert_called_once_with(context, expected_az)
        mock__validate_subnet.assert_called_once_with(
            context, fake_sn_id, az=fake_az)

    def test_subnet_create_subnet_db_error(self):
        fake_sn_id = 'fake_sn_id'
        req = fakes.HTTPRequest.blank('/subnets', version="2.51")
        context = req.environ['manila.context']
        body = {
            'share-network-subnet': self._setup_create_test_request_body()
        }
        mock_sn_get = self.mock_object(db_api, 'share_network_get')
        mock__validate_subnet = self.mock_object(
            self.controller, '_validate_subnet')
        mock_db_subnet_create = self.mock_object(
            db_api, 'share_network_subnet_create',
            mock.Mock(side_effect=db_exception.DBError()))
        expected_data = copy.deepcopy(body['share-network-subnet'])
        expected_data['availability_zone_id'] = fake_az['id']
        expected_data.pop('availability_zone')

        self.assertRaises(exc.HTTPInternalServerError,
                          self.controller.create,
                          req,
                          fake_sn_id,
                          body)

        mock_sn_get.assert_called_once_with(context, fake_sn_id)
        self.mock_az_get.assert_called_once_with(context, fake_az['name'])
        mock__validate_subnet.assert_called_once_with(
            context, fake_sn_id, az=fake_az)
        mock_db_subnet_create.assert_called_once_with(
            context, expected_data
        )

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
