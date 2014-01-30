# Copyright 2013 OpenStack Foundation
# All Rights Reserved
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
from manila.common import constants
from manila import context
from manila.db import api as db_api
from manila.db.sqlalchemy import api as sqlalchemy_api
from manila.db.sqlalchemy import models
from manila import exception
from manila import test


class ShareNetworkDBTest(test.TestCase):

    def __init__(self, *args, **kwargs):
        super(ShareNetworkDBTest, self).__init__(*args, **kwargs)
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)

    def _check_fields(self, expected, actual):
        for key in expected:
            self.assertEqual(actual[key], expected[key])

    def setUp(self):
        super(ShareNetworkDBTest, self).setUp()
        self.share_nw_dict = {'id': 'fake network id',
                              'neutron_net_id': 'fake net id',
                              'neutron_subnet_id': 'fake subnet id',
                              'project_id': self.fake_context.project_id,
                              'network_type': 'vlan',
                              'segmentation_id': 1000,
                              'cidr': '10.0.0.0/24',
                              'ip_version': 4,
                              'name': 'whatever',
                              'description': 'fake description',
                              'status': constants.STATUS_INACTIVE}
        self.allocation_dict = {'id': 'fake port id',
                                'share_network_id': self.share_nw_dict['id'],
                                'ip_address': 'fake ip address',
                                'mac_address': 'fake mac address',
                                'status': constants.STATUS_ACTIVE}

    def test_create_one_network(self):
        result = db_api.share_network_create(self.fake_context,
                                             self.share_nw_dict)

        self._check_fields(expected=self.share_nw_dict, actual=result)
        self.assertEqual(len(result['shares']), 0)
        self.assertEqual(len(result['security_services']), 0)
        self.assertEqual(len(result['network_allocations']), 0)

    def test_create_two_networks(self):
        share_nw_dict2 = self.share_nw_dict.copy()
        share_nw_dict2['id'] = None
        share_nw_dict2['project_id'] = 'fake project 2'
        result1 = db_api.share_network_create(self.fake_context,
                                              self.share_nw_dict)
        result2 = db_api.share_network_create(self.fake_context,
                                              share_nw_dict2)

        self._check_fields(expected=self.share_nw_dict, actual=result1)
        self._check_fields(expected=share_nw_dict2, actual=result2)

    def test_create_same_project_netid_and_subnetid(self):
        share_nw_dict2 = self.share_nw_dict.copy()
        share_nw_dict2['id'] = None
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        self.assertRaises(exception.DBError,
                          db_api.share_network_create,
                          self.fake_context,
                          share_nw_dict2)

    def test_create_with_duplicated_id(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        self.assertRaises(exception.DBError,
                          db_api.share_network_create,
                          self.fake_context,
                          self.share_nw_dict)

    def test_get(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self._check_fields(expected=self.share_nw_dict, actual=result)
        self.assertEqual(len(result['shares']), 0)
        self.assertEqual(len(result['security_services']), 0)
        self.assertEqual(len(result['network_allocations']), 0)

    def test_get_with_one_share(self):
        share_dict1 = {'id': 'fake share id1',
                       'share_network_id': self.share_nw_dict['id']}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_create(self.fake_context, share_dict1)

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(result['shares']), 1)
        self._check_fields(expected=share_dict1,
                           actual=result['shares'][0])

    def test_get_with_two_shares(self):
        share_dict1 = {'id': 'fake share id1',
                       'share_network_id': self.share_nw_dict['id']}
        share_dict2 = {'id': 'fake share id2',
                       'share_network_id': self.share_nw_dict['id']}
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_create(self.fake_context, share_dict1)
        db_api.share_create(self.fake_context, share_dict2)

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(result['shares']), 2)

    def test_get_with_one_security_service(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)
        db_api.share_network_add_security_service(self.fake_context,
                                                  self.share_nw_dict['id'],
                                                  security_dict1['id'])

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(result['security_services']), 1)
        self._check_fields(expected=security_dict1,
                           actual=result['security_services'][0])

    def test_get_with_two_security_services(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}
        security_dict2 = {'id': 'fake security service id2',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)
        db_api.security_service_create(self.fake_context, security_dict2)
        db_api.share_network_add_security_service(self.fake_context,
                                                  self.share_nw_dict['id'],
                                                  security_dict1['id'])
        db_api.share_network_add_security_service(self.fake_context,
                                                  self.share_nw_dict['id'],
                                                  security_dict2['id'])

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(result['security_services']), 2)

    def test_get_with_one_allocation(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.network_allocation_create(self.fake_context,
                                         self.allocation_dict)

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(result['network_allocations']), 1)
        self._check_fields(expected=self.allocation_dict,
                           actual=result['network_allocations'][0])

    def test_get_with_two_allocations(self):
        allocation_dict2 = dict(self.allocation_dict)
        allocation_dict2['id'] = 'fake port id2'
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.network_allocation_create(self.fake_context,
                                         self.allocation_dict)
        db_api.network_allocation_create(self.fake_context, allocation_dict2)

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(result['network_allocations']), 2)

    def test_get_not_found(self):
        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_get,
                          self.fake_context,
                          'fake id')

    def test_delete(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_network_delete(self.fake_context,
                                    self.share_nw_dict['id'])

        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_get,
                          self.fake_context,
                          self.share_nw_dict['id'])

    def test_delete_not_found(self):
        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_delete,
                          self.fake_context,
                          'fake id')

    def test_update(self):
        new_status = constants.STATUS_ERROR
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        result_update = db_api.share_network_update(self.fake_context,
                                                    self.share_nw_dict['id'],
                                                    {'status': new_status})
        result_get = db_api.share_network_get(self.fake_context,
                                              self.share_nw_dict['id'])

        self.assertEqual(result_update['status'], new_status)
        self._check_fields(expected=dict(result_update.iteritems()),
                           actual=dict(result_get.iteritems()))

    def test_update_not_found(self):
        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_update,
                          self.fake_context,
                          'fake id',
                          {})

    def test_get_all_one_record(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        result = db_api.share_network_get_all(self.fake_context)

        self.assertEqual(len(result), 1)
        self._check_fields(expected=self.share_nw_dict, actual=result[0])

    def test_get_all_two_records(self):
        share_nw_dict2 = dict(self.share_nw_dict)
        share_nw_dict2['id'] = 'fake subnet id2'
        share_nw_dict2['neutron_subnet_id'] = 'fake subnet id2'
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_network_create(self.fake_context, share_nw_dict2)

        result = db_api.share_network_get_all(self.fake_context)

        self.assertEqual(len(result), 2)

    def test_get_all_by_project(self):
        share_nw_dict2 = dict(self.share_nw_dict)
        share_nw_dict2['id'] = 'fake share nw id2'
        share_nw_dict2['project_id'] = 'fake project 2'
        share_nw_dict2['neutron_subnet_id'] = 'fake subnet id2'
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_network_create(self.fake_context, share_nw_dict2)

        result = db_api.share_network_get_all_by_project(
                                                self.fake_context,
                                                share_nw_dict2['project_id'])

        self.assertEqual(len(result), 1)
        self._check_fields(expected=share_nw_dict2, actual=result[0])

    def test_add_security_service(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)
        db_api.share_network_add_security_service(self.fake_context,
                                                  self.share_nw_dict['id'],
                                                  security_dict1['id'])

        result = sqlalchemy_api.model_query(
                self.fake_context,
                models.ShareNetworkSecurityServiceAssociation).\
                filter_by(security_service_id=security_dict1['id']).\
                filter_by(share_network_id=self.share_nw_dict['id']).first()

        self.assertTrue(result is not None)

    def test_add_security_service_not_found_01(self):
        security_service_id = 'unknown security service'
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.share_network_add_security_service,
                          self.fake_context,
                          self.share_nw_dict['id'],
                          security_service_id)

    def test_add_security_service_not_found_02(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}
        share_nw_id = 'unknown share network'
        db_api.security_service_create(self.fake_context, security_dict1)

        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_add_security_service,
                          self.fake_context,
                          share_nw_id,
                          security_dict1['id'])

    def test_add_security_service_association_error_already_associated(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)
        db_api.share_network_add_security_service(self.fake_context,
                                                  self.share_nw_dict['id'],
                                                  security_dict1['id'])

        self.assertRaises(
            exception.ShareNetworkSecurityServiceAssociationError,
            db_api.share_network_add_security_service,
            self.fake_context,
            self.share_nw_dict['id'],
            security_dict1['id'])

    def test_add_security_service_association_error_status_active(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_network_update(self.fake_context,
                                    self.share_nw_dict['id'],
                                    {'status': constants.STATUS_ACTIVE})
        db_api.security_service_create(self.fake_context, security_dict1)

        self.assertRaises(
            exception.ShareNetworkSecurityServiceAssociationError,
            db_api.share_network_add_security_service,
            self.fake_context,
            self.share_nw_dict['id'],
            security_dict1['id'])

        assoc_ref = sqlalchemy_api.model_query(
                self.fake_context,
                models.ShareNetworkSecurityServiceAssociation).\
                filter_by(security_service_id=security_dict1['id']).\
                filter_by(share_network_id=self.share_nw_dict['id']).first()

        self.assertTrue(assoc_ref is None)

    def test_remove_security_service(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)
        db_api.share_network_add_security_service(self.fake_context,
                                                  self.share_nw_dict['id'],
                                                  security_dict1['id'])

        db_api.share_network_remove_security_service(self.fake_context,
                                                     self.share_nw_dict['id'],
                                                     security_dict1['id'])

        result = sqlalchemy_api.model_query(
                self.fake_context,
                models.ShareNetworkSecurityServiceAssociation).\
                filter_by(security_service_id=security_dict1['id']).\
                filter_by(share_network_id=self.share_nw_dict['id']).first()

        self.assertTrue(result is None)

        share_nw_ref = db_api.share_network_get(self.fake_context,
                                                self.share_nw_dict['id'])
        self.assertEqual(len(share_nw_ref['security_services']), 0)

    def test_remove_security_service_not_found_01(self):
        security_service_id = 'unknown security service'
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.share_network_remove_security_service,
                          self.fake_context,
                          self.share_nw_dict['id'],
                          security_service_id)

    def test_remove_security_service_not_found_02(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}
        share_nw_id = 'unknown share network'
        db_api.security_service_create(self.fake_context, security_dict1)

        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_remove_security_service,
                          self.fake_context,
                          share_nw_id,
                          security_dict1['id'])

    def test_remove_security_service_dissociation_error(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)

        self.assertRaises(
            exception.ShareNetworkSecurityServiceDissociationError,
            db_api.share_network_remove_security_service,
            self.fake_context,
            self.share_nw_dict['id'],
            security_dict1['id'])

    def test_security_services_relation(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(result['security_services']), 0)

    def test_shares_relation(self):
        share_dict = {'id': 'fake share id1'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_create(self.fake_context, share_dict)

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(result['shares']), 0)

    def test_network_allocations_relation(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        db_api.network_allocation_create(self.fake_context,
                                         self.allocation_dict)
        db_api.network_allocation_delete(self.fake_context,
                                         self.allocation_dict['id'])

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(result['network_allocations']), 0)
