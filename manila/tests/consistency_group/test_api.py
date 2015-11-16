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
"""Unit tests for the Share API module."""

import copy
import datetime

import ddt
import mock
from oslo_config import cfg
from oslo_utils import timeutils

from manila.common import constants
import manila.consistency_group.api as cg_api
from manila import context
from manila import db as db_driver
from manila import exception
from manila.share import share_types
from manila import test
from manila.tests.api.contrib import stubs

CONF = cfg.CONF


def fake_cg(id, **kwargs):
    cg = {
        'id': id,
        'user_id': 'fakeuser',
        'project_id': 'fakeproject',
        'status': constants.STATUS_CREATING,
        'name': None,
        'description': None,
        'host': None,
        'source_cgsnapshot_id': None,
        'share_network_id': None,
        'share_types': None,
        'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
    }
    cg.update(kwargs)
    return cg


def fake_cgsnapshot(id, **kwargs):
    snap = {
        'id': id,
        'user_id': 'fakeuser',
        'project_id': 'fakeproject',
        'status': constants.STATUS_CREATING,
        'name': None,
        'description': None,
        'consistency_group_id': None,
        'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
    }
    snap.update(kwargs)
    return snap


@ddt.ddt
class CGAPITestCase(test.TestCase):

    def setUp(self):
        super(CGAPITestCase, self).setUp()
        self.context = context.get_admin_context()
        self.scheduler_rpcapi = mock.Mock()
        self.share_rpcapi = mock.Mock()
        self.share_api = mock.Mock()
        self.api = cg_api.API()
        self.mock_object(self.api, 'share_rpcapi', self.share_rpcapi)
        self.mock_object(self.api, 'share_api', self.share_api)
        self.mock_object(self.api, 'scheduler_rpcapi', self.scheduler_rpcapi)

        dt_utc = datetime.datetime.utcnow()
        self.mock_object(timeutils, 'utcnow', mock.Mock(return_value=dt_utc))

    def test_create_empty_request(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)

        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))
        self.api.create(self.context)

        db_driver.consistency_group_create.assert_called_once_with(
            self.context, expected_values)

    def test_create_request_spec(self):
        """Ensure the correct values are sent to the scheduler."""
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_request_spec = {
            'consistency_group_id': cg['id'],
        }
        expected_request_spec.update(cg)
        del expected_request_spec['id']
        del expected_request_spec['created_at']
        del expected_request_spec['host']
        expected_request_spec['share_types'] = []

        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))

        self.api.create(self.context)

        self.scheduler_rpcapi.create_consistency_group.assert_called_once_with(
            self.context, cg_id=cg['id'], request_spec=expected_request_spec,
            filter_properties={}
        )

    def test_create_with_name(self):
        fake_name = 'fake_name'
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['name'] = fake_name

        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'share_network_get')

        self.api.create(self.context, name=fake_name)

        db_driver.consistency_group_create.assert_called_once_with(
            self.context, expected_values)
        self.scheduler_rpcapi.create_consistency_group.assert_called_once_with(
            self.context, cg_id=cg['id'], request_spec=mock.ANY,
            filter_properties={}
        )

    def test_create_with_description(self):
        fake_desc = 'fake_desc'
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['description'] = fake_desc

        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))

        self.api.create(self.context, description=fake_desc)

        db_driver.consistency_group_create.assert_called_once_with(
            self.context, expected_values)

    def test_create_with_multiple_share_types(self):
        fake_share_type = {'name': 'default',
                           'extra_specs': {
                               'driver_handles_share_servers': 'False'},
                           'is_public': True,
                           'id': 'c01990c1-448f-435a-9de6-c7c894bb6df9'}
        fake_share_type_2 = {'name': 'default2',
                             'extra_specs': {
                                 'driver_handles_share_servers': 'False'},
                             'is_public': True,
                             'id': 'c01990c1-448f-435a-9de6-c7c894bb7df9'}
        fake_share_types = [fake_share_type, fake_share_type_2]
        self.mock_object(share_types, 'get_share_type')
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['share_types'] = fake_share_types

        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'share_network_get')

        self.api.create(self.context, share_type_ids=fake_share_types)

        db_driver.consistency_group_create.assert_called_once_with(
            self.context, expected_values)

    def test_create_with_share_type_not_found(self):
        fake_share_type = {'name': 'default',
                           'extra_specs': {
                               'driver_handles_share_servers': 'False'},
                           'is_public': True,
                           'id': 'c01990c1-448f-435a-9de6-c7c894bb6df9'}
        fake_share_types = [fake_share_type]
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(side_effect=exception.ShareTypeNotFound(
                             share_type_id=fake_share_type['id'])))
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['share_types'] = fake_share_types

        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))

        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, share_type_ids=[fake_share_type['id']])

    def test_create_driver_handles_share_servers_is_false_with_net_id(self):
        fake_share_type = {'name': 'default',
                           'extra_specs': {
                               'driver_handles_share_servers': 'False'},
                           'is_public': False,
                           'id': 'c01990c1-448f-435a-9de6-c7c894bb6df9'}

        fake_share_types = [fake_share_type]
        self.mock_object(share_types, 'get_share_type')

        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, share_type_ids=fake_share_types,
                          share_network_id="fake_share_network")

    def test_create_with_conflicting_share_types(self):
        fake_share_type = {'name': 'default',
                           'extra_specs': {
                               'driver_handles_share_servers': 'True'},
                           'is_public': True,
                           'id': 'c01990c1-448f-435a-9de6-c7c894bb6df9'}
        fake_share_type_2 = {'name': 'default2',
                             'extra_specs': {
                                 'driver_handles_share_servers': 'False'},
                             'is_public': True,
                             'id': 'c01990c1-448f-435a-9de6-c7c894bb7df9'}
        fake_share_types = [fake_share_type, fake_share_type_2]
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(side_effect=[fake_share_type,
                                                fake_share_type_2]))

        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, share_type_ids=fake_share_types)

    def test_create_with_conflicting_share_type_and_share_network(self):
        fake_share_type = {'name': 'default',
                           'extra_specs': {
                               'driver_handles_share_servers': 'False'},
                           'is_public': True,
                           'id': 'c01990c1-448f-435a-9de6-c7c894bb6df9'}
        fake_share_types = [fake_share_type]
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_share_type))

        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, share_type_ids=fake_share_types,
                          share_network_id="fake_sn")

    def test_create_with_source_cgsnapshot_id(self):
        snap = fake_cgsnapshot("fake_source_cgsnapshot_id",
                               status=constants.STATUS_AVAILABLE)
        fake_share_type_mapping = {'share_type_id': "fake_share_type_id"}
        orig_cg = fake_cg('fakeorigid',
                          user_id=self.context.user_id,
                          project_id=self.context.project_id,
                          share_types=[fake_share_type_mapping],
                          status=constants.STATUS_AVAILABLE,
                          host='fake_original_host')

        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     share_types=[fake_share_type_mapping],
                     status=constants.STATUS_CREATING,
                     host='fake_original_host')
        expected_values = cg.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        expected_values['source_cgsnapshot_id'] = snap['id']
        expected_values['share_types'] = ["fake_share_type_id"]

        self.mock_object(db_driver, 'cgsnapshot_get',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=orig_cg))
        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value={"id": "fake_share_type_id"}))
        self.mock_object(db_driver, 'share_network_get')
        self.mock_object(db_driver, 'cgsnapshot_members_get_all',
                         mock.Mock(return_value=[]))

        self.api.create(self.context,
                        source_cgsnapshot_id=snap['id'])

        db_driver.consistency_group_create.assert_called_once_with(
            self.context, expected_values)
        self.share_rpcapi.create_consistency_group.\
            assert_called_once_with(self.context, cg, orig_cg['host'])

    def test_create_with_source_cgsnapshot_id_with_member(self):
        snap = fake_cgsnapshot("fake_source_cgsnapshot_id",
                               status=constants.STATUS_AVAILABLE)
        share = stubs.stub_share('fakeshareid')
        member = stubs.stub_cgsnapshot_member('fake_member_id')
        fake_share_type_mapping = {'share_type_id': "fake_share_type_id"}
        orig_cg = fake_cg('fakeorigid',
                          user_id=self.context.user_id,
                          project_id=self.context.project_id,
                          share_types=[fake_share_type_mapping],
                          status=constants.STATUS_AVAILABLE)

        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     share_types=[fake_share_type_mapping],
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        expected_values['source_cgsnapshot_id'] = snap['id']
        expected_values['share_types'] = ["fake_share_type_id"]

        self.mock_object(db_driver, 'cgsnapshot_get',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=orig_cg))
        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value={"id": "fake_share_type_id"}))
        self.mock_object(db_driver, 'share_network_get')
        self.mock_object(db_driver, 'share_instance_get',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'cgsnapshot_members_get_all',
                         mock.Mock(return_value=[member]))
        self.mock_object(self.share_api, 'create')

        self.api.create(self.context,
                        source_cgsnapshot_id=snap['id'])

        db_driver.consistency_group_create.assert_called_once_with(
            self.context, expected_values)
        self.assertTrue(self.share_api.create.called)
        self.share_rpcapi.create_consistency_group.\
            assert_called_once_with(self.context, cg, orig_cg['host'])

    def test_create_with_source_cgsnapshot_id_with_members_error(self):
        snap = fake_cgsnapshot("fake_source_cgsnapshot_id",
                               status=constants.STATUS_AVAILABLE)
        member = stubs.stub_cgsnapshot_member('fake_member_id')
        member_2 = stubs.stub_cgsnapshot_member('fake_member2_id')
        share = stubs.stub_share('fakeshareid')
        fake_share_type_mapping = {'share_type_id': "fake_share_type_id"}
        orig_cg = fake_cg('fakeorigid',
                          user_id=self.context.user_id,
                          project_id=self.context.project_id,
                          share_types=[fake_share_type_mapping],
                          status=constants.STATUS_AVAILABLE)

        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     share_types=[fake_share_type_mapping],
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        expected_values['source_cgsnapshot_id'] = snap['id']
        expected_values['share_types'] = ["fake_share_type_id"]

        self.mock_object(db_driver, 'cgsnapshot_get',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=orig_cg))
        self.mock_object(db_driver, 'share_network_get')
        self.mock_object(db_driver, 'share_instance_get',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value={"id": "fake_share_type_id"}))
        self.mock_object(db_driver, 'cgsnapshot_members_get_all',
                         mock.Mock(return_value=[member, member_2]))
        self.mock_object(self.share_api, 'create',
                         mock.Mock(side_effect=[None, exception.Error]))
        self.mock_object(db_driver, 'consistency_group_destroy')

        self.assertRaises(exception.Error, self.api.create, self.context,
                          source_cgsnapshot_id=snap['id'])

        db_driver.consistency_group_create.assert_called_once_with(
            self.context, expected_values)
        self.assertEqual(2, self.share_api.create.call_count)
        self.assertEqual(1, db_driver.consistency_group_destroy.call_count)

    def test_create_with_source_cgsnapshot_id_error_snapshot_status(self):
        snap = fake_cgsnapshot("fake_source_cgsnapshot_id",
                               status=constants.STATUS_ERROR)
        self.mock_object(db_driver, 'cgsnapshot_get',
                         mock.Mock(return_value=snap))

        self.assertRaises(exception.InvalidCGSnapshot, self.api.create,
                          self.context, source_cgsnapshot_id=snap['id'])

    def test_create_with_source_cgsnapshot_id_snap_not_found(self):
        snap = fake_cgsnapshot("fake_source_cgsnapshot_id",
                               status=constants.STATUS_ERROR)
        self.mock_object(db_driver, 'cgsnapshot_get',
                         mock.Mock(side_effect=exception.CGSnapshotNotFound(
                             cgsnapshot_id='fake_source_cgsnapshot_id'
                         )))

        self.assertRaises(exception.CGSnapshotNotFound, self.api.create,
                          self.context, source_cgsnapshot_id=snap['id'])

    def test_create_with_multiple_fields(self):
        fake_desc = 'fake_desc'
        fake_name = 'fake_name'
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['name'] = fake_name
        expected_values['description'] = fake_desc

        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(return_value=cg))

        self.api.create(self.context, name=fake_name,
                        description=fake_desc)

        db_driver.consistency_group_create.assert_called_once_with(
            self.context, expected_values)

    def test_create_with_error_on_creation(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = cg.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)

        self.mock_object(db_driver, 'consistency_group_create',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error, self.api.create, self.context)

        db_driver.consistency_group_create.assert_called_once_with(
            self.context, expected_values)

    def test_delete_creating_no_host(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        self.mock_object(db_driver, 'consistency_group_destroy')

        self.api.delete(self.context, cg)

        db_driver.consistency_group_destroy.assert_called_once_with(
            mock.ANY, cg['id'])

    def test_delete_creating_with_host(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING,
                     host="fake_host")

        self.assertRaises(exception.InvalidConsistencyGroup, self.api.delete,
                          self.context, cg)

    def test_delete_available(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE,
                     host="fake_host")
        deleted_cg = copy.deepcopy(cg)
        deleted_cg['status'] = constants.STATUS_DELETING
        self.mock_object(db_driver, 'consistency_group_update',
                         mock.Mock(return_value=deleted_cg))
        self.mock_object(db_driver, 'count_shares_in_consistency_group',
                         mock.Mock(return_value=0))

        self.api.delete(self.context, cg)

        db_driver.consistency_group_update.assert_called_once_with(
            self.context, cg['id'], {'status': constants.STATUS_DELETING})
        self.share_rpcapi.delete_consistency_group.assert_called_once_with(
            self.context, deleted_cg
        )

    def test_delete_error_with_host(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_ERROR,
                     host="fake_host")
        deleted_cg = copy.deepcopy(cg)
        deleted_cg['status'] = constants.STATUS_DELETING
        self.mock_object(self.api, 'share_rpcapi')
        self.mock_object(db_driver, 'consistency_group_update',
                         mock.Mock(return_value=deleted_cg))
        self.mock_object(db_driver, 'count_shares_in_consistency_group',
                         mock.Mock(return_value=0))

        self.api.delete(self.context, cg)

        db_driver.consistency_group_update.assert_called_once_with(
            self.context, cg['id'], {'status': constants.STATUS_DELETING})
        self.api.share_rpcapi.delete_consistency_group.assert_called_once_with(
            self.context, deleted_cg
        )

    def test_delete_error_without_host(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_ERROR)
        self.mock_object(db_driver, 'consistency_group_destroy')

        self.api.delete(self.context, cg)

        db_driver.consistency_group_destroy.assert_called_once_with(
            mock.ANY, cg['id'])

    def test_delete_with_shares(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE,
                     host="fake_host")
        self.mock_object(db_driver, 'count_shares_in_consistency_group',
                         mock.Mock(return_value=1))

        self.assertRaises(exception.InvalidConsistencyGroup, self.api.delete,
                          self.context, cg)

    def test_delete_with_cgsnapshots(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE,
                     host="fake_host")
        self.mock_object(db_driver, 'count_cgsnapshots_in_consistency_group',
                         mock.Mock(return_value=1))

        self.assertRaises(exception.InvalidConsistencyGroup, self.api.delete,
                          self.context, cg)

    def test_update_no_values(self):
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = {}
        self.mock_object(db_driver, 'consistency_group_update',
                         mock.Mock(return_value=cg))

        self.api.update(self.context, cg, expected_values)

        db_driver.consistency_group_update.assert_called_once_with(
            self.context, cg['id'], expected_values)

    def test_update_with_name(self):
        fake_name = 'fake_name'
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = {'description': fake_name}

        self.mock_object(db_driver, 'consistency_group_update',
                         mock.Mock(return_value=cg))

        self.api.update(self.context, cg, expected_values)

        db_driver.consistency_group_update.assert_called_once_with(
            self.context, cg['id'], expected_values)

    def test_update_with_description(self):
        fake_desc = 'fake_desc'
        cg = fake_cg('fakeid',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        expected_values = {'description': fake_desc}

        self.mock_object(db_driver, 'consistency_group_update',
                         mock.Mock(return_value=cg))

        self.api.update(self.context, cg, expected_values)

        db_driver.consistency_group_update.assert_called_once_with(
            self.context, cg['id'], expected_values)

    def test_get(self):
        expected_cg = fake_cg('fakeid',
                              user_id=self.context.user_id,
                              project_id=self.context.project_id,
                              status=constants.STATUS_CREATING)
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=expected_cg))

        actual_cg = self.api.get(self.context, expected_cg['id'])
        self.assertEqual(expected_cg, actual_cg)

    def test_get_all_no_cgs(self):

        self.mock_object(db_driver, 'consistency_group_get_all',
                         mock.Mock(return_value=[]))

        actual_cg = self.api.get_all(self.context)
        self.assertEqual([], actual_cg)

    def test_get_all(self):
        expected_cgs = [fake_cg('fakeid',
                        user_id=self.context.user_id,
                        project_id=self.context.project_id,
                        status=constants.STATUS_CREATING)]
        self.mock_object(db_driver, 'consistency_group_get_all_by_project',
                         mock.Mock(return_value=expected_cgs))

        actual_cg = self.api.get_all(self.context, detailed=True)
        self.assertEqual(expected_cgs, actual_cg)

    def test_get_all_all_tenants_not_admin(self):
        cxt = context.RequestContext(user_id=None,
                                     project_id=None,
                                     is_admin=False)
        expected_cgs = [fake_cg('fakeid',
                        user_id=cxt.user_id,
                        project_id=cxt.project_id,
                        status=constants.STATUS_CREATING)]
        self.mock_object(db_driver, 'consistency_group_get_all_by_project',
                         mock.Mock(return_value=expected_cgs))

        actual_cgs = self.api.get_all(cxt,
                                      search_opts={'all_tenants': True})
        self.assertEqual(expected_cgs, actual_cgs)

    def test_get_all_all_tenants_as_admin(self):
        expected_cgs = [fake_cg('fakeid',
                        user_id=self.context.user_id,
                        project_id=self.context.project_id,
                        status=constants.STATUS_CREATING)]
        self.mock_object(db_driver, 'consistency_group_get_all',
                         mock.Mock(return_value=expected_cgs))

        actual_cgs = self.api.get_all(self.context,
                                      search_opts={'all_tenants': True})
        self.assertEqual(expected_cgs, actual_cgs)
        db_driver.consistency_group_get_all.assert_called_once_with(
            self.context, detailed=True)

    def test_create_cgsnapshot_minimal_request_no_members(self):
        cg = fake_cg('fake_cg_id',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE)
        snap = fake_cgsnapshot('fakeid',
                               user_id=self.context.user_id,
                               project_id=self.context.project_id,
                               consistency_group_id=cg['id'],
                               status=constants.STATUS_CREATING)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'cgsnapshot_create',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'share_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[]))

        self.api.create_cgsnapshot(self.context, consistency_group_id=cg['id'])

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, cg['id']
        )
        db_driver.cgsnapshot_create.assert_called_once_with(
            self.context, expected_values)
        self.share_rpcapi.create_cgsnapshot.assert_called_once_with(
            self.context, snap, cg['host']
        )

    def test_create_cgsnapshot_minimal_request_no_members_with_name(self):
        fake_name = 'fake_name'
        cg = fake_cg('fake_cg_id',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE)
        snap = fake_cgsnapshot('fakeid',
                               user_id=self.context.user_id,
                               project_id=self.context.project_id,
                               consistency_group_id=cg['id'],
                               name=fake_name,
                               status=constants.STATUS_CREATING)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'cgsnapshot_create',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'share_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[]))

        self.api.create_cgsnapshot(self.context, consistency_group_id=cg['id'],
                                   name=fake_name)

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, cg['id']
        )
        db_driver.cgsnapshot_create.assert_called_once_with(
            self.context, expected_values)
        self.share_rpcapi.create_cgsnapshot.assert_called_once_with(
            self.context, snap, cg['host']
        )

    def test_create_cgsnapshot_minimal_request_no_members_with_desc(self):
        fake_description = 'fake_description'
        cg = fake_cg('fake_cg_id',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE)
        snap = fake_cgsnapshot('fakeid',
                               user_id=self.context.user_id,
                               project_id=self.context.project_id,
                               consistency_group_id=cg['id'],
                               description=fake_description,
                               status=constants.STATUS_CREATING)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'cgsnapshot_create',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'share_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[]))

        self.api.create_cgsnapshot(self.context, consistency_group_id=cg['id'],
                                   description=fake_description)

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, cg['id']
        )
        db_driver.cgsnapshot_create.assert_called_once_with(
            self.context, expected_values)
        self.share_rpcapi.create_cgsnapshot.assert_called_once_with(
            self.context, snap, cg['host']
        )

    def test_create_cgsnapshot_cg_does_not_exist(self):
        cg = fake_cg('fake_cg_id',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_CREATING)
        snap = fake_cgsnapshot('fakeid',
                               user_id=self.context.user_id,
                               project_id=self.context.project_id,
                               consistency_group_id=cg['id'],
                               status=constants.STATUS_CREATING)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'cgsnapshot_create',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'share_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.InvalidConsistencyGroup,
                          self.api.create_cgsnapshot,
                          self.context,
                          consistency_group_id=cg['id'])

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, cg['id']
        )

    def test_create_cgsnapshot_cg_in_creating(self):
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(
                             side_effect=exception.ConsistencyGroupNotFound(
                                 consistency_group_id='fake_id'
                             )))

        self.assertRaises(exception.ConsistencyGroupNotFound,
                          self.api.create_cgsnapshot,
                          self.context,
                          consistency_group_id="fake_id")

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, "fake_id"
        )

    def test_create_cgsnapshot_with_member(self):
        cg = fake_cg('fake_cg_id',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE)
        snap = fake_cgsnapshot('fakeid',
                               user_id=self.context.user_id,
                               project_id=self.context.project_id,
                               consistency_group_id=cg['id'],
                               status=constants.STATUS_CREATING)
        share = stubs.stub_share('fake_share_id',
                                 status=constants.STATUS_AVAILABLE)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        expected_member_values = {
            'cgsnapshot_id': snap['id'],
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_CREATING,
            'size': share['size'],
            'share_proto': share['share_proto'],
            'share_type_id': share['share_type_id'],
            'share_id': share['id'],
            'share_instance_id': mock.ANY,
        }
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'cgsnapshot_create',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'cgsnapshot_member_create',
                         mock.Mock())
        self.mock_object(db_driver, 'share_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[share]))

        self.api.create_cgsnapshot(self.context, consistency_group_id=cg['id'])

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, cg['id']
        )
        db_driver.cgsnapshot_create.assert_called_once_with(
            self.context, expected_values)
        db_driver.cgsnapshot_member_create.assert_called_once_with(
            self.context, expected_member_values
        )
        self.share_rpcapi.create_cgsnapshot.assert_called_once_with(
            self.context, snap, cg['host']
        )

    def test_create_cgsnapshot_with_member_share_in_creating(self):
        cg = fake_cg('fake_cg_id',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE)
        share = stubs.stub_share('fake_share_id',
                                 status=constants.STATUS_CREATING)
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'share_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[share]))

        self.assertRaises(exception.InvalidConsistencyGroup,
                          self.api.create_cgsnapshot,
                          self.context,
                          consistency_group_id=cg['id'])

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, cg['id']
        )

    def test_create_cgsnapshot_with_two_members(self):
        cg = fake_cg('fake_cg_id',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE)
        snap = fake_cgsnapshot('fakeid',
                               user_id=self.context.user_id,
                               project_id=self.context.project_id,
                               consistency_group_id=cg['id'],
                               status=constants.STATUS_CREATING)
        share = stubs.stub_share('fake_share_id',
                                 status=constants.STATUS_AVAILABLE)
        share_2 = stubs.stub_share('fake_share2_id',
                                   status=constants.STATUS_AVAILABLE)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        expected_member_1_values = {
            'cgsnapshot_id': snap['id'],
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_CREATING,
            'size': share['size'],
            'share_proto': share['share_proto'],
            'share_type_id': share['share_type_id'],
            'share_id': share['id'],
            'share_instance_id': mock.ANY,
        }
        expected_member_2_values = {
            'cgsnapshot_id': snap['id'],
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_CREATING,
            'size': share_2['size'],
            'share_proto': share_2['share_proto'],
            'share_type_id': share_2['share_type_id'],
            'share_id': share_2['id'],
            'share_instance_id': mock.ANY,
        }
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'cgsnapshot_create',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'share_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[share, share_2]))
        self.mock_object(db_driver, 'cgsnapshot_member_create',
                         mock.Mock())

        self.api.create_cgsnapshot(self.context, consistency_group_id=cg['id'])

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, cg['id']
        )
        db_driver.cgsnapshot_create.assert_called_once_with(
            self.context, expected_values)

        db_driver.cgsnapshot_member_create.assert_any_call(
            self.context, expected_member_1_values
        )
        db_driver.cgsnapshot_member_create.assert_any_call(
            self.context, expected_member_2_values
        )
        self.share_rpcapi.create_cgsnapshot.assert_called_once_with(
            self.context, snap, cg['host']
        )

    def test_create_cgsnapshot_error_creating_member(self):
        cg = fake_cg('fake_cg_id',
                     user_id=self.context.user_id,
                     project_id=self.context.project_id,
                     status=constants.STATUS_AVAILABLE)
        snap = fake_cgsnapshot('fakeid',
                               user_id=self.context.user_id,
                               project_id=self.context.project_id,
                               consistency_group_id=cg['id'],
                               status=constants.STATUS_CREATING)
        share = stubs.stub_share('fake_share_id',
                                 status=constants.STATUS_AVAILABLE)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        expected_member_values = {
            'cgsnapshot_id': snap['id'],
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_CREATING,
            'size': share['size'],
            'share_proto': share['share_proto'],
            'share_type_id': share['share_type_id'],
            'share_id': share['id'],
            'share_instance_id': mock.ANY,
        }
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'cgsnapshot_create',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'cgsnapshot_destroy')
        self.mock_object(db_driver, 'cgsnapshot_member_create',
                         mock.Mock(side_effect=exception.Error))
        self.mock_object(db_driver, 'share_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[share]))

        self.assertRaises(exception.Error, self.api.create_cgsnapshot,
                          self.context, consistency_group_id=cg['id'])

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, cg['id']
        )
        db_driver.cgsnapshot_create.assert_called_once_with(
            self.context, expected_values)
        db_driver.cgsnapshot_member_create.assert_called_once_with(
            self.context, expected_member_values
        )
        db_driver.cgsnapshot_destroy.assert_called_once_with(
            self.context, snap['id']
        )

    def test_delete_cgsnapshot(self):
        cg = fake_cg('fake_id', host="fake_host")
        snap = fake_cgsnapshot('fake_cgsnap_id',
                               consistency_group_id='fake_id',
                               status=constants.STATUS_AVAILABLE)
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(return_value=cg))
        self.mock_object(db_driver, 'cgsnapshot_update')

        self.api.delete_cgsnapshot(self.context, snap)

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, "fake_id"
        )
        db_driver.cgsnapshot_update.assert_called_once_with(
            self.context, snap['id'], {'status': constants.STATUS_DELETING}
        )
        self.share_rpcapi.delete_cgsnapshot.assert_called_once_with(
            self.context, snap, cg['host'])

    def test_delete_cgsnapshot_cg_does_not_exist(self):
        snap = fake_cgsnapshot('fake_cgsnap_id',
                               consistency_group_id='fake_id')
        self.mock_object(db_driver, 'consistency_group_get',
                         mock.Mock(
                             side_effect=exception.ConsistencyGroupNotFound(
                                 consistency_group_id='fake_id'
                             )))

        self.assertRaises(exception.ConsistencyGroupNotFound,
                          self.api.delete_cgsnapshot,
                          self.context,
                          snap)

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, "fake_id"
        )

    def test_delete_cgsnapshot_creating_status(self):
        snap = fake_cgsnapshot('fake_cgsnap_id',
                               consistency_group_id='fake_id',
                               status=constants.STATUS_CREATING)
        self.mock_object(db_driver, 'consistency_group_get')

        self.assertRaises(exception.InvalidCGSnapshot,
                          self.api.delete_cgsnapshot,
                          self.context,
                          snap)

        db_driver.consistency_group_get.assert_called_once_with(
            self.context, "fake_id"
        )

    def test_update_cgsnapshot_no_values(self):
        snap = fake_cgsnapshot('fakeid',
                               user_id=self.context.user_id,
                               project_id=self.context.project_id,
                               status=constants.STATUS_CREATING)
        expected_values = {}
        self.mock_object(db_driver, 'cgsnapshot_update',
                         mock.Mock(return_value=snap))

        self.api.update_cgsnapshot(self.context, snap, expected_values)

        db_driver.cgsnapshot_update.assert_called_once_with(
            self.context, snap['id'], expected_values)

    def test_update_cgsnapshot_with_name(self):
        fake_name = 'fake_name'
        snap = fake_cgsnapshot('fakeid',
                               user_id=self.context.user_id,
                               project_id=self.context.project_id,
                               status=constants.STATUS_CREATING)
        expected_values = {'description': fake_name}

        self.mock_object(db_driver, 'cgsnapshot_update',
                         mock.Mock(return_value=snap))

        self.api.update_cgsnapshot(self.context, snap, expected_values)

        db_driver.cgsnapshot_update.assert_called_once_with(
            self.context, snap['id'], expected_values)

    def test_cgsnapshot_get(self):
        expected_snap = fake_cgsnapshot('fakeid',
                                        user_id=self.context.user_id,
                                        project_id=self.context.project_id,
                                        status=constants.STATUS_CREATING)
        self.mock_object(db_driver, 'cgsnapshot_get',
                         mock.Mock(return_value=expected_snap))

        actual_cg = self.api.get_cgsnapshot(self.context, expected_snap['id'])
        self.assertEqual(expected_snap, actual_cg)

    def test_cgsnapshot_get_all_no_cgs(self):

        self.mock_object(db_driver, 'cgsnapshot_get_all',
                         mock.Mock(return_value=[]))

        actual_cg = self.api.get_all_cgsnapshots(self.context)
        self.assertEqual([], actual_cg)

    def test_cgsnapshot_get_all(self):
        expected_snaps = [fake_cg('fakeid',
                                  user_id=self.context.user_id,
                                  project_id=self.context.project_id,
                                  status=constants.STATUS_CREATING)]
        self.mock_object(db_driver, 'cgsnapshot_get_all_by_project',
                         mock.Mock(return_value=expected_snaps))

        actual_cg = self.api.get_all_cgsnapshots(self.context, detailed=True)
        self.assertEqual(expected_snaps, actual_cg)

    def test_cgsnapshot_get_all_all_tenants_not_admin(self):
        cxt = context.RequestContext(user_id=None,
                                     project_id=None,
                                     is_admin=False)
        expected_snaps = [fake_cg('fakeid',
                                  user_id=cxt.user_id,
                                  project_id=cxt.project_id,
                                  status=constants.STATUS_CREATING)]
        self.mock_object(db_driver, 'cgsnapshot_get_all_by_project',
                         mock.Mock(return_value=expected_snaps))

        actual_cgs = self.api.get_all_cgsnapshots(
            cxt, search_opts={'all_tenants': True})
        self.assertEqual(expected_snaps, actual_cgs)

    def test_cgsnapshot_get_all_all_tenants_as_admin(self):
        expected_snaps = [fake_cg('fakeid',
                                  user_id=self.context.user_id,
                                  project_id=self.context.project_id,
                                  status=constants.STATUS_CREATING)]
        self.mock_object(db_driver, 'cgsnapshot_get_all',
                         mock.Mock(return_value=expected_snaps))

        actual_cgs = self.api.get_all_cgsnapshots(
            self.context, search_opts={'all_tenants': True})
        self.assertEqual(expected_snaps, actual_cgs)
        db_driver.cgsnapshot_get_all.assert_called_once_with(
            self.context, detailed=True)

    def test_get_all_cgsnapshot_members(self):
        self.mock_object(db_driver, 'cgsnapshot_members_get_all',
                         mock.Mock(return_value=[]))

        self.api.get_all_cgsnapshot_members(self.context, 'fake_id')

        db_driver.cgsnapshot_members_get_all.assert_called_once_with(
            self.context, 'fake_id'
        )
