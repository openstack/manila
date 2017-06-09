# Copyright 2016 Alex Meade
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
from manila import context
from manila import db as db_driver
from manila import exception
from manila.share import share_types
import manila.share_group.api as share_group_api
from manila import test
from manila.tests.api.contrib import stubs

CONF = cfg.CONF


def fake_share_group(id, **kwargs):
    share_group = {
        'id': id,
        'user_id': 'fakeuser',
        'project_id': 'fakeproject',
        'status': constants.STATUS_CREATING,
        'name': None,
        'description': None,
        'host': None,
        'availability_zone_id': None,
        'share_group_type_id': None,
        'source_share_group_snapshot_id': None,
        'share_network_id': None,
        'share_server_id': None,
        'share_types': mock.ANY,
        'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
    }

    if 'source_share_group_snapshot_id' in kwargs:
        share_group['share_network_id'] = 'fake_share_network_id'
        share_group['share_server_id'] = 'fake_share_server_id'

    share_group.update(kwargs)
    return share_group


def fake_share_group_snapshot(id, **kwargs):
    snap = {
        'id': id,
        'user_id': 'fakeuser',
        'project_id': 'fakeproject',
        'status': constants.STATUS_CREATING,
        'name': None,
        'description': None,
        'share_group_id': None,
        'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
    }
    snap.update(kwargs)
    return snap


@ddt.ddt
class ShareGroupsAPITestCase(test.TestCase):
    def setUp(self):
        super(ShareGroupsAPITestCase, self).setUp()
        self.user_id = 'fake_user_id'
        self.project_id = 'fake_project_id'
        self.context = context.RequestContext(
            user_id=self.user_id, project_id=self.project_id, is_admin=True)
        self.scheduler_rpcapi = mock.Mock()
        self.share_rpcapi = mock.Mock()
        self.share_api = mock.Mock()
        self.api = share_group_api.API()
        self.mock_object(self.api, 'share_rpcapi', self.share_rpcapi)
        self.mock_object(self.api, 'share_api', self.share_api)
        self.mock_object(self.api, 'scheduler_rpcapi', self.scheduler_rpcapi)

        dt_utc = datetime.datetime.utcnow()
        self.mock_object(timeutils, 'utcnow', mock.Mock(return_value=dt_utc))
        self.fake_share_type = {
            'name': 'default',
            'extra_specs': {'driver_handles_share_servers': 'False'},
            'is_public': True,
            'id': 'c01990c1-448f-435a-9de6-c7c894bb6df9'
        }
        self.fake_share_type_2 = {
            'name': 'default2',
            'extra_specs': {'driver_handles_share_servers': 'False'},
            'is_public': True,
            'id': 'c01990c1-448f-435a-9de6-c7c894bb7dfd'
        }
        self.fake_share_group_type = {
            'share_types': [
                {'share_type_id': self.fake_share_type['id']},
                {'share_type_id': self.fake_share_type_2['id']},
            ]
        }
        self.mock_object(
            db_driver, 'share_group_type_get',
            mock.Mock(return_value=self.fake_share_group_type))
        self.mock_object(share_group_api.QUOTAS, 'reserve')
        self.mock_object(share_group_api.QUOTAS, 'commit')
        self.mock_object(share_group_api.QUOTAS, 'rollback')

    def test_create_empty_request(self):
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        expected_values = share_group.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(db_driver, 'share_group_create',
                         mock.Mock(return_value=share_group))

        self.api.create(self.context)

        db_driver.share_group_create.assert_called_once_with(
            self.context, expected_values)
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_request_spec(self):
        """Ensure the correct values are sent to the scheduler."""
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        expected_values = share_group.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_request_spec = {'share_group_id': share_group['id']}
        expected_request_spec.update(share_group)
        del expected_request_spec['id']
        del expected_request_spec['created_at']
        del expected_request_spec['host']
        expected_request_spec['resource_type'] = self.fake_share_group_type
        self.mock_object(db_driver, 'share_group_create',
                         mock.Mock(return_value=share_group))

        self.api.create(self.context)

        self.scheduler_rpcapi.create_share_group.assert_called_once_with(
            self.context, share_group_id=share_group['id'],
            request_spec=expected_request_spec, filter_properties={})
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_name(self):
        fake_name = 'fake_name'
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        expected_values = share_group.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['name'] = fake_name
        self.mock_object(db_driver, 'share_group_create',
                         mock.Mock(return_value=share_group))
        self.mock_object(db_driver, 'share_network_get')

        self.api.create(self.context, name=fake_name)

        db_driver.share_group_create.assert_called_once_with(
            self.context, expected_values)
        self.scheduler_rpcapi.create_share_group.assert_called_once_with(
            self.context, share_group_id=share_group['id'],
            request_spec=mock.ANY, filter_properties={})
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_description(self):
        fake_desc = 'fake_desc'
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        expected_values = share_group.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['description'] = fake_desc
        self.mock_object(db_driver, 'share_group_create',
                         mock.Mock(return_value=share_group))

        self.api.create(self.context, description=fake_desc)

        db_driver.share_group_create.assert_called_once_with(
            self.context, expected_values)
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_multiple_share_types(self):
        fake_share_types = [self.fake_share_type, self.fake_share_type_2]
        fake_share_type_ids = [x['id'] for x in fake_share_types]
        self.mock_object(share_types, 'get_share_type')
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        expected_values = share_group.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['share_types'] = fake_share_type_ids

        self.mock_object(
            db_driver, 'share_group_create',
            mock.Mock(return_value=share_group))
        self.mock_object(db_driver, 'share_network_get')

        self.api.create(self.context, share_type_ids=fake_share_type_ids)

        db_driver.share_group_create.assert_called_once_with(
            self.context, expected_values)
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_share_type_not_found(self):
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(side_effect=exception.ShareTypeNotFound(
                             share_type_id=self.fake_share_type['id'])))
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        expected_values = share_group.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['share_types'] = self.fake_share_type['id']
        self.mock_object(db_driver, 'share_group_create',
                         mock.Mock(return_value=share_group))

        self.assertRaises(
            exception.InvalidInput,
            self.api.create,
            self.context, share_type_ids=[self.fake_share_type['id']])

        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_error_on_quota_reserve(self):
        overs = ["share_groups"]
        usages = {"share_groups": {"reserved": 1, "in_use": 3, "limit": 4}}
        quotas = {"share_groups": 5}
        share_group_api.QUOTAS.reserve.side_effect = exception.OverQuota(
            overs=overs,
            usages=usages,
            quotas=quotas,
        )
        self.mock_object(share_group_api.LOG, "warning")

        self.assertRaises(
            exception.ShareGroupsLimitExceeded,
            self.api.create, self.context)

        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()
        share_group_api.LOG.warning.assert_called_once_with(mock.ANY, mock.ANY)

    def test_create_driver_handles_share_servers_is_false_with_net_id(self):
        fake_share_types = [self.fake_share_type]
        self.mock_object(share_types, 'get_share_type')

        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, share_type_ids=fake_share_types,
                          share_network_id="fake_share_network")

    def test_create_with_conflicting_share_types(self):
        fake_share_type = {
            'name': 'default',
            'extra_specs': {'driver_handles_share_servers': 'True'},
            'is_public': True,
            'id': 'c01990c1-448f-435a-9de6-c7c894bb6df9',
        }
        fake_share_type_2 = {
            'name': 'default2',
            'extra_specs': {'driver_handles_share_servers': 'False'},
            'is_public': True,
            'id': 'c01990c1-448f-435a-9de6-c7c894bb7df9',
        }
        fake_share_types = [fake_share_type, fake_share_type_2]
        fake_share_type_ids = [x['id'] for x in fake_share_types]
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(side_effect=[fake_share_type,
                                                fake_share_type_2]))

        self.assertRaises(
            exception.InvalidInput,
            self.api.create,
            self.context, share_type_ids=fake_share_type_ids)

        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_conflicting_share_type_and_share_network(self):
        fake_share_type = {
            'name': 'default',
            'extra_specs': {'driver_handles_share_servers': 'False'},
            'is_public': True,
            'id': 'c01990c1-448f-435a-9de6-c7c894bb6df9',
        }
        fake_share_types = [fake_share_type]
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_share_type))

        self.assertRaises(
            exception.InvalidInput,
            self.api.create,
            self.context, share_type_ids=fake_share_types,
            share_network_id="fake_sn")

        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_source_share_group_snapshot_id(self):
        snap = fake_share_group_snapshot(
            "fake_source_share_group_snapshot_id",
            status=constants.STATUS_AVAILABLE)
        fake_share_type_mapping = {'share_type_id': self.fake_share_type['id']}
        orig_share_group = fake_share_group(
            'fakeorigid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_types=[fake_share_type_mapping],
            status=constants.STATUS_AVAILABLE,
            host='fake_original_host',
            share_network_id='fake_network_id',
            share_server_id='fake_server_id')

        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_types=[fake_share_type_mapping],
            status=constants.STATUS_CREATING,
            host='fake_original_host',
            share_network_id='fake_network_id',
            share_server_id='fake_server_id')
        expected_values = share_group.copy()
        for name in ('id', 'created_at', 'share_network_id',
                     'share_server_id'):
            expected_values.pop(name, None)
        expected_values['source_share_group_snapshot_id'] = snap['id']
        expected_values['share_types'] = [self.fake_share_type['id']]
        expected_values['share_network_id'] = 'fake_network_id'
        expected_values['share_server_id'] = 'fake_server_id'

        self.mock_object(
            db_driver, 'share_group_snapshot_get',
            mock.Mock(return_value=snap))
        self.mock_object(
            db_driver, 'share_group_get',
            mock.Mock(return_value=orig_share_group))
        self.mock_object(
            db_driver, 'share_group_create',
            mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_get',
            mock.Mock(return_value=stubs.stub_share('fake_share')))
        self.mock_object(
            share_types, 'get_share_type',
            mock.Mock(return_value={"id": self.fake_share_type['id']}))
        self.mock_object(db_driver, 'share_network_get')
        self.mock_object(
            db_driver, 'share_group_snapshot_members_get_all',
            mock.Mock(return_value=[]))

        self.api.create(
            self.context, source_share_group_snapshot_id=snap['id'])

        db_driver.share_group_create.assert_called_once_with(
            self.context, expected_values)
        self.share_rpcapi.create_share_group.assert_called_once_with(
            self.context, share_group, orig_share_group['host'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_source_share_group_snapshot_id_with_member(self):
        snap = fake_share_group_snapshot(
            "fake_source_share_group_snapshot_id",
            status=constants.STATUS_AVAILABLE)
        share = stubs.stub_share('fakeshareid')
        member = stubs.stub_share_group_snapshot_member('fake_member_id')
        fake_share_type_mapping = {'share_type_id': self.fake_share_type['id']}
        orig_share_group = fake_share_group(
            'fakeorigid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_types=[fake_share_type_mapping],
            status=constants.STATUS_AVAILABLE,
            share_network_id='fake_network_id',
            share_server_id='fake_server_id')
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_types=[fake_share_type_mapping],
            status=constants.STATUS_CREATING,
            share_network_id='fake_network_id',
            share_server_id='fake_server_id')
        expected_values = share_group.copy()
        for name in ('id', 'created_at', 'fake_network_id',
                     'fake_share_server_id'):
            expected_values.pop(name, None)
        expected_values['source_share_group_snapshot_id'] = snap['id']
        expected_values['share_types'] = [self.fake_share_type['id']]
        expected_values['share_network_id'] = 'fake_network_id'
        expected_values['share_server_id'] = 'fake_server_id'

        self.mock_object(
            db_driver, 'share_group_snapshot_get',
            mock.Mock(return_value=snap))
        self.mock_object(
            db_driver, 'share_group_get',
            mock.Mock(return_value=orig_share_group))
        self.mock_object(
            db_driver, 'share_group_create',
            mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_get',
            mock.Mock(return_value=stubs.stub_share('fakeshare')))
        self.mock_object(
            share_types, 'get_share_type',
            mock.Mock(return_value={"id": self.fake_share_type['id']}))
        self.mock_object(db_driver, 'share_network_get')
        self.mock_object(
            db_driver, 'share_instance_get', mock.Mock(return_value=share))
        self.mock_object(
            db_driver, 'share_group_snapshot_members_get_all',
            mock.Mock(return_value=[member]))
        self.mock_object(self.share_api, 'create')

        self.api.create(
            self.context, source_share_group_snapshot_id=snap['id'])

        db_driver.share_group_create.assert_called_once_with(
            self.context, expected_values)
        self.assertTrue(self.share_api.create.called)
        self.share_rpcapi.create_share_group.assert_called_once_with(
            self.context, share_group, orig_share_group['host'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_source_sg_snapshot_id_with_members_error(self):
        snap = fake_share_group_snapshot(
            "fake_source_share_group_snapshot_id",
            status=constants.STATUS_AVAILABLE)
        member = stubs.stub_share_group_snapshot_member('fake_member_id')
        member_2 = stubs.stub_share_group_snapshot_member('fake_member2_id')
        share = stubs.stub_share('fakeshareid')
        fake_share_type_mapping = {'share_type_id': self.fake_share_type['id']}
        orig_share_group = fake_share_group(
            'fakeorigid',
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_types=[fake_share_type_mapping],
            status=constants.STATUS_AVAILABLE,
            share_network_id='fake_network_id',
            share_server_id='fake_server_id')
        share_group = fake_share_group(
            'fakeid',
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_types=[fake_share_type_mapping],
            status=constants.STATUS_CREATING,
            share_network_id='fake_network_id',
            share_server_id='fake_server_id')
        expected_values = share_group.copy()
        for name in ('id', 'created_at', 'share_network_id',
                     'share_server_id'):
            expected_values.pop(name, None)
        expected_values['source_share_group_snapshot_id'] = snap['id']
        expected_values['share_types'] = [self.fake_share_type['id']]
        expected_values['share_network_id'] = 'fake_network_id'
        expected_values['share_server_id'] = 'fake_server_id'

        self.mock_object(db_driver, 'share_group_snapshot_get',
                         mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'share_group_get',
                         mock.Mock(return_value=orig_share_group))
        self.mock_object(db_driver, 'share_network_get')
        self.mock_object(db_driver, 'share_instance_get',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_group_create',
                         mock.Mock(return_value=share_group))
        self.mock_object(db_driver, 'share_get',
                         mock.Mock(return_value=stubs.stub_share('fakeshare')))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value={
                             "id": self.fake_share_type['id']}))
        self.mock_object(db_driver, 'share_group_snapshot_members_get_all',
                         mock.Mock(return_value=[member, member_2]))
        self.mock_object(self.share_api, 'create',
                         mock.Mock(side_effect=[None, exception.Error]))
        self.mock_object(db_driver, 'share_group_destroy')

        self.assertRaises(exception.Error, self.api.create, self.context,
                          source_share_group_snapshot_id=snap['id'])

        db_driver.share_group_create.assert_called_once_with(
            self.context, expected_values)
        self.assertEqual(2, self.share_api.create.call_count)
        self.assertEqual(1, db_driver.share_group_destroy.call_count)

        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)

    def test_create_with_source_sg_snapshot_id_error_snapshot_status(self):
        snap = fake_share_group_snapshot(
            "fake_source_share_group_snapshot_id",
            status=constants.STATUS_ERROR)
        self.mock_object(
            db_driver, 'share_group_snapshot_get',
            mock.Mock(return_value=snap))

        self.assertRaises(
            exception.InvalidShareGroupSnapshot,
            self.api.create,
            self.context, source_share_group_snapshot_id=snap['id'])

        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_source_sg_snapshot_id_snap_not_found(self):
        snap = fake_share_group_snapshot(
            "fake_source_share_group_snapshot_id",
            status=constants.STATUS_ERROR)
        self.mock_object(
            db_driver, 'share_group_snapshot_get',
            mock.Mock(side_effect=exception.ShareGroupSnapshotNotFound(
                share_group_snapshot_id='fake_source_sg_snapshot_id')))

        self.assertRaises(
            exception.ShareGroupSnapshotNotFound,
            self.api.create,
            self.context, source_share_group_snapshot_id=snap['id'])

        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_multiple_fields(self):
        fake_desc = 'fake_desc'
        fake_name = 'fake_name'
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        expected_values = share_group.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        expected_values['name'] = fake_name
        expected_values['description'] = fake_desc
        self.mock_object(db_driver, 'share_group_create',
                         mock.Mock(return_value=share_group))

        self.api.create(self.context, name=fake_name,
                        description=fake_desc)

        db_driver.share_group_create.assert_called_once_with(
            self.context, expected_values)
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_with_error_on_creation(self):
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        expected_values = share_group.copy()
        for name in ('id', 'host', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(db_driver, 'share_group_create',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error, self.api.create, self.context)

        db_driver.share_group_create.assert_called_once_with(
            self.context, expected_values)
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=1)
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)

    def test_delete_creating_no_host(self):
        share_group = fake_share_group(
            'fakeid', user_id=self.user_id + '_different_user',
            project_id=self.project_id + '_in_different_project',
            status=constants.STATUS_CREATING)
        self.mock_object(db_driver, 'share_group_destroy')

        self.api.delete(self.context, share_group)

        db_driver.share_group_destroy.assert_called_once_with(
            mock.ANY, share_group['id'])
        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_delete_creating_with_host(self):
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING, host="fake_host")

        self.assertRaises(
            exception.InvalidShareGroup,
            self.api.delete, self.context, share_group)

    def test_delete_available(self):
        share_group = fake_share_group(
            'fakeid', user_id=self.user_id + '_different_user',
            project_id=self.project_id + '_in_different_project',
            status=constants.STATUS_AVAILABLE, host="fake_host")
        deleted_share_group = copy.deepcopy(share_group)
        deleted_share_group['status'] = constants.STATUS_DELETING
        self.mock_object(db_driver, 'share_group_update',
                         mock.Mock(return_value=deleted_share_group))
        self.mock_object(db_driver, 'count_shares_in_share_group',
                         mock.Mock(return_value=0))

        self.api.delete(self.context, share_group)

        db_driver.share_group_update.assert_called_once_with(
            self.context, share_group['id'],
            {'status': constants.STATUS_DELETING})
        self.share_rpcapi.delete_share_group.assert_called_once_with(
            self.context, deleted_share_group)
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=-1,
            project_id=share_group['project_id'],
            user_id=share_group['user_id'])
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context,
            share_group_api.QUOTAS.reserve.return_value,
            project_id=share_group['project_id'],
            user_id=share_group['user_id'])
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_delete_error_with_host(self):
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_ERROR, host="fake_host")
        deleted_share_group = copy.deepcopy(share_group)
        deleted_share_group['status'] = constants.STATUS_DELETING
        self.mock_object(self.api, 'share_rpcapi')
        self.mock_object(db_driver, 'share_group_update',
                         mock.Mock(return_value=deleted_share_group))
        self.mock_object(db_driver, 'count_shares_in_share_group',
                         mock.Mock(return_value=0))

        self.api.delete(self.context, share_group)

        db_driver.share_group_update.assert_called_once_with(
            self.context, share_group['id'],
            {'status': constants.STATUS_DELETING})
        self.api.share_rpcapi.delete_share_group.assert_called_once_with(
            self.context, deleted_share_group)
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_groups=-1,
            project_id=share_group['project_id'],
            user_id=share_group['user_id'])
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context,
            share_group_api.QUOTAS.reserve.return_value,
            project_id=share_group['project_id'],
            user_id=share_group['user_id'])
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_delete_error_without_host(self):
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_ERROR)
        self.mock_object(db_driver, 'share_group_destroy')

        self.api.delete(self.context, share_group)

        db_driver.share_group_destroy.assert_called_once_with(
            mock.ANY, share_group['id'])
        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_delete_with_shares(self):
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE, host="fake_host")
        self.mock_object(
            db_driver, 'count_shares_in_share_group',
            mock.Mock(return_value=1))

        self.assertRaises(
            exception.InvalidShareGroup,
            self.api.delete, self.context, share_group)

        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_delete_with_share_group_snapshots(self):
        share_group = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE, host="fake_host")
        self.mock_object(
            db_driver, 'count_share_group_snapshots_in_share_group',
            mock.Mock(return_value=1))

        self.assertRaises(
            exception.InvalidShareGroup,
            self.api.delete, self.context, share_group)

        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    @ddt.data({}, {"name": "fake_name"}, {"description": "fake_description"})
    def test_update(self, expected_values):
        share_group = fake_share_group(
            'fakeid',
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        self.mock_object(
            db_driver, 'share_group_update',
            mock.Mock(return_value=share_group))

        self.api.update(self.context, share_group, expected_values)

        db_driver.share_group_update.assert_called_once_with(
            self.context, share_group['id'], expected_values)

    def test_get(self):
        expected = fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        self.mock_object(
            db_driver, 'share_group_get', mock.Mock(return_value=expected))

        actual = self.api.get(self.context, expected['id'])

        self.assertEqual(expected, actual)

    def test_get_all_no_groups(self):
        self.mock_object(
            db_driver, 'share_group_get_all', mock.Mock(return_value=[]))

        actual_group = self.api.get_all(self.context)

        self.assertEqual([], actual_group)

    def test_get_all(self):
        expected = [fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)]
        self.mock_object(
            db_driver, 'share_group_get_all_by_project',
            mock.Mock(return_value=expected))

        actual = self.api.get_all(self.context, detailed=True)

        self.assertEqual(expected, actual)

    def test_get_all_all_tenants_not_admin(self):
        cxt = context.RequestContext(
            user_id=None, project_id=None, is_admin=False)
        expected = [fake_share_group(
            'fakeid', user_id=cxt.user_id, project_id=cxt.project_id,
            status=constants.STATUS_CREATING)]
        self.mock_object(db_driver, 'share_group_get_all_by_project',
                         mock.Mock(return_value=expected))

        actual = self.api.get_all(cxt, search_opts={'all_tenants': True})

        self.assertEqual(expected, actual)

    def test_get_all_all_tenants_as_admin(self):
        expected = [fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)]
        self.mock_object(db_driver, 'share_group_get_all',
                         mock.Mock(return_value=expected))

        actual = self.api.get_all(
            self.context, search_opts={'all_tenants': True})

        self.assertEqual(expected, actual)
        db_driver.share_group_get_all.assert_called_once_with(
            self.context, detailed=True, filters={},
            sort_dir=None, sort_key=None)

    def test_create_share_group_snapshot_minimal_request_no_members(self):
        share_group = fake_share_group(
            'fake_group_id', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE)
        snap = fake_share_group_snapshot(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_group_id=share_group['id'],
            status=constants.STATUS_CREATING)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(
            db_driver, 'share_group_get', mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_group_snapshot_create',
            mock.Mock(return_value=snap))
        self.mock_object(
            db_driver, 'share_get_all_by_share_group_id',
            mock.Mock(return_value=[]))

        self.api.create_share_group_snapshot(
            self.context, share_group_id=share_group['id'])

        db_driver.share_group_get.assert_called_once_with(
            self.context, share_group['id'])
        db_driver.share_group_snapshot_create.assert_called_once_with(
            self.context, expected_values)
        self.share_rpcapi.create_share_group_snapshot.assert_called_once_with(
            self.context, snap, share_group['host'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_group_snapshots=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_sg_snapshot_minimal_request_no_members_with_name(self):
        fake_name = 'fake_name'
        share_group = fake_share_group(
            'fake_group_id', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE)
        snap = fake_share_group_snapshot(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_group_id=share_group['id'], name=fake_name,
            status=constants.STATUS_CREATING)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(
            db_driver, 'share_group_get', mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_group_snapshot_create',
            mock.Mock(return_value=snap))
        self.mock_object(
            db_driver, 'share_get_all_by_share_group_id',
            mock.Mock(return_value=[]))

        self.api.create_share_group_snapshot(
            self.context, share_group_id=share_group['id'], name=fake_name)

        db_driver.share_group_get.assert_called_once_with(
            self.context, share_group['id'])
        db_driver.share_group_snapshot_create.assert_called_once_with(
            self.context, expected_values)
        self.share_rpcapi.create_share_group_snapshot.assert_called_once_with(
            self.context, snap, share_group['host'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_group_snapshots=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_group_snapshot_minimal_request_no_members_with_desc(self):
        fake_description = 'fake_description'
        share_group = fake_share_group(
            'fake_group_id', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE)
        snap = fake_share_group_snapshot(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_group_id=share_group['id'],
            description=fake_description,
            status=constants.STATUS_CREATING)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(
            db_driver, 'share_group_get', mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_group_snapshot_create',
            mock.Mock(return_value=snap))
        self.mock_object(
            db_driver, 'share_get_all_by_share_group_id',
            mock.Mock(return_value=[]))

        self.api.create_share_group_snapshot(
            self.context, share_group_id=share_group['id'],
            description=fake_description)

        db_driver.share_group_get.assert_called_once_with(
            self.context, share_group['id'])
        db_driver.share_group_snapshot_create.assert_called_once_with(
            self.context, expected_values)
        self.share_rpcapi.create_share_group_snapshot.assert_called_once_with(
            self.context, snap, share_group['host'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_group_snapshots=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_share_group_snapshot_group_does_not_exist(self):
        share_group = fake_share_group(
            'fake_group_id', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        snap = fake_share_group_snapshot(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_group_id=share_group['id'],
            status=constants.STATUS_CREATING)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        self.mock_object(
            db_driver, 'share_group_get', mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_group_snapshot_create',
            mock.Mock(return_value=snap))
        self.mock_object(
            db_driver, 'share_get_all_by_share_group_id',
            mock.Mock(return_value=[]))

        self.assertRaises(
            exception.InvalidShareGroup,
            self.api.create_share_group_snapshot,
            self.context, share_group_id=share_group['id'])

        db_driver.share_group_get.assert_called_once_with(
            self.context, share_group['id'])
        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_share_group_snapshot_failure_reserving_quota(self):
        overs = ["share_group_snapshots"]
        usages = {"share_group_snapshots": {
            "reserved": 1,
            "in_use": 3,
            "limit": 4,
        }}
        quotas = {"share_group_snapshots": 5}
        share_group = fake_share_group(
            "fake_group_id", user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE)
        self.mock_object(
            db_driver, "share_group_get", mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, "share_get_all_by_share_group_id",
            mock.Mock(return_value=[]))
        share_group_api.QUOTAS.reserve.side_effect = exception.OverQuota(
            overs=overs,
            usages=usages,
            quotas=quotas,
        )
        self.mock_object(share_group_api.LOG, "warning")

        self.assertRaises(
            exception.ShareGroupSnapshotsLimitExceeded,
            self.api.create_share_group_snapshot,
            self.context, share_group_id=share_group["id"])

        db_driver.share_group_get.assert_called_once_with(
            self.context, share_group["id"])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_group_snapshots=1)
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()
        share_group_api.LOG.warning.assert_called_once_with(mock.ANY, mock.ANY)

    def test_create_share_group_snapshot_group_in_creating(self):
        self.mock_object(
            db_driver, 'share_group_get',
            mock.Mock(side_effect=exception.ShareGroupNotFound(
                share_group_id='fake_id')))

        self.assertRaises(
            exception.ShareGroupNotFound,
            self.api.create_share_group_snapshot,
            self.context, share_group_id="fake_id")

        db_driver.share_group_get.assert_called_once_with(
            self.context, "fake_id")
        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_share_group_snapshot_with_member(self):
        share_group = fake_share_group(
            'fake_group_id', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE)
        snap = fake_share_group_snapshot(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_group_id=share_group['id'],
            status=constants.STATUS_CREATING)
        share = stubs.stub_share(
            'fake_share_id', status=constants.STATUS_AVAILABLE)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        expected_member_values = {
            'share_group_snapshot_id': snap['id'],
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_CREATING,
            'size': share['size'],
            'share_proto': share['share_proto'],
            'share_instance_id': mock.ANY,
        }
        self.mock_object(
            db_driver, 'share_group_get',
            mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_group_snapshot_create',
            mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'share_group_snapshot_member_create')
        self.mock_object(
            db_driver, 'share_get_all_by_share_group_id',
            mock.Mock(return_value=[share]))

        self.api.create_share_group_snapshot(
            self.context, share_group_id=share_group['id'])

        db_driver.share_group_get.assert_called_once_with(
            self.context, share_group['id'])
        db_driver.share_group_snapshot_create.assert_called_once_with(
            self.context, expected_values)
        db_driver.share_group_snapshot_member_create.assert_called_once_with(
            self.context, expected_member_values)
        self.share_rpcapi.create_share_group_snapshot.assert_called_once_with(
            self.context, snap, share_group['host'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_group_snapshots=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_share_group_snapshot_with_member_share_in_creating(self):
        share_group = fake_share_group(
            'fake_group_id', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE)
        share = stubs.stub_share(
            'fake_share_id', status=constants.STATUS_CREATING)
        self.mock_object(
            db_driver, 'share_group_get', mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_get_all_by_share_group_id',
            mock.Mock(return_value=[share]))

        self.assertRaises(
            exception.InvalidShareGroup,
            self.api.create_share_group_snapshot,
            self.context, share_group_id=share_group['id'])

        db_driver.share_group_get.assert_called_once_with(
            self.context, share_group['id'])
        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_share_group_snapshot_with_two_members(self):
        share_group = fake_share_group(
            'fake_group_id', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE)
        snap = fake_share_group_snapshot(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_group_id=share_group['id'],
            status=constants.STATUS_CREATING)
        share = stubs.stub_share(
            'fake_share_id', status=constants.STATUS_AVAILABLE)
        share_2 = stubs.stub_share(
            'fake_share2_id', status=constants.STATUS_AVAILABLE)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        expected_member_1_values = {
            'share_group_snapshot_id': snap['id'],
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_CREATING,
            'size': share['size'],
            'share_proto': share['share_proto'],
            'share_instance_id': mock.ANY,
        }
        expected_member_2_values = {
            'share_group_snapshot_id': snap['id'],
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_CREATING,
            'size': share_2['size'],
            'share_proto': share_2['share_proto'],
            'share_instance_id': mock.ANY,
        }
        self.mock_object(
            db_driver, 'share_group_get',
            mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_group_snapshot_create',
            mock.Mock(return_value=snap))
        self.mock_object(
            db_driver, 'share_get_all_by_share_group_id',
            mock.Mock(return_value=[share, share_2]))
        self.mock_object(db_driver, 'share_group_snapshot_member_create')

        self.api.create_share_group_snapshot(
            self.context, share_group_id=share_group['id'])

        db_driver.share_group_get.assert_called_once_with(
            self.context, share_group['id'])
        db_driver.share_group_snapshot_create.assert_called_once_with(
            self.context, expected_values)
        db_driver.share_group_snapshot_member_create.assert_any_call(
            self.context, expected_member_1_values)
        db_driver.share_group_snapshot_member_create.assert_any_call(
            self.context, expected_member_2_values)
        self.share_rpcapi.create_share_group_snapshot.assert_called_once_with(
            self.context, snap, share_group['host'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_group_snapshots=1)
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_create_share_group_snapshot_error_creating_member(self):
        share_group = fake_share_group(
            'fake_group_id', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE)
        snap = fake_share_group_snapshot(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_group_id=share_group['id'],
            status=constants.STATUS_CREATING)
        share = stubs.stub_share(
            'fake_share_id', status=constants.STATUS_AVAILABLE)
        expected_values = snap.copy()
        for name in ('id', 'created_at'):
            expected_values.pop(name, None)
        expected_member_values = {
            'share_group_snapshot_id': snap['id'],
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_CREATING,
            'size': share['size'],
            'share_proto': share['share_proto'],
            'share_instance_id': mock.ANY,
        }
        self.mock_object(
            db_driver, 'share_group_get',
            mock.Mock(return_value=share_group))
        self.mock_object(
            db_driver, 'share_group_snapshot_create',
            mock.Mock(return_value=snap))
        self.mock_object(db_driver, 'share_group_snapshot_destroy')
        self.mock_object(
            db_driver, 'share_group_snapshot_member_create',
            mock.Mock(side_effect=exception.Error))
        self.mock_object(
            db_driver, 'share_get_all_by_share_group_id',
            mock.Mock(return_value=[share]))

        self.assertRaises(
            exception.Error,
            self.api.create_share_group_snapshot,
            self.context, share_group_id=share_group['id'])

        db_driver.share_group_get.assert_called_once_with(
            self.context, share_group['id'])
        db_driver.share_group_snapshot_create.assert_called_once_with(
            self.context, expected_values)
        db_driver.share_group_snapshot_member_create.assert_called_once_with(
            self.context, expected_member_values)
        db_driver.share_group_snapshot_destroy.assert_called_once_with(
            self.context, snap['id'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_group_snapshots=1)
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value)

    def test_delete_share_group_snapshot(self):
        share_group = fake_share_group('fake_id', host="fake_host")
        sg_snap = fake_share_group_snapshot(
            'fake_groupsnap_id', share_group_id='fake_id',
            status=constants.STATUS_AVAILABLE)
        self.mock_object(db_driver, 'share_group_get',
                         mock.Mock(return_value=share_group))
        self.mock_object(db_driver, 'share_group_snapshot_update')

        self.api.delete_share_group_snapshot(self.context, sg_snap)

        db_driver.share_group_get.assert_called_once_with(
            self.context, "fake_id")
        db_driver.share_group_snapshot_update.assert_called_once_with(
            self.context, sg_snap['id'], {'status': constants.STATUS_DELETING})
        self.share_rpcapi.delete_share_group_snapshot.assert_called_once_with(
            self.context, sg_snap, share_group['host'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_group_snapshots=-1,
            project_id=share_group['project_id'],
            user_id=share_group['user_id'])
        share_group_api.QUOTAS.commit.assert_called_once_with(
            self.context, share_group_api.QUOTAS.reserve.return_value,
            project_id=share_group['project_id'],
            user_id=share_group['user_id'])
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_delete_share_group_snapshot_fail_on_quota_reserve(self):
        share_group = fake_share_group('fake_id', host="fake_host")
        sg_snap = fake_share_group_snapshot(
            'fake_groupsnap_id', share_group_id='fake_id',
            status=constants.STATUS_AVAILABLE)
        self.mock_object(db_driver, 'share_group_get',
                         mock.Mock(return_value=share_group))
        self.mock_object(db_driver, 'share_group_snapshot_update')
        share_group_api.QUOTAS.reserve.side_effect = exception.OverQuota(
            'Failure')
        self.mock_object(share_group_api.LOG, 'exception')

        self.api.delete_share_group_snapshot(self.context, sg_snap)

        db_driver.share_group_get.assert_called_once_with(
            self.context, "fake_id")
        db_driver.share_group_snapshot_update.assert_called_once_with(
            self.context, sg_snap['id'], {'status': constants.STATUS_DELETING})
        self.share_rpcapi.delete_share_group_snapshot.assert_called_once_with(
            self.context, sg_snap, share_group['host'])
        share_group_api.QUOTAS.reserve.assert_called_once_with(
            self.context, share_group_snapshots=-1,
            project_id=share_group['project_id'],
            user_id=share_group['user_id'])
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()
        share_group_api.LOG.exception.assert_called_once_with(
            mock.ANY, mock.ANY)

    def test_delete_share_group_snapshot_group_does_not_exist(self):
        snap = fake_share_group_snapshot(
            'fake_groupsnap_id', share_group_id='fake_id')
        self.mock_object(
            db_driver, 'share_group_get',
            mock.Mock(side_effect=exception.ShareGroupNotFound(
                share_group_id='fake_id')))

        self.assertRaises(
            exception.ShareGroupNotFound,
            self.api.delete_share_group_snapshot, self.context, snap)

        db_driver.share_group_get.assert_called_once_with(
            self.context, "fake_id")
        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    def test_delete_share_group_snapshot_creating_status(self):
        snap = fake_share_group_snapshot(
            'fake_groupsnap_id', share_group_id='fake_id',
            status=constants.STATUS_CREATING)
        self.mock_object(db_driver, 'share_group_get')

        self.assertRaises(
            exception.InvalidShareGroupSnapshot,
            self.api.delete_share_group_snapshot, self.context, snap)

        db_driver.share_group_get.assert_called_once_with(
            self.context, snap['share_group_id'])
        share_group_api.QUOTAS.reserve.assert_not_called()
        share_group_api.QUOTAS.commit.assert_not_called()
        share_group_api.QUOTAS.rollback.assert_not_called()

    @ddt.data({}, {"name": "fake_name"})
    def test_update_share_group_snapshot_no_values(self, expected_values):
        snap = fake_share_group_snapshot(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        self.mock_object(
            db_driver, 'share_group_snapshot_update',
            mock.Mock(return_value=snap))

        self.api.update_share_group_snapshot(
            self.context, snap, expected_values)

        db_driver.share_group_snapshot_update.assert_called_once_with(
            self.context, snap['id'], expected_values)

    def test_share_group_snapshot_get(self):
        expected = fake_share_group_snapshot(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        self.mock_object(
            db_driver, 'share_group_snapshot_get',
            mock.Mock(return_value=expected))

        actual = self.api.get_share_group_snapshot(
            self.context, expected['id'])

        self.assertEqual(expected, actual)

    def test_share_group_snapshot_get_all_no_groups(self):
        self.mock_object(
            db_driver, 'share_group_snapshot_get_all',
            mock.Mock(return_value=[]))

        actual = self.api.get_all_share_group_snapshots(self.context)

        self.assertEqual([], actual)

    def test_share_group_snapshot_get_all(self):
        expected = [fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)]
        self.mock_object(
            db_driver, 'share_group_snapshot_get_all_by_project',
            mock.Mock(return_value=expected))

        actual = self.api.get_all_share_group_snapshots(
            self.context, detailed=True)

        self.assertEqual(expected, actual)

    def test_share_group_snapshot_get_all_all_tenants_not_admin(self):
        cxt = context.RequestContext(
            user_id=None, project_id=None, is_admin=False)
        expected = [fake_share_group(
            'fakeid', user_id=cxt.user_id, project_id=cxt.project_id,
            status=constants.STATUS_CREATING)]
        self.mock_object(
            db_driver, 'share_group_snapshot_get_all_by_project',
            mock.Mock(return_value=expected))

        actual = self.api.get_all_share_group_snapshots(
            cxt, search_opts={'all_tenants': True})

        self.assertEqual(expected, actual)

    def test_share_group_snapshot_get_all_all_tenants_as_admin(self):
        expected = [fake_share_group(
            'fakeid', user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)]
        self.mock_object(
            db_driver, 'share_group_snapshot_get_all',
            mock.Mock(return_value=expected))

        actual = self.api.get_all_share_group_snapshots(
            self.context, search_opts={'all_tenants': True})

        self.assertEqual(expected, actual)
        db_driver.share_group_snapshot_get_all.assert_called_once_with(
            self.context, detailed=True, filters={},
            sort_dir=None, sort_key=None)

    def test_get_all_share_group_snapshot_members(self):
        self.mock_object(
            db_driver, 'share_group_snapshot_members_get_all',
            mock.Mock(return_value=[]))

        self.api.get_all_share_group_snapshot_members(self.context, 'fake_id')

        db_driver.share_group_snapshot_members_get_all.assert_called_once_with(
            self.context, 'fake_id')
