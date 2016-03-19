# Copyright 2012 NetApp.  All rights reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
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
import uuid

import ddt
import mock
from oslo_config import cfg
from oslo_utils import timeutils

from manila.common import constants
from manila import context
from manila.data import rpcapi as data_rpc
from manila import db as db_api
from manila.db.sqlalchemy import models
from manila import exception
from manila import quota
from manila import share
from manila.share import api as share_api
from manila.share import rpcapi as share_rpc
from manila.share import share_types
from manila import test
from manila.tests import db_utils
from manila.tests import fake_share as fakes
from manila.tests import utils as test_utils
from manila import utils

CONF = cfg.CONF


def fake_share(id, **kwargs):
    share = {
        'id': id,
        'size': 1,
        'user_id': 'fakeuser',
        'project_id': 'fakeproject',
        'snapshot_id': None,
        'share_network_id': None,
        'share_type_id': None,
        'availability_zone': 'fakeaz',
        'status': 'fakestatus',
        'display_name': 'fakename',
        'metadata': None,
        'display_description': 'fakedesc',
        'share_proto': 'nfs',
        'export_location': 'fake_location',
        'host': 'fakehost',
        'is_public': False,
        'consistency_group_id': None,
        'scheduled_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        'launched_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        'terminated_at': datetime.datetime(1, 1, 1, 1, 1, 1)
    }
    share.update(kwargs)
    return share


def fake_snapshot(id, **kwargs):
    snapshot = {
        'id': id,
        'share_size': 1,
        'size': 1,
        'user_id': 'fakeuser',
        'project_id': 'fakeproject',
        'share_id': None,
        'availability_zone': 'fakeaz',
        'status': 'fakestatus',
        'display_name': 'fakename',
        'display_description': 'fakedesc',
        'share_proto': 'nfs',
        'progress': 'fakeprogress99%',
        'scheduled_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        'launched_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        'terminated_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        'share': {'host': 'fake_source_host'},
    }
    snapshot.update(kwargs)
    return snapshot


def fake_access(id, **kwargs):
    access = {
        'id': id,
        'share_id': 'fakeshareid',
        'access_type': 'fakeacctype',
        'access_to': 'fakeaccto',
        'access_level': 'rw',
        'state': 'fakeactive',
        'STATE_NEW': 'fakenew',
        'STATE_ACTIVE': 'fakeactive',
        'STATE_DELETING': 'fakedeleting',
        'STATE_DELETED': 'fakedeleted',
        'STATE_ERROR': 'fakeerror',
    }
    access.update(kwargs)
    return access


_FAKE_LIST_OF_ALL_SHARES = [
    {
        'name': 'foo',
        'status': constants.STATUS_AVAILABLE,
        'project_id': 'fake_pid_1',
        'share_server_id': 'fake_server_1',
    },
    {
        'name': 'bar',
        'status': constants.STATUS_ERROR,
        'project_id': 'fake_pid_2',
        'share_server_id': 'fake_server_2',
    },
    {
        'name': 'foo',
        'status': constants.STATUS_AVAILABLE,
        'project_id': 'fake_pid_2',
        'share_server_id': 'fake_server_3',
    },
    {
        'name': 'bar',
        'status': constants.STATUS_ERROR,
        'project_id': 'fake_pid_2',
        'share_server_id': 'fake_server_3',
    },
]


_FAKE_LIST_OF_ALL_SNAPSHOTS = [
    {
        'name': 'foo',
        'status': constants.STATUS_AVAILABLE,
        'project_id': 'fake_pid_1',
        'share_id': 'fake_server_1',
    },
    {
        'name': 'bar',
        'status': constants.STATUS_ERROR,
        'project_id': 'fake_pid_2',
        'share_id': 'fake_server_2',
    },
    {
        'name': 'foo',
        'status': constants.STATUS_AVAILABLE,
        'project_id': 'fake_pid_2',
        'share_id': 'fake_share_id_3',
    },
    {
        'name': 'bar',
        'status': constants.STATUS_ERROR,
        'project_id': 'fake_pid_2',
        'share_id': 'fake_share_id_3',
    },
]


@ddt.ddt
class ShareAPITestCase(test.TestCase):

    def setUp(self):
        super(ShareAPITestCase, self).setUp()
        self.context = context.get_admin_context()
        self.scheduler_rpcapi = mock.Mock()
        self.share_rpcapi = mock.Mock()
        self.api = share.API()
        self.mock_object(self.api, 'scheduler_rpcapi', self.scheduler_rpcapi)
        self.mock_object(self.api, 'share_rpcapi', self.share_rpcapi)
        self.mock_object(quota.QUOTAS, 'reserve',
                         lambda *args, **kwargs: None)

        self.dt_utc = datetime.datetime.utcnow()
        self.mock_object(timeutils, 'utcnow',
                         mock.Mock(return_value=self.dt_utc))
        self.mock_object(share_api.policy, 'check_policy')

    def _setup_create_mocks(self, protocol='nfs', **kwargs):
        share = db_utils.create_share(
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            share_type_id=kwargs.pop('share_type_id', 'fake'),
            **kwargs
        )
        share_data = {
            'share_proto': protocol,
            'size': 1,
            'display_name': 'fakename',
            'display_description': 'fakedesc',
            'availability_zone': 'fakeaz'
        }

        self.mock_object(db_api, 'share_create', mock.Mock(return_value=share))
        self.mock_object(self.api, 'create_instance')

        return share, share_data

    def _setup_create_instance_mocks(self):
        host = 'fake'
        share_type_id = "fake_share_type"
        share = db_utils.create_share(
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            create_share_instance=False,
            share_type_id=share_type_id,
        )
        share_instance = db_utils.create_share_instance(share_id=share['id'])
        share_type = {'fake': 'fake'}
        self.mock_object(db_api, 'share_instance_create',
                         mock.Mock(return_value=share_instance))
        self.mock_object(db_api, 'share_type_get',
                         mock.Mock(return_value=share_type))
        az_mock = mock.Mock()
        type(az_mock.return_value).id = mock.PropertyMock(
            return_value='fake_id')
        self.mock_object(db_api, 'availability_zone_get', az_mock)
        self.mock_object(self.api.share_rpcapi, 'create_share_instance')
        self.mock_object(self.api.scheduler_rpcapi, 'create_share_instance')

        return host, share, share_instance

    def _setup_create_from_snapshot_mocks(self, use_scheduler=True, host=None):
        CONF.set_default("use_scheduler_creating_share_from_snapshot",
                         use_scheduler)

        share_type = fakes.fake_share_type()

        original_share = db_utils.create_share(
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE,
            host=host if host else 'fake',
            size=1,
            share_type_id=share_type['id'],
        )
        snapshot = db_utils.create_snapshot(
            share_id=original_share['id'],
            status=constants.STATUS_AVAILABLE,
            size=1
        )

        share, share_data = self._setup_create_mocks(
            snapshot_id=snapshot['id'], share_type_id=share_type['id'])

        request_spec = {
            'share_properties': share.to_dict(),
            'share_proto': share['share_proto'],
            'share_id': share['id'],
            'share_type': None,
            'snapshot_id': share['snapshot_id'],
        }

        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value='reservation'))
        self.mock_object(quota.QUOTAS, 'commit')
        self.mock_object(
            share_types, 'get_share_type', mock.Mock(return_value=share_type))

        return snapshot, share, share_data, request_spec

    def _setup_delete_mocks(self, status, snapshots=None, **kwargs):
        if snapshots is None:
            snapshots = []
        share = db_utils.create_share(status=status, **kwargs)
        self.mock_object(db_api, 'share_delete')
        self.mock_object(db_api, 'share_server_update')
        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=snapshots))
        self.mock_object(self.api, 'delete_instance')
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value='reservation'))
        self.mock_object(quota.QUOTAS, 'commit')
        return share

    def _setup_delete_share_instance_mocks(self, **kwargs):
        share = db_utils.create_share(**kwargs)

        self.mock_object(db_api, 'share_instance_update',
                         mock.Mock(return_value=share.instance))
        self.mock_object(self.api.share_rpcapi, 'delete_share_instance')
        self.mock_object(db_api, 'share_server_update')

        return share.instance

    def test_get_all_admin_no_filters(self):
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=True)
        shares = self.api.get_all(ctx)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_1', filters={}, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[0], shares)

    def test_get_all_admin_filter_by_all_tenants(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=True)
        self.mock_object(db_api, 'share_get_all',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES))
        shares = self.api.get_all(ctx, {'all_tenants': 1})
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_api.share_get_all.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at', filters={})
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES, shares)

    def test_get_all_non_admin_filter_by_share_server(self):

        def fake_policy_checker(*args, **kwargs):
            if 'list_by_share_server_id' == args[2] and not args[0].is_admin:
                raise exception.NotAuthorized

        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        self.mock_object(share_api.policy, 'check_policy',
                         mock.Mock(side_effect=fake_policy_checker))
        self.assertRaises(
            exception.NotAuthorized,
            self.api.get_all,
            ctx,
            {'share_server_id': 'fake'},
        )
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
            mock.call(ctx, 'share', 'list_by_share_server_id'),
        ])

    def test_get_all_admin_filter_by_share_server_and_all_tenants(self):
        # NOTE(vponomaryov): if share_server_id provided, 'all_tenants' opt
        #                    should not make any influence.
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=True)
        self.mock_object(db_api, 'share_get_all_by_share_server',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[2:]))
        self.mock_object(db_api, 'share_get_all')
        self.mock_object(db_api, 'share_get_all_by_project')
        shares = self.api.get_all(
            ctx, {'share_server_id': 'fake_server_3', 'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
            mock.call(ctx, 'share', 'list_by_share_server_id'),
        ])
        db_api.share_get_all_by_share_server.assert_called_once_with(
            ctx, 'fake_server_3', sort_dir='desc', sort_key='created_at',
            filters={},
        )
        db_api.share_get_all_by_project.assert_has_calls([])
        db_api.share_get_all.assert_has_calls([])
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[2:], shares)

    def test_get_all_admin_filter_by_name(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'name': 'bar'})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1::2], shares)

    def test_get_all_admin_filter_by_name_and_all_tenants(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_api, 'share_get_all',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES))
        shares = self.api.get_all(ctx, {'name': 'foo', 'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at', filters={})
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[::2], shares)

    def test_get_all_admin_filter_by_status(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'status': constants.STATUS_AVAILABLE})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[2::4], shares)

    def test_get_all_admin_filter_by_status_and_all_tenants(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_api, 'share_get_all',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES))
        shares = self.api.get_all(
            ctx, {'status': constants.STATUS_ERROR, 'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at', filters={})
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1::2], shares)

    def test_get_all_non_admin_filter_by_all_tenants(self):
        # Expected share list only by project of non-admin user
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=False)
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1:], shares)

    def test_get_all_non_admin_with_name_and_status_filters(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=False)
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(
            ctx, {'name': 'bar', 'status': constants.STATUS_ERROR})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=False
        )

        # two items expected, one filtered
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1::2], shares)

        # one item expected, two filtered
        shares = self.api.get_all(
            ctx, {'name': 'foo', 'status': constants.STATUS_AVAILABLE})
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[2::4], shares)
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_has_calls([
            mock.call(ctx, sort_dir='desc', sort_key='created_at',
                      project_id='fake_pid_2', filters={}, is_public=False),
            mock.call(ctx, sort_dir='desc', sort_key='created_at',
                      project_id='fake_pid_2', filters={}, is_public=False),
        ])

    @ddt.data('True', 'true', '1', 'yes', 'y', 'on', 't', True)
    def test_get_all_non_admin_public(self, is_public):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2',
                                     is_admin=False)
        self.mock_object(db_api, 'share_get_all_by_project', mock.Mock(
            return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'is_public': is_public})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=True
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1:], shares)

    @ddt.data('False', 'false', '0', 'no', 'n', 'off', 'f', False)
    def test_get_all_non_admin_not_public(self, is_public):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2',
                                     is_admin=False)
        self.mock_object(db_api, 'share_get_all_by_project', mock.Mock(
            return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'is_public': is_public})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1:], shares)

    @ddt.data('truefoo', 'bartrue')
    def test_get_all_invalid_public_value(self, is_public):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2',
                                     is_admin=False)
        self.assertRaises(ValueError, self.api.get_all,
                          ctx, {'is_public': is_public})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])

    def test_get_all_with_sorting_valid(self):
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        shares = self.api.get_all(ctx, sort_key='status', sort_dir='asc')
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='asc', sort_key='status',
            project_id='fake_pid_1', filters={}, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[0], shares)

    def test_get_all_sort_key_invalid(self):
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        self.assertRaises(
            exception.InvalidInput,
            self.api.get_all,
            ctx,
            sort_key=1,
        )
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')

    def test_get_all_sort_dir_invalid(self):
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        self.assertRaises(
            exception.InvalidInput,
            self.api.get_all,
            ctx,
            sort_dir=1,
        )
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')

    def _get_all_filter_metadata_or_extra_specs_valid(self, key):
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        search_opts = {key: {'foo1': 'bar1', 'foo2': 'bar2'}}
        shares = self.api.get_all(ctx, search_opts=search_opts.copy())
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_1', filters=search_opts, is_public=False)
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[0], shares)

    def test_get_all_filter_by_metadata(self):
        self._get_all_filter_metadata_or_extra_specs_valid(key='metadata')

    def test_get_all_filter_by_extra_specs(self):
        self._get_all_filter_metadata_or_extra_specs_valid(key='extra_specs')

    def _get_all_filter_metadata_or_extra_specs_invalid(self, key):
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        search_opts = {key: "{'foo': 'bar'}"}
        self.assertRaises(exception.InvalidInput, self.api.get_all, ctx,
                          search_opts=search_opts)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')

    def test_get_all_filter_by_invalid_metadata(self):
        self._get_all_filter_metadata_or_extra_specs_invalid(key='metadata')

    def test_get_all_filter_by_invalid_extra_specs(self):
        self._get_all_filter_metadata_or_extra_specs_invalid(key='extra_specs')

    @ddt.data(True, False)
    def test_create_public_and_private_share(self, is_public):
        share, share_data = self._setup_create_mocks(is_public=is_public)
        az = share_data.pop('availability_zone')

        self.api.create(
            self.context,
            share_data['share_proto'],
            share_data['size'],
            share_data['display_name'],
            share_data['display_description'],
            availability_zone=az
        )

        share['status'] = constants.STATUS_CREATING
        share['host'] = None

        self.assertSubDictMatch(share_data,
                                db_api.share_create.call_args[0][1])

    @ddt.data('', 'fake', 'Truebar', 'Bartrue')
    def test_create_share_with_invalid_is_public_value(self, is_public):
        self.assertRaises(exception.InvalidParameterValue,
                          self.api.create, self.context, 'nfs', '1',
                          'fakename', 'fakedesc', is_public=is_public)

    @ddt.data(*constants.SUPPORTED_SHARE_PROTOCOLS)
    def test_create_share_valid_protocol(self, proto):
        share, share_data = self._setup_create_mocks(protocol=proto)
        az = share_data.pop('availability_zone')

        all_protos = ','.join(
            proto for proto in constants.SUPPORTED_SHARE_PROTOCOLS)
        data = dict(DEFAULT=dict(enabled_share_protocols=all_protos))
        with test_utils.create_temp_config_with_opts(data):
            self.api.create(
                self.context, proto, share_data['size'],
                share_data['display_name'],
                share_data['display_description'],
                availability_zone=az)

        share['status'] = constants.STATUS_CREATING
        share['host'] = None

        self.assertSubDictMatch(share_data,
                                db_api.share_create.call_args[0][1])

    @ddt.data(
        None, '', 'fake', 'nfsfake', 'cifsfake', 'glusterfsfake', 'hdfsfake')
    def test_create_share_invalid_protocol(self, proto):
        share, share_data = self._setup_create_mocks(protocol=proto)

        all_protos = ','.join(
            proto for proto in constants.SUPPORTED_SHARE_PROTOCOLS)
        data = dict(DEFAULT=dict(enabled_share_protocols=all_protos))
        with test_utils.create_temp_config_with_opts(data):
            self.assertRaises(
                exception.InvalidInput,
                self.api.create,
                self.context, proto, share_data['size'],
                share_data['display_name'],
                share_data['display_description'])

    @ddt.data({'overs': {'gigabytes': 'fake'},
               'expected_exception': exception.ShareSizeExceedsAvailableQuota},
              {'overs': {'shares': 'fake'},
               'expected_exception': exception.ShareLimitExceeded})
    @ddt.unpack
    def test_create_share_over_quota(self, overs, expected_exception):
        share, share_data = self._setup_create_mocks()

        usages = {'gigabytes': {'reserved': 5, 'in_use': 5},
                  'shares': {'reserved': 10, 'in_use': 10}}
        quotas = {'gigabytes': 5, 'shares': 10}
        exc = exception.OverQuota(overs=overs, usages=usages, quotas=quotas)
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(side_effect=exc))

        self.assertRaises(
            expected_exception,
            self.api.create,
            self.context,
            share_data['share_proto'],
            share_data['size'],
            share_data['display_name'],
            share_data['display_description']
        )
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, shares=1, gigabytes=share_data['size'])

    @ddt.data(exception.QuotaError, exception.InvalidShare)
    def test_create_share_error_on_quota_commit(self, expected_exception):
        share, share_data = self._setup_create_mocks()
        reservation = 'fake'
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value=reservation))
        self.mock_object(quota.QUOTAS, 'commit',
                         mock.Mock(side_effect=expected_exception('fake')))
        self.mock_object(quota.QUOTAS, 'rollback')
        self.mock_object(db_api, 'share_delete')

        self.assertRaises(
            expected_exception,
            self.api.create,
            self.context,
            share_data['share_proto'],
            share_data['size'],
            share_data['display_name'],
            share_data['display_description']
        )

        quota.QUOTAS.rollback.assert_called_once_with(self.context,
                                                      reservation)
        db_api.share_delete.assert_called_once_with(self.context, share['id'])

    def test_create_share_instance_with_host_and_az(self):
        host, share, share_instance = self._setup_create_instance_mocks()

        self.api.create_instance(self.context, share, host=host,
                                 availability_zone='fake')

        db_api.share_instance_create.assert_called_once_with(
            self.context, share['id'],
            {
                'share_network_id': None,
                'status': constants.STATUS_CREATING,
                'scheduled_at': self.dt_utc,
                'host': host,
                'availability_zone_id': 'fake_id',
            }
        )
        db_api.share_type_get.assert_called_once_with(self.context,
                                                      share['share_type_id'])
        self.api.share_rpcapi.create_share_instance.assert_called_once_with(
            self.context,
            share_instance,
            host,
            request_spec=mock.ANY,
            filter_properties={},
            snapshot_id=share['snapshot_id'],
        )
        self.assertFalse(
            self.api.scheduler_rpcapi.create_share_instance.called)

    def test_create_share_instance_without_host(self):
        _, share, share_instance = self._setup_create_instance_mocks()

        self.api.create_instance(self.context, share)

        self.api.scheduler_rpcapi.create_share_instance.\
            assert_called_once_with(
                self.context, request_spec=mock.ANY, filter_properties={})
        self.assertFalse(self.api.share_rpcapi.create_share_instance.called)

    @ddt.data('no_valid_host', None)
    def test_manage_new(self, exc):
        share_data = {
            'host': 'fake',
            'export_location': 'fake',
            'share_proto': 'fake',
            'share_type_id': 'fake',
        }
        driver_options = {}
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        fake_share_data = {
            'id': 'fakeid',
            'status': constants.STATUS_CREATING,
        }
        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
            },
        }

        share = db_api.share_create(self.context, fake_share_data)

        if exc:
            self.mock_object(self.scheduler_rpcapi, 'manage_share',
                             mock.Mock(side_effect=exception.NoValidHost))
        self.mock_object(db_api, 'share_create',
                         mock.Mock(return_value=share))
        self.mock_object(db_api, 'share_export_locations_update')
        self.mock_object(db_api, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))
        self.mock_object(self.api, 'get_all', mock.Mock(return_value=[]))

        if exc:
            self.assertRaises(exception.InvalidHost, self.api.manage,
                              self.context, copy.deepcopy(share_data),
                              driver_options)
        else:
            self.api.manage(self.context,
                            copy.deepcopy(share_data),
                            driver_options)

        share_data.update({
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_MANAGING,
            'scheduled_at': date,
            'snapshot_support': fake_type['extra_specs']['snapshot_support'],
        })

        expected_request_spec = self._get_request_spec_dict(
            share, fake_type, size=0)

        export_location = share_data.pop('export_location')
        self.api.get_all.assert_called_once_with(self.context, mock.ANY)
        db_api.share_create.assert_called_once_with(self.context, share_data)
        if not exc:
            db_api.share_get.assert_called_once_with(self.context, share['id'])
        db_api.share_export_locations_update.assert_called_once_with(
            self.context, share.instance['id'], export_location
        )
        self.scheduler_rpcapi.manage_share.assert_called_once_with(
            self.context, share['id'], driver_options, expected_request_spec)

    @ddt.data([{'id': 'fake', 'status': constants.STATUS_MANAGE_ERROR}])
    def test_manage_retry(self, shares):
        share_data = {
            'host': 'fake',
            'export_location': 'fake',
            'share_proto': 'fake',
            'share_type_id': 'fake',
        }
        driver_options = {}
        fake_share_data = {'id': 'fakeid'}
        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
            },
        }

        share = db_api.share_create(self.context, fake_share_data)
        self.mock_object(db_api, 'share_update',
                         mock.Mock(return_value=share))
        self.mock_object(db_api, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))

        self.mock_object(db_api, 'share_export_locations_update')
        self.mock_object(self.api, 'get_all',
                         mock.Mock(return_value=shares))

        self.api.manage(self.context,
                        copy.deepcopy(share_data),
                        driver_options)

        expected_request_spec = self._get_request_spec_dict(
            share, fake_type, size=0)

        db_api.share_update.assert_called_once_with(
            self.context, 'fake', mock.ANY)
        self.scheduler_rpcapi.manage_share.assert_called_once_with(
            self.context, share['id'], driver_options, expected_request_spec)
        db_api.share_export_locations_update.assert_called_once_with(
            self.context, share.instance['id'], mock.ANY
        )

    def test_manage_duplicate(self):
        share_data = {
            'host': 'fake',
            'export_location': 'fake',
            'share_proto': 'fake',
            'share_type_id': 'fake',
        }
        driver_options = {}
        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
            },
        }

        self.mock_object(self.api, 'get_all',
                         mock.Mock(return_value=['fake', 'fake2']))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))

        self.assertRaises(exception.ManilaException, self.api.manage,
                          self.context, share_data, driver_options)

    def _get_request_spec_dict(self, share, share_type, **kwargs):
        share_instance = share['instance']

        share_properties = {
            'size': kwargs.get('size', share['size']),
            'user_id': kwargs.get('user_id', share['user_id']),
            'project_id': kwargs.get('project_id', share['project_id']),
            'snapshot_support': kwargs.get(
                'snapshot_support',
                share_type['extra_specs']['snapshot_support']),
            'share_proto': kwargs.get('share_proto', share['share_proto']),
            'share_type_id': kwargs.get('share_type_id',
                                        share['share_type_id']),
            'is_public': kwargs.get('is_public', share['is_public']),
            'consistency_group_id': kwargs.get('consistency_group_id',
                                               share['consistency_group_id']),
            'source_cgsnapshot_member_id': kwargs.get(
                'source_cgsnapshot_member_id',
                share['source_cgsnapshot_member_id']),
            'snapshot_id': kwargs.get('snapshot_id', share['snapshot_id']),
        }
        share_instance_properties = {
            'availability_zone_id': kwargs.get(
                'availability_zone_id',
                share_instance['availability_zone_id']),
            'share_network_id': kwargs.get('share_network_id',
                                           share_instance['share_network_id']),
            'share_server_id': kwargs.get('share_server_id',
                                          share_instance['share_server_id']),
            'share_id': kwargs.get('share_id', share_instance['share_id']),
            'host': kwargs.get('host', share_instance['host']),
            'status': kwargs.get('status', share_instance['status']),
        }
        request_spec = {
            'share_properties': share_properties,
            'share_instance_properties': share_instance_properties,
            'share_type': share_type,
            'share_id': share['id']
        }
        return request_spec

    def test_unmanage(self):

        share = db_utils.create_share(
            id='fakeid',
            host='fake',
            size='1',
            status=constants.STATUS_AVAILABLE,
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            task_state=None)

        self.mock_object(db_api, 'share_update', mock.Mock())

        self.api.unmanage(self.context, share)

        self.share_rpcapi.unmanage_share.assert_called_once_with(
            self.context, mock.ANY)
        db_api.share_update.assert_called_once_with(
            mock.ANY, share['id'], mock.ANY)

    def test_unmanage_task_state_busy(self):

        share = db_utils.create_share(
            id='fakeid',
            host='fake',
            size='1',
            status=constants.STATUS_AVAILABLE,
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            task_state=constants.TASK_STATE_MIGRATION_IN_PROGRESS)

        self.assertRaises(exception.ShareBusyException, self.api.unmanage,
                          self.context, share)

    @mock.patch.object(quota.QUOTAS, 'reserve',
                       mock.Mock(return_value='reservation'))
    @mock.patch.object(quota.QUOTAS, 'commit', mock.Mock())
    def test_create_snapshot(self):
        snapshot = db_utils.create_snapshot(
            with_share=True, status=constants.STATUS_CREATING, size=1)
        share = snapshot['share']

        fake_name = 'fakename'
        fake_desc = 'fakedesc'
        options = {
            'share_id': share['id'],
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_CREATING,
            'progress': '0%',
            'share_size': share['size'],
            'size': 1,
            'display_name': fake_name,
            'display_description': fake_desc,
            'share_proto': share['share_proto'],
        }
        with mock.patch.object(db_api, 'share_snapshot_create',
                               mock.Mock(return_value=snapshot)):
            self.api.create_snapshot(self.context, share, fake_name,
                                     fake_desc)
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'create_snapshot', share)
            quota.QUOTAS.reserve.assert_called_once_with(
                self.context, snapshots=1, snapshot_gigabytes=1)
            quota.QUOTAS.commit.assert_called_once_with(
                self.context, 'reservation')
            db_api.share_snapshot_create.assert_called_once_with(
                self.context, options)

    def test_create_snapshot_for_replicated_share(self):
        share = fakes.fake_share(
            has_replicas=True, status=constants.STATUS_AVAILABLE)
        snapshot = fakes.fake_snapshot(
            create_instance=True, share_instance_id='id2')
        replicas = [
            fakes.fake_replica(
                id='id1', replica_state=constants.REPLICA_STATE_ACTIVE),
            fakes.fake_replica(
                id='id2', replica_state=constants.REPLICA_STATE_IN_SYNC)
        ]
        self.mock_object(share_api.policy, 'check_policy')
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value='reservation'))
        self.mock_object(
            db_api, 'share_snapshot_create', mock.Mock(return_value=snapshot))
        self.mock_object(db_api, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas))
        self.mock_object(
            db_api, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(quota.QUOTAS, 'commit')
        mock_instance_create_call = self.mock_object(
            db_api, 'share_snapshot_instance_create')
        mock_snapshot_rpc_call = self.mock_object(
            self.share_rpcapi, 'create_snapshot')
        mock_replicated_snapshot_rpc_call = self.mock_object(
            self.share_rpcapi, 'create_replicated_snapshot')
        snapshot_instance_args = {
            'status': constants.STATUS_CREATING,
            'progress': '0%',
            'share_instance_id': 'id1',
        }

        retval = self.api.create_snapshot(
            self.context, share, 'fake_name', 'fake_description')

        self.assertEqual(snapshot['id'], retval['id'])
        mock_instance_create_call.assert_called_once_with(
            self.context, snapshot['id'], snapshot_instance_args)
        self.assertFalse(mock_snapshot_rpc_call.called)
        self.assertTrue(mock_replicated_snapshot_rpc_call.called)

    @mock.patch.object(db_api, 'share_instances_get_all_by_share_server',
                       mock.Mock(return_value=[]))
    @mock.patch.object(db_api, 'consistency_group_get_all_by_share_server',
                       mock.Mock(return_value=[]))
    def test_delete_share_server_no_dependent_shares(self):
        server = {'id': 'fake_share_server_id'}
        server_returned = {
            'id': 'fake_share_server_id',
        }
        self.mock_object(db_api, 'share_server_update',
                         mock.Mock(return_value=server_returned))
        self.api.delete_share_server(self.context, server)
        db_api.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, server['id'])
        db_api.consistency_group_get_all_by_share_server.\
            assert_called_once_with(self.context, server['id'])
        self.share_rpcapi.delete_share_server.assert_called_once_with(
            self.context, server_returned)

    @mock.patch.object(db_api, 'share_instances_get_all_by_share_server',
                       mock.Mock(return_value=['fake_share', ]))
    @mock.patch.object(db_api, 'consistency_group_get_all_by_share_server',
                       mock.Mock(return_value=[]))
    def test_delete_share_server_dependent_share_exists(self):
        server = {'id': 'fake_share_server_id'}
        self.assertRaises(exception.ShareServerInUse,
                          self.api.delete_share_server,
                          self.context,
                          server)
        db_api.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, server['id'])

    @mock.patch.object(db_api, 'share_instances_get_all_by_share_server',
                       mock.Mock(return_value=[]))
    @mock.patch.object(db_api, 'consistency_group_get_all_by_share_server',
                       mock.Mock(return_value=['fake_cg', ]))
    def test_delete_share_server_dependent_cg_exists(self):
        server = {'id': 'fake_share_server_id'}
        self.assertRaises(exception.ShareServerInUse,
                          self.api.delete_share_server,
                          self.context,
                          server)

        db_api.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, server['id'])
        db_api.consistency_group_get_all_by_share_server.\
            assert_called_once_with(self.context, server['id'])

    @mock.patch.object(db_api, 'share_snapshot_instance_update', mock.Mock())
    def test_delete_snapshot(self):
        snapshot = db_utils.create_snapshot(
            with_share=True, status=constants.STATUS_AVAILABLE)
        share = snapshot['share']

        with mock.patch.object(db_api, 'share_get',
                               mock.Mock(return_value=share)):
            self.api.delete_snapshot(self.context, snapshot)
            self.share_rpcapi.delete_snapshot.assert_called_once_with(
                self.context, snapshot, share['host'])
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'delete_snapshot', snapshot)
            db_api.share_snapshot_instance_update.assert_called_once_with(
                self.context,
                snapshot['instance']['id'],
                {'status': constants.STATUS_DELETING})
            db_api.share_get.assert_called_once_with(
                self.context, snapshot['share_id'])

    def test_delete_snapshot_wrong_status(self):
        snapshot = db_utils.create_snapshot(
            with_share=True, status=constants.STATUS_CREATING)

        self.assertRaises(exception.InvalidShareSnapshot,
                          self.api.delete_snapshot,
                          self.context,
                          snapshot)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'delete_snapshot', snapshot)

    @ddt.data(True, False)
    def test_delete_snapshot_replicated_snapshot(self, force):
        share = fakes.fake_share(has_replicas=True)
        snapshot = fakes.fake_snapshot(
            create_instance=True, share_id=share['id'],
            status=constants.STATUS_ERROR)
        snapshot_instance = fakes.fake_snapshot_instance(
            base_snapshot=snapshot)
        expected_update_calls = [
            mock.call(self.context, x, {'status': constants.STATUS_DELETING})
            for x in (snapshot['instance']['id'], snapshot_instance['id'])
        ]
        self.mock_object(db_api, 'share_get', mock.Mock(return_value=share))
        self.mock_object(
            db_api, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=[snapshot['instance'], snapshot_instance]))
        mock_db_update_call = self.mock_object(
            db_api, 'share_snapshot_instance_update')
        mock_snapshot_rpc_call = self.mock_object(
            self.share_rpcapi, 'delete_snapshot')
        mock_replicated_snapshot_rpc_call = self.mock_object(
            self.share_rpcapi, 'delete_replicated_snapshot')

        retval = self.api.delete_snapshot(self.context, snapshot, force=force)

        self.assertIsNone(retval)
        self.assertEqual(2, mock_db_update_call.call_count)
        mock_db_update_call.assert_has_calls(expected_update_calls)
        mock_replicated_snapshot_rpc_call.assert_called_once_with(
            self.context, snapshot, share['instance']['host'],
            share_id=share['id'], force=force)
        self.assertFalse(mock_snapshot_rpc_call.called)

    def test_create_snapshot_if_share_not_available(self):
        share = db_utils.create_share(status=constants.STATUS_ERROR)
        self.assertRaises(exception.InvalidShare,
                          self.api.create_snapshot,
                          self.context,
                          share,
                          'fakename',
                          'fakedesc')
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'create_snapshot', share)

    def test_create_snapshot_invalid_task_state(self):
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            task_state=constants.TASK_STATE_MIGRATION_IN_PROGRESS)
        self.assertRaises(exception.ShareBusyException,
                          self.api.create_snapshot,
                          self.context,
                          share,
                          'fakename',
                          'fakedesc')
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'create_snapshot', share)

    @ddt.data({'use_scheduler': False, 'valid_host': 'fake'},
              {'use_scheduler': True, 'valid_host': None})
    @ddt.unpack
    def test_create_from_snapshot(self, use_scheduler, valid_host):
        snapshot, share, share_data, request_spec = (
            self._setup_create_from_snapshot_mocks(
                use_scheduler=use_scheduler, host=valid_host)
        )
        share_type = fakes.fake_share_type()

        mock_get_share_type_call = self.mock_object(
            share_types, 'get_share_type', mock.Mock(return_value=share_type))
        az = share_data.pop('availability_zone')

        self.api.create(
            self.context,
            share_data['share_proto'],
            None,  # NOTE(u_glide): Get share size from snapshot
            share_data['display_name'],
            share_data['display_description'],
            snapshot_id=snapshot['id'],
            availability_zone=az
        )

        mock_get_share_type_call.assert_called_once_with(
            self.context, share['share_type_id'])
        self.assertSubDictMatch(share_data,
                                db_api.share_create.call_args[0][1])
        self.api.create_instance.assert_called_once_with(
            self.context, share, share_network_id=share['share_network_id'],
            host=valid_host,
            availability_zone=snapshot['share']['availability_zone'],
            consistency_group=None, cgsnapshot_member=None)
        share_api.policy.check_policy.assert_has_calls([
            mock.call(self.context, 'share', 'create'),
            mock.call(self.context, 'share_snapshot', 'get_snapshot')])
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, gigabytes=1, shares=1)
        quota.QUOTAS.commit.assert_called_once_with(
            self.context, 'reservation')

    def test_create_from_snapshot_with_different_share_type(self):
        snapshot, share, share_data, request_spec = (
            self._setup_create_from_snapshot_mocks()
        )

        share_type = {'id': 'super_fake_share_type'}

        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, share_data['share_proto'],
                          share_data['size'],
                          share_data['display_name'],
                          share_data['display_description'],
                          snapshot_id=snapshot['id'],
                          availability_zone=share_data['availability_zone'],
                          share_type=share_type)

    def test_get_snapshot(self):
        fake_get_snap = {'fake_key': 'fake_val'}
        with mock.patch.object(db_api, 'share_snapshot_get',
                               mock.Mock(return_value=fake_get_snap)):
            rule = self.api.get_snapshot(self.context, 'fakeid')
            self.assertEqual(fake_get_snap, rule)
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share_snapshot', 'get_snapshot')
            db_api.share_snapshot_get.assert_called_once_with(
                self.context, 'fakeid')

    def test_create_from_snapshot_not_available(self):
        snapshot = db_utils.create_snapshot(
            with_share=True, status=constants.STATUS_ERROR)
        self.assertRaises(exception.InvalidShareSnapshot, self.api.create,
                          self.context, 'nfs', '1', 'fakename',
                          'fakedesc', snapshot_id=snapshot['id'],
                          availability_zone='fakeaz')

    def test_create_from_snapshot_larger_size(self):
        snapshot = db_utils.create_snapshot(
            size=100, status=constants.STATUS_AVAILABLE, with_share=True)
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 1, 'fakename', 'fakedesc',
                          availability_zone='fakeaz',
                          snapshot_id=snapshot['id'])

    def test_create_share_wrong_size_0(self):
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 0, 'fakename', 'fakedesc',
                          availability_zone='fakeaz')

    def test_create_share_wrong_size_some(self):
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 'some', 'fakename',
                          'fakedesc', availability_zone='fakeaz')

    @ddt.data(constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
    def test_delete(self, status):
        share = self._setup_delete_mocks(status)

        self.api.delete(self.context, share)

        self.api.delete_instance.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            utils.IsAMatcher(models.ShareInstance), force=False
        )
        db_api.share_snapshot_get_all_for_share.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share['id'])

    def test_delete_quota_with_different_user(self):
        share = self._setup_delete_mocks(constants.STATUS_AVAILABLE)
        diff_user_context = context.RequestContext(
            user_id='fake2',
            project_id='fake',
            is_admin=False
        )

        self.api.delete(diff_user_context, share)

        quota.QUOTAS.reserve.assert_called_once_with(
            diff_user_context,
            project_id=share['project_id'],
            shares=-1,
            gigabytes=-share['size'],
            user_id=share['user_id']
        )
        quota.QUOTAS.commit.assert_called_once_with(
            diff_user_context,
            mock.ANY,
            project_id=share['project_id'],
            user_id=share['user_id']
        )

    def test_delete_wrong_status(self):
        share = fake_share('fakeid')
        self.mock_object(db_api, 'share_get', mock.Mock(return_value=share))
        self.assertRaises(exception.InvalidShare, self.api.delete,
                          self.context, share)

    def test_delete_share_has_replicas(self):
        share = self._setup_delete_mocks(constants.STATUS_AVAILABLE,
                                         replication_type='writable')
        db_utils.create_share_replica(share_id=share['id'],
                                      replica_state='in_sync')
        db_utils.create_share_replica(share_id=share['id'],
                                      replica_state='out_of_sync')

        self.assertRaises(exception.Conflict, self.api.delete,
                          self.context, share)

    @mock.patch.object(db_api, 'count_cgsnapshot_members_in_share',
                       mock.Mock(return_value=2))
    def test_delete_dependent_cgsnapshot_members(self):
        share_server_id = 'fake-ss-id'
        share = self._setup_delete_mocks(constants.STATUS_AVAILABLE,
                                         share_server_id)

        self.assertRaises(exception.InvalidShare, self.api.delete,
                          self.context, share)

    @mock.patch.object(db_api, 'share_instance_delete', mock.Mock())
    def test_delete_no_host(self):
        share = self._setup_delete_mocks(constants.STATUS_AVAILABLE, host=None)

        self.api.delete(self.context, share)
        db_api.share_instance_delete.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share.instance['id'])

    def test_delete_share_with_snapshots(self):
        share = self._setup_delete_mocks(constants.STATUS_AVAILABLE,
                                         snapshots=['fake'])

        self.assertRaises(
            exception.InvalidShare,
            self.api.delete,
            self.context,
            share
        )

    def test_delete_share_invalid_task_state(self):
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            task_state=constants.TASK_STATE_MIGRATION_IN_PROGRESS)

        self.assertRaises(exception.ShareBusyException,
                          self.api.delete,
                          self.context, share)

    def test_delete_share_quota_error(self):
        share = self._setup_delete_mocks(constants.STATUS_AVAILABLE)
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=exception.QuotaError('fake')))

        self.api.delete(self.context, share)

        quota.QUOTAS.reserve.assert_called_once_with(
            self.context,
            project_id=share['project_id'],
            shares=-1,
            gigabytes=-share['size'],
            user_id=share['user_id']
        )
        self.assertFalse(quota.QUOTAS.commit.called)

    @ddt.data({'status': constants.STATUS_AVAILABLE, 'force': False},
              {'status': constants.STATUS_ERROR, 'force': True})
    @ddt.unpack
    def test_delete_share_instance(self, status, force):
        instance = self._setup_delete_share_instance_mocks(
            status=status, share_server_id='fake')

        self.api.delete_instance(self.context, instance, force=force)

        db_api.share_instance_update.assert_called_once_with(
            self.context,
            instance['id'],
            {'status': constants.STATUS_DELETING,
             'terminated_at': self.dt_utc}
        )
        self.api.share_rpcapi.delete_share_instance.assert_called_once_with(
            self.context, instance, force=force
        )
        db_api.share_server_update(
            self.context,
            instance['share_server_id'],
            {'updated_at': self.dt_utc}
        )

    def test_delete_share_instance_invalid_status(self):
        instance = self._setup_delete_share_instance_mocks(
            status=constants.STATUS_CREATING, share_server_id='fake')

        self.assertRaises(
            exception.InvalidShareInstance,
            self.api.delete_instance,
            self.context,
            instance
        )

    @ddt.data('', 'fake', 'Truebar', 'Bartrue')
    def test_update_share_with_invalid_is_public_value(self, is_public):
        self.assertRaises(exception.InvalidParameterValue,
                          self.api.update, self.context, 'fakeid',
                          {'is_public': is_public})

    def test_get(self):
        share = db_utils.create_share()
        with mock.patch.object(db_api, 'share_get',
                               mock.Mock(return_value=share)):
            result = self.api.get(self.context, 'fakeid')
            self.assertEqual(share, result)
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'get', share)
            db_api.share_get.assert_called_once_with(
                self.context, 'fakeid')

    @mock.patch.object(db_api, 'share_snapshot_get_all_by_project',
                       mock.Mock())
    def test_get_all_snapshots_admin_not_all_tenants(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=True)
        self.api.get_all_snapshots(ctx)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', sort_dir='desc', sort_key='share_id', filters={})

    @mock.patch.object(db_api, 'share_snapshot_get_all', mock.Mock())
    def test_get_all_snapshots_admin_all_tenants(self):
        self.api.get_all_snapshots(self.context,
                                   search_opts={'all_tenants': 1})
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all.assert_called_once_with(
            self.context, sort_dir='desc', sort_key='share_id', filters={})

    @mock.patch.object(db_api, 'share_snapshot_get_all_by_project',
                       mock.Mock())
    def test_get_all_snapshots_not_admin(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=False)
        self.api.get_all_snapshots(ctx)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', sort_dir='desc', sort_key='share_id', filters={})

    def test_get_all_snapshots_not_admin_search_opts(self):
        search_opts = {'size': 'fakesize'}
        fake_objs = [{'name': 'fakename1'}, search_opts]
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=False)
        self.mock_object(db_api, 'share_snapshot_get_all_by_project',
                         mock.Mock(return_value=fake_objs))

        result = self.api.get_all_snapshots(ctx, search_opts)

        self.assertEqual([search_opts], result)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', sort_dir='desc', sort_key='share_id',
            filters=search_opts)

    def test_get_all_snapshots_with_sorting_valid(self):
        self.mock_object(
            db_api, 'share_snapshot_get_all_by_project',
            mock.Mock(return_value=_FAKE_LIST_OF_ALL_SNAPSHOTS[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        snapshots = self.api.get_all_snapshots(
            ctx, sort_key='status', sort_dir='asc')
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fake_pid_1', sort_dir='asc', sort_key='status', filters={})
        self.assertEqual(_FAKE_LIST_OF_ALL_SNAPSHOTS[0], snapshots)

    def test_get_all_snapshots_sort_key_invalid(self):
        self.mock_object(
            db_api, 'share_snapshot_get_all_by_project',
            mock.Mock(return_value=_FAKE_LIST_OF_ALL_SNAPSHOTS[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        self.assertRaises(
            exception.InvalidInput,
            self.api.get_all_snapshots,
            ctx,
            sort_key=1,
        )
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')

    def test_get_all_snapshots_sort_dir_invalid(self):
        self.mock_object(
            db_api, 'share_snapshot_get_all_by_project',
            mock.Mock(return_value=_FAKE_LIST_OF_ALL_SNAPSHOTS[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        self.assertRaises(
            exception.InvalidInput,
            self.api.get_all_snapshots,
            ctx,
            sort_dir=1,
        )
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')

    @ddt.data(None, 'rw', 'ro')
    def test_allow_access(self, level):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        values = {
            'share_id': share['id'],
            'access_type': 'fake_access_type',
            'access_to': 'fake_access_to',
            'access_level': level,
        }
        fake_access_expected = copy.deepcopy(values)
        fake_access_expected.update({
            'id': 'fake_access_id',
            'state': constants.STATUS_ACTIVE,
        })
        fake_access = copy.deepcopy(fake_access_expected)
        fake_access.update({
            'deleted': 'fake_deleted',
            'deleted_at': 'fake_deleted_at',
            'instance_mappings': ['foo', 'bar'],
        })
        self.mock_object(db_api, 'share_access_create',
                         mock.Mock(return_value=fake_access))
        self.mock_object(db_api, 'share_access_get',
                         mock.Mock(return_value=fake_access))

        access = self.api.allow_access(
            self.context, share, fake_access['access_type'],
            fake_access['access_to'], level)

        self.assertEqual(fake_access_expected, access)
        self.share_rpcapi.allow_access.assert_called_once_with(
            self.context, utils.IsAMatcher(models.ShareInstance),
            fake_access)
        db_api.share_access_create.assert_called_once_with(
            self.context, values)
        share_api.policy.check_policy.assert_called_with(
            self.context, 'share', 'allow_access')

    def test_allow_access_existent_access(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        fake_access = db_utils.create_access(share_id=share['id'])

        self.assertRaises(exception.ShareAccessExists, self.api.allow_access,
                          self.context, share, fake_access['access_type'],
                          fake_access['access_to'], fake_access['access_level']
                          )

    def test_allow_access_invalid_access_level(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        self.assertRaises(exception.InvalidShareAccess, self.api.allow_access,
                          self.context, share, 'fakeacctype', 'fakeaccto',
                          'ab')

    def test_allow_access_status_not_available(self):
        share = db_utils.create_share(status=constants.STATUS_ERROR)
        self.assertRaises(exception.InvalidShare, self.api.allow_access,
                          self.context, share, 'fakeacctype', 'fakeaccto')

    def test_allow_access_no_host(self):
        share = db_utils.create_share(host=None)
        self.assertRaises(exception.InvalidShare, self.api.allow_access,
                          self.context, share, 'fakeacctype', 'fakeaccto')

    @ddt.data(constants.STATUS_ACTIVE, constants.STATUS_UPDATING)
    def test_allow_access_to_instance(self, status):
        share = db_utils.create_share(host='fake')
        share_instance = db_utils.create_share_instance(
            share_id=share['id'], access_rules_status=status, host='fake')
        access = db_utils.create_access(share_id=share['id'])
        rpc_method = self.mock_object(self.api.share_rpcapi, 'allow_access')

        self.api.allow_access_to_instance(self.context, share_instance, access)

        rpc_method.assert_called_once_with(
            self.context, share_instance, access)

    def test_allow_access_to_instance_exception(self):
        share = db_utils.create_share(host='fake')
        access = db_utils.create_access(share_id=share['id'])

        share.instance['access_rules_status'] = constants.STATUS_ERROR

        self.assertRaises(exception.InvalidShareInstance,
                          self.api.allow_access_to_instance, self.context,
                          share.instance, access)

    def test_allow_access_to_instance_out_of_sync(self):
        share = db_utils.create_share(host='fake')
        access = db_utils.create_access(share_id=share['id'])
        rpc_method = self.mock_object(self.api.share_rpcapi, 'allow_access')

        share.instance['access_rules_status'] = constants.STATUS_OUT_OF_SYNC

        self.api.allow_access_to_instance(self.context, share.instance, access)
        rpc_method.assert_called_once_with(
            self.context, share.instance, access)

    @ddt.data(constants.STATUS_ACTIVE, constants.STATUS_UPDATING,
              constants.STATUS_UPDATING_MULTIPLE)
    def test_deny_access_to_instance(self, status):
        share = db_utils.create_share(host='fake')
        share_instance = db_utils.create_share_instance(
            share_id=share['id'], access_rules_status=status, host='fake')
        access = db_utils.create_access(share_id=share['id'])
        rpc_method = self.mock_object(self.api.share_rpcapi, 'deny_access')
        self.mock_object(db_api, 'share_instance_access_get',
                         mock.Mock(return_value=access.instance_mappings[0]))
        self.mock_object(db_api, 'share_instance_update_access_status')

        self.api.deny_access_to_instance(self.context, share_instance, access)

        if status == constants.STATUS_ACTIVE:
            expected_new_status = constants.STATUS_OUT_OF_SYNC
        else:
            expected_new_status = constants.STATUS_UPDATING_MULTIPLE

        rpc_method.assert_called_once_with(
            self.context, share_instance, access)
        db_api.share_instance_update_access_status.assert_called_once_with(
            self.context,
            share_instance['id'],
            expected_new_status
        )

    @ddt.data('allow_access_to_instance', 'deny_access_to_instance')
    def test_allow_and_deny_access_to_instance_invalid_instance(self, method):
        share = db_utils.create_share(host=None)

        self.assertRaises(
            exception.InvalidShareInstance,
            getattr(self.api, method),
            self.context, share.instance, 'fake'
        )

    @mock.patch.object(db_api, 'share_get', mock.Mock())
    @mock.patch.object(share_api.API, 'deny_access_to_instance', mock.Mock())
    @mock.patch.object(db_api, 'share_instance_update_access_status',
                       mock.Mock())
    def test_deny_access_error(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        db_api.share_get.return_value = share
        access = db_utils.create_access(share_id=share['id'])
        share_instance = share.instances[0]
        db_api.share_instance_access_get_all.return_value = [share_instance, ]
        self.api.deny_access(self.context, share, access)
        db_api.share_get.assert_called_once_with(self.context, share['id'])
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')
        share_api.API.deny_access_to_instance.assert_called_once_with(
            self.context, share_instance, access)

    @mock.patch.object(db_api, 'share_get', mock.Mock())
    @mock.patch.object(db_api, 'share_instance_access_get_all', mock.Mock())
    @mock.patch.object(db_api, 'share_access_delete', mock.Mock())
    def test_deny_access_error_no_share_instance_mapping(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        db_api.share_get.return_value = share
        access = db_utils.create_access(share_id=share['id'])
        db_api.share_instance_access_get_all.return_value = []

        self.api.deny_access(self.context, share, access)

        db_api.share_get.assert_called_once_with(self.context, share['id'])
        self.assertTrue(share_api.policy.check_policy.called)

    @mock.patch.object(db_api, 'share_instance_update_access_status',
                       mock.Mock())
    def test_deny_access_active(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        access = db_utils.create_access(share_id=share['id'])
        self.api.deny_access(self.context, share, access)
        db_api.share_instance_update_access_status.assert_called_once_with(
            self.context,
            share.instance['id'],
            constants.STATUS_OUT_OF_SYNC
        )
        share_api.policy.check_policy.assert_called_with(
            self.context, 'share', 'deny_access')
        self.share_rpcapi.deny_access.assert_called_once_with(
            self.context, utils.IsAMatcher(models.ShareInstance), access)

    def test_deny_access_not_found(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        access = db_utils.create_access(share_id=share['id'])
        self.mock_object(db_api, 'share_instance_access_get',
                         mock.Mock(side_effect=[exception.NotFound('fake')]))
        self.api.deny_access(self.context, share, access)
        share_api.policy.check_policy.assert_called_with(
            self.context, 'share', 'deny_access')

    def test_deny_access_status_not_available(self):
        share = db_utils.create_share(status=constants.STATUS_ERROR)
        self.assertRaises(exception.InvalidShare, self.api.deny_access,
                          self.context, share, 'fakeacc')
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')

    def test_deny_access_no_host(self):
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE, host=None)
        self.assertRaises(exception.InvalidShare, self.api.deny_access,
                          self.context, share, 'fakeacc')
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')

    def test_access_get(self):
        with mock.patch.object(db_api, 'share_access_get',
                               mock.Mock(return_value='fake')):
            rule = self.api.access_get(self.context, 'fakeid')
            self.assertEqual('fake', rule)
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'access_get')
            db_api.share_access_get.assert_called_once_with(
                self.context, 'fakeid')

    def test_access_get_all(self):
        share = db_utils.create_share(id='fakeid')

        values = {
            'fakeacc0id': {
                'id': 'fakeacc0id',
                'access_type': 'fakeacctype',
                'access_to': 'fakeaccto',
                'access_level': 'rw',
                'share_id': share['id'],
            },
            'fakeacc1id': {
                'id': 'fakeacc1id',
                'access_type': 'fakeacctype',
                'access_to': 'fakeaccto',
                'access_level': 'rw',
                'share_id': share['id'],
            },
        }
        rules = [
            db_utils.create_access(**values['fakeacc0id']),
            db_utils.create_access(**values['fakeacc1id']),
        ]

        # add state property
        values['fakeacc0id']['state'] = constants.STATUS_ACTIVE
        values['fakeacc1id']['state'] = constants.STATUS_ACTIVE

        self.mock_object(db_api, 'share_access_get_all_for_share',
                         mock.Mock(return_value=rules))
        actual = self.api.access_get_all(self.context, share)
        for access in actual:
            expected_access = values[access['id']]
            expected_access.pop('share_id')
            self.assertEqual(expected_access, access)

        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'access_get_all')
        db_api.share_access_get_all_for_share.assert_called_once_with(
            self.context, 'fakeid')

    def test_share_metadata_get(self):
        metadata = {'a': 'b', 'c': 'd'}
        share_id = str(uuid.uuid4())
        db_api.share_create(self.context,
                            {'id': share_id, 'metadata': metadata})
        self.assertEqual(metadata,
                         db_api.share_metadata_get(self.context, share_id))

    def test_share_metadata_update(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '5'}
        should_be = {'a': '3', 'c': '2', 'd': '5'}
        share_id = str(uuid.uuid4())
        db_api.share_create(self.context,
                            {'id': share_id, 'metadata': metadata1})
        db_api.share_metadata_update(self.context, share_id, metadata2, False)
        self.assertEqual(should_be,
                         db_api.share_metadata_get(self.context, share_id))

    def test_share_metadata_update_delete(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '4'}
        should_be = metadata2
        share_id = str(uuid.uuid4())
        db_api.share_create(self.context,
                            {'id': share_id, 'metadata': metadata1})
        db_api.share_metadata_update(self.context, share_id, metadata2, True)
        self.assertEqual(should_be,
                         db_api.share_metadata_get(self.context, share_id))

    def test_extend_invalid_status(self):
        invalid_status = 'fake'
        share = db_utils.create_share(status=invalid_status)
        new_size = 123

        self.assertRaises(exception.InvalidShare,
                          self.api.extend, self.context, share, new_size)

    def test_extend_invalid_task_state(self):
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            task_state=constants.TASK_STATE_MIGRATION_IN_PROGRESS)
        new_size = 123

        self.assertRaises(exception.ShareBusyException,
                          self.api.extend, self.context, share, new_size)

    def test_extend_invalid_size(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=200)
        new_size = 123

        self.assertRaises(exception.InvalidInput,
                          self.api.extend, self.context, share, new_size)

    def test_extend_quota_error(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=100)
        new_size = 123
        usages = {'gigabytes': {'reserved': 11, 'in_use': 12}}
        quotas = {'gigabytes': 13}
        exc = exception.OverQuota(usages=usages, quotas=quotas, overs=new_size)
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(side_effect=exc))

        self.assertRaises(exception.ShareSizeExceedsAvailableQuota,
                          self.api.extend, self.context, share, new_size)

    def test_extend_quota_user(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=100)
        diff_user_context = context.RequestContext(
            user_id='fake2',
            project_id='fake',
            is_admin=False
        )
        new_size = 123
        size_increase = int(new_size) - share['size']
        self.mock_object(quota.QUOTAS, 'reserve')

        self.api.extend(diff_user_context, share, new_size)

        quota.QUOTAS.reserve.assert_called_once_with(
            diff_user_context,
            project_id=share['project_id'],
            gigabytes=size_increase,
            user_id=share['user_id']
        )

    def test_extend_valid(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=100)
        new_size = 123
        self.mock_object(self.api, 'update')
        self.mock_object(self.api.share_rpcapi, 'extend_share')

        self.api.extend(self.context, share, new_size)

        self.api.update.assert_called_once_with(
            self.context, share, {'status': constants.STATUS_EXTENDING})
        self.api.share_rpcapi.extend_share.assert_called_once_with(
            self.context, share, new_size, mock.ANY
        )

    def test_shrink_invalid_status(self):
        invalid_status = 'fake'
        share = db_utils.create_share(status=invalid_status)

        self.assertRaises(exception.InvalidShare,
                          self.api.shrink, self.context, share, 123)

    def test_shrink_invalid_task_state(self):
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            task_state=constants.TASK_STATE_MIGRATION_IN_PROGRESS)

        self.assertRaises(exception.ShareBusyException,
                          self.api.shrink, self.context, share, 123)

    @ddt.data(300, 0, -1)
    def test_shrink_invalid_size(self, new_size):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=200)

        self.assertRaises(exception.InvalidInput,
                          self.api.shrink, self.context, share, new_size)

    @ddt.data(constants.STATUS_AVAILABLE,
              constants.STATUS_SHRINKING_POSSIBLE_DATA_LOSS_ERROR)
    def test_shrink_valid(self, share_status):
        share = db_utils.create_share(status=share_status, size=100)
        new_size = 50
        self.mock_object(self.api, 'update')
        self.mock_object(self.api.share_rpcapi, 'shrink_share')

        self.api.shrink(self.context, share, new_size)

        self.api.update.assert_called_once_with(
            self.context, share, {'status': constants.STATUS_SHRINKING})
        self.api.share_rpcapi.shrink_share.assert_called_once_with(
            self.context, share, new_size
        )

    def test_migration_start(self):
        host = 'fake2@backend#pool'

        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
            },
        }

        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            host='fake@backend#pool', share_type_id=fake_type['id'])

        request_spec = self._get_request_spec_dict(
            share, fake_type, size=0)

        self.mock_object(self.scheduler_rpcapi, 'migrate_share_to_host')
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))
        self.mock_object(utils, 'validate_service_host')

        self.api.migration_start(self.context, share, host, True, True)

        self.scheduler_rpcapi.migrate_share_to_host.assert_called_once_with(
            self.context, share['id'], host, True, True, request_spec)

    def test_migration_start_status_unavailable(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            status=constants.STATUS_ERROR)

        self.assertRaises(exception.InvalidShare, self.api.migration_start,
                          self.context, share, host, True, True)

    def test_migration_start_task_state_invalid(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            task_state=constants.TASK_STATE_MIGRATION_IN_PROGRESS)

        self.assertRaises(exception.ShareBusyException,
                          self.api.migration_start,
                          self.context, share, host, True, True)

    def test_migration_start_with_snapshots(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE)
        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=True))

        self.assertRaises(exception.InvalidShare, self.api.migration_start,
                          self.context, share, host, True, True)

    def test_migration_start_has_replicas(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            replication_type='dr')
        for i in range(1, 4):
            db_utils.create_share_replica(
                share_id=share['id'], replica_state='in_sync')
        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=True))
        mock_log = self.mock_object(share_api, 'LOG')
        mock_snapshot_get_call = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share')
        # Share was updated after adding replicas, grabbing it again.
        share = db_api.share_get(self.context, share['id'])

        self.assertRaises(exception.Conflict, self.api.migration_start,
                          self.context, share, host, True)
        self.assertTrue(mock_log.error.called)
        self.assertFalse(mock_snapshot_get_call.called)

    def test_migration_start_invalid_host(self):
        host = 'fake@backend#pool'
        share = db_utils.create_share(
            host='fake2@backend', status=constants.STATUS_AVAILABLE)

        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=False))

        self.assertRaises(exception.ServiceNotFound,
                          self.api.migration_start,
                          self.context, share, host, True, True)

    def test_migration_start_same_host(self):
        host = 'fake@backend#pool'
        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE)

        self.assertRaises(exception.InvalidHost,
                          self.api.migration_start,
                          self.context, share, host, True, True)

    def test_migration_start_exception(self):
        host = 'fake2@backend#pool'
        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
            },
        }
        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=fake_type['id'])

        self.mock_object(self.scheduler_rpcapi, 'migrate_share_to_host')

        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))
        self.mock_object(utils, 'validate_service_host')
        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=False))
        self.mock_object(db_api, 'share_update', mock.Mock(return_value=True))
        self.mock_object(self.scheduler_rpcapi, 'migrate_share_to_host',
                         mock.Mock(side_effect=exception.ShareMigrationFailed(
                             reason='fake')))

        self.assertRaises(exception.InvalidHost,
                          self.api.migration_start,
                          self.context, share, host, True, True)

        db_api.share_update.assert_any_call(
            mock.ANY, share['id'], mock.ANY)

    @ddt.data({}, {'replication_type': None})
    def test_create_share_replica_invalid_share_type(self, attributes):
        share = fakes.fake_share(id='FAKE_SHARE_ID', **attributes)
        mock_request_spec_call = self.mock_object(
            self.api, '_create_share_instance_and_get_request_spec')
        mock_db_update_call = self.mock_object(db_api, 'share_replica_update')
        mock_scheduler_rpcapi_call = self.mock_object(
            self.api.scheduler_rpcapi, 'create_share_replica')

        self.assertRaises(exception.InvalidShare,
                          self.api.create_share_replica,
                          self.context, share)
        self.assertFalse(mock_request_spec_call.called)
        self.assertFalse(mock_db_update_call.called)
        self.assertFalse(mock_scheduler_rpcapi_call.called)

    def test_create_share_replica_busy_share(self):
        share = fakes.fake_share(
            id='FAKE_SHARE_ID',
            task_state='doing_something_real_important',
            is_busy=True,
            replication_type='dr')
        mock_request_spec_call = self.mock_object(
            self.api, '_create_share_instance_and_get_request_spec')
        mock_db_update_call = self.mock_object(db_api, 'share_replica_update')
        mock_scheduler_rpcapi_call = self.mock_object(
            self.api.scheduler_rpcapi, 'create_share_replica')

        self.assertRaises(exception.ShareBusyException,
                          self.api.create_share_replica,
                          self.context, share)
        self.assertFalse(mock_request_spec_call.called)
        self.assertFalse(mock_db_update_call.called)
        self.assertFalse(mock_scheduler_rpcapi_call.called)

    @ddt.data(None, [])
    def test_create_share_replica_no_active_replica(self, active_replicas):
        share = fakes.fake_share(
            id='FAKE_SHARE_ID', replication_type='dr')
        mock_request_spec_call = self.mock_object(
            self.api, '_create_share_instance_and_get_request_spec')
        mock_db_update_call = self.mock_object(db_api, 'share_replica_update')
        mock_scheduler_rpcapi_call = self.mock_object(
            self.api.scheduler_rpcapi, 'create_share_replica')
        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=active_replicas))

        self.assertRaises(exception.ReplicationException,
                          self.api.create_share_replica,
                          self.context, share)
        self.assertFalse(mock_request_spec_call.called)
        self.assertFalse(mock_db_update_call.called)
        self.assertFalse(mock_scheduler_rpcapi_call.called)

    @ddt.data(True, False)
    def test_create_share_replica(self, has_snapshots):
        request_spec = fakes.fake_replica_request_spec()
        replica = request_spec['share_instance_properties']
        share = fakes.fake_share(
            id=replica['share_id'], replication_type='dr')
        snapshots = (
            [fakes.fake_snapshot(), fakes.fake_snapshot()]
            if has_snapshots else []
        )
        fake_replica = fakes.fake_replica(id=replica['id'])
        fake_request_spec = fakes.fake_replica_request_spec()
        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value={'host': 'fake_ar_host'}))
        self.mock_object(
            share_api.API, '_create_share_instance_and_get_request_spec',
            mock.Mock(return_value=(fake_request_spec, fake_replica)))
        self.mock_object(db_api, 'share_replica_update')
        mock_sched_rpcapi_call = self.mock_object(
            self.api.scheduler_rpcapi, 'create_share_replica')
        mock_snapshot_get_all_call = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share',
            mock.Mock(return_value=snapshots))
        mock_snapshot_instance_create_call = self.mock_object(
            db_api, 'share_snapshot_instance_create')
        expected_snap_instance_create_call_count = 2 if has_snapshots else 0

        result = self.api.create_share_replica(
            self.context, share, availability_zone='FAKE_AZ')

        self.assertTrue(mock_sched_rpcapi_call.called)
        self.assertEqual(replica, result)
        mock_snapshot_get_all_call.assert_called_once_with(
            self.context, fake_replica['share_id'])
        self.assertEqual(expected_snap_instance_create_call_count,
                         mock_snapshot_instance_create_call.call_count)

    def test_delete_last_active_replica(self):
        fake_replica = fakes.fake_replica(
            share_id='FAKE_SHARE_ID',
            replica_state=constants.REPLICA_STATE_ACTIVE)
        self.mock_object(db_api, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[fake_replica]))
        mock_log = self.mock_object(share_api.LOG, 'info')

        self.assertRaises(
            exception.ReplicationException, self.api.delete_share_replica,
            self.context, fake_replica)
        self.assertFalse(mock_log.called)

    @ddt.data(True, False)
    def test_delete_share_replica_no_host(self, has_snapshots):
        snapshots = [{'id': 'xyz'}, {'id': 'abc'}, {'id': 'pqr'}]
        snapshots = snapshots if has_snapshots else []
        replica = fakes.fake_replica('FAKE_ID', host='')
        mock_sched_rpcapi_call = self.mock_object(
            self.share_rpcapi, 'delete_share_replica')
        mock_db_replica_delete_call = self.mock_object(
            db_api, 'share_replica_delete')
        mock_db_update_call = self.mock_object(db_api, 'share_replica_update')
        mock_snapshot_get_call = self.mock_object(
            db_api, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=snapshots))
        mock_snapshot_instance_delete_call = self.mock_object(
            db_api, 'share_snapshot_instance_delete')

        self.api.delete_share_replica(self.context, replica)

        self.assertFalse(mock_sched_rpcapi_call.called)
        mock_db_replica_delete_call.assert_called_once_with(
            self.context, replica['id'])
        mock_db_update_call.assert_called_once_with(
            self.context, replica['id'],
            {'status': constants.STATUS_DELETING, 'terminated_at': mock.ANY})
        mock_snapshot_get_call.assert_called_once_with(
            self.context,  {'share_instance_ids': replica['id']})
        self.assertEqual(
            len(snapshots), mock_snapshot_instance_delete_call.call_count)

    @ddt.data(True, False)
    def test_delete_share_replica(self, force):
        replica = fakes.fake_replica('FAKE_ID', host='HOSTA@BackendB#PoolC')
        mock_sched_rpcapi_call = self.mock_object(
            self.share_rpcapi, 'delete_share_replica')
        mock_db_update_call = self.mock_object(db_api, 'share_replica_update')

        self.api.delete_share_replica(self.context, replica, force=force)

        mock_sched_rpcapi_call.assert_called_once_with(
            self.context, replica, force=force)
        mock_db_update_call.assert_called_once_with(
            self.context, replica['id'],
            {'status': constants.STATUS_DELETING,
             'terminated_at': mock.ANY})

    @ddt.data(constants.STATUS_CREATING, constants.STATUS_DELETING,
              constants.STATUS_ERROR, constants.STATUS_EXTENDING,
              constants.STATUS_REPLICATION_CHANGE, constants.STATUS_MANAGING,
              constants.STATUS_ERROR_DELETING)
    def test_promote_share_replica_non_available_status(self, status):
        replica = fakes.fake_replica(
            status=status, replica_state=constants.REPLICA_STATE_IN_SYNC)
        mock_rpcapi_promote_share_replica_call = self.mock_object(
            self.share_rpcapi, 'promote_share_replica')

        self.assertRaises(exception.ReplicationException,
                          self.api.promote_share_replica,
                          self.context,
                          replica)
        self.assertFalse(mock_rpcapi_promote_share_replica_call.called)

    @ddt.data(constants.REPLICA_STATE_OUT_OF_SYNC, constants.STATUS_ERROR)
    def test_promote_share_replica_out_of_sync_non_admin(self, replica_state):
        fake_user_context = context.RequestContext(
            user_id=None, project_id=None, is_admin=False,
            read_deleted='no', overwrite=False)
        replica = fakes.fake_replica(
            status=constants.STATUS_AVAILABLE,
            replica_state=replica_state)
        mock_rpcapi_promote_share_replica_call = self.mock_object(
            self.share_rpcapi, 'promote_share_replica')

        self.assertRaises(exception.AdminRequired,
                          self.api.promote_share_replica,
                          fake_user_context,
                          replica)
        self.assertFalse(mock_rpcapi_promote_share_replica_call.called)

    @ddt.data(constants.REPLICA_STATE_OUT_OF_SYNC, constants.STATUS_ERROR)
    def test_promote_share_replica_admin_authorized(self, replica_state):
        replica = fakes.fake_replica(
            status=constants.STATUS_AVAILABLE,
            replica_state=replica_state, host='HOSTA@BackendB#PoolC')
        self.mock_object(db_api, 'share_replica_get',
                         mock.Mock(return_value=replica))
        mock_rpcapi_promote_share_replica_call = self.mock_object(
            self.share_rpcapi, 'promote_share_replica')
        mock_db_update_call = self.mock_object(db_api, 'share_replica_update')

        retval = self.api.promote_share_replica(
            self.context, replica)

        self.assertEqual(replica, retval)
        mock_db_update_call.assert_called_once_with(
            self.context, replica['id'],
            {'status': constants.STATUS_REPLICATION_CHANGE})
        mock_rpcapi_promote_share_replica_call.assert_called_once_with(
            self.context, replica)

    def test_promote_share_replica(self):
        replica = fakes.fake_replica('FAKE_ID', host='HOSTA@BackendB#PoolC')
        self.mock_object(db_api, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db_api, 'share_replica_update')
        mock_sched_rpcapi_call = self.mock_object(
            self.share_rpcapi, 'promote_share_replica')

        result = self.api.promote_share_replica(self.context, replica)

        mock_sched_rpcapi_call.assert_called_once_with(
            self.context, replica)
        self.assertEqual(replica, result)

    def test_update_share_replica_no_host(self):
        replica = fakes.fake_replica('FAKE_ID')
        replica['host'] = None
        mock_rpcapi_update_share_replica_call = self.mock_object(
            self.share_rpcapi, 'update_share_replica')

        self.assertRaises(exception.InvalidHost,
                          self.api.update_share_replica,
                          self.context,
                          replica)
        self.assertFalse(mock_rpcapi_update_share_replica_call.called)

    def test_update_share_replica(self):
        replica = fakes.fake_replica('FAKE_ID', host='HOSTA@BackendB#PoolC')
        mock_rpcapi_update_share_replica_call = self.mock_object(
            self.share_rpcapi, 'update_share_replica')

        retval = self.api.update_share_replica(self.context, replica)

        self.assertTrue(mock_rpcapi_update_share_replica_call.called)
        self.assertIsNone(retval)

    def test_migration_complete(self):

        instance1 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_MIGRATING)
        instance2 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_COMPLETED,
            instances=[instance1, instance2])

        self.mock_object(share_rpc.ShareAPI, 'migration_complete')

        self.api.migration_complete(self.context, share)

        share_rpc.ShareAPI.migration_complete.assert_called_once_with(
            self.context, share, instance1['id'], instance2['id'])

    def test_migration_complete_task_state_invalid(self):

        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_IN_PROGRESS)

        self.assertRaises(exception.InvalidShare, self.api.migration_complete,
                          self.context, share)

    def test_migration_complete_status_invalid(self):

        instance1 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_ERROR)
        instance2 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_ERROR)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_COMPLETED,
            instances=[instance1, instance2])

        self.assertRaises(exception.ShareMigrationFailed,
                          self.api.migration_complete, self.context,
                          share)

    def test_migration_cancel(self):

        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_IN_PROGRESS)

        self.mock_object(data_rpc.DataAPI, 'data_copy_cancel')

        self.api.migration_cancel(self.context, share)

        data_rpc.DataAPI.data_copy_cancel.assert_called_once_with(
            self.context, share['id'])

    def test_migration_cancel_driver(self):

        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)

        self.mock_object(share_rpc.ShareAPI, 'migration_cancel')

        self.api.migration_cancel(self.context, share)

        share_rpc.ShareAPI.migration_cancel.assert_called_once_with(
            self.context, share)

    def test_migration_cancel_task_state_invalid(self):

        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_STARTING)

        self.assertRaises(exception.InvalidShare, self.api.migration_cancel,
                          self.context, share)

    def test_migration_get_progress(self):

        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_IN_PROGRESS)

        expected = 'fake_progress'

        self.mock_object(data_rpc.DataAPI, 'data_copy_get_progress',
                         mock.Mock(return_value=expected))

        result = self.api.migration_get_progress(self.context, share)

        self.assertEqual(expected, result)

        data_rpc.DataAPI.data_copy_get_progress.assert_called_once_with(
            self.context, share['id'])

    def test_migration_get_progress_driver(self):

        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)

        expected = 'fake_progress'

        self.mock_object(share_rpc.ShareAPI, 'migration_get_progress',
                         mock.Mock(return_value=expected))

        result = self.api.migration_get_progress(self.context, share)

        self.assertEqual(expected, result)

        share_rpc.ShareAPI.migration_get_progress.assert_called_once_with(
            self.context, share)

    def test_migration_get_progress_task_state_invalid(self):

        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_STARTING)

        self.assertRaises(exception.InvalidShare,
                          self.api.migration_get_progress, self.context, share)


class OtherTenantsShareActionsTestCase(test.TestCase):
    def setUp(self):
        super(OtherTenantsShareActionsTestCase, self).setUp()
        self.api = share.API()

    def test_delete_other_tenants_public_share(self):
        share = db_utils.create_share(is_public=True)
        ctx = context.RequestContext(user_id='1111', project_id='2222')
        self.assertRaises(exception.PolicyNotAuthorized, self.api.delete, ctx,
                          share)

    def test_update_other_tenants_public_share(self):
        share = db_utils.create_share(is_public=True)
        ctx = context.RequestContext(user_id='1111', project_id='2222')
        self.assertRaises(exception.PolicyNotAuthorized, self.api.update, ctx,
                          share, {'display_name': 'newname'})

    def test_get_other_tenants_public_share(self):
        share = db_utils.create_share(is_public=True)
        ctx = context.RequestContext(user_id='1111', project_id='2222')
        self.mock_object(db_api, 'share_get',
                         mock.Mock(return_value=share))
        result = self.api.get(ctx, 'fakeid')
        self.assertEqual(share, result)
        db_api.share_get.assert_called_once_with(ctx, 'fakeid')
