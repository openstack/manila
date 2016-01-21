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
from manila import db as db_api
from manila.db.sqlalchemy import models
from manila import exception
from manila import quota
from manila import share
from manila.share import api as share_api
from manila.share import share_types
from manila import test
from manila.tests import db_utils
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
            share_type_id='fake',
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
        share_metadata = {'fake': 'fake'}
        share_type = {'fake': 'fake'}
        self.mock_object(db_api, 'share_instance_create',
                         mock.Mock(return_value=share_instance))
        self.mock_object(db_api, 'share_metadata_get',
                         mock.Mock(return_value=share_metadata))
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

        original_share = db_utils.create_share(
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_AVAILABLE,
            host=host if host else 'fake',
            size=1
        )
        snapshot = db_utils.create_snapshot(
            share_id=original_share['id'],
            status=constants.STATUS_AVAILABLE,
            size=1
        )

        share, share_data = self._setup_create_mocks(
            snapshot_id=snapshot['id'])

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
        self.mock_object(share_types, 'get_share_type')

        return snapshot, share, share_data, request_spec

    def _setup_delete_mocks(self, status, snapshots=[], **kwargs):
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
        db_api.share_metadata_get.assert_called_once_with(self.context,
                                                          share['id'])
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

    def test_manage_new(self):
        share_data = {
            'host': 'fake',
            'export_location': 'fake',
            'share_proto': 'fake',
        }
        driver_options = {}
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        fake_share_data = {
            'id': 'fakeid',
            'status': constants.STATUS_CREATING,
        }
        share = db_api.share_create(self.context, fake_share_data)

        self.mock_object(db_api, 'share_create',
                         mock.Mock(return_value=share))
        self.mock_object(db_api, 'share_export_locations_update')
        self.mock_object(db_api, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.api, 'get_all', mock.Mock(return_value=[]))

        self.api.manage(self.context,
                        copy.deepcopy(share_data),
                        driver_options)

        share_data.update({
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_MANAGING,
            'scheduled_at': date,
        })

        export_location = share_data.pop('export_location')
        self.api.get_all.assert_called_once_with(self.context, mock.ANY)
        db_api.share_create.assert_called_once_with(self.context, share_data)
        db_api.share_get.assert_called_once_with(self.context, share['id'])
        db_api.share_export_locations_update.assert_called_once_with(
            self.context, share.instance['id'], export_location
        )
        self.share_rpcapi.manage_share.assert_called_once_with(
            self.context, share, driver_options)

    @ddt.data([{'id': 'fake', 'status': constants.STATUS_MANAGE_ERROR}])
    def test_manage_retry(self, shares):
        share_data = {
            'host': 'fake',
            'export_location': 'fake',
            'share_proto': 'fake',
        }
        driver_options = {}
        fake_share_data = {'id': 'fakeid'}
        share = db_api.share_create(self.context, fake_share_data)
        self.mock_object(db_api, 'share_update',
                         mock.Mock(return_value=share))
        self.mock_object(db_api, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(db_api, 'share_export_locations_update')
        self.mock_object(self.api, 'get_all',
                         mock.Mock(return_value=shares))

        self.api.manage(self.context,
                        copy.deepcopy(share_data),
                        driver_options)

        db_api.share_update.assert_called_once_with(
            self.context, 'fake', mock.ANY)
        self.share_rpcapi.manage_share.assert_called_once_with(
            self.context, mock.ANY, driver_options)
        db_api.share_export_locations_update.assert_called_once_with(
            self.context, share.instance['id'], mock.ANY
        )

    def test_manage_duplicate(self):
        share_data = {
            'host': 'fake',
            'export_location': 'fake',
            'share_proto': 'fake',
        }
        driver_options = {}
        self.mock_object(self.api, 'get_all',
                         mock.Mock(return_value=['fake', 'fake2']))

        self.assertRaises(exception.ManilaException, self.api.manage,
                          self.context, share_data, driver_options)

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
            task_state=constants.STATUS_TASK_STATE_MIGRATION_IN_PROGRESS)

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

    @mock.patch.object(db_api, 'share_snapshot_update', mock.Mock())
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
            db_api.share_snapshot_update.assert_called_once_with(
                self.context,
                snapshot['id'],
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
            task_state=constants.STATUS_TASK_STATE_MIGRATION_IN_PROGRESS)
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
        az = share_data.pop('availability_zone')

        self.api.create(
            self.context,
            share_data['share_proto'],
            None,  # NOTE(u_glide): Get share size from snapshot
            share_data['display_name'],
            share_data['display_description'],
            snapshot=snapshot,
            availability_zone=az
        )

        self.assertEqual(0, share_types.get_share_type.call_count)
        self.assertSubDictMatch(share_data,
                                db_api.share_create.call_args[0][1])
        self.api.create_instance.assert_called_once_with(
            self.context, share, share_network_id=share['share_network_id'],
            host=valid_host,
            availability_zone=snapshot['share']['availability_zone'],
            consistency_group=None, cgsnapshot_member=None)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'create')
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
                          snapshot=snapshot,
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
                          'fakedesc', snapshot=snapshot,
                          availability_zone='fakeaz')

    def test_create_from_snapshot_larger_size(self):
        snapshot = db_utils.create_snapshot(
            size=100, status=constants.STATUS_AVAILABLE, with_share=True)
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 1, 'fakename', 'fakedesc',
                          availability_zone='fakeaz', snapshot=snapshot)

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

    def test_delete_wrong_status(self):
        share = fake_share('fakeid')
        self.mock_object(db_api, 'share_get', mock.Mock(return_value=share))
        self.assertRaises(exception.InvalidShare, self.api.delete,
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
            task_state=constants.STATUS_TASK_STATE_MIGRATION_IN_PROGRESS)

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
            gigabytes=-share['size']
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
            self.context, instance
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
            'state': 'fake_state',
        })
        fake_access = copy.deepcopy(fake_access_expected)
        fake_access.update({
            'deleted': 'fake_deleted',
            'deleted_at': 'fake_deleted_at',
            'instance_mappings': ['foo', 'bar'],
        })
        self.mock_object(db_api, 'share_access_create',
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

    def test_allow_access_to_instance(self):
        share = db_utils.create_share(host='fake')
        access = db_utils.create_access(share_id=share['id'],
                                        state=constants.STATUS_ACTIVE)
        rpc_method = self.mock_object(self.api.share_rpcapi, 'allow_access')

        self.api.allow_access_to_instance(self.context, share.instance, access)

        rpc_method.assert_called_once_with(
            self.context, share.instance, access)

    def test_deny_access_to_instance(self):
        share = db_utils.create_share(host='fake')
        access = db_utils.create_access(share_id=share['id'],
                                        state=constants.STATUS_ACTIVE)
        rpc_method = self.mock_object(self.api.share_rpcapi, 'deny_access')
        self.mock_object(db_api, 'share_instance_access_get',
                         mock.Mock(return_value=access.instance_mappings[0]))
        self.mock_object(db_api, 'share_instance_access_update_state')

        self.api.deny_access_to_instance(self.context, share.instance, access)

        rpc_method.assert_called_once_with(
            self.context, share.instance, access)
        db_api.share_instance_access_get.assert_called_once_with(
            self.context, access['id'], share.instance['id'])
        db_api.share_instance_access_update_state.assert_called_once_with(
            self.context,
            access.instance_mappings[0]['id'],
            constants.STATUS_DELETING
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
    @mock.patch.object(db_api, 'share_instance_access_get_all', mock.Mock())
    def test_deny_access_error(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        db_api.share_get.return_value = share
        access = db_utils.create_access(state=constants.STATUS_ERROR,
                                        share_id=share['id'])
        share_instance = share.instances[0]
        db_api.share_instance_access_get_all.return_value = [share_instance, ]
        self.api.deny_access(self.context, share, access)
        db_api.share_get.assert_called_once_with(self.context, share['id'])
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')
        share_api.API.deny_access_to_instance.assert_called_once_with(
            self.context, share_instance, access)
        db_api.share_instance_access_get_all.assert_called_once_with(
            self.context, access['id'])

    @mock.patch.object(db_api, 'share_get', mock.Mock())
    @mock.patch.object(db_api, 'share_instance_access_get_all', mock.Mock())
    @mock.patch.object(db_api, 'share_access_delete', mock.Mock())
    def test_deny_access_error_no_share_instance_mapping(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        db_api.share_get.return_value = share
        access = db_utils.create_access(state=constants.STATUS_ERROR,
                                        share_id=share['id'])
        db_api.share_instance_access_get_all.return_value = []
        self.api.deny_access(self.context, share, access)
        db_api.share_get.assert_called_once_with(self.context, share['id'])
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')
        db_api.share_access_delete.assert_called_once_with(
            self.context, access['id'])
        db_api.share_instance_access_get_all.assert_called_once_with(
            self.context, access['id'])

    @mock.patch.object(db_api, 'share_instance_access_update_state',
                       mock.Mock())
    def test_deny_access_active(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        access = db_utils.create_access(state=constants.STATUS_ACTIVE,
                                        share_id=share['id'])
        self.api.deny_access(self.context, share, access)
        db_api.share_instance_access_update_state.assert_called_once_with(
            self.context,
            access.instance_mappings[0]['id'],
            constants.STATUS_DELETING
        )
        share_api.policy.check_policy.assert_called_with(
            self.context, 'share', 'deny_access')
        self.share_rpcapi.deny_access.assert_called_once_with(
            self.context, utils.IsAMatcher(models.ShareInstance), access)

    def test_deny_access_not_found(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        access = db_utils.create_access(state=constants.STATUS_ACTIVE,
                                        share_id=share['id'])
        self.mock_object(db_api, 'share_instance_access_get',
                         mock.Mock(side_effect=[exception.NotFound('fake')]))
        self.api.deny_access(self.context, share, access)
        share_api.policy.check_policy.assert_called_with(
            self.context, 'share', 'deny_access')

    def test_deny_access_not_active_not_error(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        access = db_utils.create_access(share_id=share['id'])
        self.assertRaises(exception.InvalidShareAccess, self.api.deny_access,
                          self.context, share, access)
        share_api.policy.check_policy.assert_called_once_with(
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

        expected = {
            'fakeacc0id': {
                'id': 'fakeacc0id',
                'access_type': 'fakeacctype',
                'access_to': 'fakeaccto',
                'access_level': 'rw',
                'state': constants.STATUS_ACTIVE,
                'share_id': share['id'],
            },
            'fakeacc1id': {
                'id': 'fakeacc1id',
                'access_type': 'fakeacctype',
                'access_to': 'fakeaccto',
                'access_level': 'rw',
                'state': constants.STATUS_DELETING,
                'share_id': share['id'],
            },
        }
        rules = [
            db_utils.create_access(**expected['fakeacc0id']),
            db_utils.create_access(**expected['fakeacc1id']),
        ]

        self.mock_object(db_api, 'share_access_get_all_for_share',
                         mock.Mock(return_value=rules))
        actual = self.api.access_get_all(self.context, share)
        for access in actual:
            expected_access = expected[access['id']]
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
            task_state=constants.STATUS_TASK_STATE_MIGRATION_IN_PROGRESS)
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
            task_state=constants.STATUS_TASK_STATE_MIGRATION_IN_PROGRESS)

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

    def test_migrate_share(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            host='fake@backend#pool', share_type_id='fake_type_id')
        request_spec = {
            'share_properties': {
                'size': share['size'],
                'user_id': share['user_id'],
                'project_id': share['project_id'],
                'share_server_id': share['share_server_id'],
                'snapshot_support': share['snapshot_support'],
                'share_proto': share['share_proto'],
                'share_type_id': share['share_type_id'],
                'is_public': share['is_public'],
                'consistency_group_id': share['consistency_group_id'],
                'source_cgsnapshot_member_id': share[
                    'source_cgsnapshot_member_id'],
                'snapshot_id': share['snapshot_id'],
            },
            'share_instance_properties': {
                'availability_zone_id': share.instance['availability_zone_id'],
                'share_network_id': share.instance['share_network_id'],
                'share_server_id': share.instance['share_server_id'],
                'share_id': share.instance['share_id'],
                'host': share.instance['host'],
                'status': share.instance['status'],
            },
            'share_type': 'fake_type',
            'share_id': share['id'],
        }

        self.mock_object(self.scheduler_rpcapi, 'migrate_share_to_host')
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value='fake_type'))
        self.mock_object(utils, 'validate_service_host')

        self.api.migrate_share(self.context, share, host, True)

        self.scheduler_rpcapi.migrate_share_to_host.assert_called_once_with(
            self.context, share['id'], host, True, request_spec)

    def test_migrate_share_status_unavailable(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            status=constants.STATUS_ERROR)

        self.assertRaises(exception.InvalidShare, self.api.migrate_share,
                          self.context, share, host, True)

    def test_migrate_share_task_state_invalid(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            task_state=constants.STATUS_TASK_STATE_MIGRATION_IN_PROGRESS)

        self.assertRaises(exception.ShareBusyException, self.api.migrate_share,
                          self.context, share, host, True)

    def test_migrate_share_with_snapshots(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE)
        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=True))

        self.assertRaises(exception.InvalidShare, self.api.migrate_share,
                          self.context, share, host, True)

    def test_migrate_share_invalid_host(self):
        host = 'fake@backend#pool'
        share = db_utils.create_share(
            host='fake2@backend', status=constants.STATUS_AVAILABLE)

        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=False))

        self.assertRaises(exception.ServiceNotFound,
                          self.api.migrate_share,
                          self.context, share, host, True)

    def test_migrate_share_same_host(self):
        host = 'fake@backend#pool'
        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE)

        self.assertRaises(exception.InvalidHost,
                          self.api.migrate_share,
                          self.context, share, host, True)

    def test_migrate_share_exception(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE)

        self.mock_object(utils, 'validate_service_host')
        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=False))
        self.mock_object(db_api, 'share_update', mock.Mock(return_value=True))
        self.mock_object(self.scheduler_rpcapi, 'migrate_share_to_host',
                         mock.Mock(side_effect=exception.ShareMigrationFailed(
                             reason='fake')))

        self.assertRaises(exception.ShareMigrationFailed,
                          self.api.migrate_share,
                          self.context, share, host, True)

        db_api.share_update.assert_any_call(
            mock.ANY, share['id'], mock.ANY)


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
