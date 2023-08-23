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
import json
from unittest import mock


import ddt
from oslo_config import cfg
from oslo_utils import timeutils
from oslo_utils import uuidutils
from webob import exc as webob_exc

from manila.common import constants
from manila import context
from manila.data import rpcapi as data_rpc
from manila import db as db_api
from manila.db.sqlalchemy import models
from manila import exception
from manila import policy
from manila import quota
from manila import share
from manila.share import api as share_api
from manila.share import share_types
from manila import test
from manila.tests import db_utils
from manila.tests import fake_share as fakes
from manila.tests import utils as test_utils
from manila import utils

CONF = cfg.CONF


_FAKE_LIST_OF_ALL_SHARES = [
    {
        'name': 'foo',
        'description': 'ds',
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
        'name': 'foo1',
        'description': 'ds1',
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
        self.mock_object(self.api.db, 'resource_lock_get_all',
                         mock.Mock(return_value=([], None)))
        self.mock_object(self.api, 'scheduler_rpcapi', self.scheduler_rpcapi)
        self.mock_object(self.api, 'share_rpcapi', self.share_rpcapi)
        self.mock_object(quota.QUOTAS, 'reserve',
                         lambda *args, **kwargs: None)

        self.dt_utc = datetime.datetime.utcnow()
        self.mock_object(timeutils, 'utcnow',
                         mock.Mock(return_value=self.dt_utc))
        self.mock_object(share_api.policy, 'check_policy')
        self._setup_sized_share_types()

    def _setup_sized_share_types(self):
        """create a share type with size limit"""
        spec_dict = {share_types.MIN_SIZE_KEY: 2,
                     share_types.MAX_SIZE_KEY: 4,
                     share_types.MAX_EXTEND_SIZE_KEY: 6}
        db_utils.create_share_type(name='limit', extra_specs=spec_dict)
        self.sized_sha_type = db_api.share_type_get_by_name(self.context,
                                                            'limit')

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
        )
        share_instance = db_utils.create_share_instance(
            share_id=share['id'],
            share_type_id=share_type_id)
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
        self.mock_object(db_api, 'share_backups_get_all',
                         mock.Mock(return_value=[]))
        self.mock_object(self.api, 'delete_instance')
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

    def test_get_all_admin_filter_by_all_tenants_with_blank(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=True)
        self.mock_object(db_api, 'share_get_all',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES))
        shares = self.api.get_all(ctx, {'all_tenants': ''})
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_api.share_get_all.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at', filters={})
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES, shares)

    def test_get_all_admin_filter_by_all_tenants_with_false(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=True)
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        shares = self.api.get_all(ctx, {'all_tenants': 'false'})
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_1', filters={}, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[0], shares)

    def test_get_all_admin_filter_by_all_tenants_with_invaild_value(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=True)
        self.mock_object(db_api, 'share_get_all')
        self.assertRaises(
            exception.InvalidInput,
            self.api.get_all, ctx, {'all_tenants': 'wonk'})

    @ddt.data(
        ({'share_server_id': 'fake_share_server'}, 'list_by_share_server_id'),
        ({'host': 'fake_host'}, 'list_by_host'),
    )
    @ddt.unpack
    def test_get_all_by_non_admin_using_admin_filter(self, filters, policy):

        def fake_policy_checker(*args, **kwargs):
            if policy == args[2] and not args[0].is_admin:
                raise exception.NotAuthorized

        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        self.mock_object(
            share_api.policy, 'check_policy',
            mock.Mock(side_effect=fake_policy_checker))

        self.assertRaises(
            exception.NotAuthorized,
            self.api.get_all, ctx, filters)

        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
            mock.call(ctx, 'share', policy),
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
        self.mock_object(
            db_api, 'share_get_all_by_project',
            mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1::2]))
        expected_filters = {'display_name': 'bar'}
        shares = self.api.get_all(ctx, {'display_name': 'bar'})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters=expected_filters, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1::2], shares)

    @ddt.data(({'display_name': 'fo'}, 0), ({'display_description': 'd'}, 0),
              ({'display_name': 'foo', 'display_description': 'd'}, 0),
              ({'display_name': 'foo'}, 1), ({'display_description': 'ds'}, 1),
              ({'display_name~': 'foo', 'display_description~': 'ds'}, 2),
              ({'display_name': 'foo', 'display_description~': 'ds'}, 1),
              ({'display_name~': 'foo', 'display_description': 'ds'}, 1))
    @ddt.unpack
    def test_get_all_admin_filter_by_name_and_description(
            self, search_opts, get_share_number):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)

        expected_result = []

        if get_share_number == 2:
            expected_result = _FAKE_LIST_OF_ALL_SHARES[0::2]
        elif get_share_number == 1:
            expected_result = _FAKE_LIST_OF_ALL_SHARES[:1]

        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=expected_result))
        expected_filters = copy.copy(search_opts)

        shares = self.api.get_all(ctx, search_opts)
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])

        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2',
            filters=expected_filters, is_public=False
        )
        self.assertEqual(get_share_number, len(shares))
        self.assertEqual(expected_result, shares)

    @ddt.data('id', 'path')
    def test_get_all_admin_filter_by_export_location(self, type):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_api, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'export_location_' + type: 'test'})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2',
            filters={'export_location_' + type: 'test'}, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1:], shares)

    def test_get_all_admin_filter_by_name_and_all_tenants(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_api, 'share_get_all',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[:1]))
        shares = self.api.get_all(ctx, {'name': 'foo', 'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at', filters={})
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[:1], shares)

    def test_get_all_admin_filter_by_status(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        expected_filter = {'status': constants.STATUS_AVAILABLE}
        self.mock_object(
            db_api, 'share_get_all_by_project',
            mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0::2]))

        shares = self.api.get_all(ctx, {'status': constants.STATUS_AVAILABLE})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters=expected_filter, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[0::2], shares)

    def test_get_all_admin_filter_by_status_and_all_tenants(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(
            db_api, 'share_get_all',
            mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1::2]))
        expected_filter = {'status': constants.STATUS_ERROR}
        shares = self.api.get_all(
            ctx, {'status': constants.STATUS_ERROR, 'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            filters=expected_filter)
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
        self.mock_object(
            db_api, 'share_get_all_by_project',
            mock.Mock(side_effect=[
                _FAKE_LIST_OF_ALL_SHARES[1::2],
                _FAKE_LIST_OF_ALL_SHARES[2::4]]))
        shares = self.api.get_all(
            ctx, {'name': 'bar', 'status': constants.STATUS_ERROR})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        expected_filter_1 = {'status': constants.STATUS_ERROR}
        expected_filter_2 = {'status': constants.STATUS_AVAILABLE}

        db_api.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters=expected_filter_1, is_public=False
        )

        # two items expected, one filtered
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1::2], shares)

        # one item expected, two filtered
        shares = self.api.get_all(
            ctx, {'name': 'foo1', 'status': constants.STATUS_AVAILABLE})
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[2::4], shares)
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_api.share_get_all_by_project.assert_has_calls([
            mock.call(
                ctx, sort_dir='desc', sort_key='created_at',
                project_id='fake_pid_2', filters=expected_filter_1,
                is_public=False),
            mock.call(
                ctx, sort_dir='desc', sort_key='created_at',
                project_id='fake_pid_2', filters=expected_filter_2,
                is_public=False),
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
        if key == 'extra_specs':
            share_api.policy.check_policy.assert_has_calls([
                mock.call(ctx, 'share', 'get_all'),
                mock.call(ctx, 'share_types_extra_spec', 'index'),
            ])
        else:
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
        if key == 'extra_specs':
            share_api.policy.check_policy.assert_has_calls([
                mock.call(ctx, 'share', 'get_all'),
                mock.call(ctx, 'share_types_extra_spec', 'index'),
            ])
        else:
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

    @ddt.data(
        {},
        {
            constants.ExtraSpecs.SNAPSHOT_SUPPORT: True,
        },
        {
            constants.ExtraSpecs.SNAPSHOT_SUPPORT: False,
            constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT: False,
        },
        {
            constants.ExtraSpecs.SNAPSHOT_SUPPORT: True,
            constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT: False,
        },
        {
            constants.ExtraSpecs.SNAPSHOT_SUPPORT: True,
            constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT: True,
        }
    )
    def test_create_default_snapshot_semantics(self, extra_specs):
        share, share_data = self._setup_create_mocks(is_public=False)
        az = share_data.pop('availability_zone')
        share_type = fakes.fake_share_type(extra_specs=extra_specs)

        self.api.create(
            self.context,
            share_data['share_proto'],
            share_data['size'],
            share_data['display_name'],
            share_data['display_description'],
            availability_zone=az,
            share_type=share_type
        )

        share['status'] = constants.STATUS_CREATING
        share['host'] = None

        share_data.update(extra_specs)
        if extra_specs.get('snapshot_support') is None:
            share_data['snapshot_support'] = False
        if extra_specs.get('create_share_from_snapshot_support') is None:
            share_data['create_share_from_snapshot_support'] = False

        self.assertSubDictMatch(share_data,
                                db_api.share_create.call_args[0][1])

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
        {'get_all_azs_return': [], 'subnet_by_az_side_effect': []},
        {'get_all_azs_return': [{'name': 'az1', 'id': 'az_id_1'}],
         'subnet_by_az_side_effect': [None]},
        {'get_all_azs_return': [{'name': 'az1', 'id': 'az_id_1'}],
         'subnet_by_az_side_effect': ['fake_sns_1']},
        {'get_all_azs_return': [{'name': 'az1', 'id': 'az_id_1'},
                                {'name': 'az2', 'id': 'az_id_2'}],
         'subnet_by_az_side_effect': [None, 'fake_sns_2']}
    )
    @ddt.unpack
    def test__get_all_availability_zones_with_subnets(
            self, get_all_azs_return, subnet_by_az_side_effect):
        fake_share_network_id = 'fake_sn_id'
        self.mock_object(db_api, 'availability_zone_get_all',
                         mock.Mock(return_value=get_all_azs_return))
        self.mock_object(
            db_api, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(side_effect=subnet_by_az_side_effect))
        expected_az_names = ([], {})
        expected_get_az_calls = []
        for index, value in enumerate(get_all_azs_return):
            expected_get_az_calls.append(mock.call(
                self.context, share_network_id=fake_share_network_id,
                availability_zone_id=value['id']))
            if subnet_by_az_side_effect[index] is not None:
                expected_az_names = ([value['name']], {value['id']: True})

        get_all_subnets = self.api._get_all_availability_zones_with_subnets
        compatible_azs = get_all_subnets(self.context, fake_share_network_id)

        db_api.availability_zone_get_all.assert_called_once_with(
            self.context)
        db_get_azs_with_subnet = (
            db_api.share_network_subnets_get_all_by_availability_zone_id)
        db_get_azs_with_subnet.assert_has_calls(expected_get_az_calls)

        self.assertEqual(expected_az_names, compatible_azs)

    def test_create_share_with_share_type_size_limit(self):
        self.assertRaises(exception.InvalidInput,
                          self.api.create,
                          self.context,
                          'nfs',
                          1,
                          'display_name',
                          'display_description',
                          share_type=self.sized_sha_type)
        self.assertRaises(exception.InvalidInput,
                          self.api.create,
                          self.context,
                          'nfs',
                          5,
                          'display_name',
                          'display_description',
                          share_type=self.sized_sha_type)

    @ddt.data(
        {'availability_zones': None, 'compatible_azs_name': ['fake_az_1'],
         'compatible_azs_multiple': {}},
        {'availability_zones': ['fake_az_2'],
         'compatible_azs_name': ['fake_az_2'], 'compatible_azs_multiple': {}},
        {'availability_zones': ['fake_az_1', 'faze_az_2', 'fake_az_3'],
         'compatible_azs_name': ['fake_az_3'],
         'compatible_azs_multiple': {'fake_az_3': 1}}
    )
    @ddt.unpack
    def test_create_share_with_subnets(self, availability_zones,
                                       compatible_azs_name,
                                       compatible_azs_multiple):
        share, share_data = self._setup_create_mocks()
        reservation = 'fake'
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value=reservation))
        self.mock_object(self.api, '_get_all_availability_zones_with_subnets',
                         mock.Mock(return_value=[compatible_azs_name,
                                                 compatible_azs_multiple]))
        self.mock_object(quota.QUOTAS, 'commit')
        self.mock_object(self.api, 'create_instance')
        self.mock_object(db_api, 'share_get')
        fake_share_network_id = 'fake_sn_id'

        if availability_zones:
            expected_azs = (
                [az for az in availability_zones if az in compatible_azs_name])
        else:
            expected_azs = compatible_azs_name

        az_multiple_sn_support_map = None
        if compatible_azs_multiple != {}:
            az_multiple_sn_support_map = compatible_azs_multiple

        self.api.create(
            self.context,
            share_data['share_proto'],
            share_data['size'],
            share_data['display_name'],
            share_data['display_description'],
            share_network_id=fake_share_network_id,
            availability_zones=availability_zones,
            az_request_multiple_subnet_support_map=az_multiple_sn_support_map)
        share['status'] = constants.STATUS_CREATING
        share['host'] = None

        quota.QUOTAS.reserve.assert_called_once()
        get_all_azs_sns = self.api._get_all_availability_zones_with_subnets
        get_all_azs_sns.assert_called_once_with(
            self.context, fake_share_network_id)
        quota.QUOTAS.commit.assert_called_once()
        self.api.create_instance.assert_called_once_with(
            self.context, share, share_network_id=fake_share_network_id,
            host=None, availability_zone=None, share_group=None,
            share_group_snapshot_member=None, share_type_id=None,
            availability_zones=expected_azs,
            az_request_multiple_subnet_support_map=compatible_azs_multiple,
            snapshot_host=None,
            scheduler_hints=None
        )
        db_api.share_get.assert_called_once()

    @ddt.data(
        {'availability_zones': None, 'compatible_azs_name': [],
         'compatible_azs_multiple': []},
        {'availability_zones': ['fake_az_1'],
         'compatible_azs_name': ['fake_az_2'], 'compatible_azs_multiple': []}
    )
    @ddt.unpack
    def test_create_share_with_subnets_invalid_azs(self, availability_zones,
                                                   compatible_azs_name,
                                                   compatible_azs_multiple):
        share, share_data = self._setup_create_mocks()
        reservation = 'fake'
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value=reservation))
        self.mock_object(self.api, '_get_all_availability_zones_with_subnets',
                         mock.Mock(return_value=[compatible_azs_name,
                                                 compatible_azs_multiple]))
        self.mock_object(quota.QUOTAS, 'commit')
        self.mock_object(self.api, 'create_instance')
        self.mock_object(db_api, 'share_get')
        fake_share_network_id = 'fake_sn_id'

        self.assertRaises(
            exception.InvalidInput,
            self.api.create,
            self.context, share_data['share_proto'], share_data['size'],
            share_data['display_name'], share_data['display_description'],
            share_network_id=fake_share_network_id,
            availability_zones=availability_zones)

        quota.QUOTAS.reserve.assert_called_once()
        get_all_azs_sns = self.api._get_all_availability_zones_with_subnets
        get_all_azs_sns.assert_called_once_with(
            self.context, fake_share_network_id)

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
               'expected_exception': exception.ShareSizeExceedsAvailableQuota,
               'replication_type': None},
              {'overs': {'shares': 'fake'},
               'expected_exception': exception.ShareLimitExceeded,
               'replication_type': None},
              {'overs': {'replica_gigabytes': 'fake'},
               'expected_exception':
                   exception.ShareReplicaSizeExceedsAvailableQuota,
               'replication_type': constants.REPLICATION_TYPE_READABLE},
              {'overs': {'share_replicas': 'fake'},
               'expected_exception': exception.ShareReplicasLimitExceeded,
               'replication_type': constants.REPLICATION_TYPE_READABLE})
    @ddt.unpack
    def test_create_share_over_quota(self, overs, expected_exception,
                                     replication_type):
        extra_specs = {'replication_type': replication_type}
        share_type = db_utils.create_share_type(extra_specs=extra_specs)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        share, share_data = self._setup_create_mocks(
            share_type_id=share_type['id'])

        az = share_data.pop('availability_zone')

        usages = {'gigabytes': {'reserved': 5, 'in_use': 5},
                  'shares': {'reserved': 10, 'in_use': 10},
                  'replica_gigabytes': {'reserved': 5, 'in_use': 5},
                  'share_replicas': {'reserved': 10, 'in_use': 10}}

        quotas = {'gigabytes': 5, 'shares': 10,
                  'replica_gigabytes': 5, 'share_replicas': 10}

        exc = exception.OverQuota(overs=overs, usages=usages, quotas=quotas)
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(side_effect=exc))

        if replication_type:
            # Prevent the raising of an exception, to force the call to the
            # function check_if_replica_quotas_exceeded
            self.mock_object(self.api, 'check_if_share_quotas_exceeded')

        self.assertRaises(
            expected_exception,
            self.api.create,
            self.context,
            share_data['share_proto'],
            share_data['size'],
            share_data['display_name'],
            share_data['display_description'],
            availability_zone=az,
            share_type=share_type
        )

        if replication_type:
            quota.QUOTAS.reserve.assert_called_once_with(
                self.context, share_type_id=share_type['id'],
                gigabytes=1, shares=1, share_replicas=1, replica_gigabytes=1)
        else:
            quota.QUOTAS.reserve.assert_called_once_with(
                self.context, share_type_id=share_type['id'],
                shares=1, gigabytes=share_data['size'])

    @ddt.data({'overs': {'per_share_gigabytes': 'fake'},
               'expected_exception': exception.ShareSizeExceedsLimit})
    @ddt.unpack
    def test_create_share_over_per_share_quota(self, overs,
                                               expected_exception):
        share, share_data = self._setup_create_mocks()

        quota.CONF.set_default("per_share_gigabytes", 5, 'quota')
        share_data['size'] = 20

        usages = {'per_share_gigabytes': {'reserved': 0, 'in_use': 0}}
        quotas = {'per_share_gigabytes': 10}
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

        quota.QUOTAS.rollback.assert_called_once_with(
            self.context, reservation, share_type_id=None)
        db_api.share_delete.assert_called_once_with(self.context, share['id'])

    def test_create_share_instance_with_host_and_az(self):
        host, share, share_instance = self._setup_create_instance_mocks()

        self.api.create_instance(self.context, share, host=host,
                                 availability_zone='fake',
                                 share_type_id='fake_share_type')

        db_api.share_instance_create.assert_called_once_with(
            self.context, share['id'],
            {
                'share_network_id': None,
                'status': constants.STATUS_CREATING,
                'scheduled_at': self.dt_utc,
                'host': host,
                'availability_zone_id': 'fake_id',
                'share_type_id': 'fake_share_type',
                'cast_rules_to_readonly': False,
            }
        )
        db_api.share_type_get.assert_called_once_with(
            self.context, share_instance['share_type_id'])
        self.api.share_rpcapi.create_share_instance.assert_called_once_with(
            self.context,
            share_instance,
            host,
            request_spec=mock.ANY,
            filter_properties={'scheduler_hints': None},
            snapshot_id=share['snapshot_id'],
        )
        self.assertFalse(
            self.api.scheduler_rpcapi.create_share_instance.called)

    def test_create_share_instance_without_host(self):
        _, share, share_instance = self._setup_create_instance_mocks()

        self.api.create_instance(self.context, share)

        (self.api.scheduler_rpcapi.create_share_instance.
            assert_called_once_with(
                self.context, request_spec=mock.ANY,
                filter_properties={'scheduler_hints': None}))
        self.assertFalse(self.api.share_rpcapi.create_share_instance.called)

    def test_create_share_instance_from_snapshot(self):
        snapshot, share, _, _ = self._setup_create_from_snapshot_mocks()

        request_spec, share_instance = (
            self.api.create_share_instance_and_get_request_spec(
                self.context, share)
        )

        self.assertIsNotNone(share_instance)
        self.assertEqual(share['id'],
                         request_spec['share_instance_properties']['share_id'])
        self.assertEqual(share['snapshot_id'], request_spec['snapshot_id'])

        self.assertFalse(
            self.api.share_rpcapi.create_share_instance_and_get_request_spec
                .called)

    def test_create_instance_share_group_snapshot_member(self):
        fake_req_spec = {
            'share_properties': 'fake_share_properties',
            'share_instance_properties': 'fake_share_instance_properties',
        }
        share = fakes.fake_share()
        member_info = {
            'host': 'host',
            'share_network_id': 'share_network_id',
            'share_server_id': 'share_server_id',
        }

        fake_instance = fakes.fake_share_instance(
            share_id=share['id'], **member_info)
        sg_snap_member = {'share_instance': fake_instance}
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        mock_share_rpcapi_call = self.mock_object(self.share_rpcapi,
                                                  'create_share_instance')
        mock_scheduler_rpcapi_call = self.mock_object(self.scheduler_rpcapi,
                                                      'create_share_instance')
        mock_db_share_instance_update = self.mock_object(
            db_api, 'share_instance_update')
        self.mock_object(
            share_api.API, 'create_share_instance_and_get_request_spec',
            mock.Mock(return_value=(fake_req_spec, fake_instance)))

        retval = self.api.create_instance(
            self.context, fakes.fake_share(),
            share_group_snapshot_member=sg_snap_member)

        self.assertIsNone(retval)
        mock_db_share_instance_update.assert_called_once_with(
            self.context, fake_instance['id'], member_info)
        self.assertFalse(mock_scheduler_rpcapi_call.called)
        self.assertFalse(mock_share_rpcapi_call.called)

    def test_get_share_attributes_from_share_type(self):

        share_type = {
            'extra_specs': {
                'snapshot_support': True,
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
                'mount_snapshot_support': False,
                'replication_type': 'dr',
            }
        }

        result = self.api.get_share_attributes_from_share_type(share_type)

        self.assertEqual(share_type['extra_specs'], result)

    @ddt.data({}, {'extra_specs': {}}, None)
    def test_get_share_attributes_from_share_type_defaults(self, share_type):

        result = self.api.get_share_attributes_from_share_type(share_type)

        expected = {
            'snapshot_support': False,
            'create_share_from_snapshot_support': False,
            'revert_to_snapshot_support': False,
            'mount_snapshot_support': False,
            'replication_type': None,
        }
        self.assertEqual(expected, result)

    @ddt.data({'extra_specs': {'snapshot_support': 'fake'}},
              {'extra_specs': {'create_share_from_snapshot_support': 'fake'}})
    def test_get_share_attributes_from_share_type_invalid(self, share_type):

        self.assertRaises(exception.InvalidExtraSpec,
                          self.api.get_share_attributes_from_share_type,
                          share_type)

    @ddt.data(
        {'replication_type': 'dr', 'dhss': False, 'share_server_id': None},
        {'replication_type': 'readable', 'dhss': False,
         'share_server_id': None},
        {'replication_type': None, 'dhss': False, 'share_server_id': None},
        {'replication_type': None, 'dhss': True, 'share_server_id': 'fake'}
    )
    @ddt.unpack
    def test_manage_new(self, replication_type, dhss, share_server_id):
        share_data = {
            'host': 'fake',
            'export_location_path': 'fake',
            'share_proto': 'fake',
            'share_type_id': 'fake',
        }
        if dhss:
            share_data['share_server_id'] = share_server_id
        driver_options = {}
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        fake_subnet = db_utils.create_share_network_subnet(
            share_network_id='fake')
        share_server = db_utils.create_share_server(
            status=constants.STATUS_ACTIVE, id=share_server_id,
            share_network_subnets=[fake_subnet])
        share_network = db_utils.create_share_network(id='fake')
        fake_share_data = {
            'id': 'fakeid',
            'status': constants.STATUS_CREATING,
        }
        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
                'replication_type': replication_type,
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
                'mount_snapshot_support': False,
                'driver_handles_share_servers': dhss,
            },
        }

        share = db_api.share_create(self.context, fake_share_data)

        self.mock_object(self.scheduler_rpcapi, 'manage_share')
        self.mock_object(db_api, 'share_create',
                         mock.Mock(return_value=share))
        self.mock_object(db_api, 'share_export_locations_update')
        self.mock_object(db_api, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.mock_object(db_api, 'share_instances_get_all',
                         mock.Mock(return_value=[]))
        self.mock_object(db_api, 'share_network_get',
                         mock.Mock(return_value=share_network))

        self.api.manage(self.context, copy.deepcopy(share_data),
                        driver_options)

        share_data.update({
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_MANAGING,
            'scheduled_at': date,
            'snapshot_support': fake_type['extra_specs']['snapshot_support'],
            'create_share_from_snapshot_support':
                fake_type['extra_specs']['create_share_from_snapshot_support'],
            'revert_to_snapshot_support':
                fake_type['extra_specs']['revert_to_snapshot_support'],
            'mount_snapshot_support':
                fake_type['extra_specs']['mount_snapshot_support'],
            'replication_type': replication_type,
        })

        expected_request_spec = self._get_request_spec_dict(
            share, fake_type, self.context, size=0,
            share_proto=share_data['share_proto'],
            host=share_data['host'])

        if dhss:
            share_data.update({
                'share_network_id': fake_subnet['share_network_id']})
        export_location = share_data.pop('export_location_path')
        filters = {'export_location_path': export_location,
                   'host': share_data['host']
                   }
        if share_server_id:
            filters['share_server_id'] = share_server_id
        db_api.share_instances_get_all.assert_called_once_with(
            self.context, filters=filters)
        db_api.share_create.assert_called_once_with(self.context, share_data)
        db_api.share_get.assert_called_once_with(self.context, share['id'])
        db_api.share_export_locations_update.assert_called_once_with(
            self.context, share.instance['id'], export_location)
        self.scheduler_rpcapi.manage_share.assert_called_once_with(
            self.context, share['id'], driver_options, expected_request_spec)
        if dhss:
            db_api.share_server_get.assert_called_once_with(
                self.context, share_data['share_server_id'])

    @ddt.data((True, exception.InvalidInput, True),
              (True, exception.InvalidInput, False),
              (False, exception.InvalidInput, True),
              (True, exception.InvalidInput, True))
    @ddt.unpack
    def test_manage_new_dhss_true_and_false(self, dhss, exception_type,
                                            has_share_server_id):
        share_data = {
            'host': 'fake',
            'export_location_path': 'fake',
            'share_proto': 'fake',
            'share_type_id': 'fake',
        }
        if has_share_server_id:
            share_data['share_server_id'] = 'fake'

        driver_options = {}
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
                'mount_snapshot_support': False,
                'driver_handles_share_servers': dhss,
            },
        }

        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))
        self.mock_object(db_api, 'share_instances_get_all',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception_type,
                          self.api.manage,
                          self.context,
                          share_data=share_data,
                          driver_options=driver_options
                          )
        share_types.get_share_type.assert_called_once_with(
            self.context, share_data['share_type_id']
        )
        filters = {'export_location_path': share_data['export_location_path'],
                   'host': share_data['host']
                   }
        if has_share_server_id:
            filters['share_server_id'] = 'fake'
        db_api.share_instances_get_all.assert_called_once_with(
            self.context, filters=filters)

    def test_manage_new_share_server_not_found(self):
        share_data = {
            'host': 'fake',
            'export_location_path': 'fake',
            'share_proto': 'fake',
            'share_type_id': 'fake',
            'share_server_id': 'fake'

        }
        driver_options = {}
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date

        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
                'replication_type': 'dr',
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
                'mount_snapshot_support': False,
                'driver_handles_share_servers': True,
            },
        }

        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))
        self.mock_object(db_api, 'share_instances_get_all',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.InvalidInput,
                          self.api.manage,
                          self.context,
                          share_data=share_data,
                          driver_options=driver_options
                          )
        share_types.get_share_type.assert_called_once_with(
            self.context, share_data['share_type_id']
        )
        db_api.share_instances_get_all.assert_called_once_with(
            self.context, filters={
                'export_location_path': share_data['export_location_path'],
                'host': share_data['host'],
                'share_server_id': share_data['share_server_id']
            }
        )

    def test_manage_new_share_server_not_active(self):
        share_data = {
            'host': 'fake',
            'export_location_path': 'fake',
            'share_proto': 'fake',
            'share_type_id': 'fake',
            'share_server_id': 'fake'

        }
        fake_share_data = {
            'id': 'fakeid',
            'status': constants.STATUS_ERROR,
        }
        driver_options = {}
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date

        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
                'replication_type': 'dr',
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
                'mount_snapshot_support': False,
                'driver_handles_share_servers': True,
            },
        }

        share = db_api.share_create(self.context, fake_share_data)

        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))
        self.mock_object(db_api, 'share_instances_get_all',
                         mock.Mock(return_value=[]))
        self.mock_object(db_api, 'share_server_get',
                         mock.Mock(return_value=share))

        self.assertRaises(exception.InvalidShareServer,
                          self.api.manage,
                          self.context,
                          share_data=share_data,
                          driver_options=driver_options
                          )
        share_types.get_share_type.assert_called_once_with(
            self.context, share_data['share_type_id']
        )
        db_api.share_instances_get_all.assert_called_once_with(
            self.context, filters={
                'export_location_path': share_data['export_location_path'],
                'host': share_data['host'],
                'share_server_id': share_data['share_server_id']
            }
        )
        db_api.share_server_get.assert_called_once_with(
            self.context, share_data['share_server_id']
        )

    @ddt.data(constants.STATUS_MANAGE_ERROR, constants.STATUS_AVAILABLE)
    def test_manage_duplicate(self, status):
        share_data = {
            'host': 'fake',
            'export_location_path': 'fake',
            'share_proto': 'fake',
            'share_type_id': 'fake',
        }
        driver_options = {}
        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
                'create_share_from_snapshot_support': False,
                'driver_handles_share_servers': False,
            },
        }
        already_managed = [{'id': 'fake', 'status': status}]
        self.mock_object(db_api, 'share_instances_get_all',
                         mock.Mock(return_value=already_managed))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))
        self.assertRaises(exception.InvalidShare, self.api.manage,
                          self.context, share_data, driver_options)

    def _get_request_spec_dict(self, share, share_type, context, **kwargs):

        if share is None:
            share = {'instance': {}}

        share_instance = share['instance']

        share_properties = {
            'size': kwargs.get('size', share.get('size')),
            'user_id': kwargs.get('user_id', share.get('user_id')),
            'project_id': kwargs.get('project_id', share.get('project_id')),
            'metadata': db_api.share_metadata_get(context, share['id']),
            'snapshot_support': kwargs.get(
                'snapshot_support',
                share_type['extra_specs']['snapshot_support']),
            'create_share_from_snapshot_support': kwargs.get(
                'create_share_from_snapshot_support',
                share_type['extra_specs'].get(
                    'create_share_from_snapshot_support')),
            'revert_to_snapshot_support': kwargs.get(
                'revert_to_snapshot_support',
                share_type['extra_specs'].get('revert_to_snapshot_support')),
            'mount_snapshot_support': kwargs.get(
                'mount_snapshot_support',
                share_type['extra_specs'].get('mount_snapshot_support')),
            'share_proto': kwargs.get('share_proto', share.get('share_proto')),
            'share_type_id': share_type['id'],
            'is_public': kwargs.get('is_public', share.get('is_public')),
            'share_group_id': kwargs.get(
                'share_group_id', share.get('share_group_id')),
            'source_share_group_snapshot_member_id': kwargs.get(
                'source_share_group_snapshot_member_id',
                share.get('source_share_group_snapshot_member_id')),
            'snapshot_id': kwargs.get('snapshot_id', share.get('snapshot_id')),
        }
        share_instance_properties = {
            'availability_zone_id': kwargs.get(
                'availability_zone_id',
                share_instance.get('availability_zone_id')),
            'share_network_id': kwargs.get(
                'share_network_id', share_instance.get('share_network_id')),
            'share_server_id': kwargs.get(
                'share_server_id', share_instance.get('share_server_id')),
            'share_id': kwargs.get('share_id', share_instance.get('share_id')),
            'host': kwargs.get('host', share_instance.get('host')),
            'status': kwargs.get('status', share_instance.get('status')),
        }

        request_spec = {
            'share_properties': share_properties,
            'share_instance_properties': share_instance_properties,
            'share_type': share_type,
            'share_id': share.get('id'),
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

    def test_unmanage_locked_share(self):
        self.mock_object(
            self.api.db,
            'resource_lock_get_all',
            mock.Mock(return_value=([{'id': 'l1'}, {'id': 'l2'}], None))
        )
        share = db_utils.create_share(
            id='fakeid',
            host='fake',
            size='1',
            status=constants.STATUS_AVAILABLE,
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            task_state=None)
        self.mock_object(db_api, 'share_update', mock.Mock())

        self.assertRaises(exception.InvalidShare,
                          self.api.unmanage,
                          self.context,
                          share)

        # lock check decorator executed first, nothing else is invoked
        self.share_rpcapi.unmanage_share.assert_not_called()
        db_api.share_update.assert_not_called()

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
                self.context, share_type_id=None,
                snapshot_gigabytes=1, snapshots=1)
            quota.QUOTAS.commit.assert_called_once_with(
                self.context, 'reservation', share_type_id=None)
            db_api.share_snapshot_create.assert_called_once_with(
                self.context, options)

    def test_create_snapshot_space_quota_exceeded(self):

        share = fakes.fake_share(
            id=uuidutils.generate_uuid(), size=1, project_id='fake_project',
            user_id='fake_user', has_replicas=False, status='available')
        usages = {'snapshot_gigabytes': {'reserved': 10, 'in_use': 0}}
        quotas = {'snapshot_gigabytes': 10}
        side_effect = exception.OverQuota(
            overs='snapshot_gigabytes', usages=usages, quotas=quotas)
        self.mock_object(
            quota.QUOTAS, 'reserve', mock.Mock(side_effect=side_effect))
        mock_snap_create = self.mock_object(db_api, 'share_snapshot_create')

        self.assertRaises(exception.SnapshotSizeExceedsAvailableQuota,
                          self.api.create_snapshot,
                          self.context,
                          share,
                          'fake_name',
                          'fake_description')
        mock_snap_create.assert_not_called()

    def test_create_snapshot_count_quota_exceeded(self):

        share = fakes.fake_share(
            id=uuidutils.generate_uuid(), size=1, project_id='fake_project',
            user_id='fake_user', has_replicas=False, status='available')
        usages = {'snapshots': {'reserved': 10, 'in_use': 0}}
        quotas = {'snapshots': 10}
        side_effect = exception.OverQuota(
            overs='snapshots', usages=usages, quotas=quotas)
        self.mock_object(
            quota.QUOTAS, 'reserve', mock.Mock(side_effect=side_effect))
        mock_snap_create = self.mock_object(db_api, 'share_snapshot_create')

        self.assertRaises(exception.SnapshotLimitExceeded,
                          self.api.create_snapshot,
                          self.context,
                          share,
                          'fake_name',
                          'fake_description')
        mock_snap_create.assert_not_called()

    def test_manage_snapshot_share_not_found(self):
        snapshot = fakes.fake_snapshot(share_id='fake_share',
                                       as_primitive=True)
        mock_share_get_call = self.mock_object(
            db_api, 'share_get', mock.Mock(side_effect=exception.NotFound))
        mock_db_snapshot_call = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share')

        self.assertRaises(exception.ShareNotFound,
                          self.api.manage_snapshot,
                          self.context,
                          snapshot,
                          {})
        self.assertFalse(mock_db_snapshot_call.called)
        mock_share_get_call.assert_called_once_with(
            self.context, snapshot['share_id'])

    def test_manage_snapshot_share_has_replicas(self):
        share_ref = fakes.fake_share(
            has_replicas=True, status=constants.STATUS_AVAILABLE)
        self.mock_object(
            db_api, 'share_get', mock.Mock(return_value=share_ref))
        snapshot = fakes.fake_snapshot(create_instance=True, as_primitive=True)
        mock_db_snapshot_get_all_for_share_call = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share')

        self.assertRaises(exception.InvalidShare,
                          self.api.manage_snapshot,
                          context,
                          snapshot,
                          {})
        self.assertFalse(mock_db_snapshot_get_all_for_share_call.called)

    def test_manage_snapshot_already_managed(self):
        share_ref = fakes.fake_share(
            has_replicas=False, status=constants.STATUS_AVAILABLE)
        snapshot = fakes.fake_snapshot(create_instance=True, as_primitive=True)
        self.mock_object(
            db_api, 'share_get', mock.Mock(return_value=share_ref))
        mock_db_snapshot_call = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share', mock.Mock(
                return_value=[snapshot]))
        mock_db_snapshot_create_call = self.mock_object(
            db_api, 'share_snapshot_create')

        self.assertRaises(exception.ManageInvalidShareSnapshot,
                          self.api.manage_snapshot,
                          self.context,
                          snapshot,
                          {})
        mock_db_snapshot_call.assert_called_once_with(
            self.context, snapshot['share_id'])
        self.assertFalse(mock_db_snapshot_create_call.called)

    def test_manage_snapshot(self):
        share_ref = fakes.fake_share(
            has_replicas=False, status=constants.STATUS_AVAILABLE,
            host='fake_host')
        existing_snapshot = fakes.fake_snapshot(
            create_instance=True, share_id=share_ref['id'])
        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=[existing_snapshot]))
        snapshot_data = {
            'share_id': share_ref['id'],
            'provider_location': 'someproviderlocation',
        }
        expected_snapshot_data = {
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
            'status': constants.STATUS_MANAGING,
            'share_size': share_ref['size'],
            'progress': '0%',
            'share_proto': share_ref['share_proto'],
        }
        expected_snapshot_data.update(**snapshot_data)
        snapshot = fakes.fake_snapshot(
            create_instance=True, **expected_snapshot_data)
        self.mock_object(
            db_api, 'share_get', mock.Mock(return_value=share_ref))
        mock_db_snapshot_create_call = self.mock_object(
            db_api, 'share_snapshot_create', mock.Mock(return_value=snapshot))
        mock_rpc_call = self.mock_object(self.share_rpcapi, 'manage_snapshot',
                                         mock.Mock(return_value=snapshot))

        new_snap = self.api.manage_snapshot(
            self.context, snapshot_data, {})

        self.assertEqual(new_snap, snapshot)
        mock_db_snapshot_create_call.assert_called_once_with(
            self.context, expected_snapshot_data)
        mock_rpc_call.assert_called_once_with(
            self.context, snapshot, share_ref['host'], {})

    def test_manage_share_server(self):
        """Tests manage share server"""
        host = 'fake_host'
        fake_share_network = {
            'id': 'fake_net_id'
        }
        fake_share_net_subnet = [{
            'id': 'fake_subnet_id',
            'share_network_id': fake_share_network['id']
        }]
        identifier = 'fake_identifier'
        values = {
            'host': host,
            'share_network_subnets': [fake_share_net_subnet],
            'status': constants.STATUS_MANAGING,
            'is_auto_deletable': False,
            'identifier': identifier,
        }

        server_managing = {
            'id': 'fake_server_id',
            'status': constants.STATUS_MANAGING,
            'host': host,
            'share_network_subnets': [fake_share_net_subnet],
            'is_auto_deletable': False,
            'identifier': identifier,
        }

        mock_share_server_search = self.mock_object(
            db_api, 'share_server_search_by_identifier',
            mock.Mock(side_effect=exception.ShareServerNotFound('fake')))

        mock_share_server_get = self.mock_object(
            db_api, 'share_server_get',
            mock.Mock(
                return_value=server_managing)
        )
        mock_share_server_create = self.mock_object(
            db_api, 'share_server_create',
            mock.Mock(return_value=server_managing)
        )
        result = self.api.manage_share_server(
            self.context, 'fake_identifier', host, fake_share_net_subnet,
            {'opt1': 'val1', 'opt2': 'val2'}
        )

        mock_share_server_create.assert_called_once_with(
            self.context, values)

        mock_share_server_get.assert_called_once_with(
            self.context, 'fake_server_id')

        mock_share_server_search.assert_called_once_with(
            self.context, 'fake_identifier')

        result_dict = {
            'host': result['host'],
            'share_network_subnets': result['share_network_subnets'],
            'status': result['status'],
            'is_auto_deletable': result['is_auto_deletable'],
            'identifier': result['identifier'],
        }
        self.assertEqual(values, result_dict)

    def test_manage_share_server_invalid(self):

        server = {'identifier': 'fake_server'}

        mock_share_server_search = self.mock_object(
            db_api, 'share_server_search_by_identifier',
            mock.Mock(return_value=[server]))

        self.assertRaises(
            exception.InvalidInput, self.api.manage_share_server,
            self.context, 'invalid_identifier', 'fake_host', 'fake_share_net',
            {})

        mock_share_server_search.assert_called_once_with(
            self.context, 'invalid_identifier')

    def test_unmanage_snapshot(self):
        fake_host = 'fake_host'
        snapshot_data = {
            'status': constants.STATUS_UNMANAGING,
            'terminated_at': timeutils.utcnow(),
        }
        snapshot = fakes.fake_snapshot(
            create_instance=True, share_instance_id='id2', **snapshot_data)
        mock_db_snap_update_call = self.mock_object(
            db_api, 'share_snapshot_update', mock.Mock(return_value=snapshot))
        mock_rpc_call = self.mock_object(
            self.share_rpcapi, 'unmanage_snapshot')

        retval = self.api.unmanage_snapshot(
            self.context, snapshot, fake_host)

        self.assertIsNone(retval)
        mock_db_snap_update_call.assert_called_once_with(
            self.context, snapshot['id'], snapshot_data)
        mock_rpc_call.assert_called_once_with(
            self.context, snapshot, fake_host)

    def test_unmanage_share_server(self):
        shr1 = {}
        share_server = db_utils.create_share_server(**shr1)
        update_data = {'status': constants.STATUS_UNMANAGING,
                       'terminated_at': timeutils.utcnow()}

        mock_share_instances_get_all = self.mock_object(
            db_api, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value={}))
        mock_share_group_get_all = self.mock_object(
            db_api, 'share_group_get_all_by_share_server',
            mock.Mock(return_value={}))
        mock_share_server_update = self.mock_object(
            db_api, 'share_server_update',
            mock.Mock(return_value=share_server))

        mock_rpc = self.mock_object(
            self.api.share_rpcapi, 'unmanage_share_server')

        self.api.unmanage_share_server(self.context, share_server, True)

        mock_share_instances_get_all.assert_called_once_with(
            self.context, share_server['id']
        )
        mock_share_group_get_all.assert_called_once_with(
            self.context, share_server['id']
        )
        mock_share_server_update.assert_called_once_with(
            self.context, share_server['id'], update_data
        )

        mock_rpc.assert_called_once_with(
            self.context, share_server, force=True)

    def test_unmanage_share_server_in_use(self):
        fake_share = db_utils.create_share()
        fake_share_server = db_utils.create_share_server()

        fake_share_instance = db_utils.create_share_instance(
            share_id=fake_share['id'])
        share_instance_get_all_mock = self.mock_object(
            db_api, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=fake_share_instance)
        )

        self.assertRaises(exception.ShareServerInUse,
                          self.api.unmanage_share_server,
                          self.context,
                          fake_share_server, True)
        share_instance_get_all_mock.assert_called_once_with(
            self.context, fake_share_server['id']
        )

    def test_unmanage_share_server_in_use_share_groups(self):
        fake_share_server = db_utils.create_share_server()
        fake_share_groups = db_utils.create_share_group()

        share_instance_get_all_mock = self.mock_object(
            db_api, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value={})
        )
        group_get_all_mock = self.mock_object(
            db_api, 'share_group_get_all_by_share_server',
            mock.Mock(return_value=fake_share_groups)
        )

        self.assertRaises(exception.ShareServerInUse,
                          self.api.unmanage_share_server,
                          self.context,
                          fake_share_server, True)
        share_instance_get_all_mock.assert_called_once_with(
            self.context, fake_share_server['id']
        )
        group_get_all_mock.assert_called_once_with(
            self.context, fake_share_server['id']
        )

    @ddt.data(True, False)
    def test_revert_to_snapshot(self, has_replicas):

        share = fakes.fake_share(id=uuidutils.generate_uuid(),
                                 has_replicas=has_replicas)
        self.mock_object(db_api, 'share_get', mock.Mock(return_value=share))
        mock_handle_revert_to_snapshot_quotas = self.mock_object(
            self.api, '_handle_revert_to_snapshot_quotas',
            mock.Mock(return_value='fake_reservations'))
        mock_revert_to_replicated_snapshot = self.mock_object(
            self.api, '_revert_to_replicated_snapshot')
        mock_revert_to_snapshot = self.mock_object(
            self.api, '_revert_to_snapshot')
        snapshot = fakes.fake_snapshot(share_id=share['id'])

        self.api.revert_to_snapshot(self.context, share, snapshot)

        mock_handle_revert_to_snapshot_quotas.assert_called_once_with(
            self.context, share, snapshot)
        if not has_replicas:
            self.assertFalse(mock_revert_to_replicated_snapshot.called)
            mock_revert_to_snapshot.assert_called_once_with(
                self.context, share, snapshot, 'fake_reservations')
        else:
            mock_revert_to_replicated_snapshot.assert_called_once_with(
                self.context, share, snapshot, 'fake_reservations')
            self.assertFalse(mock_revert_to_snapshot.called)

    @ddt.data(None, 'fake_reservations')
    def test_revert_to_snapshot_exception(self, reservations):

        share = fakes.fake_share(id=uuidutils.generate_uuid(),
                                 has_replicas=False)
        self.mock_object(db_api, 'share_get', mock.Mock(return_value=share))
        self.mock_object(
            self.api, '_handle_revert_to_snapshot_quotas',
            mock.Mock(return_value=reservations))
        side_effect = exception.ReplicationException(reason='error')
        self.mock_object(
            self.api, '_revert_to_snapshot',
            mock.Mock(side_effect=side_effect))
        mock_quotas_rollback = self.mock_object(quota.QUOTAS, 'rollback')
        snapshot = fakes.fake_snapshot(share_id=share['id'])

        self.assertRaises(exception.ReplicationException,
                          self.api.revert_to_snapshot,
                          self.context,
                          share,
                          snapshot)

        if reservations is not None:
            mock_quotas_rollback.assert_called_once_with(
                self.context, reservations,
                share_type_id=share['instance']['share_type_id'])
        else:
            self.assertFalse(mock_quotas_rollback.called)

    def test_handle_revert_to_snapshot_quotas(self):

        share = fakes.fake_share(
            id=uuidutils.generate_uuid(), size=1, project_id='fake_project',
            user_id='fake_user', has_replicas=False)
        snapshot = fakes.fake_snapshot(
            id=uuidutils.generate_uuid(), share_id=share['id'], size=1)
        mock_quotas_reserve = self.mock_object(quota.QUOTAS, 'reserve')

        result = self.api._handle_revert_to_snapshot_quotas(
            self.context, share, snapshot)

        self.assertIsNone(result)
        self.assertFalse(mock_quotas_reserve.called)

    def test_handle_revert_to_snapshot_quotas_different_size(self):

        share = fakes.fake_share(
            id=uuidutils.generate_uuid(), size=1, project_id='fake_project',
            user_id='fake_user', has_replicas=False)
        snapshot = fakes.fake_snapshot(
            id=uuidutils.generate_uuid(), share_id=share['id'], size=2)
        mock_quotas_reserve = self.mock_object(
            quota.QUOTAS, 'reserve',
            mock.Mock(return_value='fake_reservations'))

        result = self.api._handle_revert_to_snapshot_quotas(
            self.context, share, snapshot)

        self.assertEqual('fake_reservations', result)
        mock_quotas_reserve.assert_called_once_with(
            self.context, project_id='fake_project', gigabytes=1,
            share_type_id=share['instance']['share_type_id'],
            user_id='fake_user')

    def test_handle_revert_to_snapshot_quotas_quota_exceeded(self):

        share = fakes.fake_share(
            id=uuidutils.generate_uuid(), size=1, project_id='fake_project',
            user_id='fake_user', has_replicas=False)
        snapshot = fakes.fake_snapshot(
            id=uuidutils.generate_uuid(), share_id=share['id'], size=2)
        usages = {'gigabytes': {'reserved': 10, 'in_use': 0}}
        quotas = {'gigabytes': 10}
        side_effect = exception.OverQuota(
            overs='fake', usages=usages, quotas=quotas)
        self.mock_object(
            quota.QUOTAS, 'reserve', mock.Mock(side_effect=side_effect))

        self.assertRaises(exception.ShareSizeExceedsAvailableQuota,
                          self.api._handle_revert_to_snapshot_quotas,
                          self.context,
                          share,
                          snapshot)

    def test__revert_to_snapshot(self):

        share = fakes.fake_share(
            id=uuidutils.generate_uuid(), size=1, project_id='fake_project',
            user_id='fake_user', has_replicas=False)
        snapshot = fakes.fake_snapshot(
            id=uuidutils.generate_uuid(), share_id=share['id'], size=2)
        mock_share_update = self.mock_object(db_api, 'share_update')
        mock_share_snapshot_update = self.mock_object(
            db_api, 'share_snapshot_update')
        mock_revert_rpc_call = self.mock_object(
            self.share_rpcapi, 'revert_to_snapshot')

        self.api._revert_to_snapshot(
            self.context, share, snapshot, 'fake_reservations')

        mock_share_update.assert_called_once_with(
            self.context, share['id'], {'status': constants.STATUS_REVERTING})
        mock_share_snapshot_update.assert_called_once_with(
            self.context, snapshot['id'],
            {'status': constants.STATUS_RESTORING})
        mock_revert_rpc_call.assert_called_once_with(
            self.context, share, snapshot, share['instance']['host'],
            'fake_reservations')

    def test_revert_to_replicated_snapshot(self):

        share = fakes.fake_share(
            has_replicas=True, status=constants.STATUS_AVAILABLE)
        snapshot = fakes.fake_snapshot(share_instance_id='id1')
        snapshot_instance = fakes.fake_snapshot_instance(
            base_snapshot=snapshot, id='sid1')
        replicas = [
            fakes.fake_replica(
                id='rid1', replica_state=constants.REPLICA_STATE_ACTIVE),
            fakes.fake_replica(
                id='rid2', replica_state=constants.REPLICA_STATE_IN_SYNC),
        ]
        self.mock_object(
            db_api, 'share_replicas_get_available_active_replica',
            mock.Mock(return_value=replicas[0]))
        self.mock_object(
            db_api, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=[snapshot_instance]))
        mock_share_replica_update = self.mock_object(
            db_api, 'share_replica_update')
        mock_share_snapshot_instance_update = self.mock_object(
            db_api, 'share_snapshot_instance_update')
        mock_revert_rpc_call = self.mock_object(
            self.share_rpcapi, 'revert_to_snapshot')

        self.api._revert_to_replicated_snapshot(
            self.context, share, snapshot, 'fake_reservations')

        mock_share_replica_update.assert_called_once_with(
            self.context, 'rid1', {'status': constants.STATUS_REVERTING})
        mock_share_snapshot_instance_update.assert_called_once_with(
            self.context, 'sid1', {'status': constants.STATUS_RESTORING})
        mock_revert_rpc_call.assert_called_once_with(
            self.context, share, snapshot, replicas[0]['host'],
            'fake_reservations')

    def test_revert_to_replicated_snapshot_no_active_replica(self):

        share = fakes.fake_share(
            has_replicas=True, status=constants.STATUS_AVAILABLE)
        snapshot = fakes.fake_snapshot(share_instance_id='id1')
        self.mock_object(
            db_api, 'share_replicas_get_available_active_replica',
            mock.Mock(return_value=None))

        self.assertRaises(exception.ReplicationException,
                          self.api._revert_to_replicated_snapshot,
                          self.context,
                          share,
                          snapshot,
                          'fake_reservations')

    def test_revert_to_replicated_snapshot_no_snapshot_instance(self):

        share = fakes.fake_share(
            has_replicas=True, status=constants.STATUS_AVAILABLE)
        snapshot = fakes.fake_snapshot(share_instance_id='id1')
        replicas = [
            fakes.fake_replica(
                id='rid1', replica_state=constants.REPLICA_STATE_ACTIVE),
            fakes.fake_replica(
                id='rid2', replica_state=constants.REPLICA_STATE_IN_SYNC),
        ]
        self.mock_object(
            db_api, 'share_replicas_get_available_active_replica',
            mock.Mock(return_value=replicas[0]))
        self.mock_object(
            db_api, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=[None]))

        self.assertRaises(exception.ReplicationException,
                          self.api._revert_to_replicated_snapshot,
                          self.context,
                          share,
                          snapshot,
                          'fake_reservations')

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
    @mock.patch.object(db_api, 'share_group_get_all_by_share_server',
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
        (db_api.share_group_get_all_by_share_server.
            assert_called_once_with(self.context, server['id']))
        self.share_rpcapi.delete_share_server.assert_called_once_with(
            self.context, server_returned)

    @mock.patch.object(db_api, 'share_instances_get_all_by_share_server',
                       mock.Mock(return_value=['fake_share', ]))
    @mock.patch.object(db_api, 'share_group_get_all_by_share_server',
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
    @mock.patch.object(db_api, 'share_group_get_all_by_share_server',
                       mock.Mock(return_value=['fake_group', ]))
    def test_delete_share_server_dependent_group_exists(self):
        server = {'id': 'fake_share_server_id'}
        self.assertRaises(exception.ShareServerInUse,
                          self.api.delete_share_server,
                          self.context,
                          server)

        db_api.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, server['id'])
        (db_api.share_group_get_all_by_share_server.
            assert_called_once_with(self.context, server['id']))

    @mock.patch.object(db_api, 'share_snapshot_instance_update', mock.Mock())
    def test_delete_snapshot(self):
        snapshot = db_utils.create_snapshot(
            with_share=True, status=constants.STATUS_AVAILABLE)
        share = snapshot['share']

        with mock.patch.object(db_api, 'share_get',
                               mock.Mock(return_value=share)):
            self.api.delete_snapshot(self.context, snapshot)
            self.share_rpcapi.delete_snapshot.assert_called_once_with(
                self.context, snapshot, share['host'], force=False)
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

    @ddt.data(constants.STATUS_MANAGING, constants.STATUS_ERROR_DELETING,
              constants.STATUS_CREATING, constants.STATUS_AVAILABLE)
    def test_delete_snapshot_force_delete(self, status):
        share = fakes.fake_share(id=uuidutils.generate_uuid(),
                                 has_replicas=False)
        snapshot = fakes.fake_snapshot(aggregate_status=status, share=share)
        snapshot_instance = fakes.fake_snapshot_instance(
            base_snapshot=snapshot)
        self.mock_object(db_api, 'share_get', mock.Mock(return_value=share))
        self.mock_object(
            db_api, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=[snapshot_instance]))
        mock_instance_update_call = self.mock_object(
            db_api, 'share_snapshot_instance_update')
        mock_rpc_call = self.mock_object(self.share_rpcapi, 'delete_snapshot')

        retval = self.api.delete_snapshot(self.context, snapshot, force=True)

        self.assertIsNone(retval)
        mock_instance_update_call.assert_called_once_with(
            self.context, snapshot_instance['id'],
            {'status': constants.STATUS_DELETING})
        mock_rpc_call.assert_called_once_with(
            self.context, snapshot, share['instance']['host'], force=True)

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

    def test_create_snapshot_fail(self):
        share = fakes.fake_share(
            has_replicas=False, status=constants.STATUS_AVAILABLE)
        mock_db_share_snapshot_create = self.mock_object(
            db_api, 'share_snapshot_create', mock.Mock(
                side_effect=exception.NotFound))

        self.mock_object(quota.QUOTAS, 'rollback')

        self.assertRaises(exception.NotFound,
                          self.api.create_snapshot,
                          self.context, share,
                          'fake_name', 'fake_desc')

        self.assertTrue(mock_db_share_snapshot_create.called)
        quota.QUOTAS.rollback.assert_called_once_with(
            self.context,
            mock.ANY,
            share_type_id=share['instance']['share_type_id'])

    def test_create_snapshot_quota_commit_fail(self):
        share = fakes.fake_share(
            has_replicas=False, status=constants.STATUS_AVAILABLE)
        snapshot = fakes.fake_snapshot(
            create_instance=True, share_instance_id='id2')
        self.mock_object(
            quota.QUOTAS, 'commit', mock.Mock(
                side_effect=exception.QuotaError('fake')))

        self.mock_object(db_api, 'share_snapshot_create', mock.Mock(
            return_value=snapshot))
        self.mock_object(db_api, 'share_snapshot_instance_delete')
        self.mock_object(quota.QUOTAS, 'rollback')

        self.assertRaises(exception.QuotaError,
                          self.api.create_snapshot,
                          self.context, share,
                          'fake_name', 'fake_desc')

        quota.QUOTAS.rollback.assert_called_once_with(
            self.context,
            mock.ANY,
            share_type_id=share['instance']['share_type_id'])

    @ddt.data({'use_scheduler': False, 'valid_host': 'fake',
               'az': None},
              {'use_scheduler': True, 'valid_host': None,
               'az': None},
              {'use_scheduler': True, 'valid_host': None,
               'az': "fakeaz2"})
    @ddt.unpack
    def test_create_from_snapshot(self, use_scheduler, valid_host, az):
        snapshot, share, share_data, request_spec = (
            self._setup_create_from_snapshot_mocks(
                use_scheduler=use_scheduler, host=valid_host)
        )
        share_type = fakes.fake_share_type()

        mock_get_share_type_call = self.mock_object(
            share_types, 'get_share_type', mock.Mock(return_value=share_type))

        self.api.create(
            self.context,
            share_data['share_proto'],
            None,  # NOTE(u_glide): Get share size from snapshot
            share_data['display_name'],
            share_data['display_description'],
            snapshot_id=snapshot['id'],
            availability_zone=az,
        )

        expected_az = snapshot['share']['availability_zone'] if not az else az
        share_data.pop('availability_zone')

        mock_get_share_type_call.assert_called_once_with(
            self.context, share['share_type_id'])
        self.assertSubDictMatch(share_data,
                                db_api.share_create.call_args[0][1])
        self.api.create_instance.assert_called_once_with(
            self.context, share, share_network_id=share['share_network_id'],
            host=valid_host, share_type_id=share_type['id'],
            availability_zone=expected_az,
            share_group=None, share_group_snapshot_member=None,
            availability_zones=None,
            az_request_multiple_subnet_support_map=None,
            snapshot_host=snapshot['share']['instance']['host'],
            scheduler_hints=None)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share_snapshot', 'get_snapshot')
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, share_type_id=share_type['id'],
            gigabytes=1, shares=1)
        quota.QUOTAS.commit.assert_called_once_with(
            self.context, 'reservation', share_type_id=share_type['id'])

    def test_create_share_with_share_group(self):
        extra_specs = {'replication_type': constants.REPLICATION_TYPE_READABLE}
        share_type = db_utils.create_share_type(extra_specs=extra_specs)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        group = db_utils.create_share_group(
            status=constants.STATUS_AVAILABLE,
            share_types=[share_type['id']])
        share, share_data = self._setup_create_mocks(
            share_type_id=share_type['id'],
            share_group_id=group['id'])

        share_instance = db_utils.create_share_instance(
            share_id=share['id'])
        sg_snap_member = {
            'id': 'fake_sg_snap_member_id',
            'share_instance': share_instance
        }

        az = share_data.pop('availability_zone')

        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value='reservation'))
        self.mock_object(quota.QUOTAS, 'commit')

        self.api.create(
            self.context,
            share_data['share_proto'],
            share_data['size'],
            share_data['display_name'],
            share_data['display_description'],
            availability_zone=az,
            share_type=share_type,
            share_group_id=group['id'],
            share_group_snapshot_member=sg_snap_member,
        )
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, share_type_id=share_type['id'],
            gigabytes=1, shares=1, share_replicas=1, replica_gigabytes=1)
        quota.QUOTAS.commit.assert_called_once_with(
            self.context, 'reservation', share_type_id=share_type['id']
        )

    def test_create_share_share_type_contains_replication_type(self):
        extra_specs = {'replication_type': constants.REPLICATION_TYPE_READABLE}
        share_type = db_utils.create_share_type(extra_specs=extra_specs)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        share, share_data = self._setup_create_mocks(
            share_type_id=share_type['id'])
        az = share_data.pop('availability_zone')

        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value='reservation'))
        self.mock_object(quota.QUOTAS, 'commit')

        self.api.create(
            self.context,
            share_data['share_proto'],
            share_data['size'],
            share_data['display_name'],
            share_data['display_description'],
            availability_zone=az,
            share_type=share_type
        )
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, share_type_id=share_type['id'],
            gigabytes=1, shares=1, share_replicas=1, replica_gigabytes=1)
        quota.QUOTAS.commit.assert_called_once_with(
            self.context, 'reservation', share_type_id=share_type['id']
        )

    def test_create_from_snapshot_az_different_from_source(self):
        snapshot, share, share_data, request_spec = (
            self._setup_create_from_snapshot_mocks(use_scheduler=False)
        )

        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, share_data['share_proto'],
                          share_data['size'],
                          share_data['display_name'],
                          share_data['display_description'],
                          snapshot_id=snapshot['id'],
                          availability_zone='fake_different_az')

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

    def test_delete_wrong_status(self):
        share = fakes.fake_share(status='wrongstatus')
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

    @mock.patch.object(db_api, 'count_share_group_snapshot_members_in_share',
                       mock.Mock(return_value=2))
    def test_delete_dependent_share_group_snapshot_members(self):
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
            utils.IsAMatcher(context.RequestContext), share.instance['id'],
            need_to_update_usages=True)

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

    def test_delete_locked_share(self):
        self.mock_object(
            self.api.db,
            'resource_lock_get_all',
            mock.Mock(return_value=([{'id': 'l1'}, {'id': 'l2'}], None))
        )
        share = self._setup_delete_mocks('available')

        self.assertRaises(exception.InvalidShare,
                          self.api.delete,
                          self.context,
                          share)

        # lock check decorator executed first, nothing else is invoked
        self.api.delete_instance.assert_not_called()
        db_api.share_snapshot_get_all_for_share.assert_not_called()

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

    def test_get(self):
        share = db_utils.create_share()
        with mock.patch.object(db_api, 'share_get',
                               mock.Mock(return_value=share)):
            result = self.api.get(self.context, 'fakeid')
            self.assertEqual(share, result)
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'get', share, do_raise=False)
            db_api.share_get.assert_called_once_with(
                self.context, 'fakeid')

    def test_get_not_authorized(self):
        share = db_utils.create_share(
            is_public=False,
            project_id='5db325fc4de14fe1a860ff69f190c78c')
        share_api.policy.check_policy.return_value = False
        ctx = context.RequestContext('df6d65cc1f8946ba86be06b8140ec4b3',
                                     'e8133457b853436591a7e4610e7ce679',
                                     is_admin=False)
        with mock.patch.object(db_api, 'share_get',
                               mock.Mock(return_value=share)):

            self.assertRaises(exception.NotFound,
                              self.api.get,
                              ctx,
                              share['id'])
            share_api.policy.check_policy.assert_called_once_with(
                ctx, 'share', 'get', share, do_raise=False)
            db_api.share_get.assert_called_once_with(ctx, share['id'])

    @mock.patch.object(db_api, 'share_snapshot_get_all_by_project',
                       mock.Mock())
    def test_get_all_snapshots_admin_not_all_tenants(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=True)
        self.api.get_all_snapshots(ctx)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', limit=None, offset=None, sort_dir='desc',
            sort_key='share_id', filters={})

    @mock.patch.object(db_api, 'share_snapshot_get_all', mock.Mock())
    def test_get_all_snapshots_admin_all_tenants(self):
        self.api.get_all_snapshots(self.context,
                                   search_opts={'all_tenants': 1})
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all.assert_called_once_with(
            self.context, limit=None, offset=None, sort_dir='desc',
            sort_key='share_id', filters={})

    @mock.patch.object(db_api, 'share_snapshot_get_all_by_project',
                       mock.Mock())
    def test_get_all_snapshots_not_admin(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=False)
        self.api.get_all_snapshots(ctx)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', limit=None, offset=None, sort_dir='desc',
            sort_key='share_id', filters={})

    def test_get_all_snapshots_not_admin_search_opts(self):
        search_opts = {'size': 'fakesize'}
        fake_objs = [{'name': 'fakename1'}, search_opts]
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=False)
        self.mock_object(db_api, 'share_snapshot_get_all_by_project',
                         mock.Mock(return_value=fake_objs))

        result = self.api.get_all_snapshots(ctx, search_opts)

        self.assertEqual(fake_objs, result)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', limit=None, offset=None, sort_dir='desc',
            sort_key='share_id', filters=search_opts)

    @ddt.data(({'name': 'fo'}, 0, []), ({'description': 'd'}, 0, []),
              ({'name': 'foo', 'description': 'd'}, 0, []),
              ({'name': 'foo'}, 1, [{'name': 'foo', 'description': 'ds'}]),
              ({'description': 'ds'}, 1, [{'name': 'foo',
                                           'description': 'ds'}]),
              ({'name~': 'foo', 'description~': 'ds'}, 2,
               [{'name': 'foo', 'description': 'ds'},
                {'name': 'foo1', 'description': 'ds1'}]),
              ({'name': 'foo', 'description~': 'ds'}, 1,
               [{'name': 'foo', 'description': 'ds'}]),
              ({'name~': 'foo', 'description': 'ds'}, 1,
               [{'name': 'foo', 'description': 'ds'}]))
    @ddt.unpack
    def test_get_all_snapshots_filter_by_name_and_description(
            self, search_opts, get_snapshot_number, res_snapshots):
        fake_objs = [{'name': 'fo2', 'description': 'd2'},
                     {'name': 'foo', 'description': 'ds'},
                     {'name': 'foo1', 'description': 'ds1'}]
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=False)
        self.mock_object(db_api, 'share_snapshot_get_all_by_project',
                         mock.Mock(return_value=res_snapshots))

        result = self.api.get_all_snapshots(ctx, search_opts)

        self.assertEqual(get_snapshot_number, len(result))
        if get_snapshot_number == 2:
            self.assertEqual(fake_objs[1:], result)
        elif get_snapshot_number == 1:
            self.assertEqual(fake_objs[1:2], result)

        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share_snapshot', 'get_all_snapshots')
        db_api.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', limit=None, offset=None, sort_dir='desc',
            sort_key='share_id', filters=search_opts)

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
            ctx, 'fake_pid_1', limit=None, offset=None, sort_dir='asc',
            sort_key='status', filters={})
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

    def test_allow_access_rule_already_exists(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        fake_access = db_utils.create_access(share_id=share['id'])
        self.mock_object(self.api.db, 'share_access_create')

        self.assertRaises(
            exception.ShareAccessExists, self.api.allow_access,
            self.context, share, fake_access['access_type'],
            fake_access['access_to'], fake_access['access_level'])
        self.assertFalse(self.api.db.share_access_create.called)

    def test_allow_access_invalid_access_level(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        self.mock_object(self.api.db, 'share_access_create')

        self.assertRaises(
            exception.InvalidShareAccess, self.api.allow_access,
            self.context, share, 'user', 'alice', access_level='execute')
        self.assertFalse(self.api.db.share_access_create.called)

    @ddt.data({'host': None},
              {'status': constants.STATUS_ERROR_DELETING,
               'access_rules_status': constants.STATUS_ACTIVE},
              {'host': None, 'access_rules_status': constants.STATUS_ERROR},
              {'access_rules_status': constants.STATUS_ERROR})
    def test_allow_access_invalid_instance(self, params):
        share = db_utils.create_share(host='fake')
        db_utils.create_share_instance(share_id=share['id'])
        db_utils.create_share_instance(share_id=share['id'], **params)
        self.mock_object(self.api.db, 'share_access_create')

        self.assertRaises(exception.InvalidShare, self.api.allow_access,
                          self.context, share, 'ip', '10.0.0.1')
        self.assertFalse(self.api.db.share_access_create.called)

    @ddt.data(*(constants.ACCESS_LEVELS + (None,)))
    def test_allow_access(self, level):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        values = {
            'share_id': share['id'],
            'access_type': 'fake_access_type',
            'access_to': 'fake_access_to',
            'access_level': level,
            'metadata': None,
        }
        fake_access = copy.deepcopy(values)
        fake_access.update({
            'id': 'fake_access_id',
            'state': constants.STATUS_ACTIVE,
            'deleted': 'fake_deleted',
            'deleted_at': 'fake_deleted_at',
            'instance_mappings': ['foo', 'bar'],
        })
        self.mock_object(db_api, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(db_api, 'share_access_create',
                         mock.Mock(return_value=fake_access))
        self.mock_object(db_api, 'share_access_get',
                         mock.Mock(return_value=fake_access))
        self.mock_object(db_api, 'share_access_get_all_by_type_and_access',
                         mock.Mock(return_value=[]))
        self.mock_object(self.api, 'allow_access_to_instance')

        access = self.api.allow_access(
            self.context, share, fake_access['access_type'],
            fake_access['access_to'], level)

        self.assertEqual(fake_access, access)
        db_api.share_access_create.assert_called_once_with(
            self.context, values)
        self.api.allow_access_to_instance.assert_called_once_with(
            self.context, share.instance)

    def test_allow_access_to_instance(self):
        share = db_utils.create_share(host='fake')
        rpc_method = self.mock_object(self.api.share_rpcapi, 'update_access')

        self.api.allow_access_to_instance(self.context, share.instance)

        rpc_method.assert_called_once_with(self.context, share.instance)

    @ddt.data({'host': None},
              {'status': constants.STATUS_ERROR_DELETING,
               'access_rules_status': constants.STATUS_ACTIVE},
              {'host': None, 'access_rules_status': constants.STATUS_ERROR},
              {'access_rules_status': constants.STATUS_ERROR})
    def test_deny_access_invalid_instance(self, params):
        share = db_utils.create_share(host='fake')
        db_utils.create_share_instance(share_id=share['id'])
        db_utils.create_share_instance(share_id=share['id'], **params)
        access_rule = db_utils.create_access(share_id=share['id'])
        self.mock_object(self.api, 'deny_access_to_instance')

        self.assertRaises(exception.InvalidShare, self.api.deny_access,
                          self.context, share, access_rule)
        self.assertFalse(self.api.deny_access_to_instance.called)

    def test_deny_access(self):
        share = db_utils.create_share(
            host='fake', status=constants.STATUS_AVAILABLE,
            access_rules_status=constants.STATUS_ACTIVE)
        access_rule = db_utils.create_access(share_id=share['id'])
        self.mock_object(self.api, 'deny_access_to_instance')

        retval = self.api.deny_access(self.context, share, access_rule)

        self.assertIsNone(retval)
        self.api.deny_access_to_instance.assert_called_once_with(
            self.context, share.instance, access_rule)

    def test_deny_access_to_instance(self):
        share = db_utils.create_share(host='fake')
        share_instance = db_utils.create_share_instance(
            share_id=share['id'], host='fake')
        access = db_utils.create_access(share_id=share['id'])
        rpc_method = self.mock_object(self.api.share_rpcapi, 'update_access')
        self.mock_object(db_api, 'share_instance_access_get',
                         mock.Mock(return_value=access.instance_mappings[0]))
        mock_share_instance_rules_status_update = self.mock_object(
            self.api.access_helper,
            'get_and_update_share_instance_access_rules_status')
        mock_access_rule_state_update = self.mock_object(
            self.api.access_helper,
            'get_and_update_share_instance_access_rule')

        self.api.deny_access_to_instance(self.context, share_instance, access)

        rpc_method.assert_called_once_with(self.context, share_instance)
        mock_access_rule_state_update.assert_called_once_with(
            self.context, access['id'],
            updates={'state': constants.ACCESS_STATE_QUEUED_TO_DENY},
            share_instance_id=share_instance['id'])
        expected_conditional_change = {
            constants.STATUS_ACTIVE: constants.SHARE_INSTANCE_RULES_SYNCING,
        }
        mock_share_instance_rules_status_update.assert_called_once_with(
            self.context, share_instance_id=share_instance['id'],
            conditionally_change=expected_conditional_change)

    def test_access_get(self):
        with mock.patch.object(db_api, 'share_access_get',
                               mock.Mock(return_value={'share_id': 'fake'})):
            self.mock_object(self.api, 'get')
            rule = self.api.access_get(self.context, 'fakeid')
            self.assertEqual({'share_id': 'fake'}, rule)
            db_api.share_access_get.assert_called_once_with(
                self.context, 'fakeid')
            self.api.get.assert_called_once_with(self.context, 'fake')

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

        self.assertEqual(rules, actual)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'access_get_all')
        db_api.share_access_get_all_for_share.assert_called_once_with(
            self.context, 'fakeid', filters=None)

    def test_share_metadata_get(self):
        metadata = {'a': 'b', 'c': 'd'}
        share_id = uuidutils.generate_uuid()
        db_api.share_create(self.context,
                            {'id': share_id, 'metadata': metadata})
        self.assertEqual(metadata,
                         db_api.share_metadata_get(self.context, share_id))

    def test_share_metadata_update(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '5'}
        should_be = {'a': '3', 'c': '2', 'd': '5'}
        share_id = uuidutils.generate_uuid()
        db_api.share_create(self.context,
                            {'id': share_id, 'metadata': metadata1})
        db_api.share_metadata_update(self.context, share_id, metadata2, False)
        self.assertEqual(should_be,
                         db_api.share_metadata_get(self.context, share_id))

    def test_share_metadata_update_delete(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '4'}
        should_be = metadata2
        share_id = uuidutils.generate_uuid()
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

    def test_extend_share_over_per_share_quota(self):
        quota.CONF.set_default("per_share_gigabytes", 5, 'quota')
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=4)
        new_size = 6
        self.assertRaises(exception.ShareSizeExceedsLimit,
                          self.api.extend, self.context, share, new_size)

    def test_extend_with_share_type_size_limit(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=3)
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=self.sized_sha_type))
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=False))

        new_size = 5

        self.assertRaises(exception.InvalidInput,
                          self.api.extend, ctx,
                          share, new_size)

    def test_extend_with_share_type_size_limit_admin(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=True)
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=3)
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=self.sized_sha_type))
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))

        new_size = 7

        self.assertRaises(exception.InvalidInput,
                          self.api.extend, ctx,
                          share, new_size)

    def _setup_extend_mocks(self, supports_replication):
        replica_list = []
        if supports_replication:
            replica_list.append({'id': 'fake_replica_id'})
            replica_list.append({'id': 'fake_replica_id_2'})
        self.mock_object(db_api, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replica_list))

    @ddt.data(
        (False, 'gigabytes', exception.ShareSizeExceedsAvailableQuota),
        (True, 'replica_gigabytes',
         exception.ShareReplicaSizeExceedsAvailableQuota)
    )
    @ddt.unpack
    def test_extend_quota_error(self, supports_replication, quota_key,
                                expected_exception):
        self._setup_extend_mocks(supports_replication)
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=100)
        new_size = 123
        replica_amount = len(
            db_api.share_replicas_get_all_by_share.return_value)
        value_to_be_extended = new_size - share['size']
        usages = {quota_key: {'reserved': 11, 'in_use': 12}}
        quotas = {quota_key: 13}
        overs = {quota_key: new_size}
        exc = exception.OverQuota(usages=usages, quotas=quotas, overs=overs)
        expected_deltas = {
            'project_id': share['project_id'],
            'gigabytes': value_to_be_extended,
            'user_id': share['user_id'],
            'share_type_id': share['instance']['share_type_id']
        }
        if supports_replication:
            expected_deltas.update(
                {'replica_gigabytes': value_to_be_extended * replica_amount})
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(side_effect=exc))

        self.assertRaises(expected_exception,
                          self.api.extend, self.context, share, new_size)
        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY, **expected_deltas
        )

    def test_extend_quota_user(self):
        self._setup_extend_mocks(False)
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=100)
        diff_user_context = context.RequestContext(
            user_id='fake2',
            project_id='fake',
            is_admin=False
        )
        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
                'create_share_from_snapshot_support': False,
                'driver_handles_share_servers': False,
            },
        }
        new_size = 123
        size_increase = int(new_size) - share['size']
        self.mock_object(quota.QUOTAS, 'reserve')
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))

        self.api.extend(diff_user_context, share, new_size)

        quota.QUOTAS.reserve.assert_called_once_with(
            diff_user_context,
            project_id=share['project_id'],
            gigabytes=size_increase,
            share_type_id=None,
            user_id=share['user_id']
        )

    @ddt.data(True, False)
    def test_extend_valid(self, supports_replication):
        self._setup_extend_mocks(supports_replication)
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=100)
        new_size = 123
        size_increase = int(new_size) - share['size']
        replica_amount = len(
            db_api.share_replicas_get_all_by_share.return_value)

        expected_deltas = {
            'project_id': share['project_id'],
            'gigabytes': size_increase,
            'user_id': share['user_id'],
            'share_type_id': share['instance']['share_type_id']
        }
        if supports_replication:
            new_replica_size = size_increase * replica_amount
            expected_deltas.update({'replica_gigabytes': new_replica_size})
        self.mock_object(self.api, 'update')
        self.mock_object(self.api.scheduler_rpcapi, 'extend_share')
        self.mock_object(quota.QUOTAS, 'reserve')
        self.mock_object(share_types, 'get_share_type')
        self.mock_object(share_types, 'provision_filter_on_size')
        self.mock_object(self.api, '_get_request_spec_dict')

        self.api.extend(self.context, share, new_size)

        self.api.update.assert_called_once_with(
            self.context, share, {'status': constants.STATUS_EXTENDING})

        self.api.scheduler_rpcapi.extend_share.assert_called_once_with(
            self.context, share['id'], new_size, mock.ANY, mock.ANY
        )
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, **expected_deltas)

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

    def test_shrink_with_share_type_size_limit(self):
        share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                      size=3)
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=self.sized_sha_type))
        new_size = 1

        self.assertRaises(exception.InvalidInput,
                          self.api.shrink, self.context,
                          share, new_size)

    def test_snapshot_allow_access(self):
        access_to = '1.1.1.1'
        access_type = 'ip'
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'],
                                            status=constants.STATUS_AVAILABLE)
        access = db_utils.create_snapshot_access(
            share_snapshot_id=snapshot['id'])
        values = {'share_snapshot_id': snapshot['id'],
                  'access_type': access_type,
                  'access_to': access_to}

        existing_access_check = self.mock_object(
            db_api, 'share_snapshot_check_for_existing_access',
            mock.Mock(return_value=False))
        access_create = self.mock_object(
            db_api, 'share_snapshot_access_create',
            mock.Mock(return_value=access))
        self.mock_object(self.api.share_rpcapi, 'snapshot_update_access')

        out = self.api.snapshot_allow_access(self.context, snapshot,
                                             access_type, access_to)

        self.assertEqual(access, out)
        existing_access_check.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'],
            access_type, access_to)
        access_create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), values)

    def test_snapshot_allow_access_instance_exception(self):
        access_to = '1.1.1.1'
        access_type = 'ip'
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        existing_access_check = self.mock_object(
            db_api, 'share_snapshot_check_for_existing_access',
            mock.Mock(return_value=False))

        self.assertRaises(exception.InvalidShareSnapshotInstance,
                          self.api.snapshot_allow_access, self.context,
                          snapshot, access_type, access_to)

        existing_access_check.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'],
            access_type, access_to)

    def test_snapshot_allow_access_access_exists_exception(self):
        access_to = '1.1.1.1'
        access_type = 'ip'
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        db_utils.create_snapshot_access(
            share_snapshot_id=snapshot['id'], access_to=access_to,
            access_type=access_type)

        existing_access_check = self.mock_object(
            db_api, 'share_snapshot_check_for_existing_access',
            mock.Mock(return_value=True))

        self.assertRaises(exception.ShareSnapshotAccessExists,
                          self.api.snapshot_allow_access, self.context,
                          snapshot, access_type, access_to)

        existing_access_check.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'],
            access_type, access_to)

    def test_snapshot_deny_access(self):
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'],
                                            status=constants.STATUS_AVAILABLE)
        access = db_utils.create_snapshot_access(
            share_snapshot_id=snapshot['id'])
        mapping = {'id': 'fake_id',
                   'state': constants.STATUS_ACTIVE,
                   'access_id': access['id']}

        access_get = self.mock_object(
            db_api, 'share_snapshot_instance_access_get',
            mock.Mock(return_value=mapping))
        access_update_state = self.mock_object(
            db_api, 'share_snapshot_instance_access_update')
        update_access = self.mock_object(self.api.share_rpcapi,
                                         'snapshot_update_access')

        self.api.snapshot_deny_access(self.context, snapshot, access)

        access_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), access['id'],
            snapshot['instance']['id'])
        access_update_state.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), access['id'],
            snapshot.instance['id'],
            {'state': constants.ACCESS_STATE_QUEUED_TO_DENY})
        update_access.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['instance'])

    def test_snapshot_deny_access_exception(self):
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        access = db_utils.create_snapshot_access(
            share_snapshot_id=snapshot['id'])

        self.assertRaises(exception.InvalidShareSnapshotInstance,
                          self.api.snapshot_deny_access, self.context,
                          snapshot, access)

    def test_snapshot_access_get_all(self):
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        access = []
        access.append(db_utils.create_snapshot_access(
            share_snapshot_id=snapshot['id']))

        self.mock_object(
            db_api, 'share_snapshot_access_get_all_for_share_snapshot',
            mock.Mock(return_value=access))

        out = self.api.snapshot_access_get_all(self.context, snapshot)

        self.assertEqual(access, out)

    def test_snapshot_access_get(self):
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        access = db_utils.create_snapshot_access(
            share_snapshot_id=snapshot['id'])

        self.mock_object(
            db_api, 'share_snapshot_access_get',
            mock.Mock(return_value=access))

        out = self.api.snapshot_access_get(self.context, access['id'])

        self.assertEqual(access, out)

    def test_snapshot_export_locations_get(self):
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])

        self.mock_object(
            db_api, 'share_snapshot_export_locations_get',
            mock.Mock(return_value=''))

        out = self.api.snapshot_export_locations_get(self.context, snapshot)

        self.assertEqual('', out)

    def test_snapshot_export_location_get(self):
        fake_el = '/fake_export_location'

        self.mock_object(
            db_api, 'share_snapshot_instance_export_location_get',
            mock.Mock(return_value=fake_el))

        out = self.api.snapshot_export_location_get(self.context, 'fake_id')

        self.assertEqual(fake_el, out)

    @ddt.data(True, False)
    def test__modify_quotas_for_share_migration(self, new_replication_type):
        extra_specs = (
            {'replication_type': 'readable'} if new_replication_type else {})
        share = db_utils.create_share()
        share_type = db_utils.create_share_type(extra_specs=extra_specs)

        expected_deltas = {
            'project_id': share['project_id'],
            'user_id': share['user_id'],
            'shares': 1,
            'gigabytes': share['size'],
            'share_type_id': share_type['id']
        }

        if new_replication_type:
            expected_deltas.update({
                'share_replicas': 1,
                'replica_gigabytes': share['size'],
            })
        reservations = 'reservations'

        mock_specs_get = self.mock_object(
            self.api, 'get_share_attributes_from_share_type',
            mock.Mock(return_value=extra_specs))
        mock_reserve = self.mock_object(
            quota.QUOTAS, 'reserve', mock.Mock(return_value=reservations))
        mock_commit = self.mock_object(quota.QUOTAS, 'commit')

        self.api._modify_quotas_for_share_migration(
            self.context, share, share_type)

        mock_specs_get.assert_called_once_with(share_type)
        mock_reserve.assert_called_once_with(
            self.context, **expected_deltas)
        mock_commit.assert_called_once_with(
            self.context, reservations, project_id=share['project_id'],
            user_id=share['user_id'], share_type_id=share_type['id'])

    @ddt.data(
        ('replica_gigabytes', exception.ShareReplicaSizeExceedsAvailableQuota),
        ('share_replicas', exception.ShareReplicasLimitExceeded),
        ('gigabytes', exception.ShareSizeExceedsAvailableQuota)
    )
    @ddt.unpack
    def test__modify_quotas_for_share_migration_reservation_failed(
            self, over_resource, expected_exception):
        extra_specs = {'replication_type': 'readable'}
        share = db_utils.create_share()
        share_type = db_utils.create_share_type(extra_specs=extra_specs)
        expected_deltas = {
            'project_id': share['project_id'],
            'user_id': share['user_id'],
            'share_replicas': 1,
            'shares': 1,
            'gigabytes': share['size'],
            'replica_gigabytes': share['size'],
            'share_type_id': share_type['id']
        }
        usages = {
            over_resource: {
                'reserved': 'fake',
                'in_use': 'fake'
            }
        }
        quotas = {
            over_resource: 'fake'
        }

        effect_exc = exception.OverQuota(
            overs=[over_resource], usages=usages, quotas=quotas)
        mock_specs_get = self.mock_object(
            self.api, 'get_share_attributes_from_share_type',
            mock.Mock(return_value=extra_specs))
        mock_reserve = self.mock_object(
            quota.QUOTAS, 'reserve', mock.Mock(side_effect=effect_exc))

        self.assertRaises(
            expected_exception,
            self.api._modify_quotas_for_share_migration,
            self.context, share, share_type
        )

        mock_specs_get.assert_called_once_with(share_type)
        mock_reserve.assert_called_once_with(self.context, **expected_deltas)

    @ddt.data({'share_type': True, 'share_net': True, 'dhss': True},
              {'share_type': False, 'share_net': True, 'dhss': True},
              {'share_type': False, 'share_net': False, 'dhss': True},
              {'share_type': True, 'share_net': False, 'dhss': False},
              {'share_type': False, 'share_net': False, 'dhss': False})
    @ddt.unpack
    def test_migration_start(self, share_type, share_net, dhss):
        host = 'fake2@backend#pool'
        service = {'availability_zone_id': 'fake_az_id',
                   'availability_zone': {'name': 'fake_az1'}}
        share_network = None
        share_network_id = None
        if share_net:
            share_network = db_utils.create_share_network(id='fake_net_id')
            share_network_id = share_network['id']

        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
                'mount_snapshot_support': False,
                'driver_handles_share_servers': dhss,
            },
        }

        if share_type:
            fake_type_2 = {
                'id': 'fake_type_2_id',
                'extra_specs': {
                    'snapshot_support': False,
                    'create_share_from_snapshot_support': False,
                    'revert_to_snapshot_support': False,
                    'mount_snapshot_support': False,
                    'driver_handles_share_servers': dhss,
                    'availability_zones': 'fake_az1,fake_az2',
                },
            }
        else:
            fake_type_2 = fake_type

        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            host='fake@backend#pool', share_type_id=fake_type['id'],
            share_network_id=share_network_id)

        request_spec = self._get_request_spec_dict(
            share, fake_type_2, self.context, size=0,
            availability_zone_id='fake_az_id',
            share_network_id=share_network_id)

        self.mock_object(self.scheduler_rpcapi, 'migrate_share_to_host')
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))
        self.mock_object(utils, 'validate_service_host')
        self.mock_object(db_api, 'share_instance_update')
        self.mock_object(db_api, 'share_update')
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))
        self.mock_object(share_api.API, '_modify_quotas_for_share_migration')

        if share_type:
            self.api.migration_start(self.context, share, host, False, True,
                                     True, True, True, share_network,
                                     fake_type_2)
        else:
            self.api.migration_start(self.context, share, host, False, True,
                                     True, True, True, share_network, None)

        self.scheduler_rpcapi.migrate_share_to_host.assert_called_once_with(
            self.context, share['id'], host, False, True, True, True, True,
            share_network_id, fake_type_2['id'], request_spec)
        if not share_type:
            share_types.get_share_type.assert_called_once_with(
                self.context, fake_type['id'])
        utils.validate_service_host.assert_called_once_with(
            self.context, 'fake2@backend')
        db_api.service_get_by_args.assert_called_once_with(
            self.context, 'fake2@backend', 'manila-share')
        db_api.share_update.assert_called_once_with(
            self.context, share['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_STARTING})
        db_api.share_instance_update.assert_called_once_with(
            self.context, share.instance['id'],
            {'status': constants.STATUS_MIGRATING})
        if share_type:
            (share_api.API._modify_quotas_for_share_migration.
                assert_called_once_with(self.context, share, fake_type_2))

    def test_migration_start_with_new_share_type_limit(self):
        host = 'fake2@backend#pool'
        self.mock_object(utils, 'validate_service_host')
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            size=1)
        self.assertRaises(exception.InvalidInput,
                          self.api.migration_start,
                          self.context,
                          share, host, False, True,
                          True, True, True, None,
                          self.sized_sha_type)

    def test_migration_start_destination_az_unsupported(self):
        host = 'fake2@backend#pool'
        host_without_pool = host.split('#')[0]
        service = {'availability_zone_id': 'fake_az_id',
                   'availability_zone': {'name': 'fake_az3'}}
        share_network = db_utils.create_share_network(id='fake_net_id')
        share_network_id = share_network['id']
        existing_share_type = {
            'id': '4b5b0920-a294-401b-bb7d-c55b425e1cad',
            'name': 'fake_type_1',
            'extra_specs': {
                'snapshot_support': False,
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
                'mount_snapshot_support': False,
                'driver_handles_share_servers': 'true',
                'availability_zones': 'fake_az3'
            },
        }
        new_share_type = {
            'id': 'fa844ae2-494d-4da9-95e7-37ac6a26f635',
            'name': 'fake_type_2',
            'extra_specs': {
                'snapshot_support': False,
                'create_share_from_snapshot_support': False,
                'revert_to_snapshot_support': False,
                'mount_snapshot_support': False,
                'driver_handles_share_servers': 'true',
                'availability_zones': 'fake_az1,fake_az2',
            },
        }
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            host='fake@backend#pool', share_type_id=existing_share_type['id'],
            share_network_id=share_network_id)
        self.mock_object(self.api, '_get_request_spec_dict')
        self.mock_object(self.scheduler_rpcapi, 'migrate_share_to_host')
        self.mock_object(share_types, 'get_share_type')
        self.mock_object(utils, 'validate_service_host')
        self.mock_object(db_api, 'share_instance_update')
        self.mock_object(db_api, 'share_update')
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))
        self.mock_object(share_api.API, '_modify_quotas_for_share_migration')

        self.assertRaises(exception.InvalidShare,
                          self.api.migration_start,
                          self.context, share, host, False, True, True,
                          True, False, new_share_network=share_network,
                          new_share_type=new_share_type)
        utils.validate_service_host.assert_called_once_with(
            self.context, host_without_pool)
        share_types.get_share_type.assert_not_called()
        db_api.share_update.assert_not_called()
        db_api.service_get_by_args.assert_called_once_with(
            self.context, host_without_pool, 'manila-share')
        self.api._get_request_spec_dict.assert_not_called()
        db_api.share_instance_update.assert_not_called()
        self.scheduler_rpcapi.migrate_share_to_host.assert_not_called()

    @ddt.data({'force_host_assisted': True, 'writable': True,
               'preserve_metadata': False, 'preserve_snapshots': False,
               'nondisruptive': False},
              {'force_host_assisted': True, 'writable': False,
               'preserve_metadata': True, 'preserve_snapshots': False,
               'nondisruptive': False},
              {'force_host_assisted': True, 'writable': False,
               'preserve_metadata': False, 'preserve_snapshots': True,
               'nondisruptive': False},
              {'force_host_assisted': True, 'writable': False,
               'preserve_metadata': False, 'preserve_snapshots': False,
               'nondisruptive': True})
    @ddt.unpack
    def test_migration_start_invalid_host_and_driver_assisted_params(
            self, force_host_assisted, writable, preserve_metadata,
            preserve_snapshots, nondisruptive):

        self.assertRaises(
            exception.InvalidInput, self.api.migration_start, self.context,
            'some_share', 'some_host', force_host_assisted, preserve_metadata,
            writable, preserve_snapshots, nondisruptive)

    @ddt.data(True, False)
    def test_migration_start_invalid_share_network_type_combo(self, dhss):
        host = 'fake2@backend#pool'
        share_network = None
        if not dhss:
            share_network = db_utils.create_share_network(id='fake_net_id')

        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': False,
                'driver_handles_share_servers': not dhss,
            },
        }

        fake_type_2 = {
            'id': 'fake_type_2_id',
            'extra_specs': {
                'snapshot_support': False,
                'driver_handles_share_servers': dhss,
            },
        }

        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            host='fake@backend#pool', share_type_id=fake_type['id'])

        self.mock_object(utils, 'validate_service_host')
        self.mock_object(share_api.API, '_modify_quotas_for_share_migration')

        self.assertRaises(
            exception.InvalidInput, self.api.migration_start, self.context,
            share, host, False, True, True, True, True, share_network,
            fake_type_2)

        utils.validate_service_host.assert_called_once_with(
            self.context, 'fake2@backend')

    def test_migration_start_status_unavailable(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            status=constants.STATUS_ERROR)

        self.assertRaises(exception.InvalidShare, self.api.migration_start,
                          self.context, share, host, False, True, True, True,
                          True)

    def test_migration_start_access_rules_status_error(self):
        host = 'fake2@backend#pool'
        instance = db_utils.create_share_instance(
            share_id='fake_share_id',
            access_rules_status=constants.STATUS_ERROR,
            status=constants.STATUS_AVAILABLE)
        share = db_utils.create_share(
            id='fake_share_id',
            instances=[instance])

        self.assertRaises(exception.InvalidShare, self.api.migration_start,
                          self.context, share, host, False, True, True, True,
                          True)

    def test_migration_start_task_state_invalid(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            status=constants.STATUS_AVAILABLE,
            task_state=constants.TASK_STATE_MIGRATION_IN_PROGRESS)

        self.assertRaises(exception.ShareBusyException,
                          self.api.migration_start,
                          self.context, share, host, False, True, True, True,
                          True)

    def test_migration_start_host_assisted_with_snapshots(self):
        host = 'fake2@backend#pool'
        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE)
        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=True))

        self.assertRaises(exception.Conflict, self.api.migration_start,
                          self.context, share, host, True, False, False, False,
                          False)

    def test_migration_start_with_snapshots(self):
        host = 'fake2@backend#pool'

        fake_type = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': True,
                'driver_handles_share_servers': False,
            },
        }

        service = {'availability_zone_id': 'fake_az_id',
                   'availability_zone': {'name': 'fake_az'}}
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))
        self.mock_object(utils, 'validate_service_host')
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type))

        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=fake_type['id'])

        request_spec = self._get_request_spec_dict(
            share, fake_type, self.context, availability_zone_id='fake_az_id')

        self.api.migration_start(self.context, share, host, False, True, True,
                                 True, True)

        self.scheduler_rpcapi.migrate_share_to_host.assert_called_once_with(
            self.context, share['id'], host, False, True, True, True, True,
            None, 'fake_type_id', request_spec)

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
                          self.context, share, host, False, True, True, True,
                          True)
        self.assertTrue(mock_log.error.called)
        self.assertFalse(mock_snapshot_get_call.called)

    def test_migration_start_is_member_of_group(self):
        group = db_utils.create_share_group()
        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_group_id=group['id'])
        mock_log = self.mock_object(share_api, 'LOG')

        self.assertRaises(exception.InvalidShare, self.api.migration_start,
                          self.context, share, 'fake_host', False, True, True,
                          True, True)
        self.assertTrue(mock_log.error.called)

    def test_migration_start_invalid_host(self):
        host = 'fake@backend#pool'
        share = db_utils.create_share(
            host='fake2@backend', status=constants.STATUS_AVAILABLE)

        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=False))

        self.assertRaises(exception.ServiceNotFound,
                          self.api.migration_start,
                          self.context, share, host, False, True, True, True,
                          True)

    @ddt.data({'dhss': True, 'new_share_network_id': 'fake_net_id',
               'new_share_type_id': 'fake_type_id'},
              {'dhss': False, 'new_share_network_id': None,
               'new_share_type_id': 'fake_type_id'},
              {'dhss': True, 'new_share_network_id': 'fake_net_id',
               'new_share_type_id': None})
    @ddt. unpack
    def test_migration_start_same_data_as_source(
            self, dhss, new_share_network_id, new_share_type_id):
        host = 'fake@backend#pool'

        fake_type_src = {
            'id': 'fake_type_id',
            'extra_specs': {
                'snapshot_support': True,
                'driver_handles_share_servers': True,
            },
        }

        new_share_type_param = None
        if new_share_type_id:
            new_share_type_param = {
                'id': new_share_type_id,
                'extra_specs': {
                    'snapshot_support': True,
                    'driver_handles_share_servers': dhss,
                },
            }

        new_share_net_param = None
        if new_share_network_id:
            new_share_net_param = db_utils.create_share_network(
                id=new_share_network_id)

        share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=fake_type_src['id'],
            share_network_id=new_share_network_id)

        self.mock_object(utils, 'validate_service_host')
        self.mock_object(db_api, 'share_update')
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=fake_type_src))

        result = self.api.migration_start(
            self.context, share, host, False, True, True, True, True,
            new_share_net_param, new_share_type_param)

        self.assertEqual(200, result)

        db_api.share_update.assert_called_once_with(
            self.context, share['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_SUCCESS})

    @ddt.data({}, {'replication_type': None})
    def test_create_share_replica_invalid_share_type(self, attributes):
        share = fakes.fake_share(id='FAKE_SHARE_ID', **attributes)
        mock_request_spec_call = self.mock_object(
            self.api, 'create_share_instance_and_get_request_spec')
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
            self.api, 'create_share_instance_and_get_request_spec')
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
            self.api, 'create_share_instance_and_get_request_spec')
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

    @ddt.data(None, 'fake-share-type')
    def test_create_share_replica_type_doesnt_support_AZ(self, st_name):
        share_type = fakes.fake_share_type(
            name=st_name,
            extra_specs={'availability_zones': 'zone 1,zone 3'})
        share = fakes.fake_share(
            id='FAKE_SHARE_ID', replication_type='dr',
            availability_zone='zone 2')
        share['instance'].update({
            'share_type': share_type,
            'share_type_id': '359b9851-2bd5-4404-89a9-5cd22bbc5fb9',
        })
        mock_request_spec_call = self.mock_object(
            self.api, 'create_share_instance_and_get_request_spec')
        mock_db_update_call = self.mock_object(db_api, 'share_replica_update')
        mock_scheduler_rpcapi_call = self.mock_object(
            self.api.scheduler_rpcapi, 'create_share_replica')
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=share_type))
        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=mock.Mock(
                             return_value={'host': 'fake_ar_host'})))

        self.assertRaises(exception.InvalidShare,
                          self.api.create_share_replica,
                          self.context, share, availability_zone='zone 2')
        share_types.get_share_type.assert_called_once_with(
            self.context, '359b9851-2bd5-4404-89a9-5cd22bbc5fb9')
        self.assertFalse(mock_request_spec_call.called)
        self.assertFalse(mock_db_update_call.called)
        self.assertFalse(mock_scheduler_rpcapi_call.called)

    def test_create_share_replica_subnet_not_found(self):
        request_spec = fakes.fake_replica_request_spec()
        replica = request_spec['share_instance_properties']
        extra_specs = {
            'availability_zones': 'FAKE_AZ,FAKE_AZ2',
            'replication_type': constants.REPLICATION_TYPE_DR
        }
        share_type = db_utils.create_share_type(extra_specs=extra_specs)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        az_name = 'FAKE_AZ'
        share = db_utils.create_share(
            id=replica['share_id'], replication_type='dr')
        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=mock.Mock(
                             return_value={'host': 'fake_ar_host'})))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=share_type))
        self.mock_object(db_api, 'availability_zone_get')
        self.mock_object(
            db_api, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=None))

        self.assertRaises(exception.InvalidShare,
                          self.api.create_share_replica,
                          self.context,
                          share,
                          availability_zone=az_name,
                          share_network_id='fake_id')
        (db_api.share_replicas_get_available_active_replica
            .assert_called_once_with(self.context, share['id']))
        self.assertTrue(share_types.get_share_type.called)
        db_api.availability_zone_get.assert_called_once_with(
            self.context, az_name)
        self.assertTrue(
            (db_api.share_network_subnets_get_all_by_availability_zone_id.
             called))

    def test_create_share_replica_az_not_found(self):
        request_spec = fakes.fake_replica_request_spec()
        replica = request_spec['share_instance_properties']
        extra_specs = {
            'availability_zones': 'FAKE_AZ,FAKE_AZ2',
            'replication_type': constants.REPLICATION_TYPE_DR
        }
        share_type = db_utils.create_share_type(extra_specs=extra_specs)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        az_name = 'FAKE_AZ'
        share = db_utils.create_share(
            id=replica['share_id'], replication_type='dr')
        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=mock.Mock(
                             return_value={'host': 'fake_ar_host'})))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=share_type))
        side_effect = exception.AvailabilityZoneNotFound(id=az_name)
        self.mock_object(db_api, 'availability_zone_get',
                         mock.Mock(side_effect=side_effect))

        self.assertRaises(exception.InvalidInput,
                          self.api.create_share_replica,
                          self.context,
                          share,
                          availability_zone=az_name,
                          share_network_id='fake_id')
        (db_api.share_replicas_get_available_active_replica
            .assert_called_once_with(self.context, share['id']))
        self.assertTrue(share_types.get_share_type.called)
        db_api.availability_zone_get.assert_called_once_with(
            self.context, az_name)

    @ddt.data(
        {'availability_zones': '', 'compatible_azs_name': ['fake_az_1'],
         'compatible_azs_multiple': []},
        {'availability_zones': 'fake_az_1,fake_az_2',
         'compatible_azs_name': ['fake_az_2'], 'compatible_azs_multiple': []}
    )
    @ddt.unpack
    def test_create_share_replica_azs_with_subnets(self, availability_zones,
                                                   compatible_azs_name,
                                                   compatible_azs_multiple):
        request_spec = fakes.fake_replica_request_spec()
        replica = request_spec['share_instance_properties']
        share_network_id = 'fake_share_network_id'
        extra_specs = {
            'availability_zones': availability_zones,
            'replication_type': constants.REPLICATION_TYPE_DR
        }
        share_type = db_utils.create_share_type(extra_specs=extra_specs)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        share = db_utils.create_share(
            id=replica['share_id'], replication_type='dr',
            share_type_id=share_type['id'])
        cast_rules_to_readonly = (
            share['replication_type'] == constants.REPLICATION_TYPE_READABLE)
        fake_replica = fakes.fake_replica(id=replica['id'])
        fake_request_spec = fakes.fake_replica_request_spec()

        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value={'host': 'fake_ar_host'}))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=share_type))
        mock_get_all_az_subnet = self.mock_object(
            self.api, '_get_all_availability_zones_with_subnets',
            mock.Mock(return_value=[compatible_azs_name,
                                    compatible_azs_multiple]))

        if availability_zones == '':
            expected_azs = compatible_azs_name
        else:
            availability_zones = [
                t for t in availability_zones.split(',') if availability_zones]
            expected_azs = (
                [az for az in availability_zones if az in compatible_azs_name])

        self.mock_object(
            self.api, 'create_share_instance_and_get_request_spec',
            mock.Mock(return_value=(fake_request_spec, fake_replica)))
        self.mock_object(db_api, 'share_replica_update')
        mock_snapshot_get_all_call = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share',
            mock.Mock(return_value=[]))
        mock_sched_rpcapi_call = self.mock_object(
            self.api.scheduler_rpcapi, 'create_share_replica')

        self.api.create_share_replica(
            self.context, share, share_network_id=share_network_id)

        (db_api.share_replicas_get_available_active_replica
            .assert_called_once_with(self.context, share['id']))
        self.assertTrue(share_types.get_share_type.called)
        mock_get_all_az_subnet.assert_called_once_with(
            self.context, share_network_id
        )
        (self.api.create_share_instance_and_get_request_spec.
         assert_called_once_with(
             self.context, share, availability_zone=None,
             share_network_id=share_network_id, share_type_id=share_type['id'],
             availability_zones=expected_azs,
             az_request_multiple_subnet_support_map={},
             cast_rules_to_readonly=cast_rules_to_readonly))
        db_api.share_replica_update.assert_called_once()
        mock_snapshot_get_all_call.assert_called_once()
        mock_sched_rpcapi_call.assert_called_once()

    @ddt.data(
        {'availability_zones': '', 'compatible_azs_name': [],
         'compatible_azs_multiple': []},
        {'availability_zones': 'fake_az_1,fake_az_2',
         'compatible_azs_name': ['fake_az_3'], 'compatible_azs_multiple': []}
    )
    @ddt.unpack
    def test_create_share_replica_azs_with_subnets_invalid_input(
            self, availability_zones,
            compatible_azs_name, compatible_azs_multiple):
        request_spec = fakes.fake_replica_request_spec()
        replica = request_spec['share_instance_properties']
        share_network_id = 'fake_share_network_id'
        extra_specs = {
            'availability_zones': availability_zones,
            'replication_type': constants.REPLICATION_TYPE_DR
        }
        share_type = db_utils.create_share_type(extra_specs=extra_specs)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        share = db_utils.create_share(
            id=replica['share_id'], replication_type='dr',
            share_type_id=share_type['id'])

        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value={'host': 'fake_ar_host'}))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=share_type))
        mock_get_all_az_subnet = self.mock_object(
            self.api, '_get_all_availability_zones_with_subnets',
            mock.Mock(return_value=[compatible_azs_name,
                                    compatible_azs_multiple]))

        self.assertRaises(
            exception.InvalidInput,
            self.api.create_share_replica,
            self.context, share, share_network_id=share_network_id)

        (db_api.share_replicas_get_available_active_replica
         .assert_called_once_with(self.context, share['id']))
        self.assertTrue(share_types.get_share_type.called)
        mock_get_all_az_subnet.assert_called_once_with(
            self.context, share_network_id
        )

    @ddt.data({'has_snapshots': True,
               'az_id': {},
               'extra_specs': {
                   'replication_type': constants.REPLICATION_TYPE_DR,
               },
               'share_network_id': None},
              {'has_snapshots': False,
               'az_id': {},
               'extra_specs': {
                   'availability_zones': 'FAKE_AZ,FAKE_AZ2',
                   'replication_type': constants.REPLICATION_TYPE_DR,
               },
               'share_network_id': None},
              {'has_snapshots': True,
               'az_id': {},
               'extra_specs': {
                   'availability_zones': 'FAKE_AZ,FAKE_AZ2',
                   'replication_type': constants.REPLICATION_TYPE_READABLE,
               },
               'share_network_id': None},
              {'has_snapshots': False,
               'az_id': {'fake_zone_id': False},
               'extra_specs': {
                   'replication_type': constants.REPLICATION_TYPE_READABLE,
               },
               'share_network_id': 'fake_sn_id'})
    @ddt.unpack
    def test_create_share_replica(self, has_snapshots, extra_specs,
                                  share_network_id, az_id):
        subnets = db_utils.create_share_network_subnet(
            id='fakeid', share_network_id='fake_network_id')
        az = {'id': 'fake_zone_id'}
        request_spec = fakes.fake_replica_request_spec()
        replication_type = extra_specs['replication_type']
        replica = request_spec['share_instance_properties']
        share_type = db_utils.create_share_type(extra_specs=extra_specs)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        share = db_utils.create_share(
            id=replica['share_id'], replication_type=replication_type,
            share_type_id=share_type['id'])
        snapshots = (
            [fakes.fake_snapshot(), fakes.fake_snapshot()]
            if has_snapshots else []
        )
        cast_rules_to_readonly = (
            replication_type == constants.REPLICATION_TYPE_READABLE)

        fake_replica = fakes.fake_replica(id=replica['id'])
        fake_request_spec = fakes.fake_replica_request_spec()
        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value={'host': 'fake_ar_host'}))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=share_type))
        self.mock_object(db_api, 'availability_zone_get',
                         mock.Mock(return_value=az))
        self.mock_object(
            db_api, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=[subnets]))
        self.mock_object(
            share_api.API, 'create_share_instance_and_get_request_spec',
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
            self.context, share, availability_zone='FAKE_AZ',
            share_network_id=share_network_id)

        self.assertTrue(mock_sched_rpcapi_call.called)
        self.assertEqual(replica, result)
        share_types.get_share_type.assert_called_once_with(
            self.context, share_type['id'])
        mock_snapshot_get_all_call.assert_called_once_with(
            self.context, fake_replica['share_id'])
        self.assertEqual(expected_snap_instance_create_call_count,
                         mock_snapshot_instance_create_call.call_count)
        expected_azs = extra_specs.get('availability_zones', '')
        expected_azs = expected_azs.split(',') if expected_azs else []
        (share_api.API.create_share_instance_and_get_request_spec.
         assert_called_once_with(
             self.context, share, availability_zone='FAKE_AZ',
             share_network_id=share_network_id, share_type_id=share_type['id'],
             availability_zones=expected_azs,
             az_request_multiple_subnet_support_map=az_id,
             cast_rules_to_readonly=cast_rules_to_readonly))

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
            self.context, {'share_instance_ids': replica['id']})
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
            self.context, replica, quiesce_wait_time=None)

    def test_promote_share_replica(self):
        replica = fakes.fake_replica('FAKE_ID', host='HOSTA@BackendB#PoolC')
        self.mock_object(db_api, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db_api, 'share_replica_update')
        mock_sched_rpcapi_call = self.mock_object(
            self.share_rpcapi, 'promote_share_replica')

        result = self.api.promote_share_replica(self.context, replica)

        mock_sched_rpcapi_call.assert_called_once_with(
            self.context, replica, quiesce_wait_time=None)
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

    @ddt.data({'overs': {'replica_gigabytes': 'fake'},
               'expected_exception':
                   exception.ShareReplicaSizeExceedsAvailableQuota},
              {'overs': {'share_replicas': 'fake'},
               'expected_exception': exception.ShareReplicasLimitExceeded})
    @ddt.unpack
    def test_create_share_replica_over_quota(self, overs, expected_exception):
        request_spec = fakes.fake_replica_request_spec()
        replica = request_spec['share_instance_properties']
        share = db_utils.create_share(replication_type='dr',
                                      id=replica['share_id'])
        share_type = db_utils.create_share_type()
        share_type = db_api.share_type_get(self.context, share_type['id'])
        usages = {'replica_gigabytes': {'reserved': 5, 'in_use': 5},
                  'share_replicas': {'reserved': 5, 'in_use': 5}}
        quotas = {'share_replicas': 5, 'replica_gigabytes': 5}
        exc = exception.OverQuota(overs=overs, usages=usages, quotas=quotas)

        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(side_effect=exc))
        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value={'host': 'fake_ar_host'}))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=share_type))

        self.assertRaises(
            expected_exception,
            self.api.create_share_replica,
            self.context,
            share
        )
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, share_type_id=share_type['id'],
            share_replicas=1, replica_gigabytes=share['size'])
        (db_api.share_replicas_get_available_active_replica
         .assert_called_once_with(self.context, share['id']))
        share_types.get_share_type.assert_called_once_with(
            self.context, share['instance']['share_type_id'])

    def test_create_share_replica_error_on_quota_commit(self):
        request_spec = fakes.fake_replica_request_spec()
        replica = request_spec['share_instance_properties']
        share_type = db_utils.create_share_type()
        fake_replica = fakes.fake_replica(id=replica['id'])
        share = db_utils.create_share(replication_type='dr',
                                      id=fake_replica['share_id'],
                                      share_type_id=share_type['id'])
        share_network_id = None
        share_type = db_api.share_type_get(self.context, share_type['id'])
        expected_azs = share_type['extra_specs'].get('availability_zones', '')
        expected_azs = expected_azs.split(',') if expected_azs else []

        reservation = 'fake'
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value=reservation))
        self.mock_object(quota.QUOTAS, 'commit',
                         mock.Mock(side_effect=exception.QuotaError('fake')))
        self.mock_object(db_api, 'share_replica_delete')
        self.mock_object(quota.QUOTAS, 'rollback')
        self.mock_object(db_api, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value={'host': 'fake_ar_host'}))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=share_type))
        self.mock_object(
            share_api.API, 'create_share_instance_and_get_request_spec',
            mock.Mock(return_value=(request_spec, fake_replica)))

        self.assertRaises(
            exception.QuotaError,
            self.api.create_share_replica,
            self.context,
            share
        )

        db_api.share_replica_delete.assert_called_once_with(
            self.context, replica['id'], need_to_update_usages=False)
        quota.QUOTAS.rollback.assert_called_once_with(
            self.context, reservation,
            share_type_id=share['instance']['share_type_id'])
        (db_api.share_replicas_get_available_active_replica.
         assert_called_once_with(self.context, share['id']))
        share_types.get_share_type.assert_called_once_with(
            self.context, share['instance']['share_type_id'])
        (share_api.API.create_share_instance_and_get_request_spec.
         assert_called_once_with(self.context, share, availability_zone=None,
                                 share_network_id=share_network_id,
                                 share_type_id=share_type['id'],
                                 availability_zones=expected_azs,
                                 az_request_multiple_subnet_support_map={},
                                 cast_rules_to_readonly=False))

    def test_migration_complete(self):

        instance1 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_MIGRATING)
        instance2 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_COMPLETED,
            instances=[instance1, instance2])

        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))
        self.mock_object(self.api.share_rpcapi, 'migration_complete')

        self.api.migration_complete(self.context, share)

        self.api.share_rpcapi.migration_complete.assert_called_once_with(
            self.context, instance1, instance2['id'])

    @ddt.data(constants.TASK_STATE_DATA_COPYING_STARTING,
              constants.TASK_STATE_MIGRATION_SUCCESS,
              constants.TASK_STATE_DATA_COPYING_IN_PROGRESS,
              constants.TASK_STATE_MIGRATION_ERROR,
              constants.TASK_STATE_MIGRATION_CANCELLED,
              None)
    def test_migration_complete_task_state_invalid(self, task_state):

        share = db_utils.create_share(
            id='fake_id',
            task_state=task_state)

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

    @ddt.data(None, Exception('fake'))
    def test_migration_cancel(self, exc):

        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_IN_PROGRESS)
        services = ['fake_service']

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(db_api, 'service_get_all_by_topic',
                         mock.Mock(return_value=services))
        self.mock_object(data_rpc.DataAPI, 'data_copy_cancel',
                         mock.Mock(side_effect=[exc]))

        if exc:
            self.assertRaises(
                exception.ShareMigrationError, self.api.migration_cancel,
                self.context, share)
        else:
            self.api.migration_cancel(self.context, share)

        data_rpc.DataAPI.data_copy_cancel.assert_called_once_with(
            self.context, share['id'])
        db_api.service_get_all_by_topic.assert_called_once_with(
            self.context, 'manila-data')

    def test_migration_cancel_service_down(self):
        service = 'fake_service'
        instance1 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_MIGRATING)
        instance2 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_IN_PROGRESS,
            instances=[instance1, instance2])

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=False))
        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))
        self.mock_object(db_api, 'service_get_all_by_topic',
                         mock.Mock(return_value=service))

        self.assertRaises(exception.InvalidShare,
                          self.api.migration_cancel, self.context, share)

    def test_migration_cancel_driver(self):

        service = 'fake_service'
        instance1 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING,
            host='some_host')
        instance2 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            instances=[instance1, instance2])

        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))
        self.mock_object(self.api.share_rpcapi, 'migration_cancel')
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))
        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))

        self.api.migration_cancel(self.context, share)

        self.api.share_rpcapi.migration_cancel.assert_called_once_with(
            self.context, instance1, instance2['id'])
        db_api.service_get_by_args.assert_called_once_with(
            self.context, instance1['host'], 'manila-share')

    @ddt.data(constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
              constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
              constants.TASK_STATE_DATA_COPYING_COMPLETED)
    def test_migration_cancel_driver_service_down(self, task_state):

        service = 'fake_service'
        instance1 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING,
            host='some_host')
        instance2 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=task_state,
            instances=[instance1, instance2])

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=False))
        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))

        self.assertRaises(exception.InvalidShare,
                          self.api.migration_cancel, self.context, share)

    @ddt.data(constants.TASK_STATE_DATA_COPYING_STARTING,
              constants.TASK_STATE_MIGRATION_SUCCESS,
              constants.TASK_STATE_MIGRATION_ERROR,
              constants.TASK_STATE_MIGRATION_CANCELLED,
              None)
    def test_migration_cancel_task_state_invalid(self, task_state):

        share = db_utils.create_share(
            id='fake_id',
            task_state=task_state)

        self.assertRaises(exception.InvalidShare, self.api.migration_cancel,
                          self.context, share)

    @ddt.data({'total_progress': 50}, Exception('fake'))
    def test_migration_get_progress(self, expected):

        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_IN_PROGRESS)
        services = ['fake_service']

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(db_api, 'service_get_all_by_topic',
                         mock.Mock(return_value=services))
        self.mock_object(data_rpc.DataAPI, 'data_copy_get_progress',
                         mock.Mock(side_effect=[expected]))

        if not isinstance(expected, Exception):
            result = self.api.migration_get_progress(self.context, share)
            self.assertEqual(expected, result)
        else:
            self.assertRaises(
                exception.ShareMigrationError, self.api.migration_get_progress,
                self.context, share)

        data_rpc.DataAPI.data_copy_get_progress.assert_called_once_with(
            self.context, share['id'])
        db_api.service_get_all_by_topic.assert_called_once_with(
            self.context, 'manila-data')

    def test_migration_get_progress_service_down(self):
        instance1 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_MIGRATING)
        instance2 = db_utils.create_share_instance(
            share_id='fake_id', status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_IN_PROGRESS,
            instances=[instance1, instance2])
        services = ['fake_service']

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=False))
        self.mock_object(db_api, 'service_get_all_by_topic',
                         mock.Mock(return_value=services))
        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))

        self.assertRaises(exception.InvalidShare,
                          self.api.migration_get_progress, self.context, share)

    def test_migration_get_progress_driver(self):

        expected = {'total_progress': 50}
        instance1 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING,
            host='some_host')
        instance2 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            instances=[instance1, instance2])
        service = 'fake_service'

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))
        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))
        self.mock_object(self.api.share_rpcapi, 'migration_get_progress',
                         mock.Mock(return_value=expected))

        result = self.api.migration_get_progress(self.context, share)

        self.assertEqual(expected, result)

        self.api.share_rpcapi.migration_get_progress.assert_called_once_with(
            self.context, instance1, instance2['id'])
        db_api.service_get_by_args.assert_called_once_with(
            self.context, instance1['host'], 'manila-share')

    def test_migration_get_progress_driver_error(self):

        instance1 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING,
            host='some_host')
        instance2 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            instances=[instance1, instance2])
        service = 'fake_service'

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))
        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))
        self.mock_object(self.api.share_rpcapi, 'migration_get_progress',
                         mock.Mock(side_effect=Exception('fake')))

        self.assertRaises(exception.ShareMigrationError,
                          self.api.migration_get_progress, self.context, share)

        self.api.share_rpcapi.migration_get_progress.assert_called_once_with(
            self.context, instance1, instance2['id'])

    def test_migration_get_progress_driver_service_down(self):
        service = 'fake_service'
        instance1 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING,
            host='some_host')
        instance2 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            instances=[instance1, instance2])

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=False))
        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))

        self.assertRaises(exception.InvalidShare,
                          self.api.migration_get_progress, self.context, share)

    @ddt.data(constants.TASK_STATE_MIGRATION_STARTING,
              constants.TASK_STATE_MIGRATION_DRIVER_STARTING,
              constants.TASK_STATE_DATA_COPYING_STARTING,
              constants.TASK_STATE_MIGRATION_IN_PROGRESS)
    def test_migration_get_progress_task_state_progress_0(self, task_state):

        share = db_utils.create_share(
            id='fake_id',
            task_state=task_state)
        expected = {'total_progress': 0}

        result = self.api.migration_get_progress(self.context, share)

        self.assertEqual(expected, result)

    @ddt.data(constants.TASK_STATE_MIGRATION_SUCCESS,
              constants.TASK_STATE_DATA_COPYING_ERROR,
              constants.TASK_STATE_MIGRATION_CANCELLED,
              constants.TASK_STATE_MIGRATION_COMPLETING,
              constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
              constants.TASK_STATE_DATA_COPYING_COMPLETED,
              constants.TASK_STATE_DATA_COPYING_COMPLETING,
              constants.TASK_STATE_DATA_COPYING_CANCELLED,
              constants.TASK_STATE_MIGRATION_ERROR)
    def test_migration_get_progress_task_state_progress_100(self, task_state):

        share = db_utils.create_share(
            id='fake_id',
            task_state=task_state)
        expected = {'total_progress': 100}

        result = self.api.migration_get_progress(self.context, share)

        self.assertEqual(expected, result)

    def test_migration_get_progress_task_state_None(self):

        share = db_utils.create_share(id='fake_id', task_state=None)

        self.assertRaises(exception.InvalidShare,
                          self.api.migration_get_progress, self.context, share)

    @ddt.data(None, {'invalid_progress': None}, {})
    def test_migration_get_progress_invalid(self, progress):

        instance1 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING,
            host='some_host')
        instance2 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            instances=[instance1, instance2])
        service = 'fake_service'

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))
        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))

        self.mock_object(self.api.share_rpcapi, 'migration_get_progress',
                         mock.Mock(return_value=progress))

        self.assertRaises(exception.InvalidShare,
                          self.api.migration_get_progress, self.context, share)

        self.api.share_rpcapi.migration_get_progress.assert_called_once_with(
            self.context, instance1, instance2['id'])

    @ddt.data(True, False)
    def test__migration_initial_checks(self, create_share_network):
        type_data = {
            'extra_specs': {
                'availability_zones': 'fake_az1,fake_az2'
            }
        }
        fake_server_host = 'fake@backend'
        fake_share_server = db_utils.create_share_server(host=fake_server_host)
        share_type = db_utils.create_share_type(**type_data)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        fake_share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=share_type['id'])
        fake_az = {
            'id': 'fake_az_id',
            'name': 'fake_az1'
        }
        fake_share_network = (
            db_utils.create_share_network() if create_share_network else None)
        expected_network_change = create_share_network is True

        fake_share_network_id = (
            fake_share_network['id']
            if create_share_network else fake_share['share_network_id'])
        fake_subnet = db_utils.create_share_network_subnet(
            availability_zone_id=fake_az['id'])

        fake_host = 'test@fake'
        service = {'availability_zone_id': fake_az['id'],
                   'availability_zone': {'name': fake_az['name']}}

        mock_shares_get_all = self.mock_object(
            db_api, 'share_get_all_by_share_server',
            mock.Mock(return_value=[fake_share]))
        mock_shares_in_recycle_bin_get_all = self.mock_object(
            db_api, 'get_shares_in_recycle_bin_by_share_server',
            mock.Mock(return_value=[]))
        mock_get_type = self.mock_object(
            share_types, 'get_share_type', mock.Mock(return_value=share_type))
        mock_validate_service = self.mock_object(
            utils, 'validate_service_host')
        mock_service_get = self.mock_object(
            db_api, 'service_get_by_args', mock.Mock(return_value=service))
        mock_az_get = self.mock_object(
            db_api, 'availability_zone_get', mock.Mock(return_value=fake_az))
        mock_get_subnet = self.mock_object(
            db_api, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=[fake_subnet]))

        exp_shares, exp_types, exp_service, exp_network_id, net_change = (
            self.api._migration_initial_checks(
                self.context, fake_share_server, fake_host,
                fake_share_network))

        self.assertEqual(exp_shares, [fake_share])
        self.assertEqual(exp_types, [share_type])
        self.assertEqual(exp_service, service)
        self.assertEqual(exp_network_id, fake_share_network_id)
        self.assertIs(expected_network_change, net_change)
        mock_shares_get_all.assert_has_calls([
            mock.call(self.context, fake_share_server['id']),
            mock.call(self.context, fake_share_server['id'])])
        mock_shares_in_recycle_bin_get_all.assert_has_calls([
            mock.call(self.context, fake_share_server['id'])])
        mock_get_type.assert_called_once_with(self.context, share_type['id'])
        mock_validate_service.assert_called_once_with(self.context, fake_host)
        mock_service_get.assert_called_once_with(
            self.context, fake_host, 'manila-share')
        mock_get_subnet.assert_called_once_with(
            self.context, fake_share_network_id, fake_az['id'])
        mock_az_get.assert_called_once_with(
            self.context, service['availability_zone']['name']
        )

    def test_share_server_migration_get_destination(self):
        fake_source_server_id = 'fake_source_id'
        server_data = {
            'id': 'fake',
            'source_share_server_id': fake_source_server_id,
            'status': constants.STATUS_SERVER_MIGRATING_TO,
        }
        server = db_utils.create_share_server(**server_data)
        mock_get_all = self.mock_object(
            db_api, 'share_server_get_all_with_filters',
            mock.Mock(return_value=[server]))
        filters = {
            'status': constants.STATUS_SERVER_MIGRATING_TO,
            'source_share_server_id': fake_source_server_id,
        }

        filtered_server = self.api.share_server_migration_get_destination(
            self.context, fake_source_server_id,
            status=constants.STATUS_SERVER_MIGRATING_TO
        )
        self.assertEqual(filtered_server['id'], server['id'])
        mock_get_all.assert_called_once_with(self.context, filters=filters)

    def test_share_server_migration_get_destination_no_share_server(self):
        fake_source_server_id = 'fake_source_id'
        server_data = {
            'id': 'fake',
            'source_share_server_id': fake_source_server_id,
            'status': constants.STATUS_SERVER_MIGRATING_TO,
        }
        db_utils.create_share_server(**server_data)
        mock_get_all = self.mock_object(
            db_api, 'share_server_get_all_with_filters',
            mock.Mock(return_value=[]))
        filters = {
            'status': constants.STATUS_SERVER_MIGRATING_TO,
            'source_share_server_id': fake_source_server_id,
        }

        self.assertRaises(
            exception.InvalidShareServer,
            self.api.share_server_migration_get_destination,
            self.context, fake_source_server_id,
            status=constants.STATUS_SERVER_MIGRATING_TO
        )
        mock_get_all.assert_called_once_with(self.context, filters=filters)

    def test_share_server_migration_get_destination_multiple_servers(self):
        fake_source_server_id = 'fake_source_id'
        server_data = {
            'id': 'fake',
            'source_share_server_id': fake_source_server_id,
            'status': constants.STATUS_SERVER_MIGRATING_TO,
        }
        server_1 = db_utils.create_share_server(**server_data)
        server_data['id'] = 'fake_id_2'
        server_2 = db_utils.create_share_server(**server_data)
        mock_get_all = self.mock_object(
            db_api, 'share_server_get_all_with_filters',
            mock.Mock(return_value=[server_1, server_2]))
        filters = {
            'status': constants.STATUS_SERVER_MIGRATING_TO,
            'source_share_server_id': fake_source_server_id,
        }

        self.assertRaises(
            exception.InvalidShareServer,
            self.api.share_server_migration_get_destination,
            self.context, fake_source_server_id,
            status=constants.STATUS_SERVER_MIGRATING_TO
        )
        mock_get_all.assert_called_once_with(self.context, filters=filters)

    def test__migration_initial_checks_no_shares(self):
        fake_share_server = fakes.fake_share_server_get()
        fake_share_network = {}
        fake_host = 'test@fake'
        mock_shares_get_all = self.mock_object(
            db_api, 'share_get_all_by_share_server',
            mock.Mock(return_value=[]))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_host, fake_share_network,
        )
        mock_shares_get_all.assert_called_once_with(
            self.context, fake_share_server['id'])

    def test__migration_initial_checks_server_not_active(self):
        fake_share_server = fakes.fake_share_server_get()
        fake_share_server['status'] = 'error'
        fake_share = fakes.fake_share()
        fake_share_network = {}
        fake_host = 'test@fake'

        mock_shares_get_all = self.mock_object(
            db_api, 'share_get_all_by_share_server',
            mock.Mock(return_value=[fake_share]))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_host, fake_share_network,
        )
        mock_shares_get_all.assert_called_once_with(
            self.context, fake_share_server['id'])

    def test__migration_initial_checks_share_group_related_to_server(self):
        fake_share_server = db_utils.create_share_server()
        fake_share = db_utils.create_share()
        fake_share_group = db_utils.create_share_group()
        fake_share_network = {}
        fake_host = 'test@fake'

        mock_shares_get_all = self.mock_object(
            db_api, 'share_get_all_by_share_server',
            mock.Mock(return_value=[fake_share]))
        mock_get_groups = self.mock_object(
            db_api, 'share_group_get_all_by_share_server',
            mock.Mock(return_value=[fake_share_group]))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_host, fake_share_network,
        )
        mock_shares_get_all.assert_called_once_with(
            self.context, fake_share_server['id'])
        mock_get_groups.assert_called_once_with(self.context,
                                                fake_share_server['id'])

    def _setup_mocks_for_initial_checks(self, fake_share, share_type, service,
                                        fake_az, fake_subnet):
        self.mock_object(
            db_api, 'share_get_all_by_share_server',
            mock.Mock(return_value=[fake_share]))
        self.mock_object(
            db_api, 'share_group_get_all_by_share_server',
            mock.Mock(return_value=[]))
        self.mock_object(
            share_types, 'get_share_type', mock.Mock(return_value=share_type))
        self.mock_object(
            utils, 'validate_service_host')
        self.mock_object(
            db_api, 'service_get_by_args', mock.Mock(return_value=service))
        self.mock_object(
            db_api, 'availability_zone_get', mock.Mock(return_value=fake_az))
        self.mock_object(
            db_api, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=fake_subnet))

    def test__migration_initial_checks_share_not_available(self):
        fake_share_server = fakes.fake_share_server_get()
        fake_share_server['host'] = 'fake@backend'
        type_data = {
            'extra_specs': {
                'availability_zones': 'fake_az1,fake_az2'
            }
        }
        fake_server_host = 'fake@backend'
        fake_share_server = db_utils.create_share_server(host=fake_server_host)
        share_type = db_utils.create_share_type(**type_data)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        fake_share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_ERROR,
            share_type_id=share_type['id'])
        fake_az = {
            'id': 'fake_az_id',
            'name': 'fake_az1'
        }
        fake_share_network = None
        fake_share_network_id = fake_share['share_network_id']
        fake_subnet = db_utils.create_share_network_subnet(
            availability_zone_id=fake_az['id'])
        fake_host = 'test@fake'
        service = {'availability_zone_id': fake_az['id'],
                   'availability_zone': {'name': fake_az['name']}}
        self._setup_mocks_for_initial_checks(fake_share, share_type, service,
                                             fake_az, fake_subnet)

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_host, fake_share_network,
        )
        db_api.share_get_all_by_share_server.assert_has_calls([
            mock.call(self.context, fake_share_server['id']),
            mock.call(self.context, fake_share_server['id'])])
        share_types.get_share_type.assert_called_once_with(
            self.context, share_type['id'])
        utils.validate_service_host.assert_called_once_with(
            self.context, fake_host)
        db_api.service_get_by_args.assert_called_once_with(
            self.context, fake_host, 'manila-share')
        db_api.availability_zone_get.assert_called_once_with(
            self.context, service['availability_zone']['name']
        )
        (db_api.share_network_subnets_get_all_by_availability_zone_id.
            assert_called_once_with(
                self.context, fake_share_network_id, fake_az['id']))
        db_api.share_group_get_all_by_share_server.assert_called_once_with(
            self.context, fake_share_server['id'])

    def test__migration_initial_checks_share_with_replicas(self):
        fake_share_server = fakes.fake_share_server_get()
        fake_share_server['host'] = 'fake@backend'
        type_data = {
            'extra_specs': {
                'availability_zones': 'fake_az1,fake_az2'
            }
        }
        fake_server_host = 'fake@backend'
        fake_share_server = db_utils.create_share_server(host=fake_server_host)
        share_type = db_utils.create_share_type(**type_data)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        fake_share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            replication_type='dr', share_type_id=share_type['id'])
        for i in range(1, 4):
            db_utils.create_share_replica(
                share_id=fake_share['id'], replica_state='in_sync')
        fake_share = db_api.share_get(self.context, fake_share['id'])
        fake_az = {
            'id': 'fake_az_id',
            'name': 'fake_az1'
        }
        fake_share_network = None
        fake_share_network_id = fake_share['share_network_id']
        fake_subnet = db_utils.create_share_network_subnet(
            availability_zone_id=fake_az['id'])
        fake_host = 'test@fake'
        service = {'availability_zone_id': fake_az['id'],
                   'availability_zone': {'name': fake_az['name']}}
        self._setup_mocks_for_initial_checks(fake_share, share_type, service,
                                             fake_az, fake_subnet)

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_host, fake_share_network,
        )
        db_api.share_get_all_by_share_server.assert_has_calls([
            mock.call(self.context, fake_share_server['id']),
            mock.call(self.context, fake_share_server['id'])])
        share_types.get_share_type.assert_called_once_with(
            self.context, share_type['id'])
        utils.validate_service_host.assert_called_once_with(
            self.context, fake_host)
        db_api.service_get_by_args.assert_called_once_with(
            self.context, fake_host, 'manila-share')
        db_api.availability_zone_get.assert_called_once_with(
            self.context, service['availability_zone']['name']
        )
        (db_api.share_network_subnets_get_all_by_availability_zone_id.
            assert_called_once_with(
                self.context, fake_share_network_id, fake_az['id']))
        db_api.share_group_get_all_by_share_server.assert_called_once_with(
            self.context, fake_share_server['id'])

    def test__migration_initial_checks_share_in_share_group(self):
        fake_share_server = fakes.fake_share_server_get()
        fake_share_server['host'] = 'fake@backend'
        type_data = {
            'extra_specs': {
                'availability_zones': 'fake_az1,fake_az2'
            }
        }
        fake_server_host = 'fake@backend'
        fake_share_server = db_utils.create_share_server(host=fake_server_host)
        share_type = db_utils.create_share_type(**type_data)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        fake_share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=share_type['id'], share_group_id='fake_group_id')
        fake_az = {
            'id': 'fake_az_id',
            'name': 'fake_az1'
        }
        fake_share_network = None
        fake_share_network_id = fake_share['share_network_id']
        fake_subnet = db_utils.create_share_network_subnet(
            availability_zone_id=fake_az['id'])
        fake_host = 'test@fake'
        service = {'availability_zone_id': fake_az['id'],
                   'availability_zone': {'name': fake_az['name']}}
        self._setup_mocks_for_initial_checks(fake_share, share_type, service,
                                             fake_az, fake_subnet)
        mock_snapshots_get = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share',
            mock.Mock(return_value=[]))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_host, fake_share_network,
        )
        db_api.share_get_all_by_share_server.assert_has_calls([
            mock.call(self.context, fake_share_server['id']),
            mock.call(self.context, fake_share_server['id'])])
        share_types.get_share_type.assert_called_once_with(
            self.context, share_type['id'])
        utils.validate_service_host.assert_called_once_with(
            self.context, fake_host)
        db_api.service_get_by_args.assert_called_once_with(
            self.context, fake_host, 'manila-share')
        db_api.availability_zone_get.assert_called_once_with(
            self.context, service['availability_zone']['name']
        )
        (db_api.share_network_subnets_get_all_by_availability_zone_id.
            assert_called_once_with(
                self.context, fake_share_network_id, fake_az['id']))
        mock_snapshots_get.assert_called_once_with(
            self.context, fake_share['id'])
        db_api.share_group_get_all_by_share_server.assert_called_once_with(
            self.context, fake_share_server['id'])

    def test__migration_initial_checks_same_backend_and_network(self):
        fake_server_host = 'fake@backend'
        fake_share_network = {'id': 'fake_share_network_id'}
        fake_share_server = db_utils.create_share_server(host=fake_server_host)
        fake_share = db_utils.create_share(
            host=fake_server_host, status=constants.STATUS_AVAILABLE,
            share_group_id='fake_group_id',
            share_network_id=fake_share_network['id'])

        mock_shares_get_all = self.mock_object(
            db_api, 'share_get_all_by_share_server',
            mock.Mock(return_value=[fake_share]))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_server_host,
            fake_share_network,
        )
        mock_shares_get_all.assert_called_once_with(
            self.context, fake_share_server['id'])

    def test__migration_initial_checks_another_migration_found(self):
        fake_server_host = 'fake@backend2'
        fake_share_network = {'id': 'fake_share_network_id'}
        fake_share_server = db_utils.create_share_server(host=fake_server_host)
        fake_share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_group_id='fake_group_id', share_network=fake_share_network)

        mock_shares_get_all = self.mock_object(
            db_api, 'share_get_all_by_share_server',
            mock.Mock(return_value=[fake_share]))
        mock_shares_get_servers_filters = self.mock_object(
            db_api, 'share_server_get_all_with_filters',
            mock.Mock(return_value=['fake_share_server']))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_server_host,
            fake_share_network,
        )
        mock_shares_get_all.assert_called_once_with(
            self.context, fake_share_server['id'])
        filters = {'source_share_server_id': fake_share_server['id'],
                   'status': constants.STATUS_SERVER_MIGRATING_TO}
        mock_shares_get_servers_filters.assert_called_once_with(
            self.context, filters=filters)

    def test_share_server_migration_get_request_spec_dict(self):
        share_instances = [
            db_utils.create_share_instance(share_id='fake_id')
            for i in range(1, 3)]
        snapshot_instances = [
            db_utils.create_snapshot_instance(
                snapshot_id='fake_' + str(i), share_instance_id='fake')
            for i in range(1, 3)]
        shares_req_spec = [{} for instance in share_instances]
        total_shares_size = sum(
            [instance.get('size', 0) for instance in share_instances])
        total_snapshots_size = sum(
            [instance.get('size', 0) for instance in snapshot_instances])
        expected_result = {
            'shares_size': total_shares_size,
            'snapshots_size': total_snapshots_size,
            'shares_req_spec': shares_req_spec,
        }
        fake_share_type = db_utils.create_share_type()
        get_type_calls = []
        get_request_spec_calls = []
        for instance in share_instances:
            get_type_calls.append(
                mock.call(self.context, instance['share_type_id']))
            get_request_spec_calls.append(
                mock.call(self.context, instance, fake_share_type))

        mock_get_type = self.mock_object(
            share_types, 'get_share_type',
            mock.Mock(return_value=fake_share_type))
        mock_get_request_spec = self.mock_object(
            self.api, '_get_request_spec_dict', mock.Mock(return_value={}))

        result = self.api.get_share_server_migration_request_spec_dict(
            self.context, share_instances, snapshot_instances)

        self.assertEqual(result, expected_result)
        mock_get_type.assert_has_calls(get_type_calls)
        mock_get_request_spec.assert_has_calls(get_request_spec_calls)

    def test__migration_initial_checks_instance_rules_error_status(self):
        fake_share_server = fakes.fake_share_server_get()
        fake_share_server['host'] = 'fake@backend'
        type_data = {
            'extra_specs': {
                'availability_zones': 'fake_az1,fake_az2'
            }
        }
        fake_server_host = 'fake@backend'
        fake_share_server = db_utils.create_share_server(host=fake_server_host)
        share_type = db_utils.create_share_type(**type_data)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        fake_share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=share_type['id'], share_group_id='fake_group_id')
        fake_share['instance']['access_rules_status'] = constants.STATUS_ERROR
        fake_az = {
            'id': 'fake_az_id',
            'name': 'fake_az1'
        }
        fake_share_network = None
        fake_share_network_id = fake_share['share_network_id']
        fake_subnet = db_utils.create_share_network_subnet(
            availability_zone_id=fake_az['id'])
        fake_host = 'test@fake'
        service = {'availability_zone_id': fake_az['id'],
                   'availability_zone': {'name': fake_az['name']}}
        self._setup_mocks_for_initial_checks(fake_share, share_type, service,
                                             fake_az, fake_subnet)

        mock_snapshots_get = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share',
            mock.Mock(return_value=[]))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_host, fake_share_network,
        )

        db_api.share_get_all_by_share_server.assert_has_calls([
            mock.call(self.context, fake_share_server['id']),
            mock.call(self.context, fake_share_server['id'])])
        share_types.get_share_type.assert_called_once_with(
            self.context, share_type['id'])
        utils.validate_service_host.assert_called_once_with(
            self.context, fake_host)
        db_api.service_get_by_args.assert_called_once_with(
            self.context, fake_host, 'manila-share')
        db_api.availability_zone_get.assert_called_once_with(
            self.context, service['availability_zone']['name']
        )
        (db_api.share_network_subnets_get_all_by_availability_zone_id.
            assert_called_once_with(
                self.context, fake_share_network_id, fake_az['id']))
        mock_snapshots_get.assert_called_once_with(
            self.context, fake_share['id'])
        db_api.share_group_get_all_by_share_server.assert_called_once_with(
            self.context, fake_share_server['id'])

    def test__migration_initial_checks_dest_az_not_match_host_az(self):
        type_data = {
            'extra_specs': {
                'availability_zones': 'zone1,zone2'
            }
        }
        fake_server_host = 'fake@backend'
        fake_share_server = db_utils.create_share_server(host=fake_server_host)
        share_type = db_utils.create_share_type(**type_data)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        fake_share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=share_type['id'])
        fake_share_network = {}
        fake_host = 'test@fake'
        service = {'availability_zone_id': 'fake_az_id',
                   'availability_zone': {'name': 'fake_az1'}}

        mock_shares_get_all = self.mock_object(
            db_api, 'share_get_all_by_share_server',
            mock.Mock(return_value=[fake_share]))
        mock_get_type = self.mock_object(
            share_types, 'get_share_type', mock.Mock(return_value=share_type))
        mock_validate_service = self.mock_object(
            utils, 'validate_service_host')
        mock_service_get = self.mock_object(
            db_api, 'service_get_by_args', mock.Mock(return_value=service))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_host, fake_share_network,
        )
        mock_shares_get_all.assert_called_once_with(
            self.context, fake_share_server['id'])
        mock_get_type.assert_called_once_with(self.context, share_type['id'])
        mock_validate_service.assert_called_once_with(self.context, fake_host)
        mock_service_get.assert_called_once_with(
            self.context, fake_host, 'manila-share')

    def test__migration_initial_checks_no_matching_subnet(self):
        type_data = {
            'extra_specs': {
                'availability_zones': 'fake_az1,fake_az2'
            }
        }
        fake_server_host = 'fake@backend'
        fake_share_server = db_utils.create_share_server(host=fake_server_host)
        share_type = db_utils.create_share_type(**type_data)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        fake_share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=share_type['id'])
        fake_share_network = db_utils.create_share_network()
        fake_az = {
            'id': 'fake_az_id',
            'name': 'fake_az1'
        }

        db_utils.create_share_network_subnet(
            availability_zone_id='fake',
            share_network_id=fake_share_network['id'])
        fake_share_network = db_api.share_network_get(
            self.context, fake_share_network['id'])
        fake_host = 'test@fake'
        service = {'availability_zone_id': fake_az['id'],
                   'availability_zone': {'name': fake_az['name']}}

        mock_shares_get_all = self.mock_object(
            db_api, 'share_get_all_by_share_server',
            mock.Mock(return_value=[fake_share]))
        mock_get_type = self.mock_object(
            share_types, 'get_share_type', mock.Mock(return_value=share_type))
        mock_validate_service = self.mock_object(
            utils, 'validate_service_host')
        mock_service_get = self.mock_object(
            db_api, 'service_get_by_args', mock.Mock(return_value=service))
        mock_az_get = self.mock_object(
            db_api, 'availability_zone_get', mock.Mock(return_value=fake_az))
        mock_get_subnet = self.mock_object(
            db_api, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=None))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api._migration_initial_checks,
            self.context, fake_share_server, fake_host, fake_share_network,
        )
        mock_shares_get_all.assert_called_once_with(
            self.context, fake_share_server['id'])
        mock_get_type.assert_called_once_with(self.context, share_type['id'])
        mock_validate_service.assert_called_once_with(self.context, fake_host)
        mock_service_get.assert_called_once_with(
            self.context, fake_host, 'manila-share')
        mock_get_subnet.assert_called_once_with(
            self.context, fake_share_network['id'], fake_az['id'])
        mock_az_get.assert_called_once_with(
            self.context, service['availability_zone']['name']
        )

    def test_server_migration_check_nondisruptive_and_network_change(self):
        fake_shares = [db_utils.create_share() for i in range(2)]
        fake_types = [{'id': 'fake_type_id'}]
        fake_share_server = db_utils.create_share_server()
        dest_host = fake_share_server['host']
        service = {
            'availability_zone_id': 'fake_az_id',
            'availability_zone': {'name': 'fake_az_name'}
        }
        fake_share_network = db_utils.create_share_network()
        network_has_changed = True
        writable = preserve_snapshots = False
        nondisruptive = True
        expected_result = {
            'compatible': False,
            'writable': writable,
            'nondisruptive': False,
            'preserve_snapshots': preserve_snapshots,
            'share_network_id': fake_share_network['id'],
            'migration_cancel': False,
            'migration_get_progress': False
        }

        mock_initial_checks = self.mock_object(
            self.api, '_migration_initial_checks',
            mock.Mock(
                return_value=[fake_shares, fake_types, service,
                              fake_share_network['id'], network_has_changed]))

        check_result = self.api.share_server_migration_check(
            self.context, fake_share_server, dest_host, writable,
            nondisruptive, preserve_snapshots, fake_share_network
        )

        self.assertEqual(expected_result, check_result)
        mock_initial_checks.assert_called_once_with(
            self.context, fake_share_server, dest_host, fake_share_network)

    def test_server_migration_start_nondisruptive_and_network_change(self):
        fake_shares = [db_utils.create_share() for i in range(2)]
        fake_types = [{'id': 'fake_type_id'}]
        fake_share_server = db_utils.create_share_server()
        dest_host = fake_share_server['host']
        service = {
            'availability_zone_id': 'fake_az_id',
            'availability_zone': {'name': 'fake_az_name'}
        }
        fake_share_network = db_utils.create_share_network()
        network_has_changed = True
        writable = preserve_snapshots = False
        nondisruptive = True

        mock_initial_checks = self.mock_object(
            self.api, '_migration_initial_checks',
            mock.Mock(
                return_value=[fake_shares, fake_types, service,
                              fake_share_network['id'], network_has_changed]))

        self.assertRaises(
            exception.InvalidInput,
            self.api.share_server_migration_start,
            self.context, fake_share_server, dest_host, writable,
            nondisruptive, preserve_snapshots, fake_share_network
        )

        mock_initial_checks.assert_called_once_with(
            self.context, fake_share_server, dest_host, fake_share_network)

    def test_share_server_migration_check(self):
        type_data = {
            'extra_specs': {
                'availability_zones': 'fake_az1,fake_az2'
            }
        }
        fake_share_server = db_utils.create_share_server()
        share_type = db_utils.create_share_type(**type_data)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        fake_share = db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=share_type['id'])
        fake_shares = [fake_share]
        fake_types = [share_type]
        fake_share_network = db_utils.create_share_network()
        fake_az = {
            'id': 'fake_az_id',
            'name': 'fake_az1'
        }
        writable = True
        nondisruptive = True
        preserve_snapshots = True
        fake_share_network = db_api.share_network_get(
            self.context, fake_share_network['id'])
        fake_host = 'test@fake'
        service = {'availability_zone_id': fake_az['id'],
                   'availability_zone': {'name': fake_az['name']}}
        expected_result = {
            'requested_capabilities': {},
            'supported_capabilities': {}
        }

        mock_initial_checks = self.mock_object(
            self.api, '_migration_initial_checks',
            mock.Mock(return_value=[fake_shares, fake_types, service,
                                    fake_share_network['id'], False]))
        # NOTE(carloss): Returning an "empty" dictionary should be enough for
        # this test case. The unit test to check the values being returned to
        # the user should be placed in the share manager, where the dict is
        # populated with the real info. At this level we only forward the
        # received response to the user.
        mock_migration_check = self.mock_object(
            self.share_rpcapi, 'share_server_migration_check',
            mock.Mock(return_value=expected_result))

        result = self.api.share_server_migration_check(
            self.context, fake_share_server, fake_host, writable,
            nondisruptive, preserve_snapshots, fake_share_network
        )

        mock_initial_checks.assert_called_once_with(
            self.context, fake_share_server, fake_host, fake_share_network)
        mock_migration_check.assert_called_once_with(
            self.context, fake_share_server['id'], fake_host, writable,
            nondisruptive, preserve_snapshots, fake_share_network['id']
        )
        self.assertEqual(result, expected_result)

    def test_share_server_migration_start(self):
        type_data = {
            'extra_specs': {
                'availability_zones': 'fake_az1,fake_az2'
            }
        }
        fake_share_server = db_utils.create_share_server()
        share_type = db_utils.create_share_type(**type_data)
        share_type = db_api.share_type_get(self.context, share_type['id'])
        fake_shares = [db_utils.create_share(
            host='fake@backend#pool', status=constants.STATUS_AVAILABLE,
            share_type_id=share_type['id']) for x in range(4)]
        fake_snapshots = [
            db_utils.create_snapshot(share_id=fake_shares[0]['id'])]
        instance_ids = [share['instance']['id'] for share in fake_shares]
        snap_instance_ids = []
        for fake_share in fake_shares:
            for snapshot in fake_snapshots:
                snap_instance_ids.append(snapshot['instance']['id'])
        fake_types = [share_type]
        fake_share_network = db_utils.create_share_network()
        writable = True
        nondisruptive = True
        preserve_snapshots = True
        fake_share_network = db_api.share_network_get(
            self.context, fake_share_network['id'])
        fake_host = 'test@fake'
        service = {'availability_zone_id': 'fake_az_id',
                   'availability_zone': {'name': 'fake_az1'}}
        server_expected_update = {
            'task_state': constants.TASK_STATE_MIGRATION_STARTING,
            'status': constants.STATUS_SERVER_MIGRATING
        }
        share_expected_update = {
            'status': constants.STATUS_SERVER_MIGRATING
        }
        snapshot_get_calls = [
            mock.call(self.context, share['id']) for share in fake_shares]

        mock_initial_checks = self.mock_object(
            self.api, '_migration_initial_checks',
            mock.Mock(return_value=[fake_shares, fake_types, service,
                                    fake_share_network['id'], False]))
        mock_migration_start = self.mock_object(
            self.share_rpcapi, 'share_server_migration_start')
        mock_server_update = self.mock_object(db_api, 'share_server_update')
        mock_snapshots_get = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share',
            mock.Mock(return_value=fake_snapshots))
        mock_update_instances = self.mock_object(
            db_api, 'share_and_snapshot_instances_status_update')

        self.api.share_server_migration_start(
            self.context, fake_share_server, fake_host, writable,
            nondisruptive, preserve_snapshots, fake_share_network
        )

        mock_initial_checks.assert_called_once_with(
            self.context, fake_share_server, fake_host, fake_share_network)
        mock_migration_start.assert_called_once_with(
            self.context, fake_share_server, fake_host, writable,
            nondisruptive, preserve_snapshots, fake_share_network['id']
        )
        mock_server_update.assert_called_once_with(
            self.context, fake_share_server['id'], server_expected_update)
        mock_snapshots_get.assert_has_calls(
            snapshot_get_calls)
        mock_update_instances.assert_called_once_with(
            self.context, share_expected_update,
            current_expected_status=constants.STATUS_AVAILABLE,
            share_instance_ids=instance_ids,
            snapshot_instance_ids=snap_instance_ids)

    @ddt.data(
        (constants.STATUS_ACTIVE, None),
        (constants.STATUS_SERVER_MIGRATING,
         constants.TASK_STATE_MIGRATION_STARTING)
    )
    @ddt.unpack
    def test_share_server_migration_complete_invalid_status(self, status,
                                                            task_state):
        fake_host = 'fakehost@fakebackend'
        fake_share_server = db_utils.create_share_server(
            status=status, task_state=task_state, host=fake_host)
        self.assertRaises(
            exception.InvalidShareServer,
            self.api.share_server_migration_complete,
            self.context, fake_share_server)

    def test_share_server_migration_complete(self):
        fake_service_host = 'fakehost@fakebackend'
        fake_share_server = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING,
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
            host=fake_service_host)
        fake_share_server_dest = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING_TO,
            host=fake_service_host)
        fake_service = {'availability_zone_id': 'fake_az_id',
                        'availability_zone': {'name': 'fake_az1'}}

        mock_get_destination = self.mock_object(
            self.api, 'share_server_migration_get_destination',
            mock.Mock(return_value=fake_share_server_dest))
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host',
            mock.Mock(return_value=fake_service))
        mock_migration_complete = self.mock_object(
            self.share_rpcapi, 'share_server_migration_complete')

        result = self.api.share_server_migration_complete(
            self.context, fake_share_server)

        expected = {
            'destination_share_server_id': fake_share_server_dest['id']
        }
        self.assertEqual(expected, result)
        mock_get_destination.assert_called_once_with(
            self.context, fake_share_server['id'],
            status=constants.STATUS_SERVER_MIGRATING_TO)
        mock_validate_service_host.assert_called_once_with(
            self.context, fake_service_host)
        mock_migration_complete.assert_called_once_with(
            self.context, fake_share_server['host'], fake_share_server,
            fake_share_server_dest
        )

    @ddt.data(
        (constants.STATUS_ACTIVE, None),
        (constants.STATUS_SERVER_MIGRATING,
         constants.TASK_STATE_MIGRATION_STARTING)
    )
    @ddt.unpack
    def test_share_server_migration_cancel_server_not_migrating(
            self, status, task_state):
        fake_share_server = db_utils.create_share_server(
            status=status, task_state=task_state)

        self.mock_object(self.api, '_migration_validate_error_message',
                         mock.Mock(return_value=None))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api.share_server_migration_cancel,
            self.context,
            fake_share_server
        )

    @ddt.data(constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
              constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)
    def test_share_server_migration_cancel_service_not_up(self, task_state):
        fake_service_host = 'host@backend'
        fake_share_server = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING,
            task_state=task_state,
            host=fake_service_host)
        fake_share_server_dest = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING_TO,
            host=fake_service_host)

        mock_get_destination = self.mock_object(
            self.api, 'share_server_migration_get_destination',
            mock.Mock(return_value=fake_share_server_dest))
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host',
            mock.Mock(side_effect=exception.ServiceIsDown(
                service="fake_service")))

        self.assertRaises(
            exception.ServiceIsDown,
            self.api.share_server_migration_cancel,
            self.context,
            fake_share_server
        )
        mock_get_destination.assert_called_once_with(
            self.context, fake_share_server['id'],
            status=constants.STATUS_SERVER_MIGRATING_TO)
        mock_validate_service_host.assert_called_once_with(
            self.context, fake_service_host)

    @ddt.data(constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
              constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)
    def test_share_server_migration_cancel(self, task_state):
        fake_service_host = 'host@backend'
        fake_share_server = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING,
            task_state=task_state,
            host=fake_service_host)
        fake_share_server_dest = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING_TO,
            host=fake_service_host)
        fake_service = {'availability_zone_id': 'fake_az_id',
                        'availability_zone': {'name': 'fake_az1'}}

        mock_get_destination = self.mock_object(
            self.api, 'share_server_migration_get_destination',
            mock.Mock(return_value=fake_share_server_dest))
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host',
            mock.Mock(return_value=fake_service))

        self.api.share_server_migration_cancel(
            self.context, fake_share_server)

        mock_get_destination.assert_called_once_with(
            self.context, fake_share_server['id'],
            status=constants.STATUS_SERVER_MIGRATING_TO)
        mock_validate_service_host.assert_called_once_with(
            self.context, fake_service_host)

    def test_share_server_migration_get_progress_not_migrating(self):
        fake_share_server = db_utils.create_share_server(
            status=constants.STATUS_ACTIVE)
        self.assertRaises(
            exception.InvalidShareServer,
            self.api.share_server_migration_get_progress,
            self.context, fake_share_server['id']
        )

    def test_share_server_migration_get_progress_service_not_up(self):
        fake_service_host = 'host@backend'
        fake_share_server = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING,
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            host=fake_service_host)
        fake_share_server_dest = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING_TO,
            host=fake_service_host)

        mock_get_destination = self.mock_object(
            self.api, 'share_server_migration_get_destination',
            mock.Mock(return_value=fake_share_server_dest))
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host',
            mock.Mock(side_effect=exception.ServiceIsDown(
                service="fake_service")))

        self.assertRaises(
            exception.ServiceIsDown,
            self.api.share_server_migration_get_progress,
            self.context, fake_share_server['id']
        )

        mock_get_destination.assert_called_once_with(
            self.context, fake_share_server['id'],
            status=constants.STATUS_SERVER_MIGRATING_TO)
        mock_validate_service_host.assert_called_once_with(
            self.context, fake_service_host)

    def test_share_server_migration_get_progress_rpcapi_exception(self):
        fake_service_host = 'host@backend'
        fake_share_server = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING,
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            host=fake_service_host)
        fake_share_server_dest = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING_TO,
            host=fake_service_host)
        fake_service = {'availability_zone_id': 'fake_az_id',
                        'availability_zone': {'name': 'fake_az1'}}

        mock_server_get = self.mock_object(
            db_api, 'share_server_get',
            mock.Mock(return_value=fake_share_server))
        mock_get_destination = self.mock_object(
            self.api, 'share_server_migration_get_destination',
            mock.Mock(return_value=fake_share_server_dest))
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host',
            mock.Mock(return_value=fake_service))
        mock_migration_get_progress = self.mock_object(
            self.share_rpcapi, 'share_server_migration_get_progress',
            mock.Mock(side_effect=Exception))

        self.assertRaises(
            exception.ShareServerMigrationError,
            self.api.share_server_migration_get_progress,
            self.context,
            fake_share_server['id']
        )

        mock_server_get.assert_called_once_with(self.context,
                                                fake_share_server['id'])
        mock_get_destination.assert_called_once_with(
            self.context, fake_share_server['id'],
            status=constants.STATUS_SERVER_MIGRATING_TO)
        mock_validate_service_host.assert_called_once_with(
            self.context, fake_service_host)
        mock_migration_get_progress.assert_called_once_with(
            self.context, fake_share_server_dest['host'], fake_share_server,
            fake_share_server_dest)

    @ddt.data(constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
              constants.TASK_STATE_MIGRATION_SUCCESS)
    def test_share_server_migration_get_progress(self, task_state):
        fake_service_host = 'host@backend'
        fake_share_server = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING,
            task_state=task_state, host=fake_service_host)
        fake_share_server_dest = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING_TO,
            host=fake_service_host)
        fake_service = {'availability_zone_id': 'fake_az_id',
                        'availability_zone': {'name': 'fake_az1'}}

        mock_server_get = self.mock_object(
            db_api, 'share_server_get',
            mock.Mock(return_value=fake_share_server))
        mock_get_destination = self.mock_object(
            self.api, 'share_server_migration_get_destination',
            mock.Mock(return_value=fake_share_server_dest))
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host',
            mock.Mock(return_value=fake_service))
        mock_migration_get_progress = self.mock_object(
            self.share_rpcapi, 'share_server_migration_get_progress',
            mock.Mock(return_value={'total_progress': 50}))
        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))

        result = self.api.share_server_migration_get_progress(
            self.context, fake_share_server['id'])

        self.assertIn('total_progress', result)
        mock_server_get.assert_called_once_with(self.context,
                                                fake_share_server['id'])
        if task_state == constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS:
            mock_get_destination.assert_called_once_with(
                self.context, fake_share_server['id'],
                status=constants.STATUS_SERVER_MIGRATING_TO)
            mock_validate_service_host.assert_called_once_with(
                self.context, fake_service_host)
            mock_migration_get_progress.assert_called_once_with(
                self.context, fake_share_server_dest['host'],
                fake_share_server, fake_share_server_dest)

    @ddt.data(constants.STATUS_SERVER_MIGRATING_TO,
              constants.STATUS_SERVER_MIGRATING)
    def test_share_server_migration_get_progress_invalid_share_server(self,
                                                                      status):
        fake_service_host = 'host@backend'
        fake_share_server = db_utils.create_share_server(
            status=status,
            task_state=None,
            host=fake_service_host)
        mock_server_get = self.mock_object(
            db_api, 'share_server_get',
            mock.Mock(return_value=fake_share_server))
        mock_get_progress_state = self.mock_object(
            self.api, '_migration_get_progress_state',
            mock.Mock(return_value=None))
        self.mock_object(self.api, 'share_server_migration_get_destination')

        self.assertRaises(
            exception.InvalidShareServer,
            self.api.share_server_migration_get_progress,
            self.context, fake_share_server['id'])

        mock_server_get.assert_called_once_with(self.context,
                                                fake_share_server['id'])
        if status == constants.STATUS_SERVER_MIGRATING:
            mock_get_progress_state.assert_called_once_with(fake_share_server)

    def test_share_server_migration_get_progress_source_not_found(self):
        fake_dest_hare_server = db_utils.create_share_server(
            status=constants.STATUS_ACTIVE,
            task_state=constants.TASK_STATE_MIGRATION_SUCCESS)
        mock_server_get = self.mock_object(
            db_api, 'share_server_get',
            mock.Mock(side_effect=exception.ShareServerNotFound(
                share_server_id='fake_id')))
        mock_get_destination = self.mock_object(
            self.api, 'share_server_migration_get_destination',
            mock.Mock(return_value=fake_dest_hare_server))

        result = self.api.share_server_migration_get_progress(
            self.context, 'fake_source_server_id')
        expected = {
            'total_progress': 100,
            'destination_share_server_id': fake_dest_hare_server['id'],
            'task_state': constants.TASK_STATE_MIGRATION_SUCCESS,
        }

        self.assertEqual(expected, result)
        mock_server_get.assert_called_once_with(self.context,
                                                'fake_source_server_id')
        mock_get_destination.assert_called_once_with(
            self.context, 'fake_source_server_id',
            status=constants.STATUS_ACTIVE)

    def test_share_server_migration_get_progress_has_destination_only(self):
        mock_server_get = self.mock_object(
            db_api, 'share_server_get',
            mock.Mock(side_effect=exception.ShareServerNotFound(
                share_server_id='fake_id')))
        mock_get_destination = self.mock_object(
            self.api, 'share_server_migration_get_destination',
            mock.Mock(side_effect=exception.InvalidShareServer(reason='')))

        self.assertRaises(
            exception.InvalidShareServer,
            self.api.share_server_migration_get_progress,
            self.context, 'fake_src_server_id')

        mock_server_get.assert_called_once_with(self.context,
                                                'fake_src_server_id')
        mock_get_destination.assert_called_once_with(
            self.context, 'fake_src_server_id', status=constants.STATUS_ACTIVE)

    def test_migration_get_progress_race(self):

        instance1 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING,
            host='some_host')
        instance2 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING_TO)
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            instances=[instance1, instance2])
        share_ref = fakes.fake_share(
            id='fake_id',
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)
        service = 'fake_service'
        expected = {'total_progress': 100}

        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(db_api, 'service_get_by_args',
                         mock.Mock(return_value=service))
        self.mock_object(db_api, 'share_instance_get',
                         mock.Mock(return_value=instance1))
        self.mock_object(db_api, 'share_get',
                         mock.Mock(return_value=share_ref))
        self.mock_object(self.api.share_rpcapi, 'migration_get_progress',
                         mock.Mock(side_effect=exception.InvalidShare('fake')))

        result = self.api.migration_get_progress(self.context, share)
        self.assertEqual(expected, result)

        self.api.share_rpcapi.migration_get_progress.assert_called_once_with(
            self.context, instance1, instance2['id'])

    def test__share_network_update_initial_checks_network_not_active(self):
        share_network = db_utils.create_share_network(
            status=constants.STATUS_NETWORK_CHANGE)
        new_sec_service = db_utils.create_security_service(
            share_network_id=share_network['id'], type='ldap')

        self.assertRaises(
            webob_exc.HTTPBadRequest,
            self.api._share_network_update_initial_checks,
            self.context, share_network, new_sec_service
        )

    def test__share_network_update_initial_checks_server_not_active(self):
        share_subnet = db_utils.create_share_network_subnet(
            id='fakeid', share_network_id='fakenetid')
        db_utils.create_share_server(
            share_network_subnets=[share_subnet],
            status=constants.STATUS_ERROR,
            security_service_update_support=True)
        share_network = db_utils.create_share_network(id='fakenetid')
        new_sec_service = db_utils.create_security_service(
            share_network_id='fakenetid', type='ldap')

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_network_update_initial_checks,
            self.context, share_network, new_sec_service,
        )

    def test__share_network_update_initial_checks_shares_not_available(self):
        share_subnet = db_utils.create_share_network_subnet(
            id='fakeid', share_network_id='fake_network_id')
        db_utils.create_share_server(share_network_subnets=[share_subnet],
                                     security_service_update_support=True)
        share_network = db_utils.create_share_network(
            id='fake_network_id')
        new_sec_service = db_utils.create_security_service(
            share_network_id='fake_network_id', type='ldap')
        shares = [db_utils.create_share(status=constants.STATUS_ERROR)]

        self.mock_object(utils, 'validate_service_host')
        self.mock_object(
            self.api, 'get_all', mock.Mock(return_value=shares))

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_network_update_initial_checks,
            self.context, share_network, new_sec_service
        )
        utils.validate_service_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), 'host1')
        self.api.get_all.assert_called_once_with(
            self.context,
            search_opts={'share_network_id': share_network['id']})

    def test__share_network_update_initial_checks_rules_in_error(self):
        share_subnet = db_utils.create_share_network_subnet(
            id='fakeid', share_network_id='fake_network_id')
        db_utils.create_share_server(share_network_subnets=[share_subnet],
                                     security_service_update_support=True)
        share_network = db_utils.create_share_network(
            id='fake_network_id')
        new_sec_service = db_utils.create_security_service(
            share_network_id='fake_network_id', type='ldap')
        shares = [db_utils.create_share(status=constants.STATUS_AVAILABLE)]
        shares[0]['instance']['access_rules_status'] = (
            constants.ACCESS_STATE_ERROR)

        self.mock_object(utils, 'validate_service_host')
        self.mock_object(
            self.api, 'get_all', mock.Mock(return_value=shares))

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_network_update_initial_checks,
            self.context, share_network, new_sec_service
        )
        utils.validate_service_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), 'host1')
        self.api.get_all.assert_called_once_with(
            self.context,
            search_opts={'share_network_id': share_network['id']})

    def test__share_network_update_initial_checks_share_is_busy(self):
        share_subnet = db_utils.create_share_network_subnet(
            id='fakeid', share_network_id='fake_net_id')
        db_utils.create_share_server(share_network_subnets=[share_subnet],
                                     security_service_update_support=True)
        share_network = db_utils.create_share_network(id='fake_net_id')
        new_sec_service = db_utils.create_security_service(
            share_network_id='fake_net_id', type='ldap')
        shares = [db_utils.create_share(status=constants.STATUS_AVAILABLE)]

        self.mock_object(utils, 'validate_service_host')
        self.mock_object(
            self.api, 'get_all', mock.Mock(return_value=shares))
        self.mock_object(
            self.api, '_check_is_share_busy',
            mock.Mock(side_effect=exception.ShareBusyException(message='fake'))
        )

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_network_update_initial_checks,
            self.context, share_network, new_sec_service
        )
        utils.validate_service_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), 'host1')
        self.api.get_all.assert_called_once_with(
            self.context,
            search_opts={'share_network_id': share_network['id']})
        self.api._check_is_share_busy.assert_called_once_with(shares[0])

    def test__share_network_update_initial_checks_unsupported_server(self):
        share_subnet = db_utils.create_share_network_subnet(
            id='fakeid', share_network_id='fake_net_id')
        db_utils.create_share_server(share_network_subnets=[share_subnet],
                                     security_service_update_support=False)
        share_network = db_utils.create_share_network(id='fake_net_id')

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_network_update_initial_checks,
            self.context, share_network, None
        )

    def test__share_network_update_initial_checks_update_different_types(self):
        db_utils.create_share_server(share_network_subnet_id='fakeid',
                                     security_service_update_support=True)
        db_utils.create_share_network_subnet(
            id='fakeid', share_network_id='fake_net_id')
        share_network = db_utils.create_share_network(id='fake_net_id')
        new_sec_service = db_utils.create_security_service(
            share_network_id='fake_net_id', type='ldap')
        curr_sec_service = db_utils.create_security_service(
            share_network_id='fake_net_id', type='kerberos')

        self.assertRaises(
            exception.InvalidSecurityService,
            self.api._share_network_update_initial_checks,
            self.context, share_network, new_sec_service,
            current_security_service=curr_sec_service
        )

    def test__share_network_update_initial_checks_add_type_conflict(self):
        db_utils.create_share_server(share_network_subnet_id='fakeid',
                                     security_service_update_support=True)
        db_utils.create_share_network_subnet(
            id='fakeid', share_network_id='fake_net_id')
        share_network = db_utils.create_share_network(id='fake_net_id')
        db_utils.create_security_service(
            share_network_id='fake_net_id', type='ldap')
        share_network = db_api.share_network_get(self.context,
                                                 share_network['id'])
        new_sec_service = db_utils.create_security_service(
            share_network_id='fake_net_id', type='ldap')

        self.assertRaises(
            exception.InvalidSecurityService,
            self.api._share_network_update_initial_checks,
            self.context, share_network, new_sec_service,
        )

    def test_update_share_network_security_service_no_share_servers(self):
        mock_initial_checks = self.mock_object(
            self.api, '_share_network_update_initial_checks',
            mock.Mock(return_value=([], [])))
        mock_get_key = self.mock_object(
            self.api, 'get_security_service_update_key')
        fake_share_network = {'id': 'fake_share_net_id'}
        fake_sec_service = {'id': 'fake_sec_serv_id'}

        self.api.update_share_network_security_service(
            self.context, fake_share_network, fake_sec_service,
            current_security_service=None)

        mock_initial_checks.assert_called_once_with(
            self.context, fake_share_network, fake_sec_service,
            current_security_service=None)
        mock_get_key.assert_not_called()

    def test_update_share_network_security_service_without_check(self):
        mock_initial_checks = self.mock_object(
            self.api, '_share_network_update_initial_checks',
            mock.Mock(return_value=(['fake_server'], ['fake_host'])))
        mock_get_key = self.mock_object(
            self.api, 'get_security_service_update_key',
            mock.Mock(return_value=None))
        fake_share_network = {'id': 'fake_share_net_id'}
        fake_sec_service = {'id': 'fake_sec_serv_id'}

        self.assertRaises(exception.InvalidShareNetwork,
                          self.api.update_share_network_security_service,
                          self.context, fake_share_network, fake_sec_service)

        mock_initial_checks.assert_called_once_with(
            self.context, fake_share_network, fake_sec_service,
            current_security_service=None)
        mock_get_key.assert_called_once_with(
            'hosts_check', fake_sec_service['id'],
            current_security_service_id=None)

    def test_update_share_network_security_service_update_hosts_failure(self):
        mock_initial_checks = self.mock_object(
            self.api, '_share_network_update_initial_checks',
            mock.Mock(return_value=(['fake_server'], ['fake_host'])))
        mock_get_key = self.mock_object(
            self.api, 'get_security_service_update_key',
            mock.Mock(return_value='fake_key'))
        mock_async_db_get = self.mock_object(
            db_api, 'async_operation_data_get',
            mock.Mock(return_value='fake_value'))
        mock_validate_host = self.mock_object(
            self.api, '_security_service_update_validate_hosts',
            mock.Mock(side_effect=Exception))
        mock_async_db_delete = self.mock_object(
            db_api, 'async_operation_data_delete')
        fake_share_network = {'id': 'fake_share_net_id'}
        fake_sec_service = {'id': 'fake_sec_serv_id'}

        self.assertRaises(exception.InvalidShareNetwork,
                          self.api.update_share_network_security_service,
                          self.context, fake_share_network, fake_sec_service)

        mock_initial_checks.assert_called_once_with(
            self.context, fake_share_network, fake_sec_service,
            current_security_service=None)
        mock_get_key.assert_called_once_with(
            'hosts_check', fake_sec_service['id'],
            current_security_service_id=None)
        mock_async_db_get.assert_called_once_with(
            self.context, fake_share_network['id'], 'fake_key')
        mock_validate_host.assert_called_once_with(
            self.context, fake_share_network, ['fake_host'], ['fake_server'],
            new_security_service_id=fake_sec_service['id'],
            current_security_service_id=None)
        mock_async_db_delete.assert_called_once_with(
            self.context, fake_share_network['id'], 'fake_key')

    def test_update_share_network_security_service_backend_host_failure(self):
        share_network = db_utils.create_share_network()
        security_service = db_utils.create_security_service()
        backend_host = 'fakehost'

        mock_initial_checks = self.mock_object(
            self.api, '_share_network_update_initial_checks',
            mock.Mock(return_value=(['fake_server'], [backend_host])))
        mock_get_update_key = self.mock_object(
            self.api, 'get_security_service_update_key',
            mock.Mock(return_value='fake_key'))
        mock_db_async_op = self.mock_object(
            db_api, 'async_operation_data_get',
            mock.Mock(return_value='fake_update_value'))
        mock_validate_host = self.mock_object(
            self.api, '_security_service_update_validate_hosts',
            mock.Mock(return_value=(False, None)))

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api.update_share_network_security_service,
            self.context, share_network, security_service)

        mock_initial_checks.assert_called_once_with(
            self.context, share_network, security_service,
            current_security_service=None)
        mock_db_async_op.assert_called_once_with(
            self.context, share_network['id'], 'fake_key')
        mock_get_update_key.assert_called_once_with(
            'hosts_check', security_service['id'],
            current_security_service_id=None)
        mock_validate_host.assert_called_once_with(
            self.context, share_network, [backend_host], ['fake_server'],
            new_security_service_id=security_service['id'],
            current_security_service_id=None)

    def test_update_share_network_security_service(self):
        share_network = db_utils.create_share_network()
        security_service = db_utils.create_security_service()
        backend_hosts = ['fakehost']
        fake_update_key = 'fake_key'
        servers = [
            db_utils.create_share_server() for i in range(2)]
        server_ids = [server['id'] for server in servers]

        mock_initial_checks = self.mock_object(
            self.api, '_share_network_update_initial_checks',
            mock.Mock(return_value=(servers, backend_hosts)))
        mock_get_update_key = self.mock_object(
            self.api, 'get_security_service_update_key',
            mock.Mock(return_value=fake_update_key))
        mock_db_async_op = self.mock_object(
            db_api, 'async_operation_data_get',
            mock.Mock(return_value='fake_update_value'))
        mock_validate_host = self.mock_object(
            self.api, '_security_service_update_validate_hosts',
            mock.Mock(return_value=(True, None)))
        mock_network_update = self.mock_object(
            db_api, 'share_network_update')
        mock_servers_update = self.mock_object(
            db_api, 'share_servers_update')
        mock_update_security_services = self.mock_object(
            self.share_rpcapi, 'update_share_network_security_service')
        mock_db_async_op_del = self.mock_object(
            db_api, 'async_operation_data_delete',)

        self.api.update_share_network_security_service(
            self.context, share_network, security_service)

        mock_initial_checks.assert_called_once_with(
            self.context, share_network, security_service,
            current_security_service=None)
        mock_db_async_op.assert_called_once_with(
            self.context, share_network['id'], fake_update_key)
        mock_get_update_key.assert_called_once_with(
            'hosts_check', security_service['id'],
            current_security_service_id=None)
        mock_validate_host.assert_called_once_with(
            self.context, share_network, backend_hosts, servers,
            new_security_service_id=security_service['id'],
            current_security_service_id=None)
        mock_network_update.assert_called_once_with(
            self.context, share_network['id'],
            {'status': constants.STATUS_NETWORK_CHANGE})
        mock_servers_update.assert_called_once_with(
            self.context, server_ids,
            {'status': constants.STATUS_SERVER_NETWORK_CHANGE}
        )
        mock_update_security_services.assert_called_once_with(
            self.context, backend_hosts[0], share_network['id'],
            security_service['id'], current_security_service_id=None)
        mock_db_async_op_del.assert_called_once_with(
            self.context, share_network['id'], fake_update_key)

    def test__security_service_update_validate_hosts_new_check(self):
        curr_sec_service_id = "fake_curr_sec_serv_id"
        new_sec_service_id = "fake_new_sec_serv_id"
        fake_key = (curr_sec_service_id + '_' + new_sec_service_id +
                    '_' + 'hosts_check')
        fake_share_network = {'id': 'fake_network_id'}
        backend_hosts = {'hostA', 'hostB'}
        fake_return = 'fake_update'
        mock_get_key = self.mock_object(
            self.api, 'get_security_service_update_key',
            mock.Mock(return_value=fake_key))
        mock_do_update_validate = self.mock_object(
            self.api, '_do_update_validate_hosts',
            mock.Mock(return_value=fake_return))

        res = self.api._security_service_update_validate_hosts(
            self.context, fake_share_network, backend_hosts, None,
            new_security_service_id=new_sec_service_id,
            current_security_service_id=curr_sec_service_id)

        self.assertEqual(fake_return, res)
        mock_get_key.assert_called_once_with(
            'hosts_check', new_sec_service_id,
            current_security_service_id=curr_sec_service_id)
        mock_do_update_validate.assert_called_once_with(
            self.context, fake_share_network['id'], backend_hosts, fake_key,
            new_security_service_id=new_sec_service_id,
            current_security_service_id=curr_sec_service_id)

    @ddt.data(True, False)
    def test__do_update_validate_hosts(self, update_security_service):
        curr_sec_service_id = None
        new_sec_service_id = None
        new_share_network_subnet = 'fake_new_share_network_subnet'
        if update_security_service:
            curr_sec_service_id = "fake_curr_sec_serv_id"
            new_sec_service_id = "fake_new_sec_serv_id"
            new_share_network_subnet = None

        fake_key = 'fake_key'
        fake_share_network_id = 'fake_network_id'
        backend_hosts = {'hostA', 'hostB'}
        hosts_to_validate = {}
        for bh in backend_hosts:
            hosts_to_validate[bh] = None
        mock_async_data_get = self.mock_object(
            db_api, 'async_operation_data_get', mock.Mock(return_value=None))
        mock_async_data_update = self.mock_object(
            db_api, 'async_operation_data_update')
        mock_check_update_allocations = self.mock_object(
            self.share_rpcapi, 'check_update_share_server_network_allocations')
        mock_check_update_services = self.mock_object(
            self.share_rpcapi, 'check_update_share_network_security_service')

        compatible, hosts_info = self.api._do_update_validate_hosts(
            self.context, fake_share_network_id, backend_hosts, fake_key,
            new_share_network_subnet=new_share_network_subnet,
            new_security_service_id=new_sec_service_id,
            current_security_service_id=curr_sec_service_id)

        self.assertIsNone(compatible)
        self.assertEqual(hosts_to_validate, hosts_info)
        mock_async_data_get.assert_called_once_with(
            self.context, fake_share_network_id, fake_key)
        mock_async_data_update.assert_called_once_with(
            self.context, fake_share_network_id,
            {fake_key: json.dumps(hosts_to_validate)})
        mock_share_api_check_calls = []
        for host in backend_hosts:
            if update_security_service:
                mock_share_api_check_calls.append(
                    mock.call(self.context, host, fake_share_network_id,
                              new_sec_service_id,
                              current_security_service_id=curr_sec_service_id))
            else:
                mock_share_api_check_calls.append(
                    mock.call(self.context, host, fake_share_network_id,
                              new_share_network_subnet))
        if update_security_service:
            mock_check_update_services.assert_has_calls(
                mock_share_api_check_calls)
            mock_check_update_allocations.assert_not_called()
        else:
            mock_check_update_allocations.assert_has_calls(
                mock_share_api_check_calls)
            mock_check_update_services.assert_not_called()

    @ddt.data(
        {'update_security_service': True, 'new_host': None,
         'host_support': None, 'exp_result': None},
        {'update_security_service': True, 'new_host': None,
         'host_support': False, 'exp_result': False},
        {'update_security_service': True, 'new_host': None,
         'host_support': True, 'exp_result': True},
        {'update_security_service': True, 'new_host': 'hostC',
         'host_support': None, 'exp_result': None},
        {'update_security_service': True, 'new_host': 'hostC',
         'host_support': False, 'exp_result': False},
        {'update_security_service': True, 'new_host': 'hostC',
         'host_support': True, 'exp_result': None},
        {'update_security_service': False, 'new_host': None,
         'host_support': None, 'exp_result': None},
        {'update_security_service': False, 'new_host': None,
         'host_support': False, 'exp_result': False},
        {'update_security_service': False, 'new_host': None,
         'host_support': True, 'exp_result': True},
        {'update_security_service': False, 'new_host': 'hostC',
         'host_support': None, 'exp_result': None},
        {'update_security_service': False, 'new_host': 'hostC',
         'host_support': False, 'exp_result': False},
        {'update_security_service': False, 'new_host': 'hostC',
         'host_support': True, 'exp_result': None},
    )
    @ddt.unpack
    def test__do_update_validate_hosts_all(
            self, update_security_service, new_host, host_support, exp_result):
        curr_sec_service_id = None
        new_sec_service_id = None
        new_share_network_subnet = 'fake_new_share_network_subnet'
        if update_security_service:
            curr_sec_service_id = "fake_curr_sec_serv_id"
            new_sec_service_id = "fake_new_sec_serv_id"
            new_share_network_subnet = None

        fake_key = 'fake_key'
        fake_share_network_id = 'fake_network_id'
        backend_hosts = ['hostA', 'hostB']
        hosts_to_validate = {}
        for bh in backend_hosts:
            hosts_to_validate[bh] = host_support
        json_orig_hosts = json.dumps(hosts_to_validate)

        if new_host:
            backend_hosts.append(new_host)
            hosts_to_validate[new_host] = None

        mock_async_data_get = self.mock_object(
            db_api, 'async_operation_data_get',
            mock.Mock(return_value=json_orig_hosts))
        mock_async_data_update = self.mock_object(
            db_api, 'async_operation_data_update')
        mock_check_update_allocations = self.mock_object(
            self.share_rpcapi, 'check_update_share_server_network_allocations')
        mock_check_update_services = self.mock_object(
            self.share_rpcapi, 'check_update_share_network_security_service')

        result, hosts_info = self.api._do_update_validate_hosts(
            self.context, fake_share_network_id, backend_hosts, fake_key,
            new_share_network_subnet=new_share_network_subnet,
            new_security_service_id=new_sec_service_id,
            current_security_service_id=curr_sec_service_id)

        self.assertEqual(exp_result, result)
        self.assertEqual(hosts_to_validate, hosts_info)
        mock_async_data_get.assert_called_once_with(
            self.context, fake_share_network_id, fake_key)

        # we fail earlier if one one the host answer False.
        if new_host and host_support is not False:
            mock_async_data_update.assert_called_once_with(
                self.context, fake_share_network_id,
                {fake_key: json.dumps(hosts_to_validate)})
            if update_security_service:
                mock_check_update_services.assert_called_once_with(
                    self.context, new_host, fake_share_network_id,
                    new_sec_service_id,
                    current_security_service_id=curr_sec_service_id)
            else:
                mock_check_update_allocations.assert_called_once_with(
                    self.context, new_host, fake_share_network_id,
                    new_share_network_subnet)

    def test_soft_delete_share_already_soft_deleted(self):
        share = fakes.fake_share(id='fake_id',
                                 status=constants.STATUS_AVAILABLE,
                                 is_soft_deleted=True)
        self.assertRaises(exception.InvalidShare,
                          self.api.soft_delete, self.context, share)

    def test_soft_delete_invalid_status(self):
        invalid_status = 'fake'
        share = fakes.fake_share(id='fake_id',
                                 status=invalid_status,
                                 is_soft_deleted=False)

        self.assertRaises(exception.InvalidShare,
                          self.api.soft_delete, self.context, share)

    def test_soft_delete_share_with_replicas(self):
        share = fakes.fake_share(id='fake_id',
                                 has_replicas=True,
                                 status=constants.STATUS_AVAILABLE,
                                 is_soft_deleted=False)

        self.assertRaises(exception.Conflict,
                          self.api.soft_delete, self.context, share)

    def test_soft_delete_share_with_snapshot(self):
        share = fakes.fake_share(id='fake_id',
                                 status=constants.STATUS_AVAILABLE,
                                 has_replicas=False,
                                 is_soft_deleted=False)
        snapshot = fakes.fake_snapshot(create_instance=True, as_primitive=True)
        mock_db_snapshot_call = self.mock_object(
            db_api, 'share_snapshot_get_all_for_share', mock.Mock(
                return_value=[snapshot]))

        self.assertRaises(exception.InvalidShare,
                          self.api.soft_delete, self.context, share)

        mock_db_snapshot_call.assert_called_once_with(
            self.context, share['id'])

    @mock.patch.object(db_api, 'count_share_group_snapshot_members_in_share',
                       mock.Mock(return_value=2))
    def test_soft_delete_share_with_group_snapshot_members(self):
        share = fakes.fake_share(id='fake_id',
                                 status=constants.STATUS_AVAILABLE,
                                 has_replicas=False,
                                 is_soft_deleted=False)
        self.mock_object(db_api, 'share_backups_get_all',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.InvalidShare,
                          self.api.soft_delete, self.context, share)

    def test_soft_delete_locked_share(self):
        self.mock_object(
            self.api.db,
            'resource_lock_get_all',
            mock.Mock(return_value=([{'id': 'l1'}, {'id': 'l2'}], None))
        )
        share = self._setup_delete_mocks('available')
        self.mock_object(db_api, 'share_soft_delete')

        self.assertRaises(exception.InvalidShare,
                          self.api.soft_delete,
                          self.context,
                          share)

        # lock check decorator executed first, nothing else is invoked
        db_api.share_soft_delete.assert_not_called()
        db_api.share_snapshot_get_all_for_share.assert_not_called()

    def test_soft_delete_share(self):
        share = fakes.fake_share(id='fake_id',
                                 status=constants.STATUS_AVAILABLE,
                                 has_replicas=False,
                                 is_soft_deleted=False)
        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=[]))
        self.mock_object(db_api, 'share_backups_get_all',
                         mock.Mock(return_value=[]))
        self.mock_object(db_api, 'count_share_group_snapshot_members_in_share',
                         mock.Mock(return_value=0))
        self.mock_object(db_api, 'share_soft_delete')
        self.mock_object(self.api, '_check_is_share_busy')
        self.api.soft_delete(self.context, share)
        self.api._check_is_share_busy.assert_called_once_with(share)

    def test_restore_share(self):
        share = fakes.fake_share(id='fake_id',
                                 status=constants.STATUS_AVAILABLE,
                                 is_soft_deleted=True)
        self.mock_object(db_api, 'share_restore')
        self.api.restore(self.context, share)

    def test__share_server_update_allocations_validate_hosts(self):
        update_return = 'fake_return'
        mock_do_update = self.mock_object(
            self.api, '_do_update_validate_hosts',
            mock.Mock(return_value=update_return))

        backend_hosts = 'fake_hosts'
        update_key = 'fake_key'
        share_network_id = 'fake_net_id'
        subnet = {
            'neutron_net_id': 'fake_net_id',
            'neutron_subnet_id': 'fake_subnet_id',
            'availability_zone_id': 'fake_availability_zone_id',
        }
        res = self.api._share_server_update_allocations_validate_hosts(
            self.context, backend_hosts, update_key,
            share_network_id=share_network_id,
            neutron_net_id=subnet['neutron_net_id'],
            neutron_subnet_id=subnet['neutron_subnet_id'],
            availability_zone_id=subnet['availability_zone_id'])

        self.assertEqual(update_return, res)
        mock_do_update.assert_called_once_with(
            self.context, share_network_id, backend_hosts, update_key,
            new_share_network_subnet=subnet)

    def test_get_share_server_update_allocations_key(self):
        availability_zone_id = None
        share_network_id = 'fake_share_network_id'
        expected_key = ('share_server_update_allocations_' +
                        share_network_id + '_' + str(availability_zone_id) +
                        '_' + 'hosts_check')
        res = self.api.get_share_server_update_allocations_key(
            share_network_id, availability_zone_id)

        self.assertEqual(expected_key, res)

    def test__share_server_update_allocations_initial_checks(self):
        share_network = db_utils.create_share_network()
        share1 = db_utils.create_share(
            share_network_id=share_network['id'],
            status=constants.STATUS_AVAILABLE)
        server_host = 'fake_host'
        share_server = db_utils.create_share_server(host=server_host)
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host')
        mock_share_get_all_by_share_server = self.mock_object(
            self.api.db, 'share_get_all_by_share_server',
            mock.Mock(return_value=[share1]))
        mock_share_is_busy = self.mock_object(
            self.api, '_check_is_share_busy')

        res_hosts = self.api._share_server_update_allocations_initial_checks(
            self.context, share_network, [share_server])

        self.assertEqual(set([server_host]), res_hosts)
        mock_validate_service_host.assert_called_once()
        mock_share_get_all_by_share_server.assert_called_once_with(
            self.context, share_server['id'])
        mock_share_is_busy.assert_called_once_with(share1)

    def test__share_server_update_allocations_initial_checks_no_support(self):
        fake_share_network = {
            'id': 'fake_sn_id',
            'network_allocation_update_support': False,
            'status': constants.STATUS_NETWORK_ACTIVE,
        }
        sn_subnet = db_utils.create_share_network_subnet()

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_server_update_allocations_initial_checks,
            self.context,
            fake_share_network,
            sn_subnet)

    def test__share_server_update_allocations_initial_checks_inactive(self):
        share_network = db_utils.create_share_network()
        share_server = db_utils.create_share_server(
            status=constants.STATUS_INACTIVE)

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_server_update_allocations_initial_checks,
            self.context,
            share_network,
            [share_server])

    def test__share_server_update_allocations_initial_checks_shares_na(self):
        share_network = db_utils.create_share_network()
        share1 = db_utils.create_share(
            share_network_id=share_network['id'],
            status=constants.STATUS_ERROR)
        share_server = db_utils.create_share_server()
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host')
        mock_share_get_all_by_share_server = self.mock_object(
            self.api.db, 'share_get_all_by_share_server',
            mock.Mock(return_value=[share1]))

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_server_update_allocations_initial_checks,
            self.context,
            share_network,
            [share_server])

        mock_validate_service_host.assert_called_once()
        mock_share_get_all_by_share_server.assert_called_once_with(
            self.context, share_server['id'])

    def test__share_server_update_allocations_initial_checks_rules_na(self):
        share_network = db_utils.create_share_network()
        share1 = db_utils.create_share(
            share_network_id=share_network['id'],
            status=constants.STATUS_AVAILABLE)
        share_server = db_utils.create_share_server()
        share1['instance']['access_rules_status'] = constants.STATUS_INACTIVE
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host')
        mock_share_get_all_by_share_server = self.mock_object(
            self.api.db, 'share_get_all_by_share_server',
            mock.Mock(return_value=[share1]))

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_server_update_allocations_initial_checks,
            self.context,
            share_network,
            [share_server])

        mock_validate_service_host.assert_called_once()
        mock_share_get_all_by_share_server.assert_called_once_with(
            self.context, share_server['id'])

    def test__share_server_update_allocations_initial_checks_share_busy(self):
        share_network = db_utils.create_share_network()
        share1 = db_utils.create_share(
            share_network_id=share_network['id'],
            status=constants.STATUS_AVAILABLE)
        share_server = db_utils.create_share_server()
        mock_validate_service_host = self.mock_object(
            utils, 'validate_service_host')
        mock_share_get_all_by_share_server = self.mock_object(
            self.api.db, 'share_get_all_by_share_server',
            mock.Mock(return_value=[share1]))
        mock_share_is_busy = self.mock_object(
            self.api, '_check_is_share_busy',
            mock.Mock(side_effect=exception.ShareBusyException(message='fake'))
        )

        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api._share_server_update_allocations_initial_checks,
            self.context,
            share_network,
            [share_server])

        mock_validate_service_host.assert_called_once()
        mock_share_get_all_by_share_server.assert_called_once_with(
            self.context, share_server['id'])
        mock_share_is_busy.assert_called_once_with(share1)

    def test_check_update_share_server_network_allocations(self):
        backend_hosts = 'fake_hosts'
        mock_initial_check = self.mock_object(
            self.api, '_share_server_update_allocations_initial_checks',
            mock.Mock(return_value=backend_hosts))
        update_key = 'fake_key'
        mock_get_key = self.mock_object(
            self.api, 'get_share_server_update_allocations_key',
            mock.Mock(return_value=update_key))
        mock_reset_data = self.mock_object(
            self.api.db, 'async_operation_data_delete')
        compatible = True
        hosts_info = {'fake_host': True}
        mock_validate_hosts = self.mock_object(
            self.api, '_share_server_update_allocations_validate_hosts',
            mock.Mock(return_value=(compatible, hosts_info)))

        share_network = {'id': 'fake_id'}
        new_share_network_subnet = {
            'share_servers': 'fake_servers',
            'availability_zone_id': 'fake_availability_zone_id',
            'neutron_net_id': 'fake_neutron_net_id',
            'neutron_subnet_id': 'fake_neutron_subnet_id',
        }
        res = self.api.check_update_share_server_network_allocations(
            self.context, share_network, new_share_network_subnet, True)

        self.assertEqual(
            {'compatible': compatible, 'hosts_check_result': hosts_info}, res)
        mock_initial_check.assert_called_once_with(
            self.context, share_network,
            new_share_network_subnet['share_servers'])
        mock_get_key.assert_called_once_with(
            share_network['id'],
            new_share_network_subnet['availability_zone_id'])
        mock_reset_data.assert_called_once_with(
            self.context, share_network['id'], update_key)
        mock_validate_hosts.assert_called_once_with(
            self.context, backend_hosts, update_key,
            share_network_id=share_network['id'],
            neutron_net_id=new_share_network_subnet['neutron_net_id'],
            neutron_subnet_id=new_share_network_subnet['neutron_subnet_id'],
            availability_zone_id=(
                new_share_network_subnet["availability_zone_id"]))

    def test_check_update_share_server_network_allocations_failed(self):
        backend_hosts = 'fake_hosts'
        self.mock_object(
            self.api, '_share_server_update_allocations_initial_checks',
            mock.Mock(return_value=backend_hosts))
        update_key = 'fake_key'
        self.mock_object(
            self.api, 'get_share_server_update_allocations_key',
            mock.Mock(return_value=update_key))
        self.mock_object(self.api.db, 'async_operation_data_delete')
        self.mock_object(
            self.api, '_share_server_update_allocations_validate_hosts',
            mock.Mock(side_effect=exception.InvalidShareNetwork(reason="msg")))

        share_network = {'id': 'fake_id'}
        new_share_network_subnet = {
            'share_servers': 'fake_servers',
            'availability_zone_id': 'fake_availability_zone_id',
            'neutron_net_id': 'fake_neutron_net_id',
            'neutron_subnet_id': 'fake_neutron_subnet_id',
        }
        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api.check_update_share_server_network_allocations,
            self.context, share_network, new_share_network_subnet, True)

    def test_update_share_server_network_allocations(self):
        backend_host = 'fake_host'
        backend_hosts = [backend_host]
        mock_initial_check = self.mock_object(
            self.api, '_share_server_update_allocations_initial_checks',
            mock.Mock(return_value=backend_hosts))
        update_key = 'fake_key'
        mock_get_key = self.mock_object(
            self.api, 'get_share_server_update_allocations_key',
            mock.Mock(return_value=update_key))
        mock_get_data = self.mock_object(
            self.api.db, 'async_operation_data_get',
            mock.Mock(return_value='fake_update_value'))
        mock_validate_hosts = self.mock_object(
            self.api, '_share_server_update_allocations_validate_hosts',
            mock.Mock(return_value=(True, 'fake_host')))
        mock_net_update = self.mock_object(self.api.db, 'share_network_update')
        mock_server_update = self.mock_object(self.api.db,
                                              'share_servers_update')
        new_share_network_subnet_db = {'id': 'fake_subnet_id'}
        mock_subnet_create = self.mock_object(
            self.api.db, 'share_network_subnet_create',
            mock.Mock(return_value=new_share_network_subnet_db))
        mock_update_allocations = self.mock_object(
            self.api.share_rpcapi, 'update_share_server_network_allocations')
        mock_delete_data = self.mock_object(self.api.db,
                                            'async_operation_data_delete')

        share_network = {'id': 'fake_id'}
        server1 = {'id': 'fake_id'}
        new_share_network_subnet = {
            'share_servers': [server1],
            'availability_zone_id': 'fake_availability_zone_id',
            'neutron_net_id': 'fake_neutron_net_id',
            'neutron_subnet_id': 'fake_neutron_subnet_id',
        }
        res_subnet = self.api.update_share_server_network_allocations(
            self.context, share_network, new_share_network_subnet)

        self.assertEqual(new_share_network_subnet_db, res_subnet)
        mock_initial_check.assert_called_once_with(
            self.context, share_network,
            new_share_network_subnet['share_servers'])
        mock_get_key.assert_called_once_with(
            share_network['id'],
            new_share_network_subnet['availability_zone_id'])
        mock_get_data.assert_called_once_with(
            self.context, share_network['id'], update_key)
        mock_validate_hosts.assert_called_once_with(
            self.context, backend_hosts, update_key,
            share_network_id=share_network['id'],
            neutron_net_id=new_share_network_subnet['neutron_net_id'],
            neutron_subnet_id=new_share_network_subnet['neutron_subnet_id'],
            availability_zone_id=(
                new_share_network_subnet["availability_zone_id"]))
        mock_net_update.assert_called_once_with(
            self.context, share_network['id'],
            {'status': constants.STATUS_NETWORK_CHANGE})
        mock_server_update.assert_called_once_with(
            self.context, [server1['id']],
            {'status': constants.STATUS_SERVER_NETWORK_CHANGE})
        mock_subnet_create.assert_called_once_with(
            self.context, new_share_network_subnet)
        mock_update_allocations.assert_called_once_with(
            self.context, backend_host, share_network['id'],
            new_share_network_subnet_db['id'])
        mock_delete_data.assert_called_once_with(
            self.context, share_network['id'], update_key)

    def test_update_share_server_network_allocations_no_check(self):
        backend_host = 'fake_host'
        backend_hosts = [backend_host]
        self.mock_object(
            self.api, '_share_server_update_allocations_initial_checks',
            mock.Mock(return_value=backend_hosts))
        update_key = 'fake_key'
        self.mock_object(
            self.api, 'get_share_server_update_allocations_key',
            mock.Mock(return_value=update_key))
        self.mock_object(
            self.api.db, 'async_operation_data_get',
            mock.Mock(return_value=None))

        share_network = {'id': 'fake_id'}
        server1 = {'id': 'fake_id'}
        new_share_network_subnet = {
            'share_servers': [server1],
            'availability_zone_id': 'fake_availability_zone_id',
            'neutron_net_id': 'fake_neutron_net_id',
            'neutron_subnet_id': 'fake_neutron_subnet_id',
        }
        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api.update_share_server_network_allocations,
            self.context,
            share_network,
            new_share_network_subnet)

    def test_update_share_server_network_allocations_fail_validation(self):
        backend_host = 'fake_host'
        backend_hosts = [backend_host]
        self.mock_object(
            self.api, '_share_server_update_allocations_initial_checks',
            mock.Mock(return_value=backend_hosts))
        update_key = 'fake_key'
        self.mock_object(
            self.api, 'get_share_server_update_allocations_key',
            mock.Mock(return_value=update_key))
        self.mock_object(
            self.api.db, 'async_operation_data_get',
            mock.Mock(return_value='fake_update_value'))
        self.mock_object(
            self.api, '_share_server_update_allocations_validate_hosts',
            mock.Mock(side_effect=exception.InvalidShareNetwork(
                reason='fake_reason')))
        mock_delete_data = self.mock_object(self.api.db,
                                            'async_operation_data_delete')

        share_network = {'id': 'fake_id'}
        server1 = {'id': 'fake_id'}
        new_share_network_subnet = {
            'share_servers': [server1],
            'availability_zone_id': 'fake_availability_zone_id',
            'neutron_net_id': 'fake_neutron_net_id',
            'neutron_subnet_id': 'fake_neutron_subnet_id',
        }
        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api.update_share_server_network_allocations,
            self.context,
            share_network,
            new_share_network_subnet)

        mock_delete_data.assert_called_once_with(
            self.context, share_network['id'], update_key)

    @ddt.data(False, None)
    def test_update_share_server_network_allocations_check_fail(self, result):
        backend_host = 'fake_host'
        backend_hosts = [backend_host]
        self.mock_object(
            self.api, '_share_server_update_allocations_initial_checks',
            mock.Mock(return_value=backend_hosts))
        update_key = 'fake_key'
        self.mock_object(
            self.api, 'get_share_server_update_allocations_key',
            mock.Mock(return_value=update_key))
        self.mock_object(
            self.api.db, 'async_operation_data_get',
            mock.Mock(return_value='fake_update_value'))
        self.mock_object(
            self.api, '_share_server_update_allocations_validate_hosts',
            mock.Mock(return_value=(result, 'fake_host')))

        share_network = {'id': 'fake_id'}
        server1 = {'id': 'fake_id'}
        new_share_network_subnet = {
            'share_servers': [server1],
            'availability_zone_id': 'fake_availability_zone_id',
            'neutron_net_id': 'fake_neutron_net_id',
            'neutron_subnet_id': 'fake_neutron_subnet_id',
        }
        self.assertRaises(
            exception.InvalidShareNetwork,
            self.api.update_share_server_network_allocations,
            self.context,
            share_network,
            new_share_network_subnet)

    @ddt.data(None, {'driver': test})
    def test_create_share_backup(self, backup_opts):
        share = db_utils.create_share(is_public=True, status='available')
        backup_ref = db_utils.create_backup(share['id'], status='available')

        reservation = 'fake'
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value=reservation))
        self.mock_object(quota.QUOTAS, 'commit')
        self.mock_object(db_api, 'share_backup_create',
                         mock.Mock(return_value=backup_ref))
        self.mock_object(db_api, 'share_backup_update', mock.Mock())
        self.mock_object(data_rpc.DataAPI, 'create_backup', mock.Mock())
        self.mock_object(self.share_rpcapi, 'create_backup', mock.Mock())

        backup = {'display_name': 'tmp_backup', 'backup_options': backup_opts}
        self.api.create_share_backup(self.context, share, backup)

        quota.QUOTAS.reserve.assert_called_once()
        db_api.share_backup_create.assert_called_once()
        quota.QUOTAS.commit.assert_called_once()
        db_api.share_backup_update.assert_called_once()
        if backup_opts:
            self.share_rpcapi.create_backup.assert_called_once_with(
                self.context, backup_ref)
        else:
            data_rpc.DataAPI.create_backup.assert_called_once_with(
                self.context, backup_ref)

    def test_create_share_backup_share_error_state(self):
        share = db_utils.create_share(is_public=True, status='error')
        backup = {'display_name': 'tmp_backup'}

        self.assertRaises(exception.InvalidShare,
                          self.api.create_share_backup,
                          self.context, share, backup)

    def test_create_share_backup_share_busy_task_state(self):
        share = db_utils.create_share(
            is_public=True, task_state='data_copying_in_progress')
        backup = {'display_name': 'tmp_backup'}

        self.assertRaises(exception.ShareBusyException,
                          self.api.create_share_backup,
                          self.context, share, backup)

    def test_create_share_backup_share_has_snapshots(self):
        share = db_utils.create_share(
            is_public=True, state='available')
        snapshot = db_utils.create_snapshot(
            share_id=share['id'], status='available', size=1)

        backup = {'display_name': 'tmp_backup'}

        self.mock_object(db_api, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=[snapshot]))

        self.assertRaises(exception.InvalidShare,
                          self.api.create_share_backup,
                          self.context, share, backup)

    def test_create_share_backup_share_has_replicas(self):
        share = fakes.fake_share(id='fake_id',
                                 has_replicas=True,
                                 status=constants.STATUS_AVAILABLE,
                                 is_soft_deleted=False)
        backup = {'display_name': 'tmp_backup'}

        self.assertRaises(exception.InvalidShare,
                          self.api.create_share_backup,
                          self.context, share, backup)

    @ddt.data({'overs': {'backup_gigabytes': 'fake'},
               'expected_exception':
                   exception.ShareBackupSizeExceedsAvailableQuota},
              {'overs': {'backups': 'fake'},
               'expected_exception': exception.BackupLimitExceeded},)
    @ddt.unpack
    def test_create_share_backup_over_quota(self, overs, expected_exception):
        share = fakes.fake_share(id='fake_id',
                                 status=constants.STATUS_AVAILABLE,
                                 is_soft_deleted=False, size=5)
        backup = {'display_name': 'tmp_backup'}

        usages = {'backup_gigabytes': {'reserved': 5, 'in_use': 5},
                  'backups': {'reserved': 5, 'in_use': 5}}

        quotas = {'backup_gigabytes': 5, 'backups': 5}

        exc = exception.OverQuota(overs=overs, usages=usages, quotas=quotas)
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(side_effect=exc))

        self.assertRaises(expected_exception, self.api.create_share_backup,
                          self.context, share, backup)

        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, backups=1, backup_gigabytes=share['size'])

    def test_create_share_backup_rollback_quota(self):
        share = db_utils.create_share(is_public=True, status='available')

        reservation = 'fake'
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value=reservation))
        self.mock_object(quota.QUOTAS, 'rollback')
        self.mock_object(db_api, 'share_backup_create',
                         mock.Mock(side_effect=exception.ManilaException))
        self.mock_object(data_rpc.DataAPI, 'create_backup', mock.Mock())
        self.mock_object(self.share_rpcapi, 'create_backup', mock.Mock())

        backup = {'display_name': 'tmp_backup'}
        self.assertRaises(exception.ManilaException,
                          self.api.create_share_backup,
                          self.context, share, backup)

        quota.QUOTAS.reserve.assert_called_once()
        db_api.share_backup_create.assert_called_once()
        quota.QUOTAS.rollback.assert_called_once_with(
            self.context, reservation)

    @ddt.data(CONF.share_topic, CONF.data_topic)
    def test_delete_share_backup(self, topic):
        share = db_utils.create_share(is_public=True, status='available')
        backup = db_utils.create_backup(share['id'], status='available')

        self.mock_object(db_api, 'share_backup_update', mock.Mock())
        self.mock_object(data_rpc.DataAPI, 'delete_backup', mock.Mock())
        self.mock_object(self.share_rpcapi, 'delete_backup', mock.Mock())

        backup.update({'topic': topic})
        self.api.delete_share_backup(self.context, backup)

        db_api.share_backup_update.assert_called_once()
        if topic == CONF.share_topic:
            self.share_rpcapi.delete_backup.assert_called_once_with(
                self.context, backup)
        else:
            data_rpc.DataAPI.delete_backup.assert_called_once_with(
                self.context, backup)

    @ddt.data(constants.STATUS_DELETING, constants.STATUS_CREATING)
    def test_delete_share_backup_invalid_state(self, state):
        share = db_utils.create_share(is_public=True, status='available')
        backup = db_utils.create_backup(share['id'], status=state)
        self.assertRaises(exception.InvalidBackup,
                          self.api.delete_share_backup,
                          self.context, backup)

    @ddt.data(CONF.share_topic, CONF.data_topic)
    def test_restore_share_backup(self, topic):
        share = db_utils.create_share(
            is_public=True, status='available', size=1)
        backup = db_utils.create_backup(
            share['id'], status='available', size=1)

        self.mock_object(self.api, 'get', mock.Mock(return_value=share))
        self.mock_object(db_api, 'share_backup_update', mock.Mock())
        self.mock_object(db_api, 'share_update', mock.Mock())
        self.mock_object(data_rpc.DataAPI, 'restore_backup', mock.Mock())
        self.mock_object(self.share_rpcapi, 'restore_backup', mock.Mock())

        backup.update({'topic': topic})
        self.api.restore_share_backup(self.context, backup)

        self.api.get.assert_called_once()
        db_api.share_update.assert_called_once()
        db_api.share_backup_update.assert_called_once()
        if topic == CONF.share_topic:
            self.share_rpcapi.restore_backup.assert_called_once_with(
                self.context, backup, share['id'])
        else:
            data_rpc.DataAPI.restore_backup.assert_called_once_with(
                self.context, backup, share['id'])

    def test_restore_share_backup_invalid_share_sizee(self):
        share = db_utils.create_share(
            is_public=True, status='available', size=1)
        backup = db_utils.create_backup(
            share['id'], status='available', size=2)
        self.assertRaises(exception.InvalidShare,
                          self.api.restore_share_backup,
                          self.context, backup)

    def test_restore_share_backup_invalid_share_state(self):
        share = db_utils.create_share(is_public=True, status='deleting')
        backup = db_utils.create_backup(share['id'], status='available')
        self.assertRaises(exception.InvalidShare,
                          self.api.restore_share_backup,
                          self.context, backup)

    def test_restore_share_backup_invalid_backup_state(self):
        share = db_utils.create_share(is_public=True, status='available')
        backup = db_utils.create_backup(share['id'], status='deleting')
        self.assertRaises(exception.InvalidBackup,
                          self.api.restore_share_backup,
                          self.context, backup)

    def test_update_share_backup(self):
        share = db_utils.create_share(is_public=True, status='available')
        backup = db_utils.create_backup(share['id'], status='available')
        self.mock_object(db_api, 'share_backup_update', mock.Mock())

        self.api.update_share_backup(self.context, backup,
                                     {'display_name': 'new_name'})

        db_api.share_backup_update.assert_called_once()


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
