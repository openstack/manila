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
from manila import db as db_driver
from manila import exception
from manila import quota
from manila import share
from manila.share import api as share_api
from manila.share import share_types
from manila import test
from manila.tests.db import fakes as db_fakes
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
    return db_fakes.FakeModel(access)


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

        dt_utc = datetime.datetime.utcnow()
        self.mock_object(timeutils, 'utcnow', mock.Mock(return_value=dt_utc))
        self.mock_object(share_api.policy, 'check_policy')

    def test_get_all_admin_no_filters(self):
        self.mock_object(db_driver, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=True)
        shares = self.api.get_all(ctx)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_driver.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_1', filters={}, is_public=False
        )
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES[0])

    def test_get_all_admin_filter_by_all_tenants(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=True)
        self.mock_object(db_driver, 'share_get_all',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES))
        shares = self.api.get_all(ctx, {'all_tenants': 1})
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_driver.share_get_all.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at', filters={})
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES)

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
        self.mock_object(db_driver, 'share_get_all_by_share_server',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[2:]))
        self.mock_object(db_driver, 'share_get_all')
        self.mock_object(db_driver, 'share_get_all_by_project')
        shares = self.api.get_all(
            ctx, {'share_server_id': 'fake_server_3', 'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
            mock.call(ctx, 'share', 'list_by_share_server_id'),
        ])
        db_driver.share_get_all_by_share_server.assert_called_once_with(
            ctx, 'fake_server_3', sort_dir='desc', sort_key='created_at',
            filters={},
        )
        db_driver.share_get_all_by_project.assert_has_calls([])
        db_driver.share_get_all.assert_has_calls([])
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES[2:])

    def test_get_all_admin_filter_by_name(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_driver, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'name': 'bar'})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_driver.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=False
        )
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES[1::2])

    def test_get_all_admin_filter_by_name_and_all_tenants(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_driver, 'share_get_all',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES))
        shares = self.api.get_all(ctx, {'name': 'foo', 'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_driver.share_get_all.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at', filters={})
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES[::2])

    def test_get_all_admin_filter_by_status(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_driver, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'status': constants.STATUS_AVAILABLE})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_driver.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=False
        )
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES[2::4])

    def test_get_all_admin_filter_by_status_and_all_tenants(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=True)
        self.mock_object(db_driver, 'share_get_all',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES))
        shares = self.api.get_all(
            ctx, {'status': constants.STATUS_ERROR, 'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_driver.share_get_all.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at', filters={})
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES[1::2])

    def test_get_all_non_admin_filter_by_all_tenants(self):
        # Expected share list only by project of non-admin user
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=False)
        self.mock_object(db_driver, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'all_tenants': 1})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_driver.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=False
        )
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES[1:])

    def test_get_all_non_admin_with_name_and_status_filters(self):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2', is_admin=False)
        self.mock_object(db_driver, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(
            ctx, {'name': 'bar', 'status': constants.STATUS_ERROR})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_driver.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=False
        )

        # two items expected, one filtered
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES[1::2])

        # one item expected, two filtered
        shares = self.api.get_all(
            ctx, {'name': 'foo', 'status': constants.STATUS_AVAILABLE})
        self.assertEqual(shares, _FAKE_LIST_OF_ALL_SHARES[2::4])
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_driver.share_get_all_by_project.assert_has_calls([
            mock.call(ctx, sort_dir='desc', sort_key='created_at',
                      project_id='fake_pid_2', filters={}, is_public=False),
            mock.call(ctx, sort_dir='desc', sort_key='created_at',
                      project_id='fake_pid_2', filters={}, is_public=False),
        ])

    @ddt.data('True', 'true', '1', 'yes', 'y', 'on', 't', True)
    def test_get_all_non_admin_public(self, is_public):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2',
                                     is_admin=False)
        self.mock_object(db_driver, 'share_get_all_by_project', mock.Mock(
            return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'is_public': is_public})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_driver.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_2', filters={}, is_public=True
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[1:], shares)

    @ddt.data('False', 'false', '0', 'no', 'n', 'off', 'f', False)
    def test_get_all_non_admin_not_public(self, is_public):
        ctx = context.RequestContext('fake_uid', 'fake_pid_2',
                                     is_admin=False)
        self.mock_object(db_driver, 'share_get_all_by_project', mock.Mock(
            return_value=_FAKE_LIST_OF_ALL_SHARES[1:]))
        shares = self.api.get_all(ctx, {'is_public': is_public})
        share_api.policy.check_policy.assert_has_calls([
            mock.call(ctx, 'share', 'get_all'),
        ])
        db_driver.share_get_all_by_project.assert_called_once_with(
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
        self.mock_object(db_driver, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        shares = self.api.get_all(ctx, sort_key='status', sort_dir='asc')
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_driver.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='asc', sort_key='status',
            project_id='fake_pid_1', filters={}, is_public=False
        )
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[0], shares)

    def test_get_all_sort_key_invalid(self):
        self.mock_object(db_driver, 'share_get_all_by_project',
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
        self.mock_object(db_driver, 'share_get_all_by_project',
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
        self.mock_object(db_driver, 'share_get_all_by_project',
                         mock.Mock(return_value=_FAKE_LIST_OF_ALL_SHARES[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        search_opts = {key: {'foo1': 'bar1', 'foo2': 'bar2'}}
        shares = self.api.get_all(ctx, search_opts=search_opts.copy())
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all')
        db_driver.share_get_all_by_project.assert_called_once_with(
            ctx, sort_dir='desc', sort_key='created_at',
            project_id='fake_pid_1', filters=search_opts, is_public=False)
        self.assertEqual(_FAKE_LIST_OF_ALL_SHARES[0], shares)

    def test_get_all_filter_by_metadata(self):
        self._get_all_filter_metadata_or_extra_specs_valid(key='metadata')

    def test_get_all_filter_by_extra_specs(self):
        self._get_all_filter_metadata_or_extra_specs_valid(key='extra_specs')

    def _get_all_filter_metadata_or_extra_specs_invalid(self, key):
        self.mock_object(db_driver, 'share_get_all_by_project',
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
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        share = fake_share('fakeid',
                           user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           status=constants.STATUS_CREATING,
                           is_public=is_public)
        options = share.copy()
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        with mock.patch.object(db_driver, 'share_create',
                               mock.Mock(return_value=share)):
            self.api.create(self.context, 'nfs', '1', 'fakename',
                            'fakedesc', availability_zone='fakeaz',
                            is_public=is_public)
            db_driver.share_create.assert_called_once_with(
                self.context, options)

    @ddt.data('', 'fake', 'Truebar', 'Bartrue')
    def test_create_share_with_invalid_is_public_value(self, is_public):
        self.assertRaises(exception.InvalidParameterValue,
                          self.api.create, self.context, 'nfs', '1',
                          'fakename', 'fakedesc', is_public=is_public)

    @ddt.data(*constants.SUPPORTED_SHARE_PROTOCOLS)
    def test_create_share_valid_protocol(self, proto):
        timeutils.utcnow.return_value = datetime.datetime(1, 1, 1, 1, 1, 1)
        share = fake_share('fakeid',
                           user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           status=constants.STATUS_CREATING)
        options = share.copy()
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        options.update(share_proto=proto)
        self.mock_object(
            db_driver, 'share_create', mock.Mock(return_value=share))

        all_protos = ','.join(
            proto for proto in constants.SUPPORTED_SHARE_PROTOCOLS)
        data = dict(DEFAULT=dict(enabled_share_protocols=all_protos))
        with test_utils.create_temp_config_with_opts(data):
            self.api.create(
                self.context, proto, '1', 'fakename', 'fakedesc',
                availability_zone='fakeaz')

        db_driver.share_create.assert_called_once_with(
            self.context, options)

    @ddt.data(
        None, '', 'fake', 'nfsfake', 'cifsfake', 'glusterfsfake', 'hdfsfake')
    def test_create_share_invalid_protocol(self, proto):
        options = fake_share(
            'fakeid',
            user_id=self.context.user_id,
            project_id=self.context.project_id,
            status=constants.STATUS_CREATING)
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        options.update(share_proto=proto)
        all_protos = ','.join(
            proto for proto in constants.SUPPORTED_SHARE_PROTOCOLS)
        data = dict(DEFAULT=dict(enabled_share_protocols=all_protos))
        with test_utils.create_temp_config_with_opts(data):
            self.assertRaises(
                exception.InvalidInput,
                self.api.create,
                self.context, proto, '1', 'fakename', 'fakedesc')

    def test_manage_new(self):
        share_data = {
            'host': 'fake',
            'export_location': 'fake',
            'share_proto': 'fake',
        }
        driver_options = {}
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        share = fake_share('fakeid',
                           user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           status=constants.STATUS_CREATING)
        self.mock_object(db_driver, 'share_create',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_export_locations_update')
        self.mock_object(db_driver, 'share_get',
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
        db_driver.share_create.assert_called_once_with(self.context,
                                                       share_data)
        db_driver.share_get.assert_called_once_with(self.context, share['id'])
        db_driver.share_export_locations_update.assert_called_once_with(
            self.context, share['id'], export_location
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
        share = fake_share('fakeid')
        self.mock_object(db_driver, 'share_update',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_export_locations_update')
        self.mock_object(self.api, 'get_all',
                         mock.Mock(return_value=shares))

        self.api.manage(self.context,
                        copy.deepcopy(share_data),
                        driver_options)

        db_driver.share_update.assert_called_once_with(
            self.context, 'fake', mock.ANY)
        self.share_rpcapi.manage_share.assert_called_once_with(
            self.context, mock.ANY, driver_options)
        db_driver.share_export_locations_update.assert_called_once_with(
            self.context, share['id'], mock.ANY
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
        share_data = {
            'id': 'fakeid',
            'host': 'fake',
            'size': '1',
            'status': constants.STATUS_AVAILABLE,
            'user_id': self.context.user_id,
            'project_id': self.context.project_id,
        }
        self.mock_object(db_driver, 'share_update', mock.Mock())

        self.api.unmanage(self.context, share_data)

        self.share_rpcapi.unmanage_share.assert_called_once_with(
            self.context, mock.ANY)
        db_driver.share_update.assert_called_once_with(
            mock.ANY, share_data['id'], mock.ANY)

    @mock.patch.object(quota.QUOTAS, 'reserve',
                       mock.Mock(return_value='reservation'))
    @mock.patch.object(quota.QUOTAS, 'commit', mock.Mock())
    def test_create_snapshot(self):
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        share = fake_share('fakeid', status=constants.STATUS_AVAILABLE)
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id=share['id'],
                                 status=constants.STATUS_CREATING)
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
        with mock.patch.object(db_driver, 'share_snapshot_create',
                               mock.Mock(return_value=snapshot)):
            self.api.create_snapshot(self.context, share, fake_name,
                                     fake_desc)
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'create_snapshot', share)
            quota.QUOTAS.reserve.assert_called_once_with(
                self.context, snapshots=1, snapshot_gigabytes=1)
            quota.QUOTAS.commit.assert_called_once_with(
                self.context, 'reservation')
            db_driver.share_snapshot_create.assert_called_once_with(
                self.context, options)

    @mock.patch.object(db_driver, 'share_get_all_by_share_server',
                       mock.Mock(return_value=[]))
    def test_delete_share_server_no_dependent_shares(self):
        server = {'id': 'fake_share_server_id'}
        server_returned = {
            'id': 'fake_share_server_id',
        }
        self.mock_object(db_driver, 'share_server_update',
                         mock.Mock(return_value=server_returned))
        self.api.delete_share_server(self.context, server)
        db_driver.share_get_all_by_share_server.assert_called_once_with(
            self.context, server['id'])
        self.share_rpcapi.delete_share_server.assert_called_once_with(
            self.context, server_returned)

    @mock.patch.object(db_driver, 'share_get_all_by_share_server',
                       mock.Mock(return_value=['fake_share', ]))
    def test_delete_share_server_dependent_share_exists(self):
        server = {'id': 'fake_share_server_id'}
        self.assertRaises(exception.ShareServerInUse,
                          self.api.delete_share_server,
                          self.context,
                          server)
        db_driver.share_get_all_by_share_server.assert_called_once_with(
            self.context, server['id'])

    @mock.patch.object(db_driver, 'share_snapshot_update', mock.Mock())
    def test_delete_snapshot(self):
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        share = fake_share('fakeid')
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id=share['id'],
                                 status=constants.STATUS_AVAILABLE)
        with mock.patch.object(db_driver, 'share_get',
                               mock.Mock(return_value=share)):
            self.api.delete_snapshot(self.context, snapshot)
            self.share_rpcapi.delete_snapshot.assert_called_once_with(
                self.context, snapshot, share['host'])
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'delete_snapshot', snapshot)
            db_driver.share_snapshot_update.assert_called_once_with(
                self.context,
                snapshot['id'],
                {'status': constants.STATUS_DELETING})
            db_driver.share_get.assert_called_once_with(
                self.context, snapshot['share_id'])

    def test_delete_snapshot_wrong_status(self):
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id='fakeshareid',
                                 status=constants.STATUS_CREATING)
        self.assertRaises(exception.InvalidShareSnapshot,
                          self.api.delete_snapshot,
                          self.context,
                          snapshot)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'delete_snapshot', snapshot)

    def test_create_snapshot_if_share_not_available(self):
        share = fake_share('fakeid', status=constants.STATUS_ERROR)
        self.assertRaises(exception.InvalidShare,
                          self.api.create_snapshot,
                          self.context,
                          share,
                          'fakename',
                          'fakedesc')
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'create_snapshot', share)

    @mock.patch.object(quota.QUOTAS, 'reserve',
                       mock.Mock(return_value='reservation'))
    @mock.patch.object(quota.QUOTAS, 'commit', mock.Mock())
    def test_create_from_snapshot_available(self):
        CONF.set_default("use_scheduler_creating_share_from_snapshot", False)
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        original_share = fake_share('fake_original_id',
                                    user_id=self.context.user_id,
                                    project_id=self.context.project_id,
                                    status=constants.STATUS_AVAILABLE)
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id=original_share['id'],
                                 status=constants.STATUS_AVAILABLE)
        share = fake_share('fakeid',
                           user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           snapshot_id=snapshot['id'],
                           status=constants.STATUS_CREATING)
        options = share.copy()
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        request_spec = {
            'share_properties': options,
            'share_proto': share['share_proto'],
            'share_id': share['id'],
            'share_type': None,
            'snapshot_id': share['snapshot_id'],
        }
        self.mock_object(db_driver, 'share_get',
                         mock.Mock(return_value=original_share))
        self.mock_object(share_types, 'get_share_type')
        self.mock_object(db_driver, 'share_create',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_update',
                         mock.Mock(return_value=share))

        self.api.create(self.context, 'nfs', '1', 'fakename', 'fakedesc',
                        snapshot=snapshot, availability_zone='fakeaz')

        db_driver.share_get.assert_called_once_with(
            self.context, snapshot['share_id'])
        self.assertEqual(0, share_types.get_share_type.call_count)
        self.share_rpcapi.create_share.assert_called_once_with(
            self.context, share, snapshot['share']['host'],
            request_spec=request_spec, filter_properties={},
            snapshot_id=snapshot['id'])
        db_driver.share_create.assert_called_once_with(
            self.context, options)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'create')
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, gigabytes=1, shares=1)
        quota.QUOTAS.commit.assert_called_once_with(
            self.context, 'reservation')

    @mock.patch.object(quota.QUOTAS, 'reserve',
                       mock.Mock(return_value='reservation'))
    @mock.patch.object(quota.QUOTAS, 'commit', mock.Mock())
    def test_create_from_snapshot_without_host_restriction(self):
        CONF.set_default("use_scheduler_creating_share_from_snapshot", True)
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        original_share = fake_share('fake_original_id',
                                    user_id=self.context.user_id,
                                    project_id=self.context.project_id,
                                    status=constants.STATUS_AVAILABLE)
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id=original_share['id'],
                                 status=constants.STATUS_AVAILABLE)
        share = fake_share('fakeid',
                           user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           snapshot_id=snapshot['id'],
                           status=constants.STATUS_CREATING)
        options = share.copy()
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        request_spec = {
            'share_properties': options,
            'share_proto': share['share_proto'],
            'share_id': share['id'],
            'share_type': None,
            'snapshot_id': share['snapshot_id'],
        }
        self.mock_object(db_driver, 'share_get',
                         mock.Mock(return_value=original_share))
        self.mock_object(share_types, 'get_share_type')
        self.mock_object(db_driver, 'share_create',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_update',
                         mock.Mock(return_value=share))

        self.api.create(self.context, 'nfs', '1', 'fakename', 'fakedesc',
                        snapshot=snapshot, availability_zone='fakeaz')

        db_driver.share_get.assert_called_once_with(
            self.context, snapshot['share_id'])
        self.assertEqual(0, share_types.get_share_type.call_count)
        self.scheduler_rpcapi.create_share.assert_called_once_with(
            self.context, 'manila-share', share['id'],
            share['snapshot_id'], request_spec=request_spec,
            filter_properties={})
        db_driver.share_create.assert_called_once_with(
            self.context, options)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'create')
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, gigabytes=1, shares=1)
        quota.QUOTAS.commit.assert_called_once_with(
            self.context, 'reservation')

    @mock.patch.object(quota.QUOTAS, 'reserve',
                       mock.Mock(return_value='reservation'))
    @mock.patch.object(quota.QUOTAS, 'commit', mock.Mock())
    def test_create_from_snapshot_with_share_type_same(self):
        # Prepare data for test
        CONF.set_default("use_scheduler_creating_share_from_snapshot", False)
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        share_id = 'fake_share_id'
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id=share_id,
                                 status=constants.STATUS_AVAILABLE)
        share_type = {'id': 'fake_share_type'}
        share = fake_share(share_id, user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           snapshot_id=snapshot['id'],
                           status=constants.STATUS_CREATING,
                           share_type_id=share_type['id'])
        options = share.copy()
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        request_spec = {
            'share_properties': options,
            'share_proto': share['share_proto'],
            'share_id': share_id,
            'share_type': share_type,
            'snapshot_id': share['snapshot_id'],
        }
        self.mock_object(db_driver, 'share_create',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_update',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_get',
                         mock.Mock(return_value=share))

        # Call tested method
        self.api.create(self.context, 'nfs', '1', 'fakename', 'fakedesc',
                        snapshot=snapshot, availability_zone='fakeaz',
                        share_type=share_type)

        # Verify results
        self.share_rpcapi.create_share.assert_called_once_with(
            self.context, share, snapshot['share']['host'],
            request_spec=request_spec, filter_properties={},
            snapshot_id=snapshot['id'])
        db_driver.share_create.assert_called_once_with(
            self.context, options)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'create')
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, gigabytes=1, shares=1)
        quota.QUOTAS.commit.assert_called_once_with(
            self.context, 'reservation')
        db_driver.share_get.assert_called_once_with(
            self.context, share_id)
        db_driver.share_update.assert_called_once_with(
            self.context, share_id, {'host': snapshot['share']['host']})

    @mock.patch.object(quota.QUOTAS, 'reserve',
                       mock.Mock(return_value='reservation'))
    @mock.patch.object(quota.QUOTAS, 'commit', mock.Mock())
    def test_create_from_snapshot_with_share_type_different(self):
        # Prepare data for test
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        share_id = 'fake_share_id'
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id=share_id,
                                 status=constants.STATUS_AVAILABLE)
        share_type = {'id': 'fake_share_type'}
        share = fake_share(share_id, user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           snapshot_id=snapshot['id'],
                           status=constants.STATUS_CREATING,
                           share_type_id=share_type['id'][1:])
        options = share.copy()
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        self.mock_object(db_driver, 'share_create',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_get',
                         mock.Mock(return_value=share))

        # Call tested method
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', '1', 'fakename', 'fakedesc',
                          snapshot=snapshot, availability_zone='fakeaz',
                          share_type=share_type)

        # Verify results
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'create')
        self.scheduler_rpcapi.create_share.assert_has_calls([])
        db_driver.share_create.assert_has_calls([])
        quota.QUOTAS.reserve.assert_has_calls([])
        quota.QUOTAS.commit.assert_has_calls([])
        db_driver.share_get.assert_called_once_with(
            self.context, share_id)

    @mock.patch.object(quota.QUOTAS, 'reserve',
                       mock.Mock(return_value='reservation'))
    @mock.patch.object(quota.QUOTAS, 'commit', mock.Mock())
    def test_create_from_snapshot_share_type_from_original(self):
        # Prepare data for test
        CONF.set_default("use_scheduler_creating_share_from_snapshot", False)
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.utcnow.return_value = date
        share_type = {'id': 'fake_share_type'}
        original_share = fake_share('fake_original_id',
                                    user_id=self.context.user_id,
                                    project_id=self.context.project_id,
                                    share_type_id='fake_share_type_id',
                                    status=constants.STATUS_AVAILABLE)
        share_id = 'fake_share_id'
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id=original_share['id'],
                                 status=constants.STATUS_AVAILABLE)
        share = fake_share(share_id, user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           snapshot_id=snapshot['id'],
                           status=constants.STATUS_CREATING,
                           share_type_id=original_share['share_type_id'])
        options = share.copy()
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        request_spec = {
            'share_properties': options,
            'share_proto': share['share_proto'],
            'share_id': share_id,
            'share_type': share_type,
            'snapshot_id': share['snapshot_id'],
        }
        self.mock_object(db_driver, 'share_get',
                         mock.Mock(return_value=original_share))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value=share_type))
        self.mock_object(db_driver, 'share_create',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_update',
                         mock.Mock(return_value=share))
        self.mock_object(db_driver, 'share_get',
                         mock.Mock(return_value=share))

        # Call tested method
        self.api.create(self.context, 'nfs', '1', 'fakename', 'fakedesc',
                        snapshot=snapshot, availability_zone='fakeaz')

        # Verify results
        self.share_rpcapi.create_share.assert_called_once_with(
            self.context, share, snapshot['share']['host'],
            request_spec=request_spec, filter_properties={},
            snapshot_id=snapshot['id'])
        db_driver.share_create.assert_called_once_with(
            self.context, options)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'create')
        quota.QUOTAS.reserve.assert_called_once_with(
            self.context, gigabytes=1, shares=1)
        quota.QUOTAS.commit.assert_called_once_with(
            self.context, 'reservation')
        db_driver.share_get.assert_called_once_with(
            self.context, original_share['id'])
        db_driver.share_update.assert_called_once_with(
            self.context, share_id, {'host': snapshot['share']['host']})

    def test_get_snapshot(self):
        fake_get_snap = {'fake_key': 'fake_val'}
        with mock.patch.object(db_driver, 'share_snapshot_get',
                               mock.Mock(return_value=fake_get_snap)):
            rule = self.api.get_snapshot(self.context, 'fakeid')
            self.assertEqual(rule, fake_get_snap)
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'get_snapshot')
            db_driver.share_snapshot_get.assert_called_once_with(
                self.context, 'fakeid')

    def test_create_from_snapshot_not_available(self):
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id='fakeshare_id',
                                 status=constants.STATUS_ERROR)
        self.assertRaises(exception.InvalidShareSnapshot, self.api.create,
                          self.context, 'nfs', '1', 'fakename',
                          'fakedesc', snapshot=snapshot,
                          availability_zone='fakeaz')

    def test_create_from_snapshot_larger_size(self):
        snapshot = fake_snapshot(
            1, size=100, status=constants.STATUS_AVAILABLE)
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 1, 'fakename', 'fakedesc',
                          availability_zone='fakeaz', snapshot=snapshot)

    def test_create_wrong_size_0(self):
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 0, 'fakename', 'fakedesc',
                          availability_zone='fakeaz')

    def test_create_wrong_size_some(self):
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 'some', 'fakename',
                          'fakedesc', availability_zone='fakeaz')

    def _setup_delete_mocks(self, status, share_server_id='fake'):
        date = datetime.datetime(2, 2, 2, 2, 2, 2)
        timeutils.utcnow.return_value = date
        share = fake_share('fakeid', status=status,
                           share_server_id=share_server_id)
        options = {'status': constants.STATUS_DELETING, 'terminated_at': date}
        deleting_share = share.copy()
        deleting_share.update(options)
        self.mock_object(db_driver, 'share_update',
                         mock.Mock(return_value=deleting_share))
        self.mock_object(db_driver, 'share_server_update')

        return share, deleting_share, options

    @ddt.data(constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
    def test_delete(self, status):
        share_server_id = 'fake-ss-id'
        share, deleting_share, options = self._setup_delete_mocks(
            status, share_server_id)

        self.api.delete(self.context, share)

        db_driver.share_update.assert_called_once_with(
            self.context, share['id'], options)
        self.share_rpcapi.delete_share.assert_called_once_with(
            self.context, deleting_share)
        db_driver.share_server_update.assert_called_once_with(
            self.context, share_server_id, mock.ANY)

    def test_delete_share_without_share_server(self):
        share, deleting_share, options = self._setup_delete_mocks(
            constants.STATUS_AVAILABLE, share_server_id=None)

        self.api.delete(self.context, share)

        self.assertEqual(0, db_driver.share_server_update.call_count)

    def test_delete_wrong_status(self):
        share = fake_share('fakeid')
        self.assertRaises(exception.InvalidShare, self.api.delete,
                          self.context, share)

    @mock.patch.object(db_driver, 'share_delete', mock.Mock())
    def test_delete_no_host(self):
        share = fake_share('fakeid')
        share['host'] = None
        self.api.delete(self.context, share)
        db_driver.share_delete.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), 'fakeid')

    @ddt.data('', 'fake', 'Truebar', 'Bartrue')
    def test_update_share_with_invalid_is_public_value(self, is_public):
        self.assertRaises(exception.InvalidParameterValue,
                          self.api.update, self.context, 'fakeid',
                          {'is_public': is_public})

    def test_get(self):
        share = fake_share('fakeid')
        with mock.patch.object(db_driver, 'share_get',
                               mock.Mock(return_value=share)):
            result = self.api.get(self.context, 'fakeid')
            self.assertEqual(result, share)
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'get', share)
            db_driver.share_get.assert_called_once_with(
                self.context, 'fakeid')

    @mock.patch.object(db_driver, 'share_snapshot_get_all_by_project',
                       mock.Mock())
    def test_get_all_snapshots_admin_not_all_tenants(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=True)
        self.api.get_all_snapshots(ctx)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all_snapshots')
        db_driver.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', sort_dir='desc', sort_key='share_id', filters={})

    @mock.patch.object(db_driver, 'share_snapshot_get_all', mock.Mock())
    def test_get_all_snapshots_admin_all_tenants(self):
        self.api.get_all_snapshots(self.context,
                                   search_opts={'all_tenants': 1})
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'get_all_snapshots')
        db_driver.share_snapshot_get_all.assert_called_once_with(
            self.context, sort_dir='desc', sort_key='share_id', filters={})

    @mock.patch.object(db_driver, 'share_snapshot_get_all_by_project',
                       mock.Mock())
    def test_get_all_snapshots_not_admin(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=False)
        self.api.get_all_snapshots(ctx)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all_snapshots')
        db_driver.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', sort_dir='desc', sort_key='share_id', filters={})

    def test_get_all_snapshots_not_admin_search_opts(self):
        search_opts = {'size': 'fakesize'}
        fake_objs = [{'name': 'fakename1'}, search_opts]
        ctx = context.RequestContext('fakeuid', 'fakepid', is_admin=False)
        self.mock_object(db_driver, 'share_snapshot_get_all_by_project',
                         mock.Mock(return_value=fake_objs))

        result = self.api.get_all_snapshots(ctx, search_opts)

        self.assertEqual([search_opts], result)
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all_snapshots')
        db_driver.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fakepid', sort_dir='desc', sort_key='share_id',
            filters=search_opts)

    def test_get_all_snapshots_with_sorting_valid(self):
        self.mock_object(
            db_driver, 'share_snapshot_get_all_by_project',
            mock.Mock(return_value=_FAKE_LIST_OF_ALL_SNAPSHOTS[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        snapshots = self.api.get_all_snapshots(
            ctx, sort_key='status', sort_dir='asc')
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all_snapshots')
        db_driver.share_snapshot_get_all_by_project.assert_called_once_with(
            ctx, 'fake_pid_1', sort_dir='asc', sort_key='status', filters={})
        self.assertEqual(_FAKE_LIST_OF_ALL_SNAPSHOTS[0], snapshots)

    def test_get_all_snapshots_sort_key_invalid(self):
        self.mock_object(
            db_driver, 'share_snapshot_get_all_by_project',
            mock.Mock(return_value=_FAKE_LIST_OF_ALL_SNAPSHOTS[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        self.assertRaises(
            exception.InvalidInput,
            self.api.get_all_snapshots,
            ctx,
            sort_key=1,
        )
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all_snapshots')

    def test_get_all_snapshots_sort_dir_invalid(self):
        self.mock_object(
            db_driver, 'share_snapshot_get_all_by_project',
            mock.Mock(return_value=_FAKE_LIST_OF_ALL_SNAPSHOTS[0]))
        ctx = context.RequestContext('fake_uid', 'fake_pid_1', is_admin=False)
        self.assertRaises(
            exception.InvalidInput,
            self.api.get_all_snapshots,
            ctx,
            sort_dir=1,
        )
        share_api.policy.check_policy.assert_called_once_with(
            ctx, 'share', 'get_all_snapshots')

    @ddt.data(None, 'rw', 'ro')
    def test_allow_access(self, level):
        share = fake_share('fakeid', status=constants.STATUS_AVAILABLE)
        values = {
            'share_id': share['id'],
            'access_type': 'fakeacctype',
            'access_to': 'fakeaccto',
            'access_level': level,
        }
        self.mock_object(db_driver, 'share_access_create',
                         mock.Mock(return_value='fakeacc'))
        access = self.api.allow_access(self.context, share,
                                       'fakeacctype', 'fakeaccto',
                                       level)
        self.assertEqual(access, 'fakeacc')
        self.share_rpcapi.allow_access.assert_called_once_with(
            self.context, share, 'fakeacc')
        db_driver.share_access_create.assert_called_once_with(
            self.context, values)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'allow_access')

    def test_allow_access_invalid_access_level(self):
        share = fake_share('fakeid', status=constants.STATUS_AVAILABLE)
        self.assertRaises(exception.InvalidShareAccess, self.api.allow_access,
                          self.context, share, 'fakeacctype', 'fakeaccto',
                          'ab')

    def test_allow_access_status_not_available(self):
        share = fake_share('fakeid', status=constants.STATUS_ERROR)
        self.assertRaises(exception.InvalidShare, self.api.allow_access,
                          self.context, share, 'fakeacctype', 'fakeaccto')

    def test_allow_access_no_host(self):
        share = fake_share('fakeid', host=None)
        self.assertRaises(exception.InvalidShare, self.api.allow_access,
                          self.context, share, 'fakeacctype', 'fakeaccto')

    @mock.patch.object(db_driver, 'share_access_delete', mock.Mock())
    def test_deny_access_error(self):
        share = fake_share('fakeid', status=constants.STATUS_AVAILABLE)
        access = fake_access('fakaccid', state='fakeerror')
        self.api.deny_access(self.context, share, access)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')
        db_driver.share_access_delete.assert_called_once_with(
            self.context, access['id'])

    @mock.patch.object(db_driver, 'share_access_update', mock.Mock())
    def test_deny_access_active(self):
        share = fake_share('fakeid', status=constants.STATUS_AVAILABLE)
        access = fake_access('fakaccid', state='fakeactive')
        self.api.deny_access(self.context, share, access)
        db_driver.share_access_update.assert_called_once_with(
            self.context, access['id'], {'state': 'fakedeleting'})
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')
        self.share_rpcapi.deny_access.assert_called_once_with(
            self.context, share, access)

    def test_deny_access_not_active_not_error(self):
        share = fake_share('fakeid', status=constants.STATUS_AVAILABLE)
        access = fake_access('fakaccid', state='fakenew')
        self.assertRaises(exception.InvalidShareAccess, self.api.deny_access,
                          self.context, share, access)
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')

    def test_deny_access_status_not_available(self):
        share = fake_share('fakeid', status=constants.STATUS_ERROR)
        self.assertRaises(exception.InvalidShare, self.api.deny_access,
                          self.context, share, 'fakeacc')
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')

    def test_deny_access_no_host(self):
        share = fake_share('fakeid', host=None)
        self.assertRaises(exception.InvalidShare, self.api.deny_access,
                          self.context, share, 'fakeacc')
        share_api.policy.check_policy.assert_called_once_with(
            self.context, 'share', 'deny_access')

    def test_access_get(self):
        with mock.patch.object(db_driver, 'share_access_get',
                               mock.Mock(return_value='fake')):
            rule = self.api.access_get(self.context, 'fakeid')
            self.assertEqual(rule, 'fake')
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'access_get')
            db_driver.share_access_get.assert_called_once_with(
                self.context, 'fakeid')

    def test_access_get_all(self):
        share = fake_share('fakeid')
        rules = [
            fake_access('fakeacc0id', state='fakenew'),
            fake_access('fakeacc1id', state='fakeerror'),
        ]
        expected = [
            {
                'id': 'fakeacc0id',
                'access_type': 'fakeacctype',
                'access_to': 'fakeaccto',
                'access_level': 'rw',
                'state': 'fakenew',
            },
            {
                'id': 'fakeacc1id',
                'access_type': 'fakeacctype',
                'access_to': 'fakeaccto',
                'access_level': 'rw',
                'state': 'fakeerror',
            },
        ]
        with mock.patch.object(db_driver, 'share_access_get_all_for_share',
                               mock.Mock(return_value=rules)):
            actual = self.api.access_get_all(self.context, share)
            self.assertEqual(actual, expected)
            share_api.policy.check_policy.assert_called_once_with(
                self.context, 'share', 'access_get_all')
            db_driver.share_access_get_all_for_share.assert_called_once_with(
                self.context, 'fakeid')

    def test_share_metadata_get(self):
        metadata = {'a': 'b', 'c': 'd'}
        share_id = str(uuid.uuid4())
        db_driver.share_create(self.context,
                               {'id': share_id, 'metadata': metadata})
        self.assertEqual(metadata,
                         db_driver.share_metadata_get(self.context, share_id))

    def test_share_metadata_update(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '5'}
        should_be = {'a': '3', 'c': '2', 'd': '5'}
        share_id = str(uuid.uuid4())
        db_driver.share_create(self.context,
                               {'id': share_id, 'metadata': metadata1})
        db_driver.share_metadata_update(self.context, share_id,
                                        metadata2, False)
        self.assertEqual(should_be,
                         db_driver.share_metadata_get(self.context, share_id))

    def test_share_metadata_update_delete(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '4'}
        should_be = metadata2
        share_id = str(uuid.uuid4())
        db_driver.share_create(self.context,
                               {'id': share_id, 'metadata': metadata1})
        db_driver.share_metadata_update(self.context, share_id,
                                        metadata2, True)
        self.assertEqual(should_be,
                         db_driver.share_metadata_get(self.context, share_id))

    def test_extend_invalid_status(self):
        invalid_status = 'fake'
        share = fake_share('fake', status=invalid_status)
        new_size = 123

        self.assertRaises(exception.InvalidShare,
                          self.api.extend, self.context, share, new_size)

    def test_extend_invalid_size(self):
        share = fake_share('fake', status=constants.STATUS_AVAILABLE, size=200)
        new_size = 123

        self.assertRaises(exception.InvalidInput,
                          self.api.extend, self.context, share, new_size)

    def test_extend_quota_error(self):
        share = fake_share('fake', status=constants.STATUS_AVAILABLE, size=100)
        new_size = 123
        usages = {'gigabytes': {'reserved': 'fake', 'in_use': 'fake'}}
        quotas = {'gigabytes': 'fake'}
        exc = exception.OverQuota(usages=usages, quotas=quotas)
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(side_effect=exc))

        self.assertRaises(exception.ShareSizeExceedsAvailableQuota,
                          self.api.extend, self.context, share, new_size)

    def test_extend_valid(self):
        share = fake_share('fake', status=constants.STATUS_AVAILABLE, size=100)
        new_size = 123
        self.mock_object(self.api, 'update')
        self.mock_object(self.api.share_rpcapi, 'extend_share')

        self.api.extend(self.context, share, new_size)

        self.api.update.assert_called_once_with(
            self.context, share, {'status': constants.STATUS_EXTENDING})
        self.api.share_rpcapi.extend_share.assert_called_once_with(
            self.context, share, new_size, mock.ANY
        )


class OtherTenantsShareActionsTestCase(test.TestCase):
    def setUp(self):
        super(OtherTenantsShareActionsTestCase, self).setUp()
        self.api = share.API()

    def test_delete_other_tenants_public_share(self):
        share = fake_share('fakeid', is_public=True)
        ctx = context.RequestContext(user_id='1111', project_id='2222')
        self.assertRaises(exception.PolicyNotAuthorized, self.api.delete, ctx,
                          share)

    def test_update_other_tenants_public_share(self):
        share = fake_share('fakeid', is_public=True)
        ctx = context.RequestContext(user_id='1111', project_id='2222')
        self.assertRaises(exception.PolicyNotAuthorized, self.api.update, ctx,
                          share, {'display_name': 'newname'})

    def test_get_other_tenants_public_share(self):
        share = fake_share('fakeid', is_public=True)
        ctx = context.RequestContext(user_id='1111', project_id='2222')
        self.mock_object(db_driver, 'share_get',
                         mock.Mock(return_value=share))
        result = self.api.get(ctx, 'fakeid')
        self.assertEqual(share, result)
        db_driver.share_get.assert_called_once_with(ctx, 'fakeid')
