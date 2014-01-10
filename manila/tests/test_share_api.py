# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 NetApp
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

import datetime
import mox
import random
import suds

from manila import context
from manila import db as db_driver
from manila import exception
from manila.openstack.common import timeutils
from manila import quota
from manila.scheduler import rpcapi as scheduler_rpcapi
from manila import share
from manila.share import api as share_api
from manila.share import rpcapi as share_rpcapi
from manila import test
from manila.tests.db import fakes as db_fakes


def fake_share(id, **kwargs):
    share = {
        'id': id,
        'size': 1,
        'user_id': 'fakeuser',
        'project_id': 'fakeproject',
        'snapshot_id': None,
        'availability_zone': 'fakeaz',
        'status': 'fakestatus',
        'display_name': 'fakename',
        'metadata': None,
        'display_description': 'fakedesc',
        'share_proto': 'nfs',
        'export_location': 'fake_location',
        'host': 'fakehost',
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
        'export_location': 'fake_location',
        'progress': 'fakeprogress99%',
        'scheduled_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        'launched_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        'terminated_at': datetime.datetime(1, 1, 1, 1, 1, 1)
    }
    snapshot.update(kwargs)
    return snapshot


def fake_access(id, **kwargs):
    access = {
        'id': id,
        'share_id': 'fakeshareid',
        'access_type': 'fakeacctype',
        'access_to': 'fakeaccto',
        'state': 'fakeactive',
        'STATE_NEW': 'fakenew',
        'STATE_ACTIVE': 'fakeactive',
        'STATE_DELETING': 'fakedeleting',
        'STATE_DELETED': 'fakedeleted',
        'STATE_ERROR': 'fakeerror',
    }
    access.update(kwargs)
    return db_fakes.FakeModel(access)


class ShareAPITestCase(test.TestCase):
    def setUp(self):
        super(ShareAPITestCase, self).setUp()
        self.context = context.get_admin_context()
        self.scheduler_rpcapi = self.mox.CreateMock(
                                    scheduler_rpcapi.SchedulerAPI)
        self.share_rpcapi = self.mox.CreateMock(share_rpcapi.ShareAPI)
        self.api = share.API()

        self.stubs.Set(self.api, 'scheduler_rpcapi', self.scheduler_rpcapi)
        self.stubs.Set(self.api, 'share_rpcapi', self.share_rpcapi)
        self.stubs.Set(quota.QUOTAS, 'reserve', lambda *args, **kwargs: None)

    def tearDown(self):
        super(ShareAPITestCase, self).tearDown()
        timeutils.clear_time_override()

    def test_create(self):
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.set_time_override(override_time=date)
        share = fake_share('fakeid',
                           user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           status='creating')
        options = share.copy()
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        request_spec = {'share_properties': options,
                        'share_proto': share['share_proto'],
                        'share_id': share['id'],
                        'snapshot_id': share['snapshot_id'],
                        }

        self.mox.StubOutWithMock(db_driver, 'share_create')
        db_driver.share_create(self.context, options).AndReturn(share)
        self.scheduler_rpcapi.create_share(self.context, mox.IgnoreArg(),
                                           share['id'], share['snapshot_id'],
                                           request_spec=request_spec,
                                           filter_properties={})
        self.mox.ReplayAll()
        self.api.create(self.context, 'nfs', '1', 'fakename', 'fakedesc',
                        availability_zone='fakeaz')

    def test_create_snapshot(self):
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.set_time_override(override_time=date)
        share = fake_share('fakeid',
                           status='available')
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id=share['id'],
                                 status='creating')
        fake_name = 'fakename'
        fake_desc = 'fakedesc'
        options = {'share_id': share['id'],
                   'user_id': self.context.user_id,
                   'project_id': self.context.project_id,
                   'status': "creating",
                   'progress': '0%',
                   'share_size': share['size'],
                   'size': 1,
                   'display_name': fake_name,
                   'display_description': fake_desc,
                   'share_proto': share['share_proto'],
                   'export_location': share['export_location']}

        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'create_snapshot', share)
        self.mox.StubOutWithMock(quota.QUOTAS, 'reserve')
        quota.QUOTAS.reserve(self.context, snapshots=1, gigabytes=1).\
            AndReturn('reservation')
        self.mox.StubOutWithMock(db_driver, 'share_snapshot_create')
        db_driver.share_snapshot_create(self.context,
                                        options).AndReturn(snapshot)
        self.mox.StubOutWithMock(quota.QUOTAS, 'commit')
        quota.QUOTAS.commit(self.context, 'reservation')
        self.share_rpcapi.create_snapshot(self.context, share, snapshot)
        self.mox.ReplayAll()
        self.api.create_snapshot(self.context, share, fake_name, fake_desc)

    def test_delete_snapshot(self):
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.set_time_override(override_time=date)
        share = fake_share('fakeid')
        snapshot = fake_snapshot('fakesnapshotid', share_id=share['id'],
                                 status='available')
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(
            self.context, 'delete_snapshot', snapshot)
        self.mox.StubOutWithMock(db_driver, 'share_snapshot_update')
        db_driver.share_snapshot_update(self.context, snapshot['id'],
                                        {'status': 'deleting'})
        self.mox.StubOutWithMock(db_driver, 'share_get')
        db_driver.share_get(self.context,
                            snapshot['share_id']).AndReturn(share)
        self.share_rpcapi.delete_snapshot(self.context, snapshot,
                                          share['host'])
        self.mox.ReplayAll()
        self.api.delete_snapshot(self.context, snapshot)

    def test_delete_snapshot_wrong_status(self):
        snapshot = fake_snapshot('fakesnapshotid', share_id='fakeshareid',
                                 status='creating')
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(
            self.context, 'delete_snapshot', snapshot)
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShareSnapshot,
                          self.api.delete_snapshot, self.context, snapshot)

    def test_create_snapshot_if_share_not_available(self):
        share = fake_share('fakeid',
                           status='error')
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'create_snapshot', share)
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShare, self.api.create_snapshot,
                          self.context, share, 'fakename', 'fakedesc')

    def test_create_from_snapshot_available(self):
        date = datetime.datetime(1, 1, 1, 1, 1, 1)
        timeutils.set_time_override(override_time=date)
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id='fakeshare_id',
                                 status='available')
        share = fake_share('fakeid',
                           user_id=self.context.user_id,
                           project_id=self.context.project_id,
                           snapshot_id=snapshot['id'],
                           status='creating')
        options = share.copy()
        for name in ('id', 'export_location', 'host', 'launched_at',
                     'terminated_at'):
            options.pop(name, None)
        request_spec = {'share_properties': options,
                        'share_proto': share['share_proto'],
                        'share_id': share['id'],
                        'snapshot_id': share['snapshot_id'],
                        }

        self.mox.StubOutWithMock(db_driver, 'share_create')
        db_driver.share_create(self.context, options).AndReturn(share)
        self.scheduler_rpcapi.create_share(self.context, mox.IgnoreArg(),
                                           share['id'], share['snapshot_id'],
                                           request_spec=request_spec,
                                           filter_properties={})
        self.mox.ReplayAll()
        self.api.create(self.context, 'nfs', '1', 'fakename', 'fakedesc',
                        snapshot=snapshot, availability_zone='fakeaz')

    def test_get_snapshot(self):
        fake_get_snap = {'fake_key': 'fake_val'}
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'get_snapshot')
        self.mox.StubOutWithMock(db_driver, 'share_snapshot_get')
        db_driver.share_snapshot_get(self.context,
                                     'fakeid').AndReturn(fake_get_snap)
        self.mox.ReplayAll()
        rule = self.api.get_snapshot(self.context, 'fakeid')
        self.assertEqual(rule, fake_get_snap)

    def test_create_from_snapshot_not_available(self):
        snapshot = fake_snapshot('fakesnapshotid',
                                 share_id='fakeshare_id',
                                 status='error')
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShareSnapshot, self.api.create,
                          self.context, 'nfs', '1', 'fakename',
                          'fakedesc', snapshot=snapshot,
                          availability_zone='fakeaz')

    def test_create_from_snapshot_larger_size(self):
        snapshot = fake_snapshot(1, size=100, status='available')
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 1, 'fakename', 'fakedesc',
                          availability_zone='fakeaz', snapshot=snapshot)

    def test_create_wrong_size_0(self):
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 0, 'fakename', 'fakedesc',
                          availability_zone='fakeaz')

    def test_create_wrong_size_some(self):
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidInput, self.api.create,
                          self.context, 'nfs', 'some', 'fakename',
                          'fakedesc', availability_zone='fakeaz')

    def test_delete_available(self):
        date = datetime.datetime(2, 2, 2, 2, 2, 2)
        timeutils.set_time_override(override_time=date)
        share = fake_share('fakeid', status='available')
        options = {'status': 'deleting',
                   'terminated_at': date}
        deleting_share = share.copy()
        deleting_share.update(options)

        self.mox.StubOutWithMock(db_driver, 'share_update')
        db_driver.share_update(self.context, share['id'], options).\
            AndReturn(deleting_share)
        self.share_rpcapi.delete_share(self.context, deleting_share)
        self.mox.ReplayAll()
        self.api.delete(self.context, share)
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def test_delete_error(self):
        date = datetime.datetime(2, 2, 2, 2, 2, 2)
        timeutils.set_time_override(override_time=date)
        share = fake_share('fakeid', status='error')
        options = {'status': 'deleting',
                   'terminated_at': date}
        deleting_share = share.copy()
        deleting_share.update(options)

        self.mox.StubOutWithMock(db_driver, 'share_update')
        db_driver.share_update(self.context, share['id'], options).\
            AndReturn(deleting_share)
        self.share_rpcapi.delete_share(self.context, deleting_share)
        self.mox.ReplayAll()
        self.api.delete(self.context, share)
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def test_delete_wrong_status(self):
        share = fake_share('fakeid')
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShare, self.api.delete,
                          self.context, share)

    def test_delete_no_host(self):
        share = fake_share('fakeid')
        share['host'] = None

        self.mox.StubOutWithMock(db_driver, 'share_delete')
        db_driver.share_delete(mox.IsA(context.RequestContext), 'fakeid')
        self.mox.ReplayAll()
        self.api.delete(self.context, share)

    def test_get(self):
        self.mox.StubOutWithMock(db_driver, 'share_get')
        db_driver.share_get(self.context, 'fakeid').AndReturn('fakeshare')
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'get', 'fakeshare')
        self.mox.ReplayAll()
        result = self.api.get(self.context, 'fakeid')
        self.assertEqual(result, 'fakeshare')

    def test_get_all_admin_not_all_tenants(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', id_admin=True)
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(ctx, 'get_all')
        self.mox.StubOutWithMock(db_driver, 'share_get_all_by_project')
        db_driver.share_get_all_by_project(ctx, 'fakepid')
        self.mox.ReplayAll()
        self.api.get_all(ctx)

    def test_get_all_admin_all_tenants(self):
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'get_all')
        self.mox.StubOutWithMock(db_driver, 'share_get_all')
        db_driver.share_get_all(self.context)
        self.mox.ReplayAll()
        self.api.get_all(self.context, search_opts={'all_tenants': 1})

    def test_get_all_not_admin(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', id_admin=False)
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(ctx, 'get_all')
        self.mox.StubOutWithMock(db_driver, 'share_get_all_by_project')
        db_driver.share_get_all_by_project(ctx, 'fakepid')
        self.mox.ReplayAll()
        self.api.get_all(ctx)

    def test_get_all_not_admin_search_opts(self):
        search_opts = {'size': 'fakesize'}
        fake_objs = [{'name': 'fakename1'}, search_opts]
        ctx = context.RequestContext('fakeuid', 'fakepid', id_admin=False)
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(ctx, 'get_all')
        self.mox.StubOutWithMock(db_driver, 'share_get_all_by_project')
        db_driver.share_get_all_by_project(ctx,
                                           'fakepid').AndReturn(fake_objs)
        self.mox.ReplayAll()
        result = self.api.get_all(ctx, search_opts)
        self.assertEqual([search_opts], result)

    def test_get_all_snapshots_admin_not_all_tenants(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', id_admin=True)
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(ctx, 'get_all_snapshots')
        self.mox.StubOutWithMock(db_driver,
                                 'share_snapshot_get_all_by_project')
        db_driver.share_snapshot_get_all_by_project(ctx, 'fakepid')
        self.mox.ReplayAll()
        self.api.get_all_snapshots(ctx)

    def test_get_all_snapshots_admin_all_tenants(self):
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'get_all_snapshots')
        self.mox.StubOutWithMock(db_driver, 'share_snapshot_get_all')
        db_driver.share_snapshot_get_all(self.context)
        self.mox.ReplayAll()
        self.api.get_all_snapshots(self.context,
                                   search_opts={'all_tenants': 1})

    def test_get_all_snapshots_not_admin(self):
        ctx = context.RequestContext('fakeuid', 'fakepid', id_admin=False)
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(ctx, 'get_all_snapshots')
        self.mox.StubOutWithMock(db_driver,
                                 'share_snapshot_get_all_by_project')
        db_driver.share_snapshot_get_all_by_project(ctx, 'fakepid')
        self.mox.ReplayAll()
        self.api.get_all_snapshots(ctx)

    def test_get_all_snapshots_not_admin_search_opts(self):
        search_opts = {'size': 'fakesize'}
        fake_objs = [{'name': 'fakename1'}, search_opts]
        ctx = context.RequestContext('fakeuid', 'fakepid', id_admin=False)
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(ctx, 'get_all_snapshots')
        self.mox.StubOutWithMock(db_driver,
                                 'share_snapshot_get_all_by_project')
        db_driver.share_snapshot_get_all_by_project(ctx, 'fakepid').\
            AndReturn(fake_objs)
        self.mox.ReplayAll()
        result = self.api.get_all_snapshots(ctx, search_opts)
        self.assertEqual([search_opts], result)

    def test_allow_access(self):
        share = fake_share('fakeid', status='available')
        values = {'share_id': share['id'],
                  'access_type': 'fakeacctype',
                  'access_to': 'fakeaccto'}
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'allow_access')
        self.mox.StubOutWithMock(db_driver, 'share_access_create')
        db_driver.share_access_create(self.context, values).\
            AndReturn('fakeacc')
        self.share_rpcapi.allow_access(self.context, share, 'fakeacc')
        self.mox.ReplayAll()
        access = self.api.allow_access(self.context, share, 'fakeacctype',
                                       'fakeaccto')
        self.assertEqual(access, 'fakeacc')

    def test_allow_access_status_not_available(self):
        share = fake_share('fakeid', status='error')
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShare, self.api.allow_access,
                          self.context, share, 'fakeacctype', 'fakeaccto')

    def test_allow_access_no_host(self):
        share = fake_share('fakeid', host=None)
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShare, self.api.allow_access,
                          self.context, share, 'fakeacctype', 'fakeaccto')

    def test_deny_access_error(self):
        share = fake_share('fakeid', status='available')
        access = fake_access('fakaccid', state='fakeerror')
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'deny_access')
        self.mox.StubOutWithMock(db_driver, 'share_access_delete')
        db_driver.share_access_delete(self.context, access['id'])
        self.mox.ReplayAll()
        self.api.deny_access(self.context, share, access)

    def test_deny_access_active(self):
        share = fake_share('fakeid', status='available')
        access = fake_access('fakaccid', state='fakeactive')
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'deny_access')
        self.mox.StubOutWithMock(db_driver, 'share_access_update')
        db_driver.share_access_update(self.context, access['id'],
                                      {'state': 'fakedeleting'})
        self.share_rpcapi.deny_access(self.context, share, access)
        self.mox.ReplayAll()
        self.api.deny_access(self.context, share, access)

    def test_deny_access_not_active_not_error(self):
        share = fake_share('fakeid', status='available')
        access = fake_access('fakaccid', state='fakenew')
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'deny_access')
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShareAccess, self.api.deny_access,
                          self.context, share, access)

    def test_deny_access_status_not_available(self):
        share = fake_share('fakeid', status='error')
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'deny_access')
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShare, self.api.deny_access,
                          self.context, share, 'fakeacc')

    def test_deny_access_no_host(self):
        share = fake_share('fakeid', host=None)
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'deny_access')
        self.mox.ReplayAll()
        self.assertRaises(exception.InvalidShare, self.api.deny_access,
                          self.context, share, 'fakeacc')

    def test_access_get(self):
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'access_get')
        self.mox.StubOutWithMock(db_driver, 'share_access_get')
        db_driver.share_access_get(self.context, 'fakeid').AndReturn('fake')
        self.mox.ReplayAll()
        rule = self.api.access_get(self.context, 'fakeid')
        self.assertEqual(rule, 'fake')

    def test_access_get_all(self):
        share = fake_share('fakeid')
        self.mox.StubOutWithMock(share_api.policy, 'check_policy')
        share_api.policy.check_policy(self.context, 'access_get_all')
        self.mox.StubOutWithMock(db_driver, 'share_access_get_all_for_share')
        db_driver.share_access_get_all_for_share(self.context, 'fakeid').\
            AndReturn([fake_access('fakeacc0id', state='fakenew'),
                       fake_access('fakeacc1id', state='fakeerror')])
        self.mox.ReplayAll()
        rules = self.api.access_get_all(self.context, share)
        self.assertEqual(rules, [{'id': 'fakeacc0id',
                                  'access_type': 'fakeacctype',
                                  'access_to': 'fakeaccto',
                                  'state': 'fakenew'},
                                 {'id': 'fakeacc1id',
                                  'access_type': 'fakeacctype',
                                  'access_to': 'fakeaccto',
                                  'state': 'fakeerror'}])

    def test_share_metadata_get(self):
        metadata = {'a': 'b', 'c': 'd'}
        db_driver.share_create(self.context, {'id': '1', 'metadata': metadata})

        self.assertEqual(metadata,
                         db_driver.share_metadata_get(self.context, '1'))

    def test_share_metadata_update(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '5'}
        should_be = {'a': '3', 'c': '2', 'd': '5'}

        db_driver.share_create(self.context, {'id': '1',
                                              'metadata': metadata1})
        db_driver.share_metadata_update(self.context, '1', metadata2, False)

        self.assertEqual(should_be,
                         db_driver.share_metadata_get(self.context, '1'))

    def test_share_metadata_update_delete(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '4'}
        should_be = metadata2

        db_driver.share_create(self.context, {'id': '1',
                                              'metadata': metadata1})
        db_driver.share_metadata_update(self.context, '1', metadata2, True)

        self.assertEqual(should_be,
                         db_driver.share_metadata_get(self.context, '1'))
