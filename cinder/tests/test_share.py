# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 NetApp
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
"""
Tests for Share Code.

"""

import datetime
import os

import mox
import shutil
import tempfile

from cinder import context
from cinder import db
from cinder import exception
from cinder import flags
from cinder.image import image_utils
from cinder.openstack.common import importutils
from cinder.openstack.common.notifier import api as notifier_api
from cinder.openstack.common.notifier import test_notifier
from cinder.openstack.common import rpc
import cinder.policy
from cinder.share import manager
from cinder import test
from cinder.tests import fake_flags

FLAGS = flags.FLAGS


class FakeShareDriver(object):
    def __init__(self, db, **kwargs):
        self.db = db

    def allocate_container(self, context, share):
        pass

    def allocate_container_from_snapshot(self, context, share, snapshot):
        pass

    def create_snapshot(self, context, snapshot):
        pass

    def delete_snapshot(self, context, snapshot):
        pass

    def deallocate_container(self, context, share):
        pass

    def create_share(self, context, share):
        return 'fake_location'

    def delete_share(self, context, share):
        pass

    def create_export(self, context, share):
        pass

    def remove_export(self, context, share):
        pass

    def ensure_share(self, context, share):
        pass

    def allow_access(self, context, share, access):
        pass

    def deny_access(self, context, share, access):
        pass

    def check_for_setup_error(self):
        pass

    def get_share_stats(self, refresh=False):
        return None

    def do_setup(self, context):
        pass


class ShareTestCase(test.TestCase):
    """Test Case for shares."""

    def setUp(self):
        super(ShareTestCase, self).setUp()
        self.flags(connection_type='fake',
                   share_driver='cinder.tests.test_share.FakeShareDriver')
        self.share = importutils.import_object(FLAGS.share_manager)
        self.context = context.get_admin_context()

    @staticmethod
    def _create_share(status="creating", size=0, snapshot_id=None):
        """Create a share object."""
        share = {}
        share['share_proto'] = "NFS"
        share['size'] = size
        share['snapshot_id'] = snapshot_id
        share['user_id'] = 'fake'
        share['project_id'] = 'fake'
        share['availability_zone'] = FLAGS.storage_availability_zone
        share['status'] = status
        share['host'] = FLAGS.host
        return db.share_create(context.get_admin_context(), share)

    @staticmethod
    def _create_snapshot(status="creating", size=0, share_id=None):
        """Create a snapshot object."""
        snapshot = {}
        snapshot['share_proto'] = "NFS"
        snapshot['size'] = size
        snapshot['share_id'] = share_id
        snapshot['user_id'] = 'fake'
        snapshot['project_id'] = 'fake'
        snapshot['status'] = status
        return db.share_snapshot_create(context.get_admin_context(), snapshot)

    @staticmethod
    def _create_access(state='new', share_id=None):
        """Create a access rule object."""
        access = {}
        access['access_type'] = 'fake_type'
        access['access_to'] = 'fake_IP'
        access['share_id'] = share_id
        access['state'] = state
        return db.share_access_create(context.get_admin_context(), access)

    def test_init_host_ensuring_shares(self):
        """Test init_host for ensuring shares and access rules."""

        share = self._create_share(status='available')
        share_id = share['id']

        another_share = self._create_share(status='error')

        access = self._create_access(share_id=share_id, state='active')

        self.mox.StubOutWithMock(context, 'get_admin_context')
        context.get_admin_context().AndReturn(self.context)

        self.mox.StubOutWithMock(db, 'share_get_all_by_host')
        db.share_get_all_by_host(self.context, mox.IgnoreArg())\
            .AndReturn([share, another_share])

        driver = self.mox.CreateMockAnything(FakeShareDriver)
        driver.do_setup(self.context)
        driver.check_for_setup_error()
        driver.ensure_share(self.context, share)
        driver.allow_access(self.context, share, mox.IgnoreArg())
        driver.get_share_stats(refresh=True)
        self.share.driver = driver

        self.mox.ReplayAll()

        self.share.init_host()

    def test_create_share_from_snapshot(self):
        """Test share can be created from snapshot."""
        share = self._create_share()
        share_id = share['id']
        snapshot = self._create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.share.create_share(self.context, share_id,
                                snapshot_id=snapshot_id)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEquals(shr['status'], 'available')

    def test_create_delete_share_snapshot(self):
        """Test share's snapshot can be created and deleted."""

        def _fake_create_snapshot(self, context, snapshot):
            snapshot['progress'] = '99%'
            return snapshot

        self.stubs.Set(FakeShareDriver, "create_snapshot",
                       _fake_create_snapshot)

        share = self._create_share()
        share_id = share['id']
        snapshot = self._create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.share.create_snapshot(self.context, share_id, snapshot_id)
        self.assertEqual(share_id,
                         db.share_snapshot_get(context.get_admin_context(),
                         snapshot_id).share_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEquals(snap['status'], 'available')

        self.share.delete_snapshot(self.context, snapshot_id)

        self.assertEquals('deleted', db.share_snapshot_get(
            context.get_admin_context(read_deleted='yes'), snapshot_id).status)
        self.assertRaises(exception.NotFound,
                          db.share_snapshot_get,
                          self.context,
                          snapshot_id)

    def test_create_delete_share_snapshot_error(self):
        """Test snapshot can be created and deleted with error."""

        def _fake_create_delete_snapshot(self, context, snapshot):
            raise exception.NotFound()

        self.stubs.Set(FakeShareDriver, "create_snapshot",
                       _fake_create_delete_snapshot)
        self.stubs.Set(FakeShareDriver, "delete_snapshot",
                       _fake_create_delete_snapshot)

        share = self._create_share()
        share_id = share['id']
        snapshot = self._create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.assertRaises(exception.NotFound, self.share.create_snapshot,
                          self.context, share_id, snapshot_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEquals(snap['status'], 'error')

        self.assertRaises(exception.NotFound, self.share.delete_snapshot,
                          self.context, snapshot_id)

        self.assertEquals('error_deleting', db.share_snapshot_get(
            self.context, snapshot_id).status)

    def test_delete_share_if_busy(self):
        """Test snapshot could not be deleted if busy."""

        def _fake_delete_snapshot(self, context, snapshot):
            raise exception.SnapshotIsBusy(snapshot_name='fakename')

        self.stubs.Set(FakeShareDriver, "delete_snapshot",
                       _fake_delete_snapshot)

        snapshot = self._create_snapshot(share_id='fake_id')
        snapshot_id = snapshot['id']

        self.share.delete_snapshot(self.context, snapshot_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEquals(snap['status'], 'available')

    def test_create_delete_share(self):
        """Test share can be created and deleted."""
        share = self._create_share()
        share_id = share['id']
        self._create_access(share_id=share_id)

        self.share.create_share(self.context, share_id)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEquals(shr['status'], 'available')

        self.share.delete_share(self.context, share_id)
        shr = db.share_get(context.get_admin_context(read_deleted='yes'),
                           share_id)

        self.assertEquals(shr['status'], 'deleted')
        self.assertRaises(exception.NotFound,
                          db.share_get,
                          self.context,
                          share_id)

    def test_create_delete_share_error(self):
        """Test share can be created and deleted with error."""

        def _fake_create_export(self, context, share):
            raise exception.NotFound()

        def _fake_deallocate_container(self, context, share):
            raise exception.NotFound()

        self.stubs.Set(FakeShareDriver, "create_export", _fake_create_export)
        self.stubs.Set(FakeShareDriver, "deallocate_container",
                       _fake_deallocate_container)

        share = self._create_share()
        share_id = share['id']
        self.assertRaises(exception.NotFound,
                          self.share.create_share,
                          self.context,
                          share_id)

        shr = db.share_get(self.context, share_id)
        self.assertEquals(shr['status'], 'error')
        self.assertRaises(exception.NotFound,
                          self.share.delete_share,
                          self.context,
                          share_id)

        shr = db.share_get(self.context, share_id)
        self.assertEquals(shr['status'], 'error_deleting')

    def test_allow_deny_access(self):
        """Test access rules to share can be created and deleted."""

        share = self._create_share()
        share_id = share['id']
        access = self._create_access(share_id=share_id)
        access_id = access['id']
        self.share.allow_access(self.context, access_id)
        self.assertEqual('active', db.share_access_get(self.context,
                                                       access_id).state)

        self.share.deny_access(self.context, access_id)
        acs = db.share_access_get(
            context.get_admin_context(read_deleted='yes'),
            access_id)
        self.assertEquals(acs['state'], 'deleted')
        self.assertRaises(exception.NotFound,
                          db.share_access_get,
                          self.context,
                          access_id)

    def test_allow_deny_access_error(self):
        """Test access rules to share can be created and deleted with error."""

        def _fake_allow_access(self, context, share, access):
            raise exception.NotFound()

        def _fake_deny_access(self, context, share, access):
            raise exception.NotFound()

        self.stubs.Set(FakeShareDriver, "allow_access", _fake_allow_access)
        self.stubs.Set(FakeShareDriver, "deny_access", _fake_deny_access)

        share = self._create_share()
        share_id = share['id']
        access = self._create_access(share_id=share_id)
        access_id = access['id']

        self.assertRaises(exception.NotFound,
                          self.share.allow_access,
                          self.context,
                          access_id)

        acs = db.share_access_get(self.context, access_id)
        self.assertEquals(acs['state'], 'error')

        self.assertRaises(exception.NotFound,
                          self.share.deny_access,
                          self.context,
                          access_id)

        acs = db.share_access_get(self.context, access_id)
        self.assertEquals(acs['state'], 'error')
