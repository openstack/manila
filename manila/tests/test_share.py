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
import mock

from manila import context
from manila import db
from manila import exception

from manila.openstack.common import importutils
import manila.policy
from manila.share import manager
from manila import test
from oslo.config import cfg

CONF = cfg.CONF


class FakeShareDriver(object):
    def __init__(self, db, **kwargs):
        self.db = db

        def share_network_update(*args, **kwargs):
            pass

        self.db.share_network_update = mock.Mock(
            side_effect=share_network_update)

    def create_snapshot(self, context, snapshot, share_server=None):
        pass

    def delete_snapshot(self, context, snapshot, share_server=None):
        pass

    def create_share(self, context, share, share_server=None):
        pass

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        pass

    def delete_share(self, context, share, share_server=None):
        pass

    def ensure_share(self, context, share, share_server=None):
        pass

    def allow_access(self, context, share, access, share_server=None):
        pass

    def deny_access(self, context, share, access, share_server=None):
        pass

    def check_for_setup_error(self):
        pass

    def get_share_stats(self, refresh=False):
        return None

    def do_setup(self, context):
        pass

    def setup_network(self, context, network, policy=None):
        pass

    def teardown_network(self, context, network):
        pass

    def get_network_allocations_number(self):
        pass


class ShareTestCase(test.TestCase):
    """Test Case for shares."""

    def setUp(self):
        super(ShareTestCase, self).setUp()
        self.flags(connection_type='fake',
                   share_driver='manila.tests.test_share.FakeShareDriver')
        self.share_manager = importutils.import_object(CONF.share_manager)
        self.context = context.get_admin_context()

    @staticmethod
    def _create_share(status="creating", size=0, snapshot_id=None,
                      share_network_id=None):
        """Create a share object."""
        share = {}
        share['share_proto'] = "NFS"
        share['size'] = size
        share['snapshot_id'] = snapshot_id
        share['share_network_id'] = share_network_id
        share['user_id'] = 'fake'
        share['project_id'] = 'fake'
        share['metadata'] = {'fake_key': 'fake_value'}
        share['availability_zone'] = CONF.storage_availability_zone
        share['status'] = status
        share['host'] = CONF.host
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

    @staticmethod
    def _create_share_server(state='new', share_network_id=None, host=None):
        """Create a share server object."""
        srv = {}
        srv['host'] = host
        srv['share_network_id'] = share_network_id
        srv['status'] = state
        share_srv = db.share_server_create(context.get_admin_context(), srv)
        backend_details = {'fake': 'fake'}
        db.share_server_backend_details_set(context.get_admin_context(),
                                            share_srv['id'],
                                            backend_details)
        return db.share_server_get(context.get_admin_context(),
                                   share_srv['id'])

    @staticmethod
    def _create_share_network(state='new'):
        """Create a share network object."""
        srv = {}
        srv['user_id'] = 'fake'
        srv['project_id'] = 'fake'
        srv['neutron_net_id'] = 'fake-neutron-net'
        srv['neutron_subnet_id'] = 'fake-neutron-subnet'
        srv['status'] = state
        return db.share_network_create(context.get_admin_context(), srv)

    def test_init_host_ensuring_shares(self):
        """Test init_host for ensuring shares and access rules."""

        share = self._create_share(status='available')
        share_id = share['id']

        another_share = self._create_share(status='error')

        access = self._create_access(share_id=share_id, state='active')

        context.get_admin_context = mock.Mock(return_value=self.context)
        db.share_get_all_by_host = mock.Mock(
            return_value=[share, another_share])
        driver = mock.Mock()
        driver.get_share_stats.return_value = {}
        self.share_manager.driver = driver
        self.share_manager.init_host()
        driver.ensure_share.assert_called_once_with(self.context, share)
        driver.allow_access.assert_called_once_with(
            self.context, share, mock.ANY)
        driver.get_share_stats.assert_called_once_with(refresh=True)

    def test_create_share_from_snapshot(self):
        """Test share can be created from snapshot."""
        share = self._create_share()
        share_id = share['id']
        snapshot = self._create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.share_manager.create_share(self.context, share_id,
                                snapshot_id=snapshot_id)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], 'available')

    def test_create_delete_share_snapshot(self):
        """Test share's snapshot can be created and deleted."""

        def _fake_create_snapshot(self, *args, **kwargs):
            snapshot['progress'] = '99%'
            return snapshot

        self.stubs.Set(FakeShareDriver, "create_snapshot",
                       _fake_create_snapshot)

        share = self._create_share()
        share_id = share['id']
        snapshot = self._create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.share_manager.create_snapshot(self.context, share_id, snapshot_id)
        self.assertEqual(share_id,
                         db.share_snapshot_get(context.get_admin_context(),
                         snapshot_id).share_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEqual(snap['status'], 'available')

        self.share_manager.delete_snapshot(self.context, snapshot_id)
        self.assertRaises(exception.NotFound,
                          db.share_snapshot_get,
                          self.context,
                          snapshot_id)

    def test_create_delete_share_snapshot_error(self):
        """Test snapshot can be created and deleted with error."""

        def _fake_create_delete_snapshot(self, *args, **kwargs):
            raise exception.NotFound()

        self.stubs.Set(FakeShareDriver, "create_snapshot",
                       _fake_create_delete_snapshot)
        self.stubs.Set(FakeShareDriver, "delete_snapshot",
                       _fake_create_delete_snapshot)

        share = self._create_share()
        share_id = share['id']
        snapshot = self._create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.assertRaises(exception.NotFound,
                          self.share_manager.create_snapshot,
                          self.context, share_id, snapshot_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEqual(snap['status'], 'error')

        self.assertRaises(exception.NotFound,
                          self.share_manager.delete_snapshot,
                          self.context, snapshot_id)

        self.assertEqual('error_deleting', db.share_snapshot_get(
            self.context, snapshot_id).status)

    def test_delete_share_if_busy(self):
        """Test snapshot could not be deleted if busy."""

        def _fake_delete_snapshot(self, *args, **kwargs):
            raise exception.ShareSnapshotIsBusy(snapshot_name='fakename')

        self.stubs.Set(FakeShareDriver, "delete_snapshot",
                       _fake_delete_snapshot)
        share = self._create_share(status='ACTIVE')
        snapshot = self._create_snapshot(share_id=share['id'])
        snapshot_id = snapshot['id']

        self.share_manager.delete_snapshot(self.context, snapshot_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEqual(snap['status'], 'available')

    def test_create_share_without_server(self):
        """Test share can be created without share server."""

        share_net = self._create_share_network()
        share = self._create_share(share_network_id=share_net['id'])

        share_id = share['id']

        def fake_setup_server(context, share_network, *args, **kwargs):
            return self._create_share_server(
                share_network_id=share_network['id'])

        self.share_manager.driver.create_share = mock.Mock(
            return_value='fake_location')
        self.share_manager._setup_server = fake_setup_server
        self.share_manager.create_share(self.context, share_id)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], 'available')
        self.assertTrue(shr['share_server_id'])

    def test_create_share_with_server(self):
        """Test share can be created with share server."""
        share_net = self._create_share_network()
        share = self._create_share(share_network_id=share_net['id'])
        share_srv = self._create_share_server(
            share_network_id=share_net['id'], host=self.share_manager.host,
            state='ACTIVE')

        share_id = share['id']

        self.share_manager.driver = mock.Mock()
        self.share_manager.driver.create_share.return_value = "fake_location"
        self.share_manager.create_share(self.context, share_id)
        self.assertFalse(self.share_manager.driver.setup_network.called)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEquals(shr['status'], 'available')
        self.assertEquals(shr['share_server_id'], share_srv['id'])

    def test_create_delete_share_error(self):
        """Test share can be created and deleted with error."""

        def _fake_create_share(self, *args, **kwargs):
            raise exception.NotFound()

        def _fake_delete_share(self, *args, **kwargs):
            raise exception.NotFound()

        self.stubs.Set(FakeShareDriver, "create_share", _fake_create_share)
        self.stubs.Set(FakeShareDriver, "delete_share",
                       _fake_delete_share)

        share = self._create_share()
        share_id = share['id']
        self.assertRaises(exception.NotFound,
                          self.share_manager.create_share,
                          self.context,
                          share_id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], 'error')
        self.assertRaises(exception.NotFound,
                          self.share_manager.delete_share,
                          self.context,
                          share_id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], 'error_deleting')

    def test_allow_deny_access(self):
        """Test access rules to share can be created and deleted."""
        share = self._create_share()
        share_id = share['id']
        access = self._create_access(share_id=share_id)
        access_id = access['id']
        self.share_manager.allow_access(self.context, access_id)
        self.assertEqual('active', db.share_access_get(self.context,
                                                       access_id).state)

        self.share_manager.deny_access(self.context, access_id)
        self.assertRaises(exception.NotFound,
                          db.share_access_get,
                          self.context,
                          access_id)

    def test_allow_deny_access_error(self):
        """Test access rules to share can be created and deleted with error."""

        def _fake_allow_access(self, *args, **kwargs):
            raise exception.NotFound()

        def _fake_deny_access(self, *args, **kwargs):
            raise exception.NotFound()

        self.stubs.Set(FakeShareDriver, "allow_access", _fake_allow_access)
        self.stubs.Set(FakeShareDriver, "deny_access", _fake_deny_access)

        share = self._create_share()
        share_id = share['id']
        access = self._create_access(share_id=share_id)
        access_id = access['id']

        self.assertRaises(exception.NotFound,
                          self.share_manager.allow_access,
                          self.context,
                          access_id)

        acs = db.share_access_get(self.context, access_id)
        self.assertEqual(acs['state'], 'error')

        self.assertRaises(exception.NotFound,
                          self.share_manager.deny_access,
                          self.context,
                          access_id)

        acs = db.share_access_get(self.context, access_id)
        self.assertEqual(acs['state'], 'error')
