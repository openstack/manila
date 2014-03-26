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

    def create_snapshot(self, context, snapshot):
        pass

    def delete_snapshot(self, context, snapshot):
        pass

    def create_share(self, context, share):
        pass

    def create_share_from_snapshot(self, context, share, snapshot):
        pass

    def delete_share(self, context, share):
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
        self.share = importutils.import_object(CONF.share_manager)
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
        self.share.driver = driver
        self.share.init_host()
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
            raise exception.ShareSnapshotIsBusy(snapshot_name='fakename')

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
        self.assertRaises(exception.NotFound,
                          db.share_get,
                          self.context,
                          share_id)

    def test_create_delete_share_error(self):
        """Test share can be created and deleted with error."""

        def _fake_create_share(self, context, share):
            raise exception.NotFound()

        def _fake_delete_share(self, context, share):
            raise exception.NotFound()

        self.stubs.Set(FakeShareDriver, "create_share", _fake_create_share)
        self.stubs.Set(FakeShareDriver, "delete_share",
                       _fake_delete_share)

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

    def test_create_delete_share_with_metadata(self):
        """Test share can be created with metadata and deleted."""
        test_meta = {'fake_key': 'fake_value'}
        share = self._create_share()
        share_id = share['id']
        self.share.create_share(self.context, share_id)
        result_meta = {
            share.share_metadata[0].key: share.share_metadata[0].value}
        self.assertEqual(result_meta, test_meta)

        self.share.delete_share(self.context, share_id)
        self.assertRaises(exception.NotFound,
                          db.share_get,
                          self.context,
                          share_id)

    def test_create_share_with_invalid_metadata(self):
        """Test share create with too much metadata fails."""
        share_api = manila.share.api.API()
        test_meta = {'fake_key': 'fake_value' * 1025}
        self.assertRaises(exception.InvalidShareMetadataSize,
                          share_api.create,
                          self.context,
                          'nfs',
                          1,
                          'name',
                          'description',
                          metadata=test_meta)

    def test_setup_share_network(self):
        share_network = {'id': 'fake_sn_id', 'share_network': 'share_network'}
        allocation_number = 555
        self.share.driver.get_network_allocations_number = mock.Mock(
            return_value=allocation_number)
        self.share.network_api.allocate_network = mock.Mock(
            return_value=share_network)
        self.share.driver.setup_network = mock.Mock()
        self.share._activate_share_network(context=self.context,
                                           share_network=share_network)
        self.share.network_api.allocate_network.assert_called_once_with(
            self.context, share_network, count=allocation_number)
        self.share.driver.setup_network.assert_called_once_with(
            share_network, metadata=None)

    def test_setup_share_network_error(self):
        network_info = {'fake': 'fake', 'id': 'fakeid'}
        drv_allocation_cnt = mock.patch.object(
                                self.share.driver,
                                'get_network_allocations_number').start()
        drv_allocation_cnt.return_value = 555
        nw_api_allocate_nw = mock.patch.object(self.share.network_api,
                                               'allocate_network').start()
        nw_api_allocate_nw.return_value = network_info
        nw_api_deallocate_nw = mock.patch.object(self.share.network_api,
                                                 'deallocate_network').start()

        with mock.patch.object(self.share.driver, 'setup_network',
                               mock.Mock(side_effect=exception.Invalid)):
            self.assertRaises(exception.Invalid,
                              self.share._activate_share_network,
                              self.context, network_info)
            nw_api_deallocate_nw.assert_called_once_with(self.context,
                                                         network_info)

        drv_allocation_cnt.stop()
        nw_api_allocate_nw.stop()
        nw_api_deallocate_nw.stop()

    def test_activate_network(self):
        share_network = {'id': 'fake network id'}
        db_share_nw_get = mock.patch.object(self.share.db,
                                            'share_network_get').start()
        db_share_nw_get.return_value = share_network
        drv_get_alloc_cnt = mock.patch.object(
                                self.share.driver,
                                'get_network_allocations_number').start()
        drv_get_alloc_cnt.return_value = 1
        nw_api_allocate_nw = mock.patch.object(self.share.network_api,
                                               'allocate_network').start()
        nw_api_allocate_nw.return_value = share_network

        with mock.patch.object(self.share.driver, 'setup_network',
                               mock.Mock()):
            self.share.activate_network(self.context, share_network['id'])
            db_share_nw_get.assert_called_once_with(self.context,
                                                    share_network['id'])
            drv_get_alloc_cnt.assert_any_call()
            nw_api_allocate_nw.assert_called_once_with(self.context,
                                                       share_network,
                                                       count=1)
            self.share.driver.setup_network.assert_called_once_with(
                share_network,
                metadata=None)

        db_share_nw_get.stop()
        drv_get_alloc_cnt.stop()
        nw_api_allocate_nw.stop()

    def test_deactivate_network(self):
        share_network = {'id': 'fake network id'}
        db_share_nw_get = mock.patch.object(self.share.db,
                                            'share_network_get').start()
        db_share_nw_get.return_value = share_network
        nw_api_deallocate_nw = mock.patch.object(self.share.network_api,
                                                 'deallocate_network').start()

        with mock.patch.object(self.share.driver, 'teardown_network',
                               mock.Mock()):
            self.share.deactivate_network(self.context, share_network['id'])
            db_share_nw_get.assert_called_once_with(self.context,
                                                    share_network['id'])
            nw_api_deallocate_nw.assert_called_once_with(self.context,
                                                         share_network)
            self.share.driver.teardown_network.assert_called_once_with(
                share_network)

        db_share_nw_get.stop()
        nw_api_deallocate_nw.stop()
