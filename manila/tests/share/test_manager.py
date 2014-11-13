# Copyright 2014 Mirantis Inc.
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

"""Test of Share Manager for Manila."""

import mock
from oslo.utils import importutils

from manila.common import constants
from manila import context
from manila import db
from manila.db.sqlalchemy import models
from manila import exception
from manila.share import manager
from manila import test
from manila import utils


class FakeAccessRule(object):

    def __init__(self, **kwargs):
        self.STATE_ACTIVE = 'active'
        self.STATE_NEW = 'new'
        self.STATE_ERROR = 'error'
        self.access_type = 'fake_type'
        self.id = 'fake_id'
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getitem__(self, item):
        return getattr(self, item)


class ShareManagerTestCase(test.TestCase):

    def setUp(self):
        super(ShareManagerTestCase, self).setUp()
        self.flags(connection_type='fake',
                   share_driver='manila.tests.fake_driver.FakeShareDriver')
        # Define class directly, because this test suite dedicated
        # to specific manager.
        self.share_manager = importutils.import_object(
            "manila.share.manager.ShareManager")
        self.stubs.Set(self.share_manager.driver, 'do_setup', mock.Mock())
        self.stubs.Set(self.share_manager.driver, 'check_for_setup_error',
                       mock.Mock())
        self.context = context.get_admin_context()

    @staticmethod
    def _create_share(status="creating", size=0, snapshot_id=None,
                      share_network_id=None, share_server_id=None):
        """Create a share object."""
        share = {}
        share['share_proto'] = "NFS"
        share['size'] = size
        share['snapshot_id'] = snapshot_id
        share['share_network_id'] = share_network_id
        share['share_server_id'] = share_server_id
        share['user_id'] = 'fake'
        share['project_id'] = 'fake'
        share['metadata'] = {'fake_key': 'fake_value'}
        share['availability_zone'] = 'fake_availability_zone'
        share['status'] = status
        share['host'] = 'fake_host'
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
    def _create_share_server(state='ACTIVE', share_network_id=None, host=None):
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

    @staticmethod
    def _create_security_service(share_network_id=None):
        service = {}
        service['type'] = "FAKE"
        service['project_id'] = 'fake-project-id'
        service_ref = db.security_service_create(
            context.get_admin_context(), service)
        db.share_network_add_security_service(context.get_admin_context(),
                                              share_network_id,
                                              service_ref['id'])
        return service_ref

    def test_init_host_with_no_shares(self):
        self.stubs.Set(self.share_manager.db, 'share_get_all_by_host',
                       mock.Mock(return_value=[]))

        self.share_manager.init_host()

        self.share_manager.db.share_get_all_by_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), self.share_manager.host)
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.\
            assert_called_once_with()

    def test_init_host_with_shares_and_rules(self):

        # initialisation of test data
        def raise_share_access_exists(*args, **kwargs):
            raise exception.ShareAccessExists(
                access_type='fake_access_type', access='fake_access')

        shares = [
            {'id': 'fake_id_1', 'status': 'available', },
            {'id': 'fake_id_2', 'status': 'error', 'name': 'fake_name_2'},
            {'id': 'fake_id_3', 'status': 'in-use', 'name': 'fake_name_3'},
        ]
        rules = [
            FakeAccessRule(state='active'),
            FakeAccessRule(state='error'),
        ]
        share_server = 'fake_share_server_type_does_not_matter'
        self.stubs.Set(self.share_manager.db,
                       'share_get_all_by_host',
                       mock.Mock(return_value=shares))
        self.stubs.Set(self.share_manager.driver, 'ensure_share', mock.Mock())
        self.stubs.Set(self.share_manager, '_get_share_server',
                       mock.Mock(return_value=share_server))
        self.stubs.Set(self.share_manager, 'publish_service_capabilities',
                       mock.Mock())
        self.stubs.Set(self.share_manager.db, 'share_access_get_all_for_share',
                       mock.Mock(return_value=rules))
        self.stubs.Set(self.share_manager.driver, 'allow_access',
                       mock.Mock(side_effect=raise_share_access_exists))

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        self.share_manager.db.share_get_all_by_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), self.share_manager.host)
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.\
            assert_called_once_with()
        self.share_manager._get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), shares[0])
        self.share_manager.driver.ensure_share.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), shares[0],
            share_server=share_server)
        self.share_manager.db.share_access_get_all_for_share.\
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext), shares[0]['id'])
        self.share_manager.publish_service_capabilities.\
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.allow_access.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), shares[0], rules[0],
            share_server=share_server)

    def test_init_host_with_exception_on_ensure_share(self):
        def raise_exception(*args, **kwargs):
            raise exception.ManilaException(message="Fake raise")

        shares = [
            {'id': 'fake_id_1', 'status': 'available', 'name': 'fake_name_1'},
            {'id': 'fake_id_2', 'status': 'error', 'name': 'fake_name_2'},
            {'id': 'fake_id_3', 'status': 'available', 'name': 'fake_name_3'},
        ]
        share_server = 'fake_share_server_type_does_not_matter'
        self.stubs.Set(self.share_manager.db,
                       'share_get_all_by_host',
                       mock.Mock(return_value=shares))
        self.stubs.Set(self.share_manager.driver, 'ensure_share',
                       mock.Mock(side_effect=raise_exception))
        self.stubs.Set(self.share_manager, '_get_share_server',
                       mock.Mock(return_value=share_server))
        self.stubs.Set(self.share_manager, 'publish_service_capabilities',
                       mock.Mock())
        self.stubs.Set(manager.LOG, 'error', mock.Mock())
        self.stubs.Set(manager.LOG, 'info', mock.Mock())

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        self.share_manager.db.share_get_all_by_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), self.share_manager.host)
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.assert_called_with()
        self.share_manager._get_share_server.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), shares[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), shares[2]),
        ])
        self.share_manager.driver.ensure_share.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), shares[0],
                      share_server=share_server),
            mock.call(utils.IsAMatcher(context.RequestContext), shares[2],
                      share_server=share_server),
        ])
        self.share_manager.publish_service_capabilities.\
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))
        manager.LOG.info.assert_called_once_with(
            mock.ANY,
            {'name': shares[1]['name'], 'status': shares[1]['status']},
        )

    def test_init_host_with_exception_on_rule_access_allow(self):
        def raise_exception(*args, **kwargs):
            raise exception.ManilaException(message="Fake raise")

        shares = [
            {'id': 'fake_id_1', 'status': 'available', 'name': 'fake_name_1'},
            {'id': 'fake_id_2', 'status': 'error', 'name': 'fake_name_2'},
            {'id': 'fake_id_3', 'status': 'available', 'name': 'fake_name_3'},
        ]
        rules = [
            FakeAccessRule(state='active'),
            FakeAccessRule(state='error'),
        ]
        share_server = 'fake_share_server_type_does_not_matter'
        self.stubs.Set(self.share_manager.db,
                       'share_get_all_by_host',
                       mock.Mock(return_value=shares))
        self.stubs.Set(self.share_manager.driver, 'ensure_share', mock.Mock())
        self.stubs.Set(self.share_manager, '_get_share_server',
                       mock.Mock(return_value=share_server))
        self.stubs.Set(self.share_manager, 'publish_service_capabilities',
                       mock.Mock())
        self.stubs.Set(manager.LOG, 'error', mock.Mock())
        self.stubs.Set(manager.LOG, 'info', mock.Mock())
        self.stubs.Set(self.share_manager.db, 'share_access_get_all_for_share',
                       mock.Mock(return_value=rules))
        self.stubs.Set(self.share_manager.driver, 'allow_access',
                       mock.Mock(side_effect=raise_exception))

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        self.share_manager.db.share_get_all_by_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), self.share_manager.host)
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.assert_called_with()
        self.share_manager._get_share_server.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), shares[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), shares[2]),
        ])
        self.share_manager.driver.ensure_share.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), shares[0],
                      share_server=share_server),
            mock.call(utils.IsAMatcher(context.RequestContext), shares[2],
                      share_server=share_server),
        ])
        self.share_manager.publish_service_capabilities.\
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))
        manager.LOG.info.assert_called_once_with(
            mock.ANY,
            {'name': shares[1]['name'], 'status': shares[1]['status']},
        )
        self.share_manager.driver.allow_access.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), shares[0],
                      rules[0], share_server=share_server),
            mock.call(utils.IsAMatcher(context.RequestContext), shares[2],
                      rules[0], share_server=share_server),
        ])
        manager.LOG.error.assert_has_calls([
            mock.call(mock.ANY, mock.ANY),
            mock.call(mock.ANY, mock.ANY),
        ])

    def test_create_share_from_snapshot_with_server(self):
        """Test share can be created from snapshot if server exists."""
        network = self._create_share_network()
        server = self._create_share_server(share_network_id=network['id'],
                                           host='fake_host')
        parent_share = self._create_share(share_network_id='net-id',
                                          share_server_id=server['id'])
        share = self._create_share()
        share_id = share['id']
        snapshot = self._create_snapshot(share_id=parent_share['id'])
        snapshot_id = snapshot['id']

        self.share_manager.create_share(self.context, share_id,
                                        snapshot_id=snapshot_id)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], 'available')
        self.assertEqual(shr['share_server_id'], server['id'])

    def test_create_share_from_snapshot_with_server_not_found(self):
        """Test creation from snapshot fails if server not found."""
        parent_share = self._create_share(share_network_id='net-id',
                                          share_server_id='fake-id')
        share = self._create_share()
        share_id = share['id']
        snapshot = self._create_snapshot(share_id=parent_share['id'])
        snapshot_id = snapshot['id']

        self.assertRaises(exception.ShareServerNotFound,
                          self.share_manager.create_share,
                          self.context,
                          share_id,
                          snapshot_id=snapshot_id
                          )

        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], 'error')

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

        self.stubs.Set(self.share_manager.driver, "create_snapshot",
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

        def _raise_not_found(self, *args, **kwargs):
            raise exception.NotFound()

        self.stubs.Set(self.share_manager.driver, "create_snapshot",
                       mock.Mock(side_effect=_raise_not_found))
        self.stubs.Set(self.share_manager.driver, "delete_snapshot",
                       mock.Mock(side_effect=_raise_not_found))

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
        self.share_manager.driver.create_snapshot.assert_called_once_with(
            self.context, utils.IsAMatcher(models.ShareSnapshot),
            share_server=None)
        self.share_manager.driver.delete_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            utils.IsAMatcher(models.ShareSnapshot),
            share_server=None)

    def test_delete_share_if_busy(self):
        """Test snapshot could not be deleted if busy."""

        def _raise_share_snapshot_is_busy(self, *args, **kwargs):
            raise exception.ShareSnapshotIsBusy(snapshot_name='fakename')

        self.stubs.Set(self.share_manager.driver, "delete_snapshot",
                       mock.Mock(side_effect=_raise_share_snapshot_is_busy))
        share = self._create_share(status='ACTIVE')
        snapshot = self._create_snapshot(share_id=share['id'])
        snapshot_id = snapshot['id']

        self.share_manager.delete_snapshot(self.context, snapshot_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEqual(snap['status'], 'available')
        self.share_manager.driver.delete_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            utils.IsAMatcher(models.ShareSnapshot),
            share_server=None)

    def test_create_share_with_share_network_server_not_exists(self):
        """Test share can be created without share server."""

        share_net = self._create_share_network()
        share = self._create_share(share_network_id=share_net['id'])

        share_id = share['id']

        def fake_setup_server(context, share_network, *args, **kwargs):
            return self._create_share_server(
                share_network_id=share_network['id'],
                host='fake_host')

        self.share_manager.driver.create_share = mock.Mock(
            return_value='fake_location')
        self.share_manager._setup_server = fake_setup_server
        self.share_manager.create_share(self.context, share_id)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

    def test_create_share_with_share_network_server_creation_failed(self):
        fake_share = {'id': 'fake_share_id', 'share_network_id': 'fake_sn_id'}
        fake_server = {'id': 'fake_srv_id'}
        self.stubs.Set(db, 'share_server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(db, 'share_update',
                       mock.Mock(return_value=fake_share))
        self.stubs.Set(db, 'share_get',
                       mock.Mock(return_value=fake_share))

        def raise_share_server_not_found(*args, **kwargs):
            raise exception.ShareServerNotFound(
                share_server_id=fake_server['id'])

        def raise_manila_exception(*args, **kwargs):
            raise exception.ManilaException()

        self.stubs.Set(db, 'share_server_get_by_host_and_share_net_valid',
                       mock.Mock(side_effect=raise_share_server_not_found))
        self.stubs.Set(self.share_manager, '_setup_server',
                       mock.Mock(side_effect=raise_manila_exception))

        self.assertRaises(
            exception.ManilaException,
            self.share_manager.create_share,
            self.context,
            fake_share['id'],
        )
        db.share_server_get_by_host_and_share_net_valid.\
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.share_manager.host,
                fake_share['share_network_id'],
            )
        db.share_server_create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), mock.ANY)
        db.share_update.assert_has_calls([
            mock.call(
                utils.IsAMatcher(context.RequestContext),
                fake_share['id'],
                {'share_server_id': fake_server['id']},
            ),
            mock.call(
                utils.IsAMatcher(context.RequestContext),
                fake_share['id'],
                {'status': 'error'},
            )
        ])
        self.share_manager._setup_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_server)

    def test_create_share_with_share_network_not_found(self):
        """Test creation fails if share network not found."""

        share = self._create_share(share_network_id='fake-net-id')
        share_id = share['id']
        self.assertRaises(
            exception.ShareNetworkNotFound,
            self.share_manager.create_share,
            self.context,
            share_id
        )
        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], 'error')

    def test_create_share_with_share_network_server_exists(self):
        """Test share can be created with existing share server."""
        share_net = self._create_share_network()
        share = self._create_share(share_network_id=share_net['id'])
        share_srv = self._create_share_server(
            share_network_id=share_net['id'], host=self.share_manager.host)

        share_id = share['id']

        self.share_manager.driver = mock.Mock()
        self.share_manager.driver.create_share.return_value = "fake_location"
        self.share_manager.create_share(self.context, share_id)
        self.assertFalse(self.share_manager.driver.setup_network.called)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], 'available')
        self.assertEqual(shr['share_server_id'], share_srv['id'])

    def test_create_share_with_error_in_driver(self):
        """Test db updates if share creation fails in driver."""
        share = self._create_share()
        share_id = share['id']
        some_data = 'fake_location'
        self.share_manager.driver = mock.Mock()
        e = exception.ManilaException(
            detail_data={'export_location': some_data})
        self.share_manager.driver.create_share.side_effect = e
        self.assertRaises(
            exception.ManilaException,
            self.share_manager.create_share,
            self.context,
            share_id
        )
        self.assertTrue(self.share_manager.driver.create_share.called)
        shr = db.share_get(self.context, share_id)
        self.assertEqual(some_data, shr['export_location'])

    def test_create_share_with_server_created(self):
        """Test share can be created and share server is created."""
        share_net = self._create_share_network()
        share = self._create_share(share_network_id=share_net['id'])
        self._create_share_server(
            share_network_id=share_net['id'], host=self.share_manager.host,
            state='ERROR')
        share_id = share['id']
        fake_server = {'id': 'fake_srv_id'}
        self.stubs.Set(db, 'share_server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self.share_manager, '_setup_server',
                       mock.Mock(return_value=fake_server))

        self.share_manager.create_share(self.context, share_id)

        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)
        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], 'available')
        self.assertEqual(shr['share_server_id'], 'fake_srv_id')
        db.share_server_create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), mock.ANY)
        self.share_manager._setup_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_server)

    def test_create_delete_share_error(self):
        """Test share can be created and deleted with error."""

        def _raise_not_found(self, *args, **kwargs):
            raise exception.NotFound()

        self.stubs.Set(self.share_manager.driver, "create_share",
                       mock.Mock(side_effect=_raise_not_found))
        self.stubs.Set(self.share_manager.driver, "delete_share",
                       mock.Mock(side_effect=_raise_not_found))

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
        self.share_manager.driver.create_share.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            utils.IsAMatcher(models.Share),
            share_server=None)
        self.share_manager.driver.delete_share.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            utils.IsAMatcher(models.Share),
            share_server=None)

    def test_delete_share_share_server_not_found(self):
        share_net = self._create_share_network()
        share = self._create_share(share_network_id=share_net['id'],
                                   share_server_id='fake-id')

        share_id = share['id']
        self.assertRaises(
            exception.ShareServerNotFound,
            self.share_manager.delete_share,
            self.context,
            share_id
        )

    def test_delete_share_last_on_server_with_sec_services(self):
        share_net = self._create_share_network()
        sec_service = self._create_security_service(share_net['id'])
        share_srv = self._create_share_server(
            share_network_id=share_net['id'],
            host=self.share_manager.host
        )
        share = self._create_share(share_network_id=share_net['id'],
                                   share_server_id=share_srv['id'])

        share_id = share['id']

        self.share_manager.driver = mock.Mock()
        manager.CONF.delete_share_server_with_last_share = True
        self.share_manager.delete_share(self.context, share_id)
        self.assertTrue(self.share_manager.driver.teardown_server.called)
        call_args = self.share_manager.driver.teardown_server.call_args[0]
        call_kwargs = self.share_manager.driver.teardown_server.call_args[1]
        self.assertEqual(
            call_args[0],
            share_srv.get('backend_details'))

        self.assertEqual(
            len(call_kwargs['security_services']), 1)
        self.assertTrue(
            call_kwargs['security_services'][0]['id'],
            sec_service['id'])

    def test_delete_share_last_on_server(self):
        share_net = self._create_share_network()
        share_srv = self._create_share_server(
            share_network_id=share_net['id'],
            host=self.share_manager.host
        )
        share = self._create_share(share_network_id=share_net['id'],
                                   share_server_id=share_srv['id'])

        share_id = share['id']

        self.share_manager.driver = mock.Mock()
        manager.CONF.delete_share_server_with_last_share = True
        self.share_manager.delete_share(self.context, share_id)
        self.share_manager.driver.teardown_server.assert_called_once_with(
            share_srv.get('backend_details'), security_services=[]
        )

    def test_delete_share_last_on_server_deletion_disabled(self):
        share_net = self._create_share_network()
        share_srv = self._create_share_server(
            share_network_id=share_net['id'],
            host=self.share_manager.host
        )
        share = self._create_share(share_network_id=share_net['id'],
                                   share_server_id=share_srv['id'])

        share_id = share['id']
        manager.CONF.delete_share_server_with_last_share = False
        self.share_manager.driver = mock.Mock()
        self.share_manager.delete_share(self.context, share_id)
        self.assertFalse(self.share_manager.driver.teardown_network.called)

    def test_delete_share_not_last_on_server(self):
        share_net = self._create_share_network()
        share_srv = self._create_share_server(
            share_network_id=share_net['id'],
            host=self.share_manager.host
        )
        share = self._create_share(share_network_id=share_net['id'],
                                   share_server_id=share_srv['id'])
        self._create_share(share_network_id=share_net['id'],
                           share_server_id=share_srv['id'])
        share_id = share['id']

        manager.CONF.delete_share_server_with_last_share = True
        self.share_manager.driver = mock.Mock()
        self.share_manager.delete_share(self.context, share_id)
        self.assertFalse(self.share_manager.driver.teardown_network.called)

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

        self.stubs.Set(self.share_manager.driver, "allow_access",
                       _fake_allow_access)
        self.stubs.Set(self.share_manager.driver, "deny_access",
                       _fake_deny_access)

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

    def test_setup_server_2_net_allocations(self):
        # Setup required test data
        allocation_number = 2
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = {'id': 'fake_sn_id'}
        network_info = {'fake_network_info_key': 'fake_network_info_value'}
        server_info = {'fake_server_info_key': 'fake_server_info_value'}

        # mock required stuff
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(return_value=allocation_number))
        self.stubs.Set(self.share_manager.network_api, 'allocate_network',
                       mock.Mock())
        self.stubs.Set(self.share_manager, '_form_server_setup_info',
                       mock.Mock(return_value=network_info))
        self.stubs.Set(self.share_manager.driver, 'setup_server',
                       mock.Mock(return_value=server_info))
        self.stubs.Set(self.share_manager.db,
                       'share_server_backend_details_set',
                       mock.Mock())
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock(return_value=share_server))

        # execute method _setup_server
        result = self.share_manager._setup_server(
            context, share_server, metadata=metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_has_calls([
            mock.call(context, share_server['share_network_id']),
            mock.call(context, share_server['share_network_id']),
        ])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager.network_api.allocate_network.\
            assert_called_once_with(context, share_server, share_network,
                                    count=allocation_number)
        self.share_manager._form_server_setup_info.assert_called_once_with(
            context, share_server, share_network)
        self.share_manager.driver.setup_server.assert_called_once_with(
            network_info, metadata=metadata)
        self.share_manager.db.share_server_backend_details_set.\
            assert_called_once_with(context, share_server['id'], server_info)
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ACTIVE})

    def test_setup_server_no_net_allocations(self):
        # Setup required test data
        allocation_number = 0
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = {'id': 'fake_sn_id'}
        network_info = {'fake_network_info_key': 'fake_network_info_value'}
        server_info = {'fake_server_info_key': 'fake_server_info_value'}

        # mock required stuff
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(return_value=allocation_number))
        self.stubs.Set(self.share_manager, '_form_server_setup_info',
                       mock.Mock(return_value=network_info))
        self.stubs.Set(self.share_manager.driver, 'setup_server',
                       mock.Mock(return_value=server_info))
        self.stubs.Set(self.share_manager.db,
                       'share_server_backend_details_set',
                       mock.Mock())
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock(return_value=share_server))

        # execute method _setup_server
        result = self.share_manager._setup_server(
            context, share_server, metadata=metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_called_once_with(
            context, share_server['share_network_id'])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager._form_server_setup_info.assert_called_once_with(
            context, share_server, share_network)
        self.share_manager.driver.setup_server.assert_called_once_with(
            network_info, metadata=metadata)
        self.share_manager.db.share_server_backend_details_set.\
            assert_called_once_with(context, share_server['id'], server_info)
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ACTIVE})

    def test_setup_server_server_info_not_present_no_net_allocations(self):
        # Setup required test data
        allocation_number = 0
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = {'id': 'fake_sn_id'}
        network_info = {'fake_network_info_key': 'fake_network_info_value'}
        server_info = {}

        # mock required stuff
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(return_value=allocation_number))
        self.stubs.Set(self.share_manager, '_form_server_setup_info',
                       mock.Mock(return_value=network_info))
        self.stubs.Set(self.share_manager.driver, 'setup_server',
                       mock.Mock(return_value=server_info))
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock(return_value=share_server))

        # execute method _setup_server
        result = self.share_manager._setup_server(
            context, share_server, metadata=metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_called_once_with(
            context, share_server['share_network_id'])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager._form_server_setup_info.assert_called_once_with(
            context, share_server, share_network)
        self.share_manager.driver.setup_server.assert_called_once_with(
            network_info, metadata=metadata)
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ACTIVE})

    def test_setup_server_exception_raised(self):
        # Setup required test data
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        share_network = {'id': 'fake_sn_id'}

        # mock required stuff
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(side_effect=exception.ManilaException()))
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock())
        self.stubs.Set(self.share_manager.network_api, 'deallocate_network',
                       mock.Mock())

        # execute method _setup_server
        self.assertRaises(
            exception.ManilaException,
            self.share_manager._setup_server,
            context,
            share_server,
        )
        self.share_manager.db.share_network_get.assert_called_once_with(
            context, share_server['share_network_id'])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ERROR})
        self.share_manager.network_api.deallocate_network.\
            assert_called_once_with(context, share_network)

    def test_setup_server_exception_in_driver(self):
        # Setup required test data
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        share_network = {'id': 'fake_sn_id'}
        server_info = {'details_key': 'value'}
        network_info = {'fake_network_info_key': 'fake_network_info_value'}
        allocation_number = 0

        # Mock required parameters
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(return_value=allocation_number))
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock())
        self.stubs.Set(self.share_manager.network_api, 'deallocate_network',
                       mock.Mock())
        self.stubs.Set(self.share_manager, '_form_server_setup_info',
                       mock.Mock(return_value=network_info))
        self.stubs.Set(self.share_manager.db,
                       'share_server_backend_details_set',
                       mock.Mock())
        self.stubs.Set(self.share_manager.driver, 'setup_server',
                       mock.Mock(side_effect=exception.ManilaException(
                           detail_data={'server_details': server_info})))

        # execute method _setup_server
        self.assertRaises(
            exception.ManilaException,
            self.share_manager._setup_server,
            context,
            share_server,
        )
        self.share_manager.db.share_network_get.assert_called_once_with(
            context, share_server['share_network_id'])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager._form_server_setup_info.assert_called_once_with(
            context, share_server, share_network)
        self.share_manager.db.share_server_backend_details_set.\
            assert_called_once_with(context, share_server['id'], server_info)
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ERROR})
        self.share_manager.network_api.deallocate_network.\
            assert_called_once_with(context, share_network)

    def test_setup_server_incorrect_detail_data(self):
        # Setup required test data
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        share_network = {'id': 'fake_sn_id'}
        network_info = {'fake_network_info_key': 'fake_network_info_value'}
        allocation_number = 0

        # Mock required parameters
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(return_value=allocation_number))
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock())
        self.stubs.Set(self.share_manager.network_api, 'deallocate_network',
                       mock.Mock())
        self.stubs.Set(self.share_manager, '_form_server_setup_info',
                       mock.Mock(return_value=network_info))
        self.stubs.Set(self.share_manager.db,
                       'share_server_backend_details_set',
                       mock.Mock())
        self.stubs.Set(self.share_manager.driver, 'setup_server',
                       mock.Mock(side_effect=exception.ManilaException(
                           detail_data='not dictionary detail data')))

        # execute method _setup_server
        self.assertRaises(
            exception.ManilaException,
            self.share_manager._setup_server,
            context,
            share_server,
        )
        self.share_manager.db.share_network_get.assert_called_once_with(
            context, share_server['share_network_id'])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager._form_server_setup_info.assert_called_once_with(
            context, share_server, share_network)
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ERROR})
        self.share_manager.network_api.deallocate_network.\
            assert_called_once_with(context, share_network)
