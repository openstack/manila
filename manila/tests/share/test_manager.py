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

import ddt
import mock
from oslo_serialization import jsonutils
from oslo_utils import importutils

from manila.common import constants
from manila import context
from manila import db
from manila.db.sqlalchemy import models
from manila import exception
from manila import quota
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


@ddt.ddt
class ShareManagerTestCase(test.TestCase):

    def setUp(self):
        super(ShareManagerTestCase, self).setUp()
        self.flags(share_driver='manila.tests.fake_driver.FakeShareDriver')
        # Define class directly, because this test suite dedicated
        # to specific manager.
        self.share_manager = importutils.import_object(
            "manila.share.manager.ShareManager")
        self.mock_object(self.share_manager.driver, 'do_setup')
        self.mock_object(self.share_manager.driver, 'check_for_setup_error')
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
    def _create_share_server(state='ACTIVE', share_network_id=None, host=None,
                             backend_details=None):
        """Create a share server object."""
        srv = {}
        srv['host'] = host
        srv['share_network_id'] = share_network_id
        srv['status'] = state
        share_srv = db.share_server_create(context.get_admin_context(), srv)
        if backend_details:
            db.share_server_backend_details_set(
                context.get_admin_context(), share_srv['id'], backend_details)
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
        self.mock_object(self.share_manager.db, 'share_get_all_by_host',
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
        self.mock_object(self.share_manager.db,
                         'share_get_all_by_host',
                         mock.Mock(return_value=shares))
        self.mock_object(self.share_manager.driver, 'ensure_share')
        self.mock_object(self.share_manager, '_ensure_share_has_pool')
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager, 'publish_service_capabilities',
                         mock.Mock())
        self.mock_object(self.share_manager.db,
                         'share_access_get_all_for_share',
                         mock.Mock(return_value=rules))
        self.mock_object(self.share_manager.driver, 'allow_access',
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
        self.share_manager._ensure_share_has_pool.\
            assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    shares[0])
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
        self.mock_object(self.share_manager.db,
                         'share_get_all_by_host',
                         mock.Mock(return_value=shares))
        self.mock_object(self.share_manager.driver, 'ensure_share',
                         mock.Mock(side_effect=raise_exception))
        self.mock_object(self.share_manager, '_ensure_share_has_pool')
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager, 'publish_service_capabilities')
        self.mock_object(manager.LOG, 'error')
        self.mock_object(manager.LOG, 'info')

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        self.share_manager.db.share_get_all_by_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), self.share_manager.host)
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.assert_called_with()
        self.share_manager._ensure_share_has_pool.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), shares[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), shares[2]),
        ])
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
        self.mock_object(self.share_manager.db,
                         'share_get_all_by_host',
                         mock.Mock(return_value=shares))
        self.mock_object(self.share_manager.driver, 'ensure_share')
        self.mock_object(self.share_manager, '_ensure_share_has_pool')
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager, 'publish_service_capabilities')
        self.mock_object(manager.LOG, 'error')
        self.mock_object(manager.LOG, 'info')
        self.mock_object(self.share_manager.db,
                         'share_access_get_all_for_share',
                         mock.Mock(return_value=rules))
        self.mock_object(self.share_manager.driver, 'allow_access',
                         mock.Mock(side_effect=raise_exception))

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        self.share_manager.db.share_get_all_by_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), self.share_manager.host)
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.assert_called_with()
        self.share_manager._ensure_share_has_pool.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), shares[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), shares[2]),
        ])
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
        server = self._create_share_server(
            share_network_id=network['id'], host='fake_host',
            backend_details=dict(fake='fake'))
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
        self.assertTrue(len(shr['export_location']) > 0)
        self.assertEqual(2, len(shr['export_locations']))

    def test_create_delete_share_snapshot(self):
        """Test share's snapshot can be created and deleted."""

        def _fake_create_snapshot(self, *args, **kwargs):
            snapshot['progress'] = '99%'
            return snapshot

        self.mock_object(self.share_manager.driver, "create_snapshot",
                         _fake_create_snapshot)

        share = self._create_share()
        share_id = share['id']
        snapshot = self._create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.share_manager.create_snapshot(self.context, share_id,
                                           snapshot_id)
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

        self.mock_object(self.share_manager.driver, "create_snapshot",
                         mock.Mock(side_effect=_raise_not_found))
        self.mock_object(self.share_manager.driver, "delete_snapshot",
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

        self.mock_object(self.share_manager.driver, "delete_snapshot",
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

    def test_create_share_with_share_network_driver_not_handles_servers(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=False))
        share_id = 'fake_share_id'
        share_network_id = 'fake_sn'
        self.mock_object(
            self.share_manager.db, 'share_get',
            mock.Mock(return_value=self._create_share(
                share_network_id=share_network_id)))
        self.mock_object(self.share_manager.db, 'share_update')

        self.assertRaises(
            exception.ManilaException,
            self.share_manager.create_share, self.context, share_id)

        self.share_manager.db.share_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id)
        self.share_manager.db.share_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id,
            {'status': 'error'})

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
        self.mock_object(db, 'share_server_create',
                         mock.Mock(return_value=fake_server))
        self.mock_object(db, 'share_update',
                         mock.Mock(return_value=fake_share))
        self.mock_object(db, 'share_get',
                         mock.Mock(return_value=fake_share))

        def raise_share_server_not_found(*args, **kwargs):
            raise exception.ShareServerNotFound(
                share_server_id=fake_server['id'])

        def raise_manila_exception(*args, **kwargs):
            raise exception.ManilaException()

        self.mock_object(db, 'share_server_get_by_host_and_share_net_valid',
                         mock.Mock(side_effect=raise_share_server_not_found))
        self.mock_object(self.share_manager, '_setup_server',
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
        self.assertTrue(len(shr['export_location']) > 0)
        self.assertEqual(1, len(shr['export_locations']))

    @ddt.data('export_location', 'export_locations')
    def test_create_share_with_error_in_driver(self, details_key):
        """Test db updates if share creation fails in driver."""
        share = self._create_share()
        share_id = share['id']
        some_data = 'fake_location'
        self.share_manager.driver = mock.Mock()
        e = exception.ManilaException(detail_data={details_key: some_data})
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
        self.mock_object(db, 'share_server_create',
                         mock.Mock(return_value=fake_server))
        self.mock_object(self.share_manager, '_setup_server',
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

        self.mock_object(self.share_manager.driver, "create_share",
                         mock.Mock(side_effect=_raise_not_found))
        self.mock_object(self.share_manager.driver, "delete_share",
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

    def test_manage_share_invalid_driver(self):
        self.mock_object(self.share_manager, 'driver', mock.Mock())
        self.share_manager.driver.driver_handles_share_servers = True
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        share = self._create_share()
        share_id = share['id']

        self.share_manager.manage_share(self.context, share_id, {})

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, {'status': constants.STATUS_MANAGE_ERROR}
        )

    def test_manage_share_driver_exception(self):
        self.mock_object(self.share_manager, 'driver', mock.Mock())
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(self.share_manager.driver,
                         "manage_existing", mock.Mock(side_effect=Exception()))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        share = self._create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.share_manager.manage_share(self.context, share_id, driver_options)

        self.share_manager.driver.manage_existing.\
            assert_called_once_with(mock.ANY, driver_options)

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, {'status': constants.STATUS_MANAGE_ERROR}
        )

    def test_manage_share_invalid_size(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(self.share_manager.driver,
                         "manage_existing",
                         mock.Mock(return_value=None))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        share = self._create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.share_manager.manage_share(self.context, share_id, driver_options)

        self.share_manager.driver.manage_existing.\
            assert_called_once_with(mock.ANY, driver_options)

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, {'status': constants.STATUS_MANAGE_ERROR}
        )

    def test_manage_share_quota_error(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(self.share_manager.driver,
                         "manage_existing",
                         mock.Mock(return_value={'size': 1}))
        self.mock_object(self.share_manager, '_update_quota_usages',
                         mock.Mock(side_effect=exception.QuotaError))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        share = self._create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.share_manager.manage_share(self.context, share_id, driver_options)

        self.share_manager.driver.manage_existing.\
            assert_called_once_with(mock.ANY, driver_options)

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, {'status': constants.STATUS_MANAGE_ERROR}
        )

    @ddt.data({'size': 1},
              {'size': 1, 'name': 'fake'})
    def test_manage_share_valid_share(self, driver_data):
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        self.mock_object(self.share_manager, 'driver', mock.Mock())
        self.mock_object(self.share_manager, '_update_quota_usages',
                         mock.Mock())
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(self.share_manager.driver,
                         "manage_existing",
                         mock.Mock(return_value=driver_data))
        share = self._create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.share_manager.manage_share(self.context, share_id, driver_options)

        self.share_manager.driver.manage_existing.\
            assert_called_once_with(mock.ANY, driver_options)

        valid_share_data = {'status': 'available', 'launched_at': mock.ANY}
        valid_share_data.update(driver_data)
        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, valid_share_data
        )

    def test_update_quota_usages_new(self):
        self.mock_object(self.share_manager.db, 'quota_usage_get',
                         mock.Mock(return_value={'in_use': 1}))
        self.mock_object(self.share_manager.db, 'quota_usage_update')
        project_id = 'fake_project_id'
        resource_name = 'fake'
        usage = 1

        self.share_manager._update_quota_usages(
            self.context, project_id, {resource_name: usage})

        self.share_manager.db.quota_usage_get.assert_called_once_with(
            mock.ANY, project_id, resource_name, mock.ANY)
        self.share_manager.db.quota_usage_update.assert_called_once_with(
            mock.ANY, project_id, mock.ANY, resource_name, in_use=2)

    def test_update_quota_usages_update(self):
        project_id = 'fake_project_id'
        resource_name = 'fake'
        usage = 1
        side_effect = exception.QuotaUsageNotFound(project_id=project_id)
        self.mock_object(
            self.share_manager.db,
            'quota_usage_get',
            mock.Mock(side_effect=side_effect))
        self.mock_object(self.share_manager.db, 'quota_usage_create')

        self.share_manager._update_quota_usages(
            self.context, project_id, {resource_name: usage})

        self.share_manager.db.quota_usage_get.assert_called_once_with(
            mock.ANY, project_id, resource_name, mock.ANY)
        self.share_manager.db.quota_usage_create.assert_called_once_with(
            mock.ANY, project_id, mock.ANY, resource_name, usage)

    def _setup_unmanage_mocks(self, mock_driver=True, mock_unmanage=None):
        if mock_driver:
            self.mock_object(self.share_manager, 'driver')

        if mock_unmanage:
            self.mock_object(self.share_manager.driver, "unmanage",
                             mock_unmanage)

        self.mock_object(self.share_manager.db, 'share_update')

    @ddt.data(True, False)
    def test_unmanage_share_invalid_driver(self, driver_handles_share_servers):
        self._setup_unmanage_mocks()
        self.share_manager.driver.driver_handles_share_servers = (
            driver_handles_share_servers
        )
        share_net = self._create_share_network()
        share_srv = self._create_share_server(share_network_id=share_net['id'],
                                              host=self.share_manager.host)
        share = self._create_share(share_network_id=share_net['id'],
                                   share_server_id=share_srv['id'])

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share['id'], {'status': constants.STATUS_UNMANAGE_ERROR})

    def test_unmanage_share_invalid_share(self):
        unmanage = mock.Mock(side_effect=exception.InvalidShare(reason="fake"))
        self._setup_unmanage_mocks(mock_driver=False, mock_unmanage=unmanage)
        share = self._create_share()

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share['id'], {'status': constants.STATUS_UNMANAGE_ERROR})

    def test_unmanage_share_valid_share(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self._setup_unmanage_mocks(mock_driver=False,
                                   mock_unmanage=mock.Mock())
        share = self._create_share()
        share_id = share['id']

        self.share_manager.unmanage_share(self.context, share_id)

        self.share_manager.driver.unmanage.\
            assert_called_once_with(mock.ANY)
        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id,
            {'status': constants.STATUS_UNMANAGED, 'deleted': True})

    def test_unmanage_share_valid_share_with_quota_error(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self._setup_unmanage_mocks(mock_driver=False,
                                   mock_unmanage=mock.Mock())
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=Exception()))
        share = self._create_share()

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.driver.unmanage.\
            assert_called_once_with(mock.ANY)
        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share['id'],
            {'status': constants.STATUS_UNMANAGED, 'deleted': True})

    def test_unmanage_share_remove_access_rules_error(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        manager.CONF.unmanage_remove_access_rules = True
        self._setup_unmanage_mocks(mock_driver=False,
                                   mock_unmanage=mock.Mock())
        self.mock_object(self.share_manager, '_remove_share_access_rules',
                         mock.Mock(side_effect=Exception()))
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(return_value=[]))
        share = self._create_share()

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share['id'], {'status': constants.STATUS_UNMANAGE_ERROR})

    def test_unmanage_share_valid_share_remove_access_rules(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        manager.CONF.unmanage_remove_access_rules = True
        self._setup_unmanage_mocks(mock_driver=False,
                                   mock_unmanage=mock.Mock())
        self.mock_object(self.share_manager, '_remove_share_access_rules')
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(return_value=[]))
        share = self._create_share()
        share_id = share['id']

        self.share_manager.unmanage_share(self.context, share_id)

        self.share_manager.driver.unmanage.\
            assert_called_once_with(mock.ANY)
        self.share_manager._remove_share_access_rules.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY
        )
        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id,
            {'status': constants.STATUS_UNMANAGED, 'deleted': True})

    def test_remove_share_access_rules(self):
        self.mock_object(self.share_manager.db,
                         'share_access_get_all_for_share',
                         mock.Mock(return_value=['fake_ref', 'fake_ref2']))
        self.mock_object(self.share_manager, '_deny_access')
        share_ref = {'id': 'fake_id'}
        share_server = 'fake'

        self.share_manager._remove_share_access_rules(self.context,
                                                      share_ref, share_server)

        self.share_manager.db.share_access_get_all_for_share.\
            assert_called_once_with(mock.ANY, share_ref['id'])
        self.assertEqual(2, self.share_manager._deny_access.call_count)

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

    @ddt.data(True, False)
    def test_delete_share_last_on_server_with_sec_services(self, with_details):
        share_net = self._create_share_network()
        sec_service = self._create_security_service(share_net['id'])
        backend_details = dict(
            security_service_ldap=jsonutils.dumps(sec_service))
        if with_details:
            share_srv = self._create_share_server(
                share_network_id=share_net['id'],
                host=self.share_manager.host,
                backend_details=backend_details)
        else:
            share_srv = self._create_share_server(
                share_network_id=share_net['id'],
                host=self.share_manager.host)
            db.share_server_backend_details_set(
                context.get_admin_context(), share_srv['id'], backend_details)
        share = self._create_share(share_network_id=share_net['id'],
                                   share_server_id=share_srv['id'])
        share_id = share['id']
        self.share_manager.driver = mock.Mock()
        manager.CONF.delete_share_server_with_last_share = True

        self.share_manager.delete_share(self.context, share_id)

        self.share_manager.driver.teardown_server.assert_called_once_with(
            server_details=backend_details,
            security_services=[jsonutils.loads(
                backend_details['security_service_ldap'])])

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
            server_details=share_srv.get('backend_details'),
            security_services=[])

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

        self.mock_object(self.share_manager.driver, "allow_access",
                         _fake_allow_access)
        self.mock_object(self.share_manager.driver, "deny_access",
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

    def test_setup_server(self):
        # Setup required test data
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = {'id': 'fake_sn_id'}
        network_info = {'security_services': []}
        for ss_type in constants.SECURITY_SERVICES_ALLOWED_TYPES:
            network_info['security_services'].append({
                'name': 'fake_name' + ss_type,
                'domain': 'fake_domain' + ss_type,
                'server': 'fake_server' + ss_type,
                'dns_ip': 'fake_dns_ip' + ss_type,
                'user': 'fake_user' + ss_type,
                'type': ss_type,
                'password': 'fake_password' + ss_type,
            })
        sec_services = network_info['security_services']
        server_info = {'fake_server_info_key': 'fake_server_info_value'}

        # mock required stuff
        self.mock_object(self.share_manager.db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(self.share_manager.driver, 'allocate_network')
        self.mock_object(self.share_manager, '_form_server_setup_info',
                         mock.Mock(return_value=network_info))
        self.mock_object(self.share_manager.driver, 'setup_server',
                         mock.Mock(return_value=server_info))
        self.mock_object(self.share_manager.db,
                         'share_server_backend_details_set')
        self.mock_object(self.share_manager.db, 'share_server_update',
                         mock.Mock(return_value=share_server))

        # execute method _setup_server
        result = self.share_manager._setup_server(
            self.context, share_server, metadata=metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_has_calls([
            mock.call(self.context, share_server['share_network_id']),
            mock.call(self.context, share_server['share_network_id']),
        ])
        self.share_manager.driver.allocate_network.assert_called_once_with(
            self.context, share_server, share_network)
        self.share_manager._form_server_setup_info.assert_called_once_with(
            self.context, share_server, share_network)
        self.share_manager.driver.setup_server.assert_called_once_with(
            network_info, metadata=metadata)
        self.share_manager.db.share_server_backend_details_set.\
            assert_has_calls([
                mock.call(self.context, share_server['id'],
                          {'security_service_' + sec_services[0]['type']:
                              jsonutils.dumps(sec_services[0])}),
                mock.call(self.context, share_server['id'],
                          {'security_service_' + sec_services[1]['type']:
                              jsonutils.dumps(sec_services[1])}),
                mock.call(self.context, share_server['id'],
                          {'security_service_' + sec_services[2]['type']:
                              jsonutils.dumps(sec_services[2])}),
                mock.call(self.context, share_server['id'], server_info),
            ])
        self.share_manager.db.share_server_update.assert_called_once_with(
            self.context, share_server['id'],
            {'status': constants.STATUS_ACTIVE})

    def test_setup_server_server_info_not_present(self):
        # Setup required test data
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = {'id': 'fake_sn_id'}
        network_info = {
            'fake_network_info_key': 'fake_network_info_value',
            'security_services': [],
        }
        server_info = {}

        # mock required stuff
        self.mock_object(self.share_manager.db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(self.share_manager, '_form_server_setup_info',
                         mock.Mock(return_value=network_info))
        self.mock_object(self.share_manager.driver, 'setup_server',
                         mock.Mock(return_value=server_info))
        self.mock_object(self.share_manager.db, 'share_server_update',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager.driver, 'allocate_network')

        # execute method _setup_server
        result = self.share_manager._setup_server(
            self.context, share_server, metadata=metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_has_calls([
            mock.call(self.context, share_server['share_network_id']),
            mock.call(self.context, share_server['share_network_id'])])
        self.share_manager._form_server_setup_info.assert_called_once_with(
            self.context, share_server, share_network)
        self.share_manager.driver.setup_server.assert_called_once_with(
            network_info, metadata=metadata)
        self.share_manager.db.share_server_update.assert_called_once_with(
            self.context, share_server['id'],
            {'status': constants.STATUS_ACTIVE})
        self.share_manager.driver.allocate_network.assert_called_once_with(
            self.context, share_server, share_network)

    def setup_server_raise_exception(self, detail_data_proper):
        # Setup required test data
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        server_info = {'details_key': 'value'}
        share_network = {'id': 'fake_sn_id'}
        network_info = {
            'fake_network_info_key': 'fake_network_info_value',
            'security_services': [],
        }
        if detail_data_proper:
            detail_data = {'server_details': server_info}
            self.mock_object(self.share_manager.db,
                             'share_server_backend_details_set')
        else:
            detail_data = 'not dictionary detail data'

        # Mock required parameters
        self.mock_object(self.share_manager.db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(self.share_manager.db, 'share_server_update')
        for m in ['deallocate_network', 'allocate_network']:
            self.mock_object(self.share_manager.driver, m)
        self.mock_object(self.share_manager, '_form_server_setup_info',
                         mock.Mock(return_value=network_info))
        self.mock_object(self.share_manager.db,
                         'share_server_backend_details_set')
        self.mock_object(self.share_manager.driver, 'setup_server',
                         mock.Mock(side_effect=exception.ManilaException(
                             detail_data=detail_data)))

        # execute method _setup_server
        self.assertRaises(
            exception.ManilaException,
            self.share_manager._setup_server,
            self.context,
            share_server,
        )

        # verify results
        if detail_data_proper:
            self.share_manager.db.share_server_backend_details_set.\
                assert_called_once_with(
                    self.context, share_server['id'], server_info)
        self.share_manager._form_server_setup_info.assert_called_once_with(
            self.context, share_server, share_network)
        self.share_manager.db.share_server_update.assert_called_once_with(
            self.context, share_server['id'],
            {'status': constants.STATUS_ERROR})
        self.share_manager.db.share_network_get.assert_has_calls([
            mock.call(self.context, share_server['share_network_id']),
            mock.call(self.context, share_server['share_network_id'])])
        self.share_manager.driver.allocate_network.assert_has_calls([
            mock.call(self.context, share_server, share_network)])
        self.share_manager.driver.deallocate_network.assert_has_calls(
            mock.call(self.context, share_server['id']))

    def test_setup_server_incorrect_detail_data(self):
        self.setup_server_raise_exception(detail_data_proper=False)

    def test_setup_server_exception_in_driver(self):
        self.setup_server_raise_exception(detail_data_proper=True)

    def test_ensure_share_has_pool_with_only_host(self):
        fake_share = {'status': 'available', 'host': 'host1', 'id': 1}
        host = self.share_manager._ensure_share_has_pool(context.
                                                         get_admin_context(),
                                                         fake_share)
        self.assertIsNone(host)

    def test_ensure_share_has_pool_with_full_pool_name(self):
        fake_share = {'host': 'host1#pool0', 'id': 1,
                      'status': 'available'}
        fake_share_expected_value = 'pool0'
        host = self.share_manager._ensure_share_has_pool(context.
                                                         get_admin_context(),
                                                         fake_share)
        self.assertEqual(fake_share_expected_value, host)

    def test_ensure_share_has_pool_unable_to_fetch_share(self):
        fake_share = {'host': 'host@backend', 'id': 1,
                      'status': 'available'}
        with mock.patch.object(self.share_manager.driver, 'get_pool',
                               side_effect=Exception):
            with mock.patch.object(manager, 'LOG') as mock_LOG:
                self.share_manager._ensure_share_has_pool(context.
                                                          get_admin_context(),
                                                          fake_share)
                self.assertEqual(1, mock_LOG.error.call_count)

    def test__form_server_setup_info(self):
        fake_network_allocations = ['foo', 'bar']
        self.mock_object(
            self.share_manager.db, 'network_allocations_get_for_share_server',
            mock.Mock(return_value=fake_network_allocations))
        fake_share_server = dict(
            id='fake_share_server_id', backend_details=dict(foo='bar'))
        fake_share_network = dict(
            segmentation_id='fake_segmentation_id',
            cidr='fake_cidr',
            neutron_net_id='fake_neutron_net_id',
            neutron_subnet_id='fake_neutron_subnet_id',
            nova_net_id='fake_nova_net_id',
            security_services='fake_security_services')
        expected = dict(
            server_id=fake_share_server['id'],
            segmentation_id=fake_share_network['segmentation_id'],
            cidr=fake_share_network['cidr'],
            neutron_net_id=fake_share_network['neutron_net_id'],
            neutron_subnet_id=fake_share_network['neutron_subnet_id'],
            nova_net_id=fake_share_network['nova_net_id'],
            security_services=fake_share_network['security_services'],
            network_allocations=fake_network_allocations,
            backend_details=fake_share_server['backend_details'])

        network_info = self.share_manager._form_server_setup_info(
            self.context, fake_share_server, fake_share_network)

        self.assertEqual(expected, network_info)
        self.share_manager.db.network_allocations_get_for_share_server.\
            assert_called_once_with(self.context, fake_share_server['id'])
