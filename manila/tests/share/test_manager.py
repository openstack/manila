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
import datetime
import random

import ddt
import mock
from oslo_concurrency import lockutils
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import timeutils
import six

from manila.common import constants
from manila import context
from manila.data import rpcapi as data_rpc
from manila import db
from manila.db.sqlalchemy import models
from manila import exception
from manila import quota
from manila.share import access as share_access
from manila.share import drivers_private_data
from manila.share import manager
from manila.share import migration as migration_api
from manila.share import rpcapi
from manila.share import share_types
from manila import test
from manila.tests.api import fakes as test_fakes
from manila.tests import db_utils
from manila.tests import fake_share as fakes
from manila.tests import fake_utils
from manila.tests import utils as test_utils
from manila import utils


def fake_replica(**kwargs):
    return fakes.fake_replica(for_manager=True, **kwargs)


class LockedOperationsTestCase(test.TestCase):

    class FakeManager(object):

        @manager.locked_share_replica_operation
        def fake_replica_operation(self, context, replica, share_id=None):
            pass

    def setUp(self):
        super(self.__class__, self).setUp()
        self.manager = self.FakeManager()
        self.fake_context = test_fakes.FakeRequestContext
        self.lock_call = self.mock_object(
            utils, 'synchronized', mock.Mock(return_value=lambda f: f))

    @ddt.data({'id': 'FAKE_REPLICA_ID'}, 'FAKE_REPLICA_ID')
    @ddt.unpack
    def test_locked_share_replica_operation(self, **replica):

        self.manager.fake_replica_operation(self.fake_context, replica,
                                            share_id='FAKE_SHARE_ID')

        self.assertTrue(self.lock_call.called)


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
        self.share_manager.driver.initialized = True
        mock.patch.object(
            lockutils, 'lock', fake_utils.get_fake_lock_context())
        self.synchronized_lock_decorator_call = self.mock_object(
            utils, 'synchronized', mock.Mock(return_value=lambda f: f))

    def test_share_manager_instance(self):
        fake_service_name = "fake_service"
        import_mock = mock.Mock()
        self.mock_object(importutils, "import_object", import_mock)
        private_data_mock = mock.Mock()
        self.mock_object(drivers_private_data, "DriverPrivateData",
                         private_data_mock)
        self.mock_object(manager.ShareManager, '_init_hook_drivers')

        share_manager = manager.ShareManager(service_name=fake_service_name)

        private_data_mock.assert_called_once_with(
            context=mock.ANY,
            backend_host=share_manager.host,
            config_group=fake_service_name
        )
        self.assertTrue(import_mock.called)
        self.assertTrue(manager.ShareManager._init_hook_drivers.called)

    def test__init_hook_drivers(self):
        fake_service_name = "fake_service"
        import_mock = mock.Mock()
        self.mock_object(importutils, "import_object", import_mock)
        self.mock_object(drivers_private_data, "DriverPrivateData")
        share_manager = manager.ShareManager(service_name=fake_service_name)
        share_manager.configuration.safe_get = mock.Mock(
            return_value=["Foo", "Bar"])
        self.assertEqual(0, len(share_manager.hooks))
        import_mock.reset()

        share_manager._init_hook_drivers()

        self.assertEqual(
            len(share_manager.configuration.safe_get.return_value),
            len(share_manager.hooks))
        import_mock.assert_has_calls([
            mock.call(
                hook,
                configuration=share_manager.configuration,
                host=share_manager.host
            ) for hook in share_manager.configuration.safe_get.return_value
        ], any_order=True)

    def test__execute_periodic_hook(self):
        share_instances_mock = mock.Mock()
        hook_data_mock = mock.Mock()
        self.mock_object(
            self.share_manager.db,
            "share_instances_get_all_by_host",
            share_instances_mock)
        self.mock_object(
            self.share_manager.driver,
            "get_periodic_hook_data",
            hook_data_mock)
        self.share_manager.hooks = [mock.Mock(return_value=i) for i in (0, 1)]

        self.share_manager._execute_periodic_hook(self.context)

        share_instances_mock.assert_called_once_with(
            context=self.context, host=self.share_manager.host)
        hook_data_mock.assert_called_once_with(
            context=self.context,
            share_instances=share_instances_mock.return_value)
        for mock_hook in self.share_manager.hooks:
            mock_hook.execute_periodic_hook.assert_called_once_with(
                context=self.context,
                periodic_hook_data=hook_data_mock.return_value)

    def test_init_host_with_no_shares(self):
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_host',
                         mock.Mock(return_value=[]))

        self.share_manager.init_host()

        self.assertTrue(self.share_manager.driver.initialized)
        self.share_manager.db.share_instances_get_all_by_host.\
            assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    self.share_manager.host)
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.\
            assert_called_once_with()

    @ddt.data(
        "migration_get_driver_info",
        "migration_get_info",
        "migration_cancel",
        "migration_get_progress",
        "migration_complete",
        "migration_start",
        "create_share_instance",
        "manage_share",
        "unmanage_share",
        "delete_share_instance",
        "delete_free_share_servers",
        "create_snapshot",
        "delete_snapshot",
        "allow_access",
        "deny_access",
        "_report_driver_status",
        "_execute_periodic_hook",
        "publish_service_capabilities",
        "delete_share_server",
        "extend_share",
        "shrink_share",
        "create_consistency_group",
        "delete_consistency_group",
        "create_cgsnapshot",
        "delete_cgsnapshot",
        "create_share_replica",
        "delete_share_replica",
        "promote_share_replica",
        "periodic_share_replica_update",
        "update_share_replica",
        "create_replicated_snapshot",
        "delete_replicated_snapshot",
        "periodic_share_replica_snapshot_update",
    )
    def test_call_driver_when_its_init_failed(self, method_name):
        self.mock_object(self.share_manager.driver, 'do_setup',
                         mock.Mock(side_effect=Exception()))
        self.share_manager.init_host()

        self.assertRaises(
            exception.DriverNotInitialized,
            getattr(self.share_manager, method_name),
            'foo', 'bar', 'quuz'
        )

    @ddt.data("do_setup", "check_for_setup_error")
    def test_init_host_with_driver_failure(self, method_name):
        self.mock_object(self.share_manager.driver, method_name,
                         mock.Mock(side_effect=Exception()))
        self.mock_object(manager.LOG, 'exception')
        self.share_manager.driver.initialized = False

        self.share_manager.init_host()

        manager.LOG.exception.assert_called_once_with(
            mock.ANY, {'name': self.share_manager.driver.__class__.__name__,
                       'host': self.share_manager.host,
                       'exc': mock.ANY})
        self.assertFalse(self.share_manager.driver.initialized)

    def _setup_init_mocks(self, setup_access_rules=True):
        instances = [
            db_utils.create_share(id='fake_id_1',
                                  status=constants.STATUS_AVAILABLE,
                                  display_name='fake_name_1').instance,
            db_utils.create_share(id='fake_id_2',
                                  status=constants.STATUS_ERROR,
                                  display_name='fake_name_2').instance,
            db_utils.create_share(id='fake_id_3',
                                  status=constants.STATUS_AVAILABLE,
                                  display_name='fake_name_3').instance,
            db_utils.create_share(
                id='fake_id_4',
                status=constants.STATUS_AVAILABLE,
                task_state=constants.TASK_STATE_MIGRATION_IN_PROGRESS,
                display_name='fake_name_4').instance,
            db_utils.create_share(id='fake_id_5',
                                  status=constants.STATUS_AVAILABLE,
                                  display_name='fake_name_5').instance,
        ]

        instances[4]['access_rules_status'] = constants.STATUS_OUT_OF_SYNC

        if not setup_access_rules:
            return instances

        rules = [
            db_utils.create_access(share_id='fake_id_1'),
            db_utils.create_access(share_id='fake_id_3'),
        ]

        return instances, rules

    def test_init_host_with_shares_and_rules(self):

        # initialization of test data
        def raise_share_access_exists(*args, **kwargs):
            raise exception.ShareAccessExists(
                access_type='fake_access_type', access='fake_access')

        instances, rules = self._setup_init_mocks()
        fake_export_locations = ['fake/path/1', 'fake/path']
        share_server = 'fake_share_server_type_does_not_matter'
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_host',
                         mock.Mock(return_value=instances))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instances[0], instances[2],
                                                instances[4]]))
        self.mock_object(self.share_manager.db,
                         'share_export_locations_update')
        self.mock_object(self.share_manager.driver, 'ensure_share',
                         mock.Mock(return_value=fake_export_locations))
        self.mock_object(self.share_manager, '_ensure_share_instance_has_pool')
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager, 'publish_service_capabilities',
                         mock.Mock())
        self.mock_object(self.share_manager.db,
                         'share_access_get_all_for_share',
                         mock.Mock(return_value=rules))
        self.mock_object(
            self.share_manager.access_helper,
            'update_access_rules',
            mock.Mock(side_effect=raise_share_access_exists)
        )

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        self.share_manager.db.share_instances_get_all_by_host.\
            assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    self.share_manager.host)
        exports_update = self.share_manager.db.share_export_locations_update
        exports_update.assert_has_calls([
            mock.call(mock.ANY, instances[0]['id'], fake_export_locations),
            mock.call(mock.ANY, instances[2]['id'], fake_export_locations)
        ])
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.\
            assert_called_once_with()
        self.share_manager._ensure_share_instance_has_pool.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        self.share_manager._get_share_server.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        self.share_manager.driver.ensure_share.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0],
                      share_server=share_server),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2],
                      share_server=share_server),
        ])
        self.share_manager.publish_service_capabilities.\
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))
        self.share_manager.access_helper.update_access_rules.assert_has_calls([
            mock.call(mock.ANY, instances[4]['id'], share_server=share_server),
        ])

    def test_init_host_with_exception_on_ensure_share(self):
        def raise_exception(*args, **kwargs):
            raise exception.ManilaException(message="Fake raise")

        instances = self._setup_init_mocks(setup_access_rules=False)
        share_server = 'fake_share_server_type_does_not_matter'
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_host',
                         mock.Mock(return_value=instances))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instances[0], instances[2],
                                                instances[3]]))
        self.mock_object(self.share_manager.driver, 'ensure_share',
                         mock.Mock(side_effect=raise_exception))
        self.mock_object(self.share_manager, '_ensure_share_instance_has_pool')
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager, 'publish_service_capabilities')
        self.mock_object(manager.LOG, 'error')
        self.mock_object(manager.LOG, 'info')

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        self.share_manager.db.share_instances_get_all_by_host.\
            assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    self.share_manager.host)
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.assert_called_with()
        self.share_manager._ensure_share_instance_has_pool.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        self.share_manager._get_share_server.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        self.share_manager.driver.ensure_share.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0],
                      share_server=share_server),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2],
                      share_server=share_server),
        ])
        self.share_manager.publish_service_capabilities.\
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))
        manager.LOG.info.assert_any_call(
            mock.ANY,
            {'task': constants.TASK_STATE_MIGRATION_IN_PROGRESS,
             'id': instances[3]['id']},
        )
        manager.LOG.info.assert_any_call(
            mock.ANY,
            {'id': instances[1]['id'], 'status': instances[1]['status']},
        )

    def test_init_host_with_exception_on_update_access_rules(self):
        def raise_exception(*args, **kwargs):
            raise exception.ManilaException(message="Fake raise")

        instances, rules = self._setup_init_mocks()
        share_server = 'fake_share_server_type_does_not_matter'
        smanager = self.share_manager
        self.mock_object(smanager.db, 'share_instances_get_all_by_host',
                         mock.Mock(return_value=instances))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instances[0], instances[2],
                                                instances[4]]))
        self.mock_object(self.share_manager.driver, 'ensure_share',
                         mock.Mock(return_value=None))
        self.mock_object(smanager, '_ensure_share_instance_has_pool')
        self.mock_object(smanager, '_get_share_server',
                         mock.Mock(return_value=share_server))
        self.mock_object(smanager, 'publish_service_capabilities')
        self.mock_object(manager.LOG, 'error')
        self.mock_object(manager.LOG, 'info')
        self.mock_object(smanager.db, 'share_access_get_all_for_share',
                         mock.Mock(return_value=rules))
        self.mock_object(smanager.access_helper, 'update_access_rules',
                         mock.Mock(side_effect=raise_exception))

        # call of 'init_host' method
        smanager.init_host()

        # verification of call
        smanager.db.share_instances_get_all_by_host.\
            assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    smanager.host)
        smanager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        smanager.driver.check_for_setup_error.assert_called_with()
        smanager._ensure_share_instance_has_pool.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        smanager._get_share_server.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        smanager.driver.ensure_share.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0],
                      share_server=share_server),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2],
                      share_server=share_server),
        ])
        self.share_manager.publish_service_capabilities.\
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))
        manager.LOG.info.assert_any_call(
            mock.ANY,
            {'task': constants.TASK_STATE_MIGRATION_IN_PROGRESS,
             'id': instances[3]['id']},
        )
        manager.LOG.info.assert_any_call(
            mock.ANY,
            {'id': instances[1]['id'], 'status': instances[1]['status']},
        )
        smanager.access_helper.update_access_rules.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext),
                      instances[4]['id'], share_server=share_server),
        ])
        manager.LOG.error.assert_has_calls([
            mock.call(mock.ANY, mock.ANY),
        ])

    def test_create_share_instance_from_snapshot_with_server(self):
        """Test share can be created from snapshot if server exists."""
        network = db_utils.create_share_network()
        server = db_utils.create_share_server(
            share_network_id=network['id'], host='fake_host',
            backend_details=dict(fake='fake'))
        parent_share = db_utils.create_share(share_network_id='net-id',
                                             share_server_id=server['id'])
        share = db_utils.create_share()
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=parent_share['id'])
        snapshot_id = snapshot['id']

        self.share_manager.create_share_instance(
            self.context, share.instance['id'], snapshot_id=snapshot_id)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_AVAILABLE, shr['status'])
        self.assertEqual(server['id'], shr['instance']['share_server_id'])

    def test_create_share_instance_from_snapshot_with_server_not_found(self):
        """Test creation from snapshot fails if server not found."""
        parent_share = db_utils.create_share(share_network_id='net-id',
                                             share_server_id='fake-id')
        share = db_utils.create_share()
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=parent_share['id'])
        snapshot_id = snapshot['id']

        self.assertRaises(exception.ShareServerNotFound,
                          self.share_manager.create_share_instance,
                          self.context,
                          share.instance['id'],
                          snapshot_id=snapshot_id
                          )

        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_ERROR, shr['status'])

    def test_create_share_instance_from_snapshot(self):
        """Test share can be created from snapshot."""
        share = db_utils.create_share()
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.share_manager.create_share_instance(
            self.context, share.instance['id'], snapshot_id=snapshot_id)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_AVAILABLE, shr['status'])
        self.assertTrue(len(shr['export_location']) > 0)
        self.assertEqual(2, len(shr['export_locations']))

    def test_create_share_instance_for_share_with_replication_support(self):
        """Test update call is made to update replica_state."""
        share = db_utils.create_share(replication_type='writable')
        share_id = share['id']

        self.share_manager.create_share_instance(self.context,
                                                 share.instance['id'])

        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        shr_instance = db.share_instance_get(self.context,
                                             share.instance['id'])

        self.assertEqual(constants.STATUS_AVAILABLE, shr['status'],)
        self.assertEqual(constants.REPLICA_STATE_ACTIVE,
                         shr_instance['replica_state'])

    @ddt.data([], None)
    def test_create_share_replica_no_active_replicas(self, active_replicas):
        replica = fake_replica()
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=active_replicas))
        self.mock_object(
            db, 'share_replica_get', mock.Mock(return_value=replica))
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_driver_replica_call = self.mock_object(
            self.share_manager.driver, 'create_replica')

        self.assertRaises(exception.ReplicationException,
                          self.share_manager.create_share_replica,
                          self.context, replica)
        mock_replica_update_call.assert_called_once_with(
            mock.ANY, replica['id'], {'status': constants.STATUS_ERROR,
                                      'replica_state': constants.STATUS_ERROR})
        self.assertFalse(mock_driver_replica_call.called)

    def test_create_share_replica_with_share_network_id_and_not_dhss(self):
        replica = fake_replica()
        manager.CONF.set_default('driver_handles_share_servers', False)
        self.mock_object(db, 'share_access_get_all_for_share',
                         mock.Mock(return_value=[]))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=fake_replica(id='fake2')))
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_driver_replica_call = self.mock_object(
            self.share_manager.driver, 'create_replica')

        self.assertRaises(exception.InvalidDriverMode,
                          self.share_manager.create_share_replica,
                          self.context, replica)
        mock_replica_update_call.assert_called_once_with(
            mock.ANY, replica['id'], {'status': constants.STATUS_ERROR,
                                      'replica_state': constants.STATUS_ERROR})
        self.assertFalse(mock_driver_replica_call.called)

    def test_create_share_replica_with_share_server_exception(self):
        replica = fake_replica()
        manager.CONF.set_default('driver_handles_share_servers', True)
        self.mock_object(db, 'share_instance_access_copy',
                         mock.Mock(return_value=[]))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=fake_replica(id='fake2')))
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_driver_replica_call = self.mock_object(
            self.share_manager.driver, 'create_replica')

        self.assertRaises(exception.NotFound,
                          self.share_manager.create_share_replica,
                          self.context, replica)
        mock_replica_update_call.assert_called_once_with(
            mock.ANY, replica['id'], {'status': constants.STATUS_ERROR,
                                      'replica_state': constants.STATUS_ERROR})
        self.assertFalse(mock_driver_replica_call.called)

    def test_create_share_replica_driver_error_on_creation(self):
        fake_access_rules = [{'id': '1'}, {'id': '2'}, {'id': '3'}]
        replica = fake_replica(share_network_id='')
        replica_2 = fake_replica(id='fake2')
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_instance_access_copy',
                         mock.Mock(return_value=fake_access_rules))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=replica_2))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, replica_2]))
        self.mock_object(self.share_manager,
                         '_provide_share_server_for_share',
                         mock.Mock(return_value=('FAKE_SERVER', replica)))
        self.mock_object(self.share_manager,
                         '_get_replica_snapshots_for_snapshot',
                         mock.Mock(return_value=[]))
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_export_locs_update_call = self.mock_object(
            db, 'share_export_locations_update')
        mock_log_error = self.mock_object(manager.LOG, 'error')
        mock_log_info = self.mock_object(manager.LOG, 'info')
        self.mock_object(db, 'share_instance_access_get',
                         mock.Mock(return_value=fake_access_rules[0]))
        mock_share_replica_access_update = self.mock_object(
            db, 'share_instance_update_access_status')
        self.mock_object(self.share_manager, '_get_share_server')

        driver_call = self.mock_object(
            self.share_manager.driver, 'create_replica',
            mock.Mock(side_effect=exception.ManilaException))

        self.assertRaises(exception.ManilaException,
                          self.share_manager.create_share_replica,
                          self.context, replica)
        mock_replica_update_call.assert_called_once_with(
            mock.ANY, replica['id'], {'status': constants.STATUS_ERROR,
                                      'replica_state': constants.STATUS_ERROR})
        self.assertEqual(1, mock_share_replica_access_update.call_count)
        self.assertFalse(mock_export_locs_update_call.called)
        self.assertTrue(mock_log_error.called)
        self.assertFalse(mock_log_info.called)
        self.assertTrue(driver_call.called)

    def test_create_share_replica_invalid_locations_state(self):
        driver_retval = {
            'export_locations': 'FAKE_EXPORT_LOC',
        }
        replica = fake_replica(share_network='')
        replica_2 = fake_replica(id='fake2')
        fake_access_rules = [{'id': '1'}, {'id': '2'}]
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=replica_2))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, replica_2]))
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_instance_access_copy',
                         mock.Mock(return_value=fake_access_rules))
        self.mock_object(self.share_manager,
                         '_provide_share_server_for_share',
                         mock.Mock(return_value=('FAKE_SERVER', replica)))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        self.mock_object(self.share_manager,
                         '_get_replica_snapshots_for_snapshot',
                         mock.Mock(return_value=[]))
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_export_locs_update_call = self.mock_object(
            db, 'share_export_locations_update')
        mock_log_info = self.mock_object(manager.LOG, 'info')
        mock_log_warning = self.mock_object(manager.LOG, 'warning')
        mock_log_error = self.mock_object(manager.LOG, 'error')
        driver_call = self.mock_object(
            self.share_manager.driver, 'create_replica',
            mock.Mock(return_value=driver_retval))
        self.mock_object(db, 'share_instance_access_get',
                         mock.Mock(return_value=fake_access_rules[0]))
        mock_share_replica_access_update = self.mock_object(
            db, 'share_instance_update_access_status')

        self.share_manager.create_share_replica(self.context, replica)

        self.assertFalse(mock_replica_update_call.called)
        self.assertEqual(1, mock_share_replica_access_update.call_count)
        self.assertFalse(mock_export_locs_update_call.called)
        self.assertTrue(mock_log_info.called)
        self.assertTrue(mock_log_warning.called)
        self.assertFalse(mock_log_error.called)
        self.assertTrue(driver_call.called)
        call_args = driver_call.call_args_list[0][0]
        replica_list_arg = call_args[1]
        r_ids = [r['id'] for r in replica_list_arg]
        for r in (replica, replica_2):
            self.assertIn(r['id'], r_ids)
        self.assertEqual(2, len(r_ids))

    def test_create_share_replica_no_availability_zone(self):
        replica = fake_replica(
            availability_zone=None, share_network='',
            replica_state=constants.REPLICA_STATE_OUT_OF_SYNC)
        replica_2 = fake_replica(id='fake2')
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, replica_2]))
        manager.CONF.set_default('storage_availability_zone', 'fake_az')
        fake_access_rules = [{'id': '1'}, {'id': '2'}, {'id': '3'}]
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_instance_access_copy',
                         mock.Mock(return_value=fake_access_rules))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=replica_2))
        self.mock_object(self.share_manager,
                         '_provide_share_server_for_share',
                         mock.Mock(return_value=('FAKE_SERVER', replica)))
        self.mock_object(self.share_manager,
                         '_get_replica_snapshots_for_snapshot',
                         mock.Mock(return_value=[]))
        mock_replica_update_call = self.mock_object(
            db, 'share_replica_update', mock.Mock(return_value=replica))
        mock_calls = [
            mock.call(mock.ANY, replica['id'],
                      {'availability_zone': 'fake_az'}, with_share_data=True),
            mock.call(mock.ANY, replica['id'],
                      {'status': constants.STATUS_AVAILABLE,
                       'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC}),
        ]
        mock_export_locs_update_call = self.mock_object(
            db, 'share_export_locations_update')
        mock_log_info = self.mock_object(manager.LOG, 'info')
        mock_log_warning = self.mock_object(manager.LOG, 'warning')
        mock_log_error = self.mock_object(manager.LOG, 'warning')
        self.mock_object(db, 'share_instance_access_get',
                         mock.Mock(return_value=fake_access_rules[0]))
        mock_share_replica_access_update = self.mock_object(
            self.share_manager, '_update_share_replica_access_rules_state')
        driver_call = self.mock_object(
            self.share_manager.driver, 'create_replica',
            mock.Mock(return_value=replica))
        self.mock_object(self.share_manager, '_get_share_server', mock.Mock())

        self.share_manager.create_share_replica(self.context, replica)

        mock_replica_update_call.assert_has_calls(mock_calls, any_order=False)
        mock_share_replica_access_update.assert_called_once_with(
            mock.ANY, replica['id'], replica['access_rules_status'])
        self.assertTrue(mock_export_locs_update_call.called)
        self.assertTrue(mock_log_info.called)
        self.assertFalse(mock_log_warning.called)
        self.assertFalse(mock_log_error.called)
        self.assertTrue(driver_call.called)

    @ddt.data(True, False)
    def test_create_share_replica(self, has_snapshots):
        replica = fake_replica(
            share_network='', replica_state=constants.REPLICA_STATE_IN_SYNC)
        replica_2 = fake_replica(id='fake2')
        snapshots = ([fakes.fake_snapshot(create_instance=True)]
                     if has_snapshots else [])
        snapshot_instances = [
            fakes.fake_snapshot_instance(share_instance_id=replica['id']),
            fakes.fake_snapshot_instance(share_instance_id='fake2'),
        ]
        fake_access_rules = [{'id': '1'}, {'id': '2'}, {'id': '3'}]
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_instance_access_copy',
                         mock.Mock(return_value=fake_access_rules))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=replica_2))
        self.mock_object(self.share_manager,
                         '_provide_share_server_for_share',
                         mock.Mock(return_value=('FAKE_SERVER', replica)))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, replica_2]))
        self.mock_object(db, 'share_snapshot_get_all_for_share', mock.Mock(
            return_value=snapshots))
        mock_instance_get_call = self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=snapshot_instances))

        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_export_locs_update_call = self.mock_object(
            db, 'share_export_locations_update')
        mock_log_info = self.mock_object(manager.LOG, 'info')
        mock_log_warning = self.mock_object(manager.LOG, 'warning')
        mock_log_error = self.mock_object(manager.LOG, 'warning')
        self.mock_object(db, 'share_instance_access_get',
                         mock.Mock(return_value=fake_access_rules[0]))
        mock_share_replica_access_update = self.mock_object(
            db, 'share_instance_update_access_status')
        driver_call = self.mock_object(
            self.share_manager.driver, 'create_replica',
            mock.Mock(return_value=replica))
        self.mock_object(self.share_manager, '_get_share_server')

        self.share_manager.create_share_replica(self.context, replica)

        mock_replica_update_call.assert_called_once_with(
            mock.ANY, replica['id'],
            {'status': constants.STATUS_AVAILABLE,
             'replica_state': constants.REPLICA_STATE_IN_SYNC})
        self.assertEqual(1, mock_share_replica_access_update.call_count)
        self.assertTrue(mock_export_locs_update_call.called)
        self.assertTrue(mock_log_info.called)
        self.assertFalse(mock_log_warning.called)
        self.assertFalse(mock_log_error.called)
        self.assertTrue(driver_call.called)
        call_args = driver_call.call_args_list[0][0]
        replica_list_arg = call_args[1]
        snapshot_list_arg = call_args[4]
        r_ids = [r['id'] for r in replica_list_arg]
        for r in (replica, replica_2):
            self.assertIn(r['id'], r_ids)
        self.assertEqual(2, len(r_ids))
        if has_snapshots:
            for snapshot_dict in snapshot_list_arg:
                self.assertTrue('active_replica_snapshot' in snapshot_dict)
                self.assertTrue('share_replica_snapshot' in snapshot_dict)
        else:
            self.assertFalse(mock_instance_get_call.called)

    def test_delete_share_replica_access_rules_exception(self):
        replica = fake_replica()
        replica_2 = fake_replica(id='fake_2')
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, replica_2]))
        active_replica = fake_replica(
            id='Current_active_replica',
            replica_state=constants.REPLICA_STATE_ACTIVE)
        mock_exception_log = self.mock_object(manager.LOG, 'exception')
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=active_replica))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(self.share_manager.access_helper,
                         'update_access_rules')
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_replica_delete_call = self.mock_object(db, 'share_replica_delete')
        mock_drv_delete_replica_call = self.mock_object(
            self.share_manager.driver, 'delete_replica')
        self.mock_object(
            self.share_manager.access_helper, 'update_access_rules',
            mock.Mock(side_effect=exception.ManilaException))

        self.assertRaises(exception.ManilaException,
                          self.share_manager.delete_share_replica,
                          self.context, replica['id'],
                          share_id=replica['share_id'])
        mock_replica_update_call.assert_called_once_with(
            mock.ANY, replica['id'], {'status': constants.STATUS_ERROR})
        self.assertFalse(mock_drv_delete_replica_call.called)
        self.assertFalse(mock_replica_delete_call.called)
        self.assertFalse(mock_exception_log.called)

    def test_delete_share_replica_drv_misbehavior_ignored_with_the_force(self):
        replica = fake_replica()
        active_replica = fake_replica(id='Current_active_replica')
        mock_exception_log = self.mock_object(manager.LOG, 'exception')
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, active_replica]))
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=active_replica))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        self.mock_object(self.share_manager.access_helper,
                         'update_access_rules')
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=[]))
        mock_snap_instance_delete = self.mock_object(
            db, 'share_snapshot_instance_delete')
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_replica_delete_call = self.mock_object(db, 'share_replica_delete')
        mock_drv_delete_replica_call = self.mock_object(
            self.share_manager.driver, 'delete_replica',
            mock.Mock(side_effect=exception.ManilaException))
        self.mock_object(
            self.share_manager.access_helper, 'update_access_rules')

        self.share_manager.delete_share_replica(
            self.context, replica['id'], share_id=replica['share_id'],
            force=True)

        self.assertFalse(mock_replica_update_call.called)
        self.assertTrue(mock_replica_delete_call.called)
        self.assertEqual(1, mock_exception_log.call_count)
        self.assertTrue(mock_drv_delete_replica_call.called)
        self.assertFalse(mock_snap_instance_delete.called)

    def test_delete_share_replica_driver_exception(self):
        replica = fake_replica()
        active_replica = fake_replica(id='Current_active_replica')
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, active_replica]))
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=active_replica))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        mock_snapshot_get_call = self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=[]))
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_replica_delete_call = self.mock_object(db, 'share_replica_delete')
        self.mock_object(
            self.share_manager.access_helper, 'update_access_rules')
        mock_drv_delete_replica_call = self.mock_object(
            self.share_manager.driver, 'delete_replica',
            mock.Mock(side_effect=exception.ManilaException))

        self.assertRaises(exception.ManilaException,
                          self.share_manager.delete_share_replica,
                          self.context, replica['id'],
                          share_id=replica['share_id'])
        self.assertTrue(mock_replica_update_call.called)
        self.assertFalse(mock_replica_delete_call.called)
        self.assertTrue(mock_drv_delete_replica_call.called)
        self.assertTrue(mock_snapshot_get_call.called)

    def test_delete_share_replica_both_exceptions_ignored_with_the_force(self):
        replica = fake_replica()
        active_replica = fake_replica(id='Current_active_replica')
        snapshots = [
            fakes.fake_snapshot(share_id=replica['id'],
                                status=constants.STATUS_AVAILABLE),
            fakes.fake_snapshot(share_id=replica['id'],
                                id='test_creating_to_err',
                                status=constants.STATUS_CREATING)
        ]
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, active_replica]))
        mock_exception_log = self.mock_object(manager.LOG, 'exception')
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=active_replica))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=snapshots))
        mock_snapshot_instance_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_replica_delete_call = self.mock_object(db, 'share_replica_delete')
        self.mock_object(
            self.share_manager.access_helper, 'update_access_rules',
            mock.Mock(side_effect=exception.ManilaException))
        mock_drv_delete_replica_call = self.mock_object(
            self.share_manager.driver, 'delete_replica',
            mock.Mock(side_effect=exception.ManilaException))

        self.share_manager.delete_share_replica(
            self.context, replica['id'], share_id=replica['share_id'],
            force=True)

        mock_replica_update_call.assert_called_once_with(
            mock.ANY, replica['id'], {'status': constants.STATUS_ERROR})
        self.assertTrue(mock_replica_delete_call.called)
        self.assertEqual(2, mock_exception_log.call_count)
        self.assertTrue(mock_drv_delete_replica_call.called)
        self.assertEqual(2, mock_snapshot_instance_delete_call.call_count)

    def test_delete_share_replica(self):
        replica = fake_replica()
        active_replica = fake_replica(id='current_active_replica')
        snapshots = [
            fakes.fake_snapshot(share_id=replica['share_id'],
                                status=constants.STATUS_AVAILABLE),
            fakes.fake_snapshot(share_id=replica['share_id'],
                                id='test_creating_to_err',
                                status=constants.STATUS_CREATING)
        ]
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=snapshots))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, active_replica]))
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=active_replica))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        mock_info_log = self.mock_object(manager.LOG, 'info')
        mock_snapshot_instance_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')
        mock_replica_update_call = self.mock_object(db, 'share_replica_update')
        mock_replica_delete_call = self.mock_object(db, 'share_replica_delete')
        self.mock_object(
            self.share_manager.access_helper, 'update_access_rules')
        mock_drv_delete_replica_call = self.mock_object(
            self.share_manager.driver, 'delete_replica')

        self.share_manager.delete_share_replica(self.context, replica)

        self.assertFalse(mock_replica_update_call.called)
        self.assertTrue(mock_replica_delete_call.called)
        self.assertTrue(mock_info_log.called)
        self.assertTrue(mock_drv_delete_replica_call.called)
        self.assertEqual(2, mock_snapshot_instance_delete_call.call_count)

    def test_promote_share_replica_no_active_replica(self):
        replica = fake_replica()
        replica_list = [replica]
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=replica_list))
        mock_info_log = self.mock_object(manager.LOG, 'info')
        mock_driver_call = self.mock_object(self.share_manager.driver,
                                            'promote_replica')
        mock_replica_update = self.mock_object(db, 'share_replica_update')
        expected_update_call = mock.call(
            mock.ANY, replica['id'], {'status': constants.STATUS_AVAILABLE})

        self.assertRaises(exception.ReplicationException,
                          self.share_manager.promote_share_replica,
                          self.context, replica)
        self.assertFalse(mock_info_log.called)
        self.assertFalse(mock_driver_call.called)
        mock_replica_update.assert_has_calls([expected_update_call])

    def test_promote_share_replica_driver_exception(self):
        replica = fake_replica()
        active_replica = fake_replica(
            id='current_active_replica',
            replica_state=constants.REPLICA_STATE_ACTIVE)
        replica_list = [replica, active_replica]
        self.mock_object(db, 'share_access_get_all_for_share',
                         mock.Mock(return_value=[]))
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replica_list))
        self.mock_object(self.share_manager.driver, 'promote_replica',
                         mock.Mock(side_effect=exception.ManilaException))
        mock_info_log = self.mock_object(manager.LOG, 'info')
        mock_replica_update = self.mock_object(db, 'share_replica_update')
        expected_update_calls = [mock.call(
            mock.ANY, r['id'], {'status': constants.STATUS_ERROR})
            for r in(replica, active_replica)]

        self.assertRaises(exception.ManilaException,
                          self.share_manager.promote_share_replica,
                          self.context, replica)
        mock_replica_update.assert_has_calls(expected_update_calls)
        self.assertFalse(mock_info_log.called)

    @ddt.data([], None)
    def test_promote_share_replica_driver_update_nothing_has_snaps(self,
                                                                   retval):
        replica = fake_replica()
        active_replica = fake_replica(
            id='current_active_replica',
            replica_state=constants.REPLICA_STATE_ACTIVE)
        snapshots_instances = [
            fakes.fake_snapshot(create_instance=True,
                                share_id=replica['share_id'],
                                status=constants.STATUS_AVAILABLE),
            fakes.fake_snapshot(create_instance=True,
                                share_id=replica['share_id'],
                                id='test_creating_to_err',
                                status=constants.STATUS_CREATING)
        ]
        replica_list = [replica, active_replica]
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_access_get_all_for_share',
                         mock.Mock(return_value=[]))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replica_list))
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=snapshots_instances))
        self.mock_object(
            self.share_manager.driver, 'promote_replica',
            mock.Mock(return_value=retval))
        mock_snap_instance_update = self.mock_object(
            db, 'share_snapshot_instance_update')
        mock_info_log = self.mock_object(manager.LOG, 'info')
        mock_export_locs_update = self.mock_object(
            db, 'share_export_locations_update')
        mock_replica_update = self.mock_object(db, 'share_replica_update')
        call_1 = mock.call(mock.ANY, replica['id'],
                           {'status': constants.STATUS_AVAILABLE,
                            'replica_state': constants.REPLICA_STATE_ACTIVE})
        call_2 = mock.call(
            mock.ANY, 'current_active_replica',
            {'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC})
        expected_update_calls = [call_1, call_2]

        self.share_manager.promote_share_replica(self.context, replica)

        self.assertFalse(mock_export_locs_update.called)
        mock_replica_update.assert_has_calls(expected_update_calls,
                                             any_order=True)
        mock_snap_instance_update.assert_called_once_with(
            mock.ANY, 'test_creating_to_err',
            {'status': constants.STATUS_ERROR})
        self.assertEqual(2, mock_info_log.call_count)

    def test_promote_share_replica_driver_updates_replica_list(self):
        replica = fake_replica()
        active_replica = fake_replica(
            id='current_active_replica',
            replica_state=constants.REPLICA_STATE_ACTIVE)
        replica_list = [replica, active_replica, fake_replica(id=3)]
        updated_replica_list = [
            {
                'id': replica['id'],
                'export_locations': ['TEST1', 'TEST2'],
                'replica_state': constants.REPLICA_STATE_ACTIVE,
            },
            {
                'id': 'current_active_replica',
                'export_locations': 'junk_return_value',
                'replica_state': constants.REPLICA_STATE_IN_SYNC,
            },
            {
                'id': 'other_replica',
                'export_locations': ['TEST1', 'TEST2'],
            },
        ]
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=[]))
        self.mock_object(db, 'share_access_get_all_for_share',
                         mock.Mock(return_value=[]))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replica_list))
        mock_snap_instance_update = self.mock_object(
            db, 'share_snapshot_instance_update')
        self.mock_object(
            self.share_manager.driver, 'promote_replica',
            mock.Mock(return_value=updated_replica_list))
        mock_info_log = self.mock_object(manager.LOG, 'info')
        mock_export_locs_update = self.mock_object(
            db, 'share_export_locations_update')
        mock_replica_update = self.mock_object(db, 'share_replica_update')
        reset_replication_change_call = mock.call(
            mock.ANY, replica['id'], {'replica_state': constants.STATUS_ACTIVE,
                                      'status': constants.STATUS_AVAILABLE})

        self.share_manager.promote_share_replica(self.context, replica)

        self.assertEqual(2, mock_export_locs_update.call_count)
        self.assertEqual(2, mock_replica_update.call_count)
        self.assertTrue(
            reset_replication_change_call in mock_replica_update.mock_calls)
        self.assertTrue(mock_info_log.called)
        self.assertFalse(mock_snap_instance_update.called)

    @ddt.data('openstack1@watson#_pool0', 'openstack1@newton#_pool0')
    def test_periodic_share_replica_update(self, host):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        replicas = [
            fake_replica(host='openstack1@watson#pool4'),
            fake_replica(host='openstack1@watson#pool5'),
            fake_replica(host='openstack1@newton#pool5'),
            fake_replica(host='openstack1@newton#pool5'),

        ]
        self.mock_object(self.share_manager.db, 'share_replicas_get_all',
                         mock.Mock(return_value=replicas))
        mock_update_method = self.mock_object(
            self.share_manager, '_share_replica_update')

        self.share_manager.host = host

        self.share_manager.periodic_share_replica_update(self.context)

        self.assertEqual(2, mock_update_method.call_count)
        self.assertEqual(1, mock_debug_log.call_count)

    @ddt.data(constants.REPLICA_STATE_IN_SYNC,
              constants.REPLICA_STATE_OUT_OF_SYNC)
    def test__share_replica_update_driver_exception(self, replica_state):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        replica = fake_replica(replica_state=replica_state)
        active_replica = fake_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE)
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, active_replica]))
        self.mock_object(self.share_manager.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value='fake_share_server'))
        self.mock_object(self.share_manager.driver, 'update_replica_state',
                         mock.Mock(side_effect=exception.ManilaException))
        mock_db_update_call = self.mock_object(
            self.share_manager.db, 'share_replica_update')

        self.share_manager._share_replica_update(
            self.context,  replica, share_id=replica['share_id'])

        mock_db_update_call.assert_called_once_with(
            self.context, replica['id'],
            {'replica_state': constants.STATUS_ERROR,
             'status': constants.STATUS_ERROR}
        )
        self.assertEqual(1, mock_debug_log.call_count)

    def test__share_replica_update_driver_exception_ignored(self):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        replica = fake_replica(replica_state=constants.STATUS_ERROR)
        active_replica = fake_replica(replica_state=constants.STATUS_ACTIVE)
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, active_replica]))
        self.mock_object(self.share_manager.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value='fake_share_server'))
        self.share_manager.host = replica['host']
        self.mock_object(self.share_manager.driver, 'update_replica_state',
                         mock.Mock(side_effect=exception.ManilaException))
        mock_db_update_call = self.mock_object(
            self.share_manager.db, 'share_replica_update')

        self.share_manager._share_replica_update(
            self.context, replica, share_id=replica['share_id'])

        mock_db_update_call.assert_called_once_with(
            self.context, replica['id'],
            {'replica_state': constants.STATUS_ERROR,
             'status': constants.STATUS_ERROR}
        )
        self.assertEqual(1, mock_debug_log.call_count)

    @ddt.data({'status': constants.STATUS_AVAILABLE,
               'replica_state': constants.REPLICA_STATE_ACTIVE, },
              {'status': constants.STATUS_DELETING,
               'replica_state': constants.REPLICA_STATE_IN_SYNC, },
              {'status': constants.STATUS_CREATING,
               'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC, },
              {'status': constants.STATUS_MANAGING,
               'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC, },
              {'status': constants.STATUS_UNMANAGING,
               'replica_state': constants.REPLICA_STATE_ACTIVE, },
              {'status': constants.STATUS_EXTENDING,
               'replica_state': constants.REPLICA_STATE_IN_SYNC, },
              {'status': constants.STATUS_SHRINKING,
               'replica_state': constants.REPLICA_STATE_IN_SYNC, })
    def test__share_replica_update_unqualified_replica(self, state):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        mock_warning_log = self.mock_object(manager.LOG, 'warning')
        mock_driver_call = self.mock_object(
            self.share_manager.driver, 'update_replica_state')
        mock_db_update_call = self.mock_object(
            self.share_manager.db, 'share_replica_update')
        replica = fake_replica(**state)
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value='fake_share_server'))
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))

        self.share_manager._share_replica_update(self.context, replica,
                                                 share_id=replica['share_id'])

        self.assertFalse(mock_debug_log.called)
        self.assertFalse(mock_warning_log.called)
        self.assertFalse(mock_driver_call.called)
        self.assertFalse(mock_db_update_call.called)

    @ddt.data(None, constants.REPLICA_STATE_IN_SYNC,
              constants.REPLICA_STATE_OUT_OF_SYNC,
              constants.REPLICA_STATE_ACTIVE,
              constants.STATUS_ERROR)
    def test__share_replica_update(self, retval):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        mock_warning_log = self.mock_object(manager.LOG, 'warning')
        replica_states = [constants.REPLICA_STATE_IN_SYNC,
                          constants.REPLICA_STATE_OUT_OF_SYNC]
        replica = fake_replica(replica_state=random.choice(replica_states),
                               share_server='fake_share_server')
        active_replica = fake_replica(
            id='fake2', replica_state=constants.STATUS_ACTIVE)
        snapshots = [fakes.fake_snapshot(
            create_instance=True, aggregate_status=constants.STATUS_AVAILABLE)]
        snapshot_instances = [
            fakes.fake_snapshot_instance(share_instance_id=replica['id']),
            fakes.fake_snapshot_instance(share_instance_id='fake2'),
        ]
        del replica['availability_zone']
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, active_replica]))
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value='fake_share_server'))
        mock_db_update_calls = []
        self.mock_object(self.share_manager.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        mock_driver_call = self.mock_object(
            self.share_manager.driver, 'update_replica_state',
            mock.Mock(return_value=retval))
        mock_db_update_call = self.mock_object(
            self.share_manager.db, 'share_replica_update')
        self.mock_object(db, 'share_snapshot_get_all_for_share',
                         mock.Mock(return_value=snapshots))
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))

        self.share_manager._share_replica_update(
            self.context, replica, share_id=replica['share_id'])

        if retval == constants.REPLICA_STATE_ACTIVE:
                self.assertEqual(1, mock_warning_log.call_count)
        elif retval:
            self.assertEqual(0, mock_warning_log.call_count)
        self.assertTrue(mock_driver_call.called)
        snapshot_list_arg = mock_driver_call.call_args[0][4]
        self.assertTrue('active_replica_snapshot' in snapshot_list_arg[0])
        self.assertTrue('share_replica_snapshot' in snapshot_list_arg[0])
        mock_db_update_call.assert_has_calls(mock_db_update_calls)
        self.assertEqual(1, mock_debug_log.call_count)

    def test_update_share_replica_replica_not_found(self):
        replica = fake_replica()
        self.mock_object(
            self.share_manager.db, 'share_replica_get', mock.Mock(
                side_effect=exception.ShareReplicaNotFound(replica_id='fake')))
        self.mock_object(self.share_manager, '_get_share_server')
        driver_call = self.mock_object(
            self.share_manager, '_share_replica_update')

        self.assertRaises(
            exception.ShareReplicaNotFound,
            self.share_manager.update_share_replica,
            self.context, replica, share_id=replica['share_id'])

        self.assertFalse(driver_call.called)

    def test_update_share_replica_replica(self):
        replica_update_call = self.mock_object(
            self.share_manager, '_share_replica_update')
        self.mock_object(self.share_manager.db, 'share_replica_get')

        retval = self.share_manager.update_share_replica(
            self.context, 'fake_replica_id', share_id='fake_share_id')

        self.assertIsNone(retval)
        self.assertTrue(replica_update_call.called)

    def test_create_delete_share_snapshot(self):
        """Test share's snapshot can be created and deleted."""

        def _fake_create_snapshot(self, snapshot, **kwargs):
            snapshot['progress'] = '99%'
            return snapshot.to_dict()

        self.mock_object(self.share_manager.driver, "create_snapshot",
                         _fake_create_snapshot)

        share = db_utils.create_share()
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']
        self.share_manager.create_snapshot(self.context, share_id,
                                           snapshot_id)
        self.assertEqual(share_id,
                         db.share_snapshot_get(context.get_admin_context(),
                                               snapshot_id).share_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEqual(constants.STATUS_AVAILABLE, snap['status'])

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

        share = db_utils.create_share()
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.assertRaises(exception.NotFound,
                          self.share_manager.create_snapshot,
                          self.context, share_id, snapshot_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEqual(constants.STATUS_ERROR, snap['status'])

        self.assertRaises(exception.NotFound,
                          self.share_manager.delete_snapshot,
                          self.context, snapshot_id)

        self.assertEqual(
            constants.STATUS_ERROR_DELETING,
            db.share_snapshot_get(self.context, snapshot_id).status)
        self.share_manager.driver.create_snapshot.assert_called_once_with(
            self.context, utils.IsAMatcher(models.ShareSnapshotInstance),
            share_server=None)
        self.share_manager.driver.delete_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            utils.IsAMatcher(models.ShareSnapshotInstance),
            share_server=None)

    def test_delete_snapshot_quota_error(self):
        share = db_utils.create_share()
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']
        snapshot = db_utils.create_snapshot(
            with_share=True, status=constants.STATUS_AVAILABLE)

        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=exception.QuotaError('fake')))
        self.mock_object(quota.QUOTAS, 'commit')

        self.share_manager.delete_snapshot(self.context, snapshot_id)

        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY,
            project_id=six.text_type(snapshot['project_id']),
            snapshots=-1,
            snapshot_gigabytes=-snapshot['size'],
            user_id=six.text_type(snapshot['user_id'])
        )
        self.assertFalse(quota.QUOTAS.commit.called)

    def test_delete_share_instance_if_busy(self):
        """Test snapshot could not be deleted if busy."""

        def _raise_share_snapshot_is_busy(self, *args, **kwargs):
            raise exception.ShareSnapshotIsBusy(snapshot_name='fakename')

        self.mock_object(self.share_manager.driver, "delete_snapshot",
                         mock.Mock(side_effect=_raise_share_snapshot_is_busy))
        share = db_utils.create_share(status=constants.STATUS_ACTIVE)
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        snapshot_id = snapshot['id']

        self.share_manager.delete_snapshot(self.context, snapshot_id)

        snap = db.share_snapshot_get(self.context, snapshot_id)
        self.assertEqual(constants.STATUS_AVAILABLE, snap['status'])
        self.share_manager.driver.delete_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            utils.IsAMatcher(models.ShareSnapshotInstance),
            share_server=None)

    def test_create_share_instance_with_share_network_dhss_false(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=False))
        share_network_id = 'fake_sn'
        share_instance = db_utils.create_share(
            share_network_id=share_network_id).instance
        self.mock_object(
            self.share_manager.db, 'share_instance_get',
            mock.Mock(return_value=share_instance))
        self.mock_object(self.share_manager.db, 'share_instance_update')

        self.assertRaisesRegex(
            exception.ManilaException,
            '.*%s.*' % share_instance['id'],
            self.share_manager.create_share_instance, self.context,
            share_instance['id'])
        self.share_manager.db.share_instance_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_instance['id'],
            with_share_data=True
        )
        self.share_manager.db.share_instance_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_instance['id'],
            {'status': constants.STATUS_ERROR})

    def test_create_share_instance_with_share_network_server_not_exists(self):
        """Test share can be created without share server."""

        share_net = db_utils.create_share_network()
        share = db_utils.create_share(share_network_id=share_net['id'])

        share_id = share['id']

        def fake_setup_server(context, share_network, *args, **kwargs):
            return db_utils.create_share_server(
                share_network_id=share_network['id'],
                host='fake_host')

        self.mock_object(manager.LOG, 'info')
        self.share_manager.driver.create_share = mock.Mock(
            return_value='fake_location')
        self.share_manager._setup_server = fake_setup_server
        self.share_manager.create_share_instance(self.context,
                                                 share.instance['id'])
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)
        manager.LOG.info.assert_called_with(mock.ANY, share.instance['id'])

    def test_create_share_instance_with_share_network_server_fail(self):
        fake_share = db_utils.create_share(share_network_id='fake_sn_id',
                                           size=1)
        fake_server = {
            'id': 'fake_srv_id',
            'status': constants.STATUS_CREATING,
        }
        self.mock_object(db, 'share_server_create',
                         mock.Mock(return_value=fake_server))
        self.mock_object(db, 'share_instance_update',
                         mock.Mock(return_value=fake_share.instance))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=fake_share.instance))
        self.mock_object(manager.LOG, 'error')

        def raise_share_server_not_found(*args, **kwargs):
            raise exception.ShareServerNotFound(
                share_server_id=fake_server['id'])

        def raise_manila_exception(*args, **kwargs):
            raise exception.ManilaException()

        self.mock_object(db,
                         'share_server_get_all_by_host_and_share_net_valid',
                         mock.Mock(side_effect=raise_share_server_not_found))
        self.mock_object(self.share_manager, '_setup_server',
                         mock.Mock(side_effect=raise_manila_exception))

        self.assertRaises(
            exception.ManilaException,
            self.share_manager.create_share_instance,
            self.context,
            fake_share.instance['id'],
        )
        db.share_server_get_all_by_host_and_share_net_valid.\
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.share_manager.host,
                fake_share['share_network_id'],
            )
        db.share_server_create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), mock.ANY)
        db.share_instance_update.assert_has_calls([
            mock.call(
                utils.IsAMatcher(context.RequestContext),
                fake_share.instance['id'],
                {'status': constants.STATUS_ERROR},
            )
        ])
        self.share_manager._setup_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_server)
        manager.LOG.error.assert_called_with(mock.ANY,
                                             fake_share.instance['id'])

    def test_create_share_instance_with_share_network_not_found(self):
        """Test creation fails if share network not found."""

        self.mock_object(manager.LOG, 'error')

        share = db_utils.create_share(share_network_id='fake-net-id')
        share_id = share['id']
        self.assertRaises(
            exception.ShareNetworkNotFound,
            self.share_manager.create_share_instance,
            self.context,
            share.instance['id']
        )
        manager.LOG.error.assert_called_with(mock.ANY, share.instance['id'])
        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_ERROR, shr['status'])

    def test_create_share_instance_with_share_network_server_exists(self):
        """Test share can be created with existing share server."""
        share_net = db_utils.create_share_network()
        share = db_utils.create_share(share_network_id=share_net['id'])
        share_srv = db_utils.create_share_server(
            share_network_id=share_net['id'], host=self.share_manager.host)

        share_id = share['id']

        self.mock_object(manager.LOG, 'info')
        driver_mock = mock.Mock()
        driver_mock.create_share.return_value = "fake_location"
        driver_mock.choose_share_server_compatible_with_share.return_value = (
            share_srv
        )
        self.share_manager.driver = driver_mock
        self.share_manager.create_share_instance(self.context,
                                                 share.instance['id'])
        self.assertFalse(self.share_manager.driver.setup_network.called)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], constants.STATUS_AVAILABLE)
        self.assertEqual(shr['share_server_id'], share_srv['id'])
        self.assertTrue(len(shr['export_location']) > 0)
        self.assertEqual(1, len(shr['export_locations']))
        manager.LOG.info.assert_called_with(mock.ANY, share.instance['id'])

    @ddt.data('export_location', 'export_locations')
    def test_create_share_instance_with_error_in_driver(self, details_key):
        """Test db updates if share creation fails in driver."""
        share = db_utils.create_share()
        share_id = share['id']
        some_data = 'fake_location'
        self.share_manager.driver = mock.Mock()
        e = exception.ManilaException(detail_data={details_key: some_data})
        self.share_manager.driver.create_share.side_effect = e
        self.assertRaises(
            exception.ManilaException,
            self.share_manager.create_share_instance,
            self.context,
            share.instance['id']
        )
        self.assertTrue(self.share_manager.driver.create_share.called)
        shr = db.share_get(self.context, share_id)
        self.assertEqual(some_data, shr['export_location'])

    def test_create_share_instance_with_server_created(self):
        """Test share can be created and share server is created."""
        share_net = db_utils.create_share_network()
        share = db_utils.create_share(share_network_id=share_net['id'])
        db_utils.create_share_server(
            share_network_id=share_net['id'], host=self.share_manager.host,
            status=constants.STATUS_ERROR)
        share_id = share['id']
        fake_server = {
            'id': 'fake_srv_id',
            'status': constants.STATUS_CREATING,
        }
        self.mock_object(db, 'share_server_create',
                         mock.Mock(return_value=fake_server))
        self.mock_object(self.share_manager, '_setup_server',
                         mock.Mock(return_value=fake_server))

        self.share_manager.create_share_instance(self.context,
                                                 share.instance['id'])

        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)
        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_AVAILABLE, shr['status'])
        self.assertEqual('fake_srv_id', shr['share_server_id'])
        db.share_server_create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), mock.ANY)
        self.share_manager._setup_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_server)

    def test_create_share_instance_update_replica_state(self):
        share_net = db_utils.create_share_network()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      replication_type='dr')
        db_utils.create_share_server(
            share_network_id=share_net['id'], host=self.share_manager.host,
            status=constants.STATUS_ERROR)
        share_id = share['id']
        fake_server = {
            'id': 'fake_srv_id',
            'status': constants.STATUS_CREATING,
        }
        self.mock_object(db, 'share_server_create',
                         mock.Mock(return_value=fake_server))
        self.mock_object(self.share_manager, '_setup_server',
                         mock.Mock(return_value=fake_server))

        self.share_manager.create_share_instance(self.context,
                                                 share.instance['id'])

        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)
        shr = db.share_get(self.context, share_id)
        shr_instances = db.share_instances_get_all_by_share(
            self.context, shr['id'])
        self.assertEqual(1, len(shr_instances))
        self.assertEqual(constants.STATUS_AVAILABLE, shr['status'])
        self.assertEqual(
            constants.REPLICA_STATE_ACTIVE, shr_instances[0]['replica_state'])
        self.assertEqual('fake_srv_id', shr['share_server_id'])
        db.share_server_create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), mock.ANY)
        self.share_manager._setup_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_server)

    @ddt.data(True, False)
    def test_create_delete_share_instance_error(self, exception_update_access):
        """Test share can be created and deleted with error."""

        def _raise_exception(self, *args, **kwargs):
            raise exception.ManilaException('fake')

        self.mock_object(self.share_manager.driver, "create_share",
                         mock.Mock(side_effect=_raise_exception))
        self.mock_object(self.share_manager.driver, "delete_share",
                         mock.Mock(side_effect=_raise_exception))
        if exception_update_access:
            self.mock_object(
                self.share_manager.access_helper, "update_access_rules",
                mock.Mock(side_effect=_raise_exception))

        share = db_utils.create_share()
        share_id = share['id']
        self.assertRaises(exception.ManilaException,
                          self.share_manager.create_share_instance,
                          self.context,
                          share.instance['id'])

        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_ERROR, shr['status'])
        self.assertRaises(exception.ManilaException,
                          self.share_manager.delete_share_instance,
                          self.context,
                          share.instance['id'])

        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_ERROR_DELETING, shr['status'])
        self.share_manager.driver.create_share.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            utils.IsAMatcher(models.ShareInstance),
            share_server=None)
        if not exception_update_access:
            self.share_manager.driver.delete_share.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                utils.IsAMatcher(models.ShareInstance),
                share_server=None)

    def test_create_share_instance_update_availability_zone(self):
        share = db_utils.create_share(availability_zone=None)
        share_id = share['id']

        self.share_manager.create_share_instance(
            self.context, share.instance['id'])

        actual_share = db.share_get(context.get_admin_context(), share_id)
        self.assertIsNotNone(actual_share.availability_zone)
        self.assertEqual(manager.CONF.storage_availability_zone,
                         actual_share.availability_zone)

    def test_provide_share_server_for_share_incompatible_servers(self):
        fake_exception = exception.ManilaException("fake")
        fake_share_server = {'id': 'fake'}
        share = db_utils.create_share()

        self.mock_object(db,
                         'share_server_get_all_by_host_and_share_net_valid',
                         mock.Mock(return_value=[fake_share_server]))
        self.mock_object(
            self.share_manager.driver,
            "choose_share_server_compatible_with_share",
            mock.Mock(side_effect=fake_exception)
        )

        self.assertRaises(exception.ManilaException,
                          self.share_manager._provide_share_server_for_share,
                          self.context, "fake_id", share.instance)
        driver_mock = self.share_manager.driver
        driver_method_mock = (
            driver_mock.choose_share_server_compatible_with_share
        )
        driver_method_mock.assert_called_once_with(
            self.context, [fake_share_server], share.instance, snapshot=None,
            consistency_group=None)

    def test_provide_share_server_for_share_invalid_arguments(self):
        self.assertRaises(ValueError,
                          self.share_manager._provide_share_server_for_share,
                          self.context, None, None)

    def test_provide_share_server_for_share_parent_ss_not_found(self):
        fake_parent_id = "fake_server_id"
        fake_exception = exception.ShareServerNotFound("fake")
        share = db_utils.create_share()
        fake_snapshot = {
            'share': {
                'instance': {
                    'share_server_id': fake_parent_id
                }
            }
        }
        self.mock_object(db, 'share_server_get',
                         mock.Mock(side_effect=fake_exception))

        self.assertRaises(exception.ShareServerNotFound,
                          self.share_manager._provide_share_server_for_share,
                          self.context, "fake_id", share.instance,
                          snapshot=fake_snapshot)

        db.share_server_get.assert_called_once_with(
            self.context, fake_parent_id)

    def test_provide_share_server_for_share_parent_ss_invalid(self):
        fake_parent_id = "fake_server_id"
        share = db_utils.create_share()
        fake_snapshot = {
            'share': {
                'instance': {
                    'share_server_id': fake_parent_id
                }
            }
        }
        fake_parent_share_server = {'status': 'fake'}
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value=fake_parent_share_server))

        self.assertRaises(exception.InvalidShareServer,
                          self.share_manager._provide_share_server_for_share,
                          self.context, "fake_id", share.instance,
                          snapshot=fake_snapshot)

        db.share_server_get.assert_called_once_with(
            self.context, fake_parent_id)

    def test_provide_share_server_for_cg_incompatible_servers(self):
        fake_exception = exception.ManilaException("fake")
        fake_share_server = {'id': 'fake'}
        cg = db_utils.create_consistency_group()

        self.mock_object(db,
                         'share_server_get_all_by_host_and_share_net_valid',
                         mock.Mock(return_value=[fake_share_server]))
        self.mock_object(
            self.share_manager.driver,
            "choose_share_server_compatible_with_cg",
            mock.Mock(side_effect=fake_exception)
        )

        self.assertRaises(exception.ManilaException,
                          self.share_manager._provide_share_server_for_cg,
                          self.context, "fake_id", cg)
        driver_mock = self.share_manager.driver
        driver_method_mock = (
            driver_mock.choose_share_server_compatible_with_cg
        )
        driver_method_mock.assert_called_once_with(
            self.context, [fake_share_server], cg, cgsnapshot=None)

    def test_provide_share_server_for_cg_invalid_arguments(self):
        self.assertRaises(exception.InvalidInput,
                          self.share_manager._provide_share_server_for_cg,
                          self.context, None, None)

    def test_manage_share_invalid_driver(self):
        self.mock_object(self.share_manager, 'driver', mock.Mock())
        self.share_manager.driver.driver_handles_share_servers = True
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        share = db_utils.create_share()
        share_id = share['id']

        self.assertRaises(
            exception.InvalidDriverMode,
            self.share_manager.manage_share, self.context, share_id, {})

        self.share_manager.db.share_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id,
            {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})

    def test_manage_share_invalid_share_type(self):
        self.mock_object(self.share_manager, 'driver', mock.Mock())
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value='True'))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        share = db_utils.create_share()
        share_id = share['id']

        self.assertRaises(
            exception.ManageExistingShareTypeMismatch,
            self.share_manager.manage_share, self.context, share_id, {})

        self.share_manager.db.share_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id,
            {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})

    def test_manage_share_driver_exception(self):
        CustomException = type('CustomException', (Exception,), dict())
        self.mock_object(self.share_manager, 'driver', mock.Mock())
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(self.share_manager.driver,
                         'manage_existing',
                         mock.Mock(side_effect=CustomException))
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        share = db_utils.create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.assertRaises(
            CustomException,
            self.share_manager.manage_share,
            self.context, share_id, driver_options)

        self.share_manager.driver.manage_existing.\
            assert_called_once_with(mock.ANY, driver_options)

        self.share_manager.db.share_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id,
            {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})

    def test_manage_share_invalid_size(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))
        self.mock_object(self.share_manager.driver,
                         "manage_existing",
                         mock.Mock(return_value=None))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        share = db_utils.create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.assertRaises(
            exception.InvalidShare,
            self.share_manager.manage_share,
            self.context, share_id, driver_options)

        self.share_manager.driver.manage_existing.\
            assert_called_once_with(mock.ANY, driver_options)
        self.share_manager.db.share_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id,
            {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})

    def test_manage_share_quota_error(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))
        self.mock_object(self.share_manager.driver,
                         "manage_existing",
                         mock.Mock(return_value={'size': 3}))
        self.mock_object(self.share_manager, '_update_quota_usages',
                         mock.Mock(side_effect=exception.QuotaError))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        share = db_utils.create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.assertRaises(
            exception.QuotaError,
            self.share_manager.manage_share,
            self.context, share_id, driver_options)

        self.share_manager.driver.manage_existing.\
            assert_called_once_with(mock.ANY, driver_options)
        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id,
            {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})
        self.share_manager._update_quota_usages.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share['project_id'], {'shares': 1, 'gigabytes': 3})

    @ddt.data(
        {'size': 1},
        {'size': 2, 'name': 'fake'},
        {'size': 3, 'export_locations': ['foo', 'bar', 'quuz']})
    def test_manage_share_valid_share(self, driver_data):
        export_locations = driver_data.get('export_locations')
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        self.mock_object(self.share_manager, 'driver', mock.Mock())
        self.mock_object(self.share_manager, '_update_quota_usages',
                         mock.Mock())
        self.mock_object(
            self.share_manager.db,
            'share_export_locations_update',
            mock.Mock(side_effect=(
                self.share_manager.db.share_export_locations_update)))
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))
        self.mock_object(self.share_manager.driver,
                         "manage_existing",
                         mock.Mock(return_value=driver_data))
        share = db_utils.create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.share_manager.manage_share(self.context, share_id, driver_options)

        self.share_manager.driver.manage_existing.\
            assert_called_once_with(mock.ANY, driver_options)
        if export_locations:
            self.share_manager.db.share_export_locations_update.\
                assert_called_once_with(
                    utils.IsAMatcher(context.RequestContext),
                    share.instance['id'], export_locations, delete=True)
        else:
            self.assertFalse(
                self.share_manager.db.share_export_locations_update.called)
        valid_share_data = {
            'status': constants.STATUS_AVAILABLE, 'launched_at': mock.ANY}
        valid_share_data.update(driver_data)
        self.share_manager.db.share_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_id, valid_share_data)

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
        self.mock_object(self.share_manager.db, 'share_instance_delete')

    @ddt.data(True, False)
    def test_unmanage_share_invalid_driver(self, driver_handles_share_servers):
        self._setup_unmanage_mocks()
        self.share_manager.driver.driver_handles_share_servers = (
            driver_handles_share_servers
        )
        share_net = db_utils.create_share_network()
        share_srv = db_utils.create_share_server(
            share_network_id=share_net['id'], host=self.share_manager.host)
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'])

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share['id'], {'status': constants.STATUS_UNMANAGE_ERROR})

    def test_unmanage_share_invalid_share(self):
        unmanage = mock.Mock(side_effect=exception.InvalidShare(reason="fake"))
        self._setup_unmanage_mocks(mock_driver=False, mock_unmanage=unmanage)
        share = db_utils.create_share()

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share['id'], {'status': constants.STATUS_UNMANAGE_ERROR})

    def test_unmanage_share_valid_share(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self._setup_unmanage_mocks(mock_driver=False,
                                   mock_unmanage=mock.Mock())
        share = db_utils.create_share()
        share_id = share['id']
        share_instance_id = share.instance['id']

        self.share_manager.unmanage_share(self.context, share_id)

        self.share_manager.driver.unmanage.\
            assert_called_once_with(mock.ANY)
        self.share_manager.db.share_instance_delete.assert_called_once_with(
            mock.ANY, share_instance_id)

    def test_unmanage_share_valid_share_with_quota_error(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self._setup_unmanage_mocks(mock_driver=False,
                                   mock_unmanage=mock.Mock())
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=Exception()))
        share = db_utils.create_share()
        share_instance_id = share.instance['id']

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.driver.unmanage.\
            assert_called_once_with(mock.ANY)
        self.share_manager.db.share_instance_delete.assert_called_once_with(
            mock.ANY, share_instance_id)

    def test_unmanage_share_remove_access_rules_error(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        manager.CONF.unmanage_remove_access_rules = True
        self._setup_unmanage_mocks(mock_driver=False,
                                   mock_unmanage=mock.Mock())
        self.mock_object(
            self.share_manager.access_helper,
            'update_access_rules',
            mock.Mock(side_effect=Exception())
        )
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(return_value=[]))
        share = db_utils.create_share()

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share['id'], {'status': constants.STATUS_UNMANAGE_ERROR})

    def test_unmanage_share_valid_share_remove_access_rules(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        manager.CONF.unmanage_remove_access_rules = True
        self._setup_unmanage_mocks(mock_driver=False,
                                   mock_unmanage=mock.Mock())
        smanager = self.share_manager
        self.mock_object(smanager.access_helper, 'update_access_rules')
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(return_value=[]))
        share = db_utils.create_share()
        share_id = share['id']
        share_instance_id = share.instance['id']

        smanager.unmanage_share(self.context, share_id)

        smanager.driver.unmanage.assert_called_once_with(mock.ANY)
        smanager.access_helper.update_access_rules.assert_called_once_with(
            mock.ANY, mock.ANY, delete_rules='all', share_server=None
        )
        smanager.db.share_instance_delete.assert_called_once_with(
            mock.ANY, share_instance_id)

    def test_delete_share_instance_share_server_not_found(self):
        share_net = db_utils.create_share_network()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id='fake-id')

        self.assertRaises(
            exception.ShareServerNotFound,
            self.share_manager.delete_share_instance,
            self.context,
            share.instance['id']
        )

    @ddt.data(True, False)
    def test_delete_share_instance_last_on_srv_with_sec_service(
            self, with_details):
        share_net = db_utils.create_share_network()
        sec_service = db_utils.create_security_service(
            share_network_id=share_net['id'])
        backend_details = dict(
            security_service_ldap=jsonutils.dumps(sec_service))
        if with_details:
            share_srv = db_utils.create_share_server(
                share_network_id=share_net['id'],
                host=self.share_manager.host,
                backend_details=backend_details)
        else:
            share_srv = db_utils.create_share_server(
                share_network_id=share_net['id'],
                host=self.share_manager.host)
            db.share_server_backend_details_set(
                context.get_admin_context(), share_srv['id'], backend_details)
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'])
        self.share_manager.driver = mock.Mock()
        manager.CONF.delete_share_server_with_last_share = True

        self.share_manager.delete_share_instance(self.context,
                                                 share.instance['id'])

        self.share_manager.driver.teardown_server.assert_called_once_with(
            server_details=backend_details,
            security_services=[jsonutils.loads(
                backend_details['security_service_ldap'])])

    @ddt.data({'force': True, 'side_effect': 'update_access'},
              {'force': True, 'side_effect': 'delete_share'},
              {'force': False, 'side_effect': None})
    @ddt.unpack
    def test_delete_share_instance_last_on_server(self, force, side_effect):
        share_net = db_utils.create_share_network()
        share_srv = db_utils.create_share_server(
            share_network_id=share_net['id'],
            host=self.share_manager.host
        )
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'])

        self.share_manager.driver = mock.Mock()
        if side_effect == 'update_access':
            self.mock_object(
                self.share_manager.access_helper, 'update_access_rules',
                mock.Mock(side_effect=Exception('fake')))
        if side_effect == 'delete_share':
            self.mock_object(self.share_manager.driver, 'delete_share',
                             mock.Mock(side_effect=Exception('fake')))
        self.mock_object(manager.LOG, 'error')
        manager.CONF.delete_share_server_with_last_share = True
        self.share_manager.delete_share_instance(
            self.context, share.instance['id'], force=force)
        self.share_manager.driver.teardown_server.assert_called_once_with(
            server_details=share_srv.get('backend_details'),
            security_services=[])
        self.assertEqual(force, manager.LOG.error.called)

    def test_delete_share_instance_last_on_server_deletion_disabled(self):
        share_net = db_utils.create_share_network()
        share_srv = db_utils.create_share_server(
            share_network_id=share_net['id'],
            host=self.share_manager.host
        )
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'])

        manager.CONF.delete_share_server_with_last_share = False
        self.share_manager.driver = mock.Mock()
        self.share_manager.delete_share_instance(self.context,
                                                 share.instance['id'])
        self.assertFalse(self.share_manager.driver.teardown_network.called)

    def test_delete_share_instance_not_last_on_server(self):
        share_net = db_utils.create_share_network()
        share_srv = db_utils.create_share_server(
            share_network_id=share_net['id'],
            host=self.share_manager.host
        )
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'])
        db_utils.create_share(share_network_id=share_net['id'],
                              share_server_id=share_srv['id'])

        manager.CONF.delete_share_server_with_last_share = True
        self.share_manager.driver = mock.Mock()
        self.share_manager.delete_share_instance(self.context,
                                                 share.instance['id'])
        self.assertFalse(self.share_manager.driver.teardown_network.called)

    @ddt.data('update_access', 'delete_share')
    def test_delete_share_instance_not_found(self, side_effect):
        share_net = db_utils.create_share_network()
        share_srv = db_utils.create_share_server(
            share_network_id=share_net['id'],
            host=self.share_manager.host)
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'])
        access = db_utils.create_access(share_id=share['id'])
        db_utils.create_share(share_network_id=share_net['id'],
                              share_server_id=share_srv['id'])

        manager.CONF.delete_share_server_with_last_share = False

        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value=share_srv))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share.instance))
        self.mock_object(db, 'share_access_get_all_for_instance',
                         mock.Mock(return_value=[access]))
        self.share_manager.driver = mock.Mock()
        self.share_manager.access_helper.driver = mock.Mock()
        if side_effect == 'update_access':
            self.mock_object(
                self.share_manager.access_helper.driver, 'update_access',
                mock.Mock(side_effect=exception.ShareResourceNotFound(
                    share_id=share['id'])))
        if side_effect == 'delete_share':
            self.mock_object(
                self.share_manager.driver, 'delete_share',
                mock.Mock(side_effect=exception.ShareResourceNotFound(
                    share_id=share['id'])))
            self.mock_object(
                self.share_manager.access_helper, '_check_needs_refresh',
                mock.Mock(return_value=False)
            )

        self.mock_object(manager.LOG, 'warning')

        self.share_manager.delete_share_instance(self.context,
                                                 share.instance['id'])
        self.assertFalse(self.share_manager.driver.teardown_network.called)

        (self.share_manager.access_helper.driver.update_access.
            assert_called_once_with(utils.IsAMatcher(
                context.RequestContext), share.instance, [], add_rules=[],
                delete_rules=[access], share_server=share_srv))

        self.assertTrue(manager.LOG.warning.called)

    def test_allow_deny_access(self):
        """Test access rules to share can be created and deleted."""
        self.mock_object(share_access.LOG, 'info')

        share = db_utils.create_share()
        share_id = share['id']
        share_instance = db_utils.create_share_instance(
            share_id=share_id,
            access_rules_status=constants.STATUS_OUT_OF_SYNC)
        share_instance_id = share_instance['id']
        access = db_utils.create_access(share_id=share_id,
                                        share_instance_id=share_instance_id)
        access_id = access['id']

        self.share_manager.allow_access(self.context, share_instance_id,
                                        [access_id])
        self.assertEqual('active', db.share_instance_get(
            self.context, share_instance_id).access_rules_status)

        share_access.LOG.info.assert_called_with(mock.ANY,
                                                 share_instance_id)
        share_access.LOG.info.reset_mock()

        self.share_manager.deny_access(self.context, share_instance_id,
                                       [access_id])

        share_access.LOG.info.assert_called_with(mock.ANY,
                                                 share_instance_id)
        share_access.LOG.info.reset_mock()

    def test_allow_deny_access_error(self):
        """Test access rules to share can be created and deleted with error."""

        def _fake_allow_access(self, *args, **kwargs):
            raise exception.NotFound()

        def _fake_deny_access(self, *args, **kwargs):
            raise exception.NotFound()

        self.mock_object(self.share_manager.access_helper.driver,
                         "allow_access", _fake_allow_access)
        self.mock_object(self.share_manager.access_helper.driver,
                         "deny_access", _fake_deny_access)

        share = db_utils.create_share()
        share_id = share['id']
        share_instance = db_utils.create_share_instance(
            share_id=share_id,
            access_rules_status=constants.STATUS_OUT_OF_SYNC)
        share_instance_id = share_instance['id']
        access = db_utils.create_access(share_id=share_id,
                                        share_instance_id=share_instance_id)
        access_id = access['id']

        def validate(method):
            self.assertRaises(exception.ManilaException, method, self.context,
                              share_instance_id, [access_id])

            inst = db.share_instance_get(self.context, share_instance_id)
            self.assertEqual(constants.STATUS_ERROR,
                             inst['access_rules_status'])

        validate(self.share_manager.allow_access)
        validate(self.share_manager.deny_access)

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
        network_info['network_type'] = 'fake_network_type'

        # mock required stuff
        self.mock_object(self.share_manager.db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(self.share_manager.driver, 'allocate_network')
        self.mock_object(self.share_manager, '_form_server_setup_info',
                         mock.Mock(return_value=network_info))
        self.mock_object(self.share_manager, '_validate_segmentation_id')
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
        self.share_manager._validate_segmentation_id.assert_called_once_with(
            network_info)
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
            'network_type': 'fake_network_type',
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
            'network_type': 'fake_network_type',
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
        self.share_manager.driver.deallocate_network.assert_has_calls([
            mock.call(self.context, share_server['id'])])

    def test_setup_server_incorrect_detail_data(self):
        self.setup_server_raise_exception(detail_data_proper=False)

    def test_setup_server_exception_in_driver(self):
        self.setup_server_raise_exception(detail_data_proper=True)

    @ddt.data({},
              {'detail_data': 'fake'},
              {'detail_data': {'server_details': 'fake'}},
              {'detail_data': {'server_details': {'fake': 'fake'}}},
              {'detail_data': {
                  'server_details': {'fake': 'fake', 'fake2': 'fake2'}}},)
    def test_setup_server_exception_in_cleanup_after_error(self, data):

        def get_server_details_from_data(data):
            d = data.get('detail_data')
            if not isinstance(d, dict):
                return {}
            d = d.get('server_details')
            if not isinstance(d, dict):
                return {}
            return d

        share_server = {'id': 'fake', 'share_network_id': 'fake'}
        details = get_server_details_from_data(data)

        exc_mock = mock.Mock(side_effect=exception.ManilaException(**data))
        details_mock = mock.Mock(side_effect=exception.ManilaException())
        self.mock_object(self.share_manager.db, 'share_network_get', exc_mock)
        self.mock_object(self.share_manager.db,
                         'share_server_backend_details_set', details_mock)
        self.mock_object(self.share_manager.db, 'share_server_update')
        self.mock_object(self.share_manager.driver, 'deallocate_network')
        self.mock_object(manager.LOG, 'debug')
        self.mock_object(manager.LOG, 'warning')

        self.assertRaises(
            exception.ManilaException,
            self.share_manager._setup_server,
            self.context,
            share_server,
        )

        self.assertTrue(self.share_manager.db.share_network_get.called)
        if details:
            self.assertEqual(len(details), details_mock.call_count)
            expected = [mock.call(mock.ANY, share_server['id'], {k: v})
                        for k, v in details.items()]
            self.assertEqual(expected, details_mock.call_args_list)
        self.share_manager.db.share_server_update.assert_called_once_with(
            self.context,
            share_server['id'],
            {'status': constants.STATUS_ERROR})
        self.share_manager.driver.deallocate_network.assert_called_once_with(
            self.context, share_server['id']
        )
        self.assertFalse(manager.LOG.warning.called)
        if get_server_details_from_data(data):
            self.assertTrue(manager.LOG.debug.called)

    def test_ensure_share_instance_has_pool_with_only_host(self):
        fake_share = {
            'status': constants.STATUS_AVAILABLE, 'host': 'host1', 'id': 1}
        host = self.share_manager._ensure_share_instance_has_pool(
            context.get_admin_context(), fake_share)
        self.assertIsNone(host)

    def test_ensure_share_instance_has_pool_with_full_pool_name(self):
        fake_share = {'host': 'host1#pool0', 'id': 1,
                      'status': constants.STATUS_AVAILABLE}
        fake_share_expected_value = 'pool0'
        host = self.share_manager._ensure_share_instance_has_pool(
            context.get_admin_context(), fake_share)
        self.assertEqual(fake_share_expected_value, host)

    def test_ensure_share_instance_has_pool_unable_to_fetch_share(self):
        fake_share = {'host': 'host@backend', 'id': 1,
                      'status': constants.STATUS_AVAILABLE}
        with mock.patch.object(self.share_manager.driver, 'get_pool',
                               side_effect=Exception):
            with mock.patch.object(manager, 'LOG') as mock_LOG:
                self.share_manager._ensure_share_instance_has_pool(
                    context.get_admin_context(), fake_share)
                self.assertEqual(1, mock_LOG.error.call_count)

    def test__form_server_setup_info(self):
        def fake_network_allocations_get_for_share_server(*args, **kwargs):
            if kwargs.get('label') != 'admin':
                return ['foo', 'bar']
            return ['admin-foo', 'admin-bar']

        self.mock_object(
            self.share_manager.db, 'network_allocations_get_for_share_server',
            mock.Mock(
                side_effect=fake_network_allocations_get_for_share_server))
        fake_share_server = dict(
            id='fake_share_server_id', backend_details=dict(foo='bar'))
        fake_share_network = dict(
            segmentation_id='fake_segmentation_id',
            cidr='fake_cidr',
            neutron_net_id='fake_neutron_net_id',
            neutron_subnet_id='fake_neutron_subnet_id',
            nova_net_id='fake_nova_net_id',
            security_services='fake_security_services',
            network_type='fake_network_type')
        expected = dict(
            server_id=fake_share_server['id'],
            segmentation_id=fake_share_network['segmentation_id'],
            cidr=fake_share_network['cidr'],
            neutron_net_id=fake_share_network['neutron_net_id'],
            neutron_subnet_id=fake_share_network['neutron_subnet_id'],
            nova_net_id=fake_share_network['nova_net_id'],
            security_services=fake_share_network['security_services'],
            network_allocations=(
                fake_network_allocations_get_for_share_server()),
            admin_network_allocations=(
                fake_network_allocations_get_for_share_server(label='admin')),
            backend_details=fake_share_server['backend_details'],
            network_type=fake_share_network['network_type'])

        network_info = self.share_manager._form_server_setup_info(
            self.context, fake_share_server, fake_share_network)

        self.assertEqual(expected, network_info)
        self.share_manager.db.network_allocations_get_for_share_server.\
            assert_has_calls([
                mock.call(self.context, fake_share_server['id'], label='user'),
                mock.call(self.context, fake_share_server['id'], label='admin')
            ])

    @ddt.data(
        {'network_info': {'network_type': 'vlan', 'segmentation_id': '100'}},
        {'network_info': {'network_type': 'vlan', 'segmentation_id': '1'}},
        {'network_info': {'network_type': 'vlan', 'segmentation_id': '4094'}},
        {'network_info': {'network_type': 'vxlan', 'segmentation_id': '100'}},
        {'network_info': {'network_type': 'vxlan', 'segmentation_id': '1'}},
        {'network_info': {'network_type': 'vxlan',
                          'segmentation_id': '16777215'}},
        {'network_info': {'network_type': 'gre', 'segmentation_id': '100'}},
        {'network_info': {'network_type': 'gre', 'segmentation_id': '1'}},
        {'network_info': {'network_type': 'gre',
                          'segmentation_id': '4294967295'}},
        {'network_info': {'network_type': 'flat', 'segmentation_id': None}},
        {'network_info': {'network_type': 'flat', 'segmentation_id': 0}},
        {'network_info': {'network_type': None, 'segmentation_id': None}},
        {'network_info': {'network_type': None, 'segmentation_id': 0}})
    @ddt.unpack
    def test_validate_segmentation_id_with_valid_values(self, network_info):
        self.share_manager._validate_segmentation_id(network_info)

    @ddt.data(
        {'network_info': {'network_type': 'vlan', 'segmentation_id': None}},
        {'network_info': {'network_type': 'vlan', 'segmentation_id': -1}},
        {'network_info': {'network_type': 'vlan', 'segmentation_id': 0}},
        {'network_info': {'network_type': 'vlan', 'segmentation_id': '4095'}},
        {'network_info': {'network_type': 'vxlan', 'segmentation_id': None}},
        {'network_info': {'network_type': 'vxlan', 'segmentation_id': 0}},
        {'network_info': {'network_type': 'vxlan',
                          'segmentation_id': '16777216'}},
        {'network_info': {'network_type': 'gre', 'segmentation_id': None}},
        {'network_info': {'network_type': 'gre', 'segmentation_id': 0}},
        {'network_info': {'network_type': 'gre',
                          'segmentation_id': '4294967296'}},
        {'network_info': {'network_type': 'flat', 'segmentation_id': '1000'}},
        {'network_info': {'network_type': None, 'segmentation_id': '1000'}})
    @ddt.unpack
    def test_validate_segmentation_id_with_invalid_values(self, network_info):
        self.assertRaises(exception.NetworkBadConfigurationException,
                          self.share_manager._validate_segmentation_id,
                          network_info)

    @ddt.data(5, 70)
    def test_verify_server_cleanup_interval_invalid_cases(self, val):
        data = dict(DEFAULT=dict(unused_share_server_cleanup_interval=val))
        with test_utils.create_temp_config_with_opts(data):
            self.assertRaises(exception.InvalidParameterValue,
                              manager.ShareManager)

    @ddt.data(10, 36, 60)
    def test_verify_server_cleanup_interval_valid_cases(self, val):
        data = dict(DEFAULT=dict(unused_share_server_cleanup_interval=val))
        with test_utils.create_temp_config_with_opts(data):
            manager.ShareManager()

    @mock.patch.object(db, 'share_server_get_all_unused_deletable',
                       mock.Mock())
    @mock.patch.object(manager.ShareManager, 'delete_share_server',
                       mock.Mock())
    def test_delete_free_share_servers_cleanup_disabled(self):
        data = dict(DEFAULT=dict(automatic_share_server_cleanup=False))
        with test_utils.create_temp_config_with_opts(data):
            share_manager = manager.ShareManager()
            share_manager.driver.initialized = True
            share_manager.delete_free_share_servers(self.context)
            self.assertFalse(db.share_server_get_all_unused_deletable.called)

    @mock.patch.object(db, 'share_server_get_all_unused_deletable',
                       mock.Mock())
    @mock.patch.object(manager.ShareManager, 'delete_share_server',
                       mock.Mock())
    def test_delete_free_share_servers_driver_handles_ss_disabled(self):
        data = dict(DEFAULT=dict(driver_handles_share_servers=False))
        with test_utils.create_temp_config_with_opts(data):
            share_manager = manager.ShareManager()
            share_manager.driver.initialized = True
            share_manager.delete_free_share_servers(self.context)
            self.assertFalse(db.share_server_get_all_unused_deletable.called)
            self.assertFalse(share_manager.delete_share_server.called)

    @mock.patch.object(db, 'share_server_get_all_unused_deletable',
                       mock.Mock(return_value=['server1', ]))
    @mock.patch.object(manager.ShareManager, 'delete_share_server',
                       mock.Mock())
    @mock.patch.object(timeutils, 'utcnow', mock.Mock(
                       return_value=datetime.timedelta(minutes=20)))
    def test_delete_free_share_servers(self):
        self.share_manager.delete_free_share_servers(self.context)
        db.share_server_get_all_unused_deletable.assert_called_once_with(
            self.context,
            self.share_manager.host,
            datetime.timedelta(minutes=10))
        self.share_manager.delete_share_server.assert_called_once_with(
            self.context,
            'server1')
        timeutils.utcnow.assert_called_once_with()

    def test_extend_share_invalid(self):
        share = db_utils.create_share()
        share_id = share['id']
        reservations = {}

        self.mock_object(self.share_manager, 'driver')
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(quota.QUOTAS, 'rollback')
        self.mock_object(self.share_manager.driver, 'extend_share',
                         mock.Mock(side_effect=Exception('fake')))

        self.assertRaises(
            exception.ShareExtendingError,
            self.share_manager.extend_share, self.context, share_id, 123, {})

        quota.QUOTAS.rollback.assert_called_once_with(
            mock.ANY,
            reservations,
            project_id=six.text_type(share['project_id']),
            user_id=six.text_type(share['user_id'])
        )

    def test_extend_share(self):
        share = db_utils.create_share()
        share_id = share['id']
        new_size = 123
        shr_update = {
            'size': int(new_size),
            'status': constants.STATUS_AVAILABLE.lower()
        }
        reservations = {}
        fake_share_server = 'fake'

        manager = self.share_manager
        self.mock_object(manager, 'driver')
        self.mock_object(manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(manager.db, 'share_update',
                         mock.Mock(return_value=share))
        self.mock_object(quota.QUOTAS, 'commit')
        self.mock_object(manager.driver, 'extend_share')
        self.mock_object(manager, '_get_share_server',
                         mock.Mock(return_value=fake_share_server))

        self.share_manager.extend_share(self.context, share_id,
                                        new_size, reservations)

        self.assertTrue(manager._get_share_server.called)
        manager.driver.extend_share.assert_called_once_with(
            utils.IsAMatcher(models.ShareInstance),
            new_size, share_server=fake_share_server
        )
        quota.QUOTAS.commit.assert_called_once_with(
            mock.ANY, reservations, project_id=share['project_id'],
            user_id=share['user_id'])
        manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, shr_update
        )

    def test_shrink_share_quota_error(self):
        size = 5
        new_size = 1
        share = db_utils.create_share(size=size)
        share_id = share['id']

        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=Exception('fake')))

        self.assertRaises(
            exception.ShareShrinkingError,
            self.share_manager.shrink_share, self.context, share_id, new_size)

        quota.QUOTAS.reserve.assert_called_with(
            mock.ANY,
            project_id=six.text_type(share['project_id']),
            user_id=six.text_type(share['user_id']),
            gigabytes=new_size - size
        )
        self.assertTrue(self.share_manager.db.share_update.called)

    @ddt.data({'exc': exception.InvalidShare('fake'),
               'status': constants.STATUS_SHRINKING_ERROR},
              {'exc': exception.ShareShrinkingPossibleDataLoss("fake"),
               'status': constants.STATUS_SHRINKING_POSSIBLE_DATA_LOSS_ERROR})
    @ddt.unpack
    def test_shrink_share_invalid(self, exc, status):
        share = db_utils.create_share()
        new_size = 1
        share_id = share['id']
        size_decrease = int(share['size']) - new_size

        self.mock_object(self.share_manager, 'driver')
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(quota.QUOTAS, 'reserve')
        self.mock_object(quota.QUOTAS, 'rollback')
        self.mock_object(self.share_manager.driver, 'shrink_share',
                         mock.Mock(side_effect=exc))

        self.assertRaises(
            exception.ShareShrinkingError,
            self.share_manager.shrink_share, self.context, share_id, new_size)

        self.share_manager.driver.shrink_share.assert_called_once_with(
            utils.IsAMatcher(models.ShareInstance),
            new_size, share_server=None
        )
        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, {'status': status}
        )
        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY, gigabytes=-size_decrease, project_id=share['project_id'],
            user_id=share['user_id']
        )
        quota.QUOTAS.rollback.assert_called_once_with(
            mock.ANY, mock.ANY, project_id=share['project_id'],
            user_id=share['user_id']
        )
        self.assertTrue(self.share_manager.db.share_get.called)

    def test_shrink_share(self):
        share = db_utils.create_share()
        share_id = share['id']
        new_size = 123
        shr_update = {
            'size': int(new_size),
            'status': constants.STATUS_AVAILABLE
        }
        fake_share_server = 'fake'
        size_decrease = int(share['size']) - new_size

        manager = self.share_manager
        self.mock_object(manager, 'driver')
        self.mock_object(manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(manager.db, 'share_update',
                         mock.Mock(return_value=share))
        self.mock_object(quota.QUOTAS, 'commit')
        self.mock_object(quota.QUOTAS, 'reserve')
        self.mock_object(manager.driver, 'shrink_share')
        self.mock_object(manager, '_get_share_server',
                         mock.Mock(return_value=fake_share_server))

        self.share_manager.shrink_share(self.context, share_id, new_size)

        self.assertTrue(manager._get_share_server.called)
        manager.driver.shrink_share.assert_called_once_with(
            utils.IsAMatcher(models.ShareInstance),
            new_size, share_server=fake_share_server
        )

        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY, gigabytes=-size_decrease, project_id=share['project_id'],
            user_id=share['user_id']
        )
        quota.QUOTAS.commit.assert_called_once_with(
            mock.ANY, mock.ANY, project_id=share['project_id'],
            user_id=share['user_id']
        )
        manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, shr_update
        )

    def test_report_driver_status_driver_handles_ss_false(self):
        fake_stats = {'field': 'val'}
        fake_pool = {'name': 'pool1'}
        self.share_manager.last_capabilities = {'field': 'old_val'}

        self.mock_object(self.share_manager, 'driver', mock.Mock())
        driver = self.share_manager.driver

        driver.get_share_stats = mock.Mock(return_value=fake_stats)
        self.mock_object(db, 'share_server_get_all_by_host', mock.Mock())
        driver.driver_handles_share_servers = False
        driver.get_share_server_pools = mock.Mock(return_value=fake_pool)

        self.share_manager._report_driver_status(self.context)

        driver.get_share_stats.assert_called_once_with(
            refresh=True)
        self.assertFalse(db.share_server_get_all_by_host.called)
        self.assertFalse(driver.get_share_server_pools.called)
        self.assertEqual(fake_stats, self.share_manager.last_capabilities)

    def test_report_driver_status_driver_handles_ss(self):
        fake_stats = {'field': 'val'}
        fake_ss = {'id': '1234'}
        fake_pool = {'name': 'pool1'}

        self.mock_object(self.share_manager, 'driver', mock.Mock())
        driver = self.share_manager.driver

        driver.get_share_stats = mock.Mock(return_value=fake_stats)
        self.mock_object(db, 'share_server_get_all_by_host', mock.Mock(
            return_value=[fake_ss]))
        driver.driver_handles_share_servers = True
        driver.get_share_server_pools = mock.Mock(return_value=fake_pool)

        self.share_manager._report_driver_status(self.context)

        driver.get_share_stats.assert_called_once_with(refresh=True)
        db.share_server_get_all_by_host.assert_called_once_with(
            self.context,
            self.share_manager.host)
        driver.get_share_server_pools.assert_called_once_with(fake_ss)
        expected_stats = {
            'field': 'val',
            'server_pools_mapping': {
                '1234': fake_pool},
        }
        self.assertEqual(expected_stats, self.share_manager.last_capabilities)

    def test_report_driver_status_empty_share_stats(self):
        old_capabilities = {'field': 'old_val'}
        fake_pool = {'name': 'pool1'}
        self.share_manager.last_capabilities = old_capabilities

        self.mock_object(self.share_manager, 'driver', mock.Mock())
        driver = self.share_manager.driver

        driver.get_share_stats = mock.Mock(return_value={})
        self.mock_object(db, 'share_server_get_all_by_host', mock.Mock())
        driver.driver_handles_share_servers = True
        driver.get_share_server_pools = mock.Mock(return_value=fake_pool)

        self.share_manager._report_driver_status(self.context)

        driver.get_share_stats.assert_called_once_with(refresh=True)
        self.assertFalse(db.share_server_get_all_by_host.called)
        self.assertFalse(driver.get_share_server_pools.called)
        self.assertEqual(old_capabilities,
                         self.share_manager.last_capabilities)

    def test_create_consistency_group(self):
        fake_cg = {'id': 'fake_id'}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group',
                         mock.Mock(return_value=None))

        self.share_manager.create_consistency_group(self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_called_once_with(mock.ANY, 'fake_id',
                                    {'status': constants.STATUS_AVAILABLE,
                                     'created_at': mock.ANY})

    def test_create_cg_with_share_network_driver_not_handles_servers(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=False))
        cg_id = 'fake_cg_id'
        share_network_id = 'fake_sn'
        fake_cg = {'id': 'fake_id', 'share_network_id': share_network_id}
        self.mock_object(
            self.share_manager.db, 'consistency_group_get',
            mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_update')

        self.assertRaises(
            exception.ManilaException,
            self.share_manager.create_consistency_group, self.context, cg_id)

        self.share_manager.db.consistency_group_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), cg_id)
        self.share_manager.db.consistency_group_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), cg_id,
            {'status': constants.STATUS_ERROR})

    def test_create_cg_with_share_network_driver_handles_servers(self):
        manager.CONF.set_default('driver_handles_share_servers', True)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=True))
        share_network_id = 'fake_sn'
        fake_cg = {'id': 'fake_id', 'share_network_id': share_network_id,
                   'host': "fake_host"}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager, '_provide_share_server_for_cg',
                         mock.Mock(return_value=({}, fake_cg)))
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group',
                         mock.Mock(return_value=None))

        self.share_manager.create_consistency_group(self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_called_once_with(mock.ANY, 'fake_id',
                                    {'status': constants.STATUS_AVAILABLE,
                                     'created_at': mock.ANY})

    def test_create_consistency_group_with_update(self):
        fake_cg = {'id': 'fake_id'}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group',
                         mock.Mock(return_value={'foo': 'bar'}))

        self.share_manager.create_consistency_group(self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_any_call(mock.ANY, 'fake_id', {'foo': 'bar'})
        self.share_manager.db.consistency_group_update.\
            assert_any_call(mock.ANY, 'fake_id',
                            {'status': constants.STATUS_AVAILABLE,
                             'created_at': mock.ANY})

    def test_create_consistency_group_with_error(self):
        fake_cg = {'id': 'fake_id'}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error,
                          self.share_manager.create_consistency_group,
                          self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_called_once_with(mock.ANY, 'fake_id',
                                    {'status': constants.STATUS_ERROR})

    def test_create_consistency_group_from_cgsnapshot(self):
        fake_cg = {'id': 'fake_id', 'source_cgsnapshot_id': 'fake_snap_id',
                   'shares': [], 'share_server_id': 'fake_ss_id'}
        fake_ss = {'id': 'fake_ss_id', 'share_network_id': 'fake_sn'}
        fake_snap = {'id': 'fake_snap_id', 'cgsnapshot_members': [],
                     'consistency_group': {'share_server_id': fake_ss['id']}}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(
                             return_value=fake_ss))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group_from_cgsnapshot',
                         mock.Mock(return_value=(None, None)))

        self.share_manager.create_consistency_group(self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_called_once_with(mock.ANY, 'fake_id',
                                    {'status': constants.STATUS_AVAILABLE,
                                     'created_at': mock.ANY})
        self.share_manager.db.share_server_get(mock.ANY, 'fake_ss_id')
        self.share_manager.driver.create_consistency_group_from_cgsnapshot.\
            assert_called_once_with(
                mock.ANY, fake_cg, fake_snap, share_server=fake_ss)

    def test_create_cg_cgsnapshot_share_network_driver_not_handles_servers(
            self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=False))
        cg_id = 'fake_cg_id'
        share_network_id = 'fake_sn'
        fake_cg = {'id': 'fake_id', 'source_cgsnapshot_id': 'fake_snap_id',
                   'shares': [], 'share_network_id': share_network_id,
                   'host': "fake_host"}
        self.mock_object(
            self.share_manager.db, 'consistency_group_get',
            mock.Mock(return_value=fake_cg))
        fake_snap = {'id': 'fake_snap_id', 'cgsnapshot_members': []}
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'consistency_group_update')

        self.assertRaises(exception.ManilaException,
                          self.share_manager.create_consistency_group,
                          self.context, cg_id)

        self.share_manager.db.consistency_group_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), cg_id)
        self.share_manager.db.consistency_group_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), cg_id,
            {'status': constants.STATUS_ERROR})

    def test_create_cg_from_cgsnapshot_share_network_driver_handles_servers(
            self):
        manager.CONF.set_default('driver_handles_share_servers', True)
        self.mock_object(self.share_manager.driver.configuration, 'safe_get',
                         mock.Mock(return_value=True))
        share_network_id = 'fake_sn'
        fake_cg = {'id': 'fake_id', 'source_cgsnapshot_id': 'fake_snap_id',
                   'shares': [], 'share_network_id': share_network_id}
        fake_snap = {'id': 'fake_snap_id', 'cgsnapshot_members': []}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager, '_provide_share_server_for_cg',
                         mock.Mock(return_value=({}, fake_cg)))
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group_from_cgsnapshot',
                         mock.Mock(return_value=(None, None)))

        self.share_manager.create_consistency_group(self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_called_once_with(mock.ANY, 'fake_id',
                                    {'status': constants.STATUS_AVAILABLE,
                                     'created_at': mock.ANY})

    def test_create_consistency_group_from_cgsnapshot_with_update(self):
        fake_cg = {'id': 'fake_id', 'source_cgsnapshot_id': 'fake_snap_id',
                   'shares': []}
        fake_snap = {'id': 'fake_snap_id', 'cgsnapshot_members': []}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group_from_cgsnapshot',
                         mock.Mock(return_value=({'foo': 'bar'}, None)))

        self.share_manager.create_consistency_group(self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_any_call(mock.ANY, 'fake_id', {'foo': 'bar'})
        self.share_manager.db.consistency_group_update.\
            assert_any_call(mock.ANY, 'fake_id',
                            {'status': constants.STATUS_AVAILABLE,
                             'created_at': mock.ANY})

    def test_create_consistency_group_from_cgsnapshot_with_share_update(self):
        fake_share = {'id': 'fake_share_id'}
        fake_export_locations = ['my_export_location']
        fake_cg = {'id': 'fake_id', 'source_cgsnapshot_id': 'fake_snap_id',
                   'shares': [fake_share]}
        fake_snap = {'id': 'fake_snap_id', 'cgsnapshot_members': []}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'consistency_group_update')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db,
                         'share_export_locations_update')
        fake_share_update_list = [{'id': fake_share['id'],
                                   'foo': 'bar',
                                   'export_locations': fake_export_locations}]
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group_from_cgsnapshot',
                         mock.Mock(
                             return_value=(None, fake_share_update_list)))

        self.share_manager.create_consistency_group(self.context, "fake_id")

        self.share_manager.db.share_instance_update.\
            assert_any_call(mock.ANY, 'fake_share_id', {'foo': 'bar'})
        self.share_manager.db.share_export_locations_update.\
            assert_any_call(mock.ANY, 'fake_share_id', fake_export_locations)
        self.share_manager.db.consistency_group_update.\
            assert_any_call(mock.ANY, 'fake_id',
                            {'status': constants.STATUS_AVAILABLE,
                             'created_at': mock.ANY})

    def test_create_consistency_group_from_cgsnapshot_with_error(self):
        fake_cg = {'id': 'fake_id', 'source_cgsnapshot_id': 'fake_snap_id',
                   'shares': []}
        fake_snap = {'id': 'fake_snap_id', 'cgsnapshot_members': []}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[]))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group_from_cgsnapshot',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error,
                          self.share_manager.create_consistency_group,
                          self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_called_once_with(mock.ANY, 'fake_id',
                                    {'status': constants.STATUS_ERROR})

    def test_create_consistency_group_from_cgsnapshot_with_share_error(self):
        fake_share = {'id': 'fake_share_id'}
        fake_cg = {'id': 'fake_id', 'source_cgsnapshot_id': 'fake_snap_id',
                   'shares': [fake_share]}
        fake_snap = {'id': 'fake_snap_id', 'cgsnapshot_members': []}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_consistency_group_id',
                         mock.Mock(return_value=[fake_share]))
        self.mock_object(self.share_manager.db, 'consistency_group_update')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.driver,
                         'create_consistency_group_from_cgsnapshot',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error,
                          self.share_manager.create_consistency_group,
                          self.context, "fake_id")

        self.share_manager.db.share_instance_update.\
            assert_any_call(mock.ANY, 'fake_share_id',
                            {'status': constants.STATUS_ERROR})
        self.share_manager.db.consistency_group_update.\
            assert_called_once_with(mock.ANY, 'fake_id',
                                    {'status': constants.STATUS_ERROR})

    def test_delete_consistency_group(self):
        fake_cg = {'id': 'fake_id'}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_destroy',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.driver,
                         'delete_consistency_group',
                         mock.Mock(return_value=None))

        self.share_manager.delete_consistency_group(self.context, "fake_id")

        self.share_manager.db.consistency_group_destroy.\
            assert_called_once_with(mock.ANY, 'fake_id')

    def test_delete_consistency_group_with_update(self):
        fake_cg = {'id': 'fake_id'}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_destroy',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.driver,
                         'delete_consistency_group',
                         mock.Mock(return_value={'foo': 'bar'}))

        self.share_manager.delete_consistency_group(self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_called_once_with(mock.ANY, 'fake_id', {'foo': 'bar'})
        self.share_manager.db.consistency_group_destroy.\
            assert_called_once_with(mock.ANY, 'fake_id')

    def test_delete_consistency_group_with_error(self):
        fake_cg = {'id': 'fake_id'}
        self.mock_object(self.share_manager.db, 'consistency_group_get',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.db, 'consistency_group_update',
                         mock.Mock(return_value=fake_cg))
        self.mock_object(self.share_manager.driver,
                         'delete_consistency_group',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error,
                          self.share_manager.delete_consistency_group,
                          self.context, "fake_id")

        self.share_manager.db.consistency_group_update.\
            assert_called_once_with(mock.ANY, 'fake_id',
                                    {'status': constants.STATUS_ERROR})

    def test_create_cgsnapshot(self):
        fake_snap = {'id': 'fake_snap_id', 'consistency_group': {},
                     'cgsnapshot_members': []}
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'cgsnapshot_update',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.driver,
                         'create_cgsnapshot',
                         mock.Mock(return_value=(None, None)))

        self.share_manager.create_cgsnapshot(self.context, fake_snap['id'])

        self.share_manager.db.cgsnapshot_update.\
            assert_called_once_with(mock.ANY, fake_snap['id'],
                                    {'status': constants.STATUS_AVAILABLE,
                                     'created_at': mock.ANY})

    def test_create_cgsnapshot_with_update(self):
        fake_snap = {'id': 'fake_snap_id', 'consistency_group': {},
                     'cgsnapshot_members': []}
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'cgsnapshot_update',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.driver,
                         'create_cgsnapshot',
                         mock.Mock(return_value=({'foo': 'bar'}, None)))

        self.share_manager.create_cgsnapshot(self.context, fake_snap['id'])

        self.share_manager.db.cgsnapshot_update.\
            assert_any_call(mock.ANY, 'fake_snap_id', {'foo': 'bar'})
        self.share_manager.db.cgsnapshot_update.assert_any_call(
            mock.ANY, fake_snap['id'],
            {'status': constants.STATUS_AVAILABLE, 'created_at': mock.ANY})

    def test_create_cgsnapshot_with_member_update(self):
        fake_member = {
            'id': 'fake_member_id',
            'share_instance_id': 'blah',
        }
        fake_member_update = {
            'id': 'fake_member_id',
            'foo': 'bar'
        }
        fake_snap = {'id': 'fake_snap_id', 'consistency_group': {},
                     'cgsnapshot_members': [fake_member]}
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'cgsnapshot_update',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'cgsnapshot_member_update')
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value={'id': 'blah'}))
        self.mock_object(self.share_manager.driver, 'create_cgsnapshot',
                         mock.Mock(return_value=(None, [fake_member_update])))

        self.share_manager.create_cgsnapshot(self.context, fake_snap['id'])

        self.share_manager.db.cgsnapshot_update.assert_any_call(
            mock.ANY, fake_snap['id'],
            {'cgsnapshot_members': [fake_member_update]})
        self.share_manager.db.cgsnapshot_update.\
            assert_any_call(mock.ANY, fake_snap['id'],
                            {'status': constants.STATUS_AVAILABLE,
                             'created_at': mock.ANY})
        self.assertTrue(self.share_manager.db.cgsnapshot_member_update.called)

    def test_create_cgsnapshot_with_error(self):
        fake_snap = {'id': 'fake_snap_id', 'consistency_group': {},
                     'cgsnapshot_members': []}
        self.mock_object(self.share_manager.db, 'cgsnapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'cgsnapshot_update',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.driver,
                         'create_cgsnapshot',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error,
                          self.share_manager.create_cgsnapshot,
                          self.context, fake_snap['id'])

        self.share_manager.db.cgsnapshot_update.\
            assert_called_once_with(mock.ANY, fake_snap['id'],
                                    {'status': constants.STATUS_ERROR})

    def test_migration_get_info(self):
        share_instance = {'share_server_id': 'fake_server_id'}
        share_instance_id = 'fake_id'
        share_server = 'fake_share_server'
        migration_info = 'fake_info'

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=share_instance))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager.driver, 'migration_get_info',
                         mock.Mock(return_value=migration_info))

        # run
        result = self.share_manager.migration_get_info(
            self.context, share_instance_id)

        # asserts
        self.assertEqual(migration_info, result)

        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, share_instance_id, with_share_data=True)

        self.share_manager.driver.migration_get_info.assert_called_once_with(
            self.context, share_instance, share_server)

    def test_migration_get_driver_info(self):
        share_instance = {'share_server_id': 'fake_server_id'}
        share_instance_id = 'fake-id'
        share_server = 'fake-share-server'
        migration_info = 'fake_info'

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=share_instance))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager.driver,
                         'migration_get_driver_info',
                         mock.Mock(return_value=migration_info))

        result = self.share_manager.migration_get_driver_info(
            self.context, share_instance_id)

        # asserts
        self.assertEqual(migration_info, result)

        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, share_instance_id, with_share_data=True)

        self.share_manager.driver.migration_get_driver_info.\
            assert_called_once_with(self.context, share_instance, share_server)

    @ddt.data((True, 'fake_model_update'), exception.ManilaException())
    def test_migration_start(self, exc):

        server = 'fake_share_server'
        instance = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_AVAILABLE,
            share_server_id='fake_server_id')
        share = db_utils.create_share(id='fake_id', instances=[instance])
        host = 'fake_host'
        driver_migration_info = 'driver_fake_info'

        # mocks
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=instance))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(rpcapi.ShareAPI, 'migration_get_driver_info',
                         mock.Mock(return_value=driver_migration_info))

        if isinstance(exc, exception.ManilaException):
            self.mock_object(self.share_manager.driver, 'migration_start',
                             mock.Mock(side_effect=exc))
            self.mock_object(self.share_manager, '_migration_start_generic',
                             mock.Mock(side_effect=Exception('fake')))
            self.mock_object(manager.LOG, 'exception')
        else:
            self.mock_object(self.share_manager.driver, 'migration_start',
                             mock.Mock(return_value=exc))

        # run
        if isinstance(exc, exception.ManilaException):
            self.assertRaises(exception.ShareMigrationFailed,
                              self.share_manager.migration_start,
                              self.context, 'fake_id', host, False, False)
        else:
            self.share_manager.migration_start(
                self.context, 'fake_id', host, False, False)

        # asserts
        self.share_manager.db.share_get.assert_called_once_with(
            self.context, share['id'])
        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, instance['id'], with_share_data=True)
        self.share_manager.db.share_server_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            instance['share_server_id'])

        share_update_calls = [
            mock.call(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS}),
            mock.call(
                self.context, share['id'],
                {'task_state': (
                    constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)})
        ]
        share_instance_update_calls = [
            mock.call(self.context, instance['id'],
                      {'status': constants.STATUS_MIGRATING})
        ]
        if isinstance(exc, exception.ManilaException):
            share_update_calls.append(mock.call(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR}))
            share_instance_update_calls.append(
                mock.call(self.context, instance['id'],
                          {'status': constants.STATUS_AVAILABLE}))
            self.share_manager._migration_start_generic.\
                assert_called_once_with(self.context, share, instance, host,
                                        False)
            self.assertTrue(manager.LOG.exception.called)
        else:
            share_update_calls.append(mock.call(
                self.context, share['id'],
                {'task_state':
                 constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE}))
            share_instance_update_calls.append(
                mock.call(self.context, instance['id'], 'fake_model_update'))

        self.share_manager.db.share_update.assert_has_calls(share_update_calls)
        self.share_manager.db.share_instance_update.assert_has_calls(
            share_instance_update_calls)
        rpcapi.ShareAPI.migration_get_driver_info.assert_called_once_with(
            self.context, instance)
        self.share_manager.driver.migration_start.assert_called_once_with(
            self.context, instance, server, host, driver_migration_info, False)

    @ddt.data(None, Exception('fake'))
    def test__migration_start_generic(self, exc):
        instance = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_AVAILABLE,
            share_server_id='fake_server_id')
        new_instance = db_utils.create_share_instance(
            share_id='new_fake_id',
            status=constants.STATUS_AVAILABLE)
        share = db_utils.create_share(id='fake_id', instances=[instance])
        server = 'share_server'
        src_migration_info = 'src_fake_info'
        dest_migration_info = 'dest_fake_info'

        # mocks
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(self.share_manager.db, 'share_instance_update',
                         mock.Mock(return_value=server))
        self.mock_object(migration_api.ShareMigrationHelper,
                         'change_to_read_only')
        if exc is None:
            self.mock_object(migration_api.ShareMigrationHelper,
                             'create_instance_and_wait',
                             mock.Mock(return_value=new_instance))
            self.mock_object(self.share_manager.driver, 'migration_get_info',
                             mock.Mock(return_value=src_migration_info))
            self.mock_object(rpcapi.ShareAPI, 'migration_get_info',
                             mock.Mock(return_value=dest_migration_info))
            self.mock_object(data_rpc.DataAPI, 'migration_start',
                             mock.Mock(side_effect=Exception('fake')))
            self.mock_object(migration_api.ShareMigrationHelper,
                             'cleanup_new_instance')
        else:
            self.mock_object(migration_api.ShareMigrationHelper,
                             'create_instance_and_wait',
                             mock.Mock(side_effect=exc))
        self.mock_object(migration_api.ShareMigrationHelper,
                         'cleanup_access_rules')

        # run
        self.assertRaises(
            exception.ShareMigrationFailed,
            self.share_manager._migration_start_generic,
            self.context, share, instance, 'fake_host', False)

        # asserts
        self.share_manager.db.share_server_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            instance['share_server_id'])

        migration_api.ShareMigrationHelper.change_to_read_only.\
            assert_called_once_with(instance, server, True,
                                    self.share_manager.driver)
        migration_api.ShareMigrationHelper.create_instance_and_wait.\
            assert_called_once_with(share, instance, 'fake_host')
        migration_api.ShareMigrationHelper.\
            cleanup_access_rules.assert_called_once_with(
                instance, server, self.share_manager.driver)
        if exc is None:
            self.share_manager.db.share_instance_update.\
                assert_called_once_with(
                    self.context, new_instance['id'],
                    {'status': constants.STATUS_MIGRATING_TO})
            self.share_manager.driver.migration_get_info.\
                assert_called_once_with(self.context, instance, server)
            rpcapi.ShareAPI.migration_get_info.assert_called_once_with(
                self.context, new_instance)
            data_rpc.DataAPI.migration_start.assert_called_once_with(
                self.context, share['id'], ['lost+found'], instance['id'],
                new_instance['id'], src_migration_info, dest_migration_info,
                False)
            migration_api.ShareMigrationHelper.\
                cleanup_new_instance.assert_called_once_with(new_instance)

    @ddt.data('fake_model_update', Exception('fake'))
    def test_migration_complete_driver(self, exc):
        server = 'fake_server'
        model_update = 'fake_model_update'
        instance = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_AVAILABLE,
            share_server_id='fake_server_id')
        share = db_utils.create_share(
            id='fake_id',
            instances=[instance],
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)

        # mocks
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=instance))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(self.share_manager.db, 'share_update')
        if isinstance(exc, Exception):
            self.mock_object(self.share_manager.driver, 'migration_complete',
                             mock.Mock(side_effect=exc))
        else:
            self.mock_object(self.share_manager.driver, 'migration_complete',
                             mock.Mock(return_value=exc))
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(rpcapi.ShareAPI, 'migration_get_driver_info',
                         mock.Mock(return_value='fake_info'))
        self.mock_object(manager.LOG, 'exception')

        # run
        if isinstance(exc, Exception):
            self.assertRaises(
                exception.ShareMigrationFailed,
                self.share_manager.migration_complete,
                self.context, 'fake_id', 'fake_ins_id', 'new_fake_ins_id')
        else:
            self.share_manager.migration_complete(
                self.context, 'fake_id', 'fake_ins_id', 'new_fake_ins_id')

        # asserts
        self.share_manager.db.share_get.assert_called_once_with(
            self.context, share['id'])
        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, instance['id'], with_share_data=True)
        self.share_manager.db.share_server_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), 'fake_server_id')
        self.share_manager.driver.migration_complete.assert_called_once_with(
            self.context, instance, server, 'fake_info')
        rpcapi.ShareAPI.migration_get_driver_info.assert_called_once_with(
            self.context, instance)
        if isinstance(exc, Exception):
            self.share_manager.db.share_update.assert_called_once_with(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
            self.assertTrue(manager.LOG.exception.called)
        else:
            self.share_manager.db.share_update.assert_called_once_with(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_SUCCESS})
            self.share_manager.db.share_instance_update.\
                assert_called_once_with(self.context, instance['id'],
                                        model_update)

    @ddt.data(None, Exception('fake'))
    def test_migration_complete_generic(self, exc):
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_COMPLETED)

        # mocks
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager, '_migration_complete',
                         mock.Mock(side_effect=exc))
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(manager.LOG, 'exception')

        # run
        if exc:
            self.assertRaises(
                exception.ShareMigrationFailed,
                self.share_manager.migration_complete,
                self.context, 'fake_id', 'fake_ins_id', 'new_fake_ins_id')
        else:
            self.share_manager.migration_complete(
                self.context, 'fake_id', 'fake_ins_id', 'new_fake_ins_id')

        # asserts
        self.share_manager.db.share_get.assert_called_once_with(
            self.context, share['id'])
        self.share_manager._migration_complete.assert_called_once_with(
            self.context, share, 'fake_ins_id', 'new_fake_ins_id')
        if exc:
            self.share_manager.db.share_update.assert_called_once_with(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
            self.share_manager.db.share_instance_update.\
                assert_called_once_with(
                    self.context, 'fake_ins_id',
                    {'status': constants.STATUS_AVAILABLE})
            self.assertTrue(manager.LOG.exception.called)

    @ddt.data(constants.TASK_STATE_DATA_COPYING_ERROR,
              constants.TASK_STATE_DATA_COPYING_CANCELLED,
              constants.TASK_STATE_DATA_COPYING_COMPLETED,
              'other')
    def test__migration_complete_status(self, status):

        instance = db_utils.create_share_instance(
            share_id='fake_id',
            share_server_id='fake_server_id')
        new_instance = db_utils.create_share_instance(share_id='fake_id')
        share = db_utils.create_share(id='fake_id', task_state=status)
        server = 'fake_server'

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instance, new_instance]))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(migration_api.ShareMigrationHelper,
                         'cleanup_new_instance')
        self.mock_object(migration_api.ShareMigrationHelper,
                         'cleanup_access_rules')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db, 'share_update')
        if status == constants.TASK_STATE_DATA_COPYING_COMPLETED:
            self.mock_object(migration_api.ShareMigrationHelper,
                             'apply_new_access_rules',
                             mock.Mock(side_effect=Exception('fake')))
            self.mock_object(manager.LOG, 'exception')

        # run
        if status == constants.TASK_STATE_DATA_COPYING_CANCELLED:
            self.share_manager._migration_complete(
                self.context, share, instance['id'], new_instance['id'])
        else:
            self.assertRaises(
                exception.ShareMigrationFailed,
                self.share_manager._migration_complete, self.context, share,
                instance['id'], new_instance['id'])

        # asserts
        self.share_manager.db.share_instance_get.assert_has_calls([
            mock.call(self.context, instance['id'], with_share_data=True),
            mock.call(self.context, new_instance['id'], with_share_data=True)
        ])
        self.share_manager.db.share_server_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), 'fake_server_id')

        if status != 'other':
            migration_api.ShareMigrationHelper.cleanup_new_instance.\
                assert_called_once_with(new_instance)
            migration_api.ShareMigrationHelper.cleanup_access_rules.\
                assert_called_once_with(instance, server,
                                        self.share_manager.driver)
        if status == constants.TASK_STATE_MIGRATION_CANCELLED:
            self.share_manager.db.share_instance_update.\
                assert_called_once_with(self.context, instance['id'],
                                        {'status': constants.STATUS_AVAILABLE})
            self.share_manager.db.share_update.assert_called_once_with(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED})
        if status == constants.TASK_STATE_DATA_COPYING_COMPLETED:
            migration_api.ShareMigrationHelper.apply_new_access_rules.\
                assert_called_once_with(new_instance)
            self.assertTrue(manager.LOG.exception.called)

    def test__migration_complete(self):

        instance = db_utils.create_share_instance(
            share_id='fake_id',
            share_server_id='fake_server_id')
        new_instance = db_utils.create_share_instance(share_id='fake_id')
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_COMPLETED)
        server = 'fake_server'

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instance, new_instance]))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(migration_api.ShareMigrationHelper,
                         'delete_instance_and_wait')
        self.mock_object(migration_api.ShareMigrationHelper,
                         'apply_new_access_rules')

        # run
        self.share_manager._migration_complete(
            self.context, share, instance['id'], new_instance['id'])

        # asserts
        self.share_manager.db.share_instance_get.assert_has_calls([
            mock.call(self.context, instance['id'], with_share_data=True),
            mock.call(self.context, new_instance['id'], with_share_data=True)
        ])
        self.share_manager.db.share_server_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), 'fake_server_id')

        self.share_manager.db.share_instance_update.assert_has_calls([
            mock.call(self.context, new_instance['id'],
                      {'status': constants.STATUS_AVAILABLE}),
            mock.call(self.context, instance['id'],
                      {'status': constants.STATUS_INACTIVE})
        ])
        self.share_manager.db.share_update.assert_has_calls([
            mock.call(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING}),
            mock.call(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_SUCCESS}),
        ])
        migration_api.ShareMigrationHelper.apply_new_access_rules.\
            assert_called_once_with(new_instance)
        migration_api.ShareMigrationHelper.delete_instance_and_wait.\
            assert_called_once_with(instance)

    def test_migration_cancel(self):

        server = db_utils.create_share_server()
        share = db_utils.create_share(
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            share_server_id=server['id'])

        self.mock_object(db, 'share_get', mock.Mock(return_value=share))

        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value=server))

        self.mock_object(rpcapi.ShareAPI, 'migration_get_driver_info',
                         mock.Mock(return_value='migration_info'))

        self.mock_object(self.share_manager.driver, 'migration_cancel')

        self.share_manager.migration_cancel(self.context, share)

        rpcapi.ShareAPI.migration_get_driver_info.assert_called_once_with(
            self.context, share.instance)

        self.share_manager.driver.migration_cancel.assert_called_once_with(
            self.context, share.instance, server, 'migration_info')

    def test_migration_cancel_invalid(self):

        share = db_utils.create_share()

        self.mock_object(db, 'share_get', mock.Mock(return_value=share))

        self.assertRaises(
            exception.InvalidShare, self.share_manager.migration_cancel,
            self.context, share)

    def test_migration_get_progress(self):

        server = db_utils.create_share_server()
        share = db_utils.create_share(
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            share_server_id=server['id'])

        expected = 'fake_progress'

        self.mock_object(db, 'share_get', mock.Mock(return_value=share))

        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value=server))

        self.mock_object(rpcapi.ShareAPI, 'migration_get_driver_info',
                         mock.Mock(return_value='migration_info'))

        self.mock_object(self.share_manager.driver, 'migration_get_progress',
                         mock.Mock(return_value=expected))

        result = self.share_manager.migration_get_progress(self.context, share)

        self.assertEqual(expected, result)

        rpcapi.ShareAPI.migration_get_driver_info.assert_called_once_with(
            self.context, share.instance)

        self.share_manager.driver.migration_get_progress.\
            assert_called_once_with(
                self.context, share.instance, server, 'migration_info')

    def test_migration_get_progress_invalid(self):

        share = db_utils.create_share()

        self.mock_object(db, 'share_get', mock.Mock(return_value=share))

        self.assertRaises(
            exception.InvalidShare, self.share_manager.migration_get_progress,
            self.context, share)

    def test_manage_snapshot_invalid_driver_mode(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = True
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        driver_options = {'fake': 'fake'}

        self.assertRaises(
            exception.InvalidDriverMode,
            self.share_manager.manage_snapshot, self.context,
            snapshot['id'], driver_options)

    def test_manage_snapshot_invalid_snapshot(self):
        fake_share_server = 'fake_share_server'
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        mock_get_share_server = self.mock_object(
            self.share_manager,
            '_get_share_server',
            mock.Mock(return_value=fake_share_server))
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        driver_options = {'fake': 'fake'}
        mock_get = self.mock_object(self.share_manager.db,
                                    'share_snapshot_get',
                                    mock.Mock(return_value=snapshot))

        self.assertRaises(
            exception.InvalidShareSnapshot,
            self.share_manager.manage_snapshot, self.context,
            snapshot['id'], driver_options)

        mock_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        mock_get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['share'])

    def test_manage_snapshot_driver_exception(self):
        CustomException = type('CustomException', (Exception,), {})
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        mock_manage = self.mock_object(self.share_manager.driver,
                                       'manage_existing_snapshot',
                                       mock.Mock(side_effect=CustomException))
        mock_get_share_server = self.mock_object(self.share_manager,
                                                 '_get_share_server',
                                                 mock.Mock(return_value=None))
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        driver_options = {}
        mock_get = self.mock_object(self.share_manager.db,
                                    'share_snapshot_get',
                                    mock.Mock(return_value=snapshot))

        self.assertRaises(
            CustomException,
            self.share_manager.manage_snapshot,
            self.context, snapshot['id'], driver_options)

        mock_manage.assert_called_once_with(mock.ANY, driver_options)
        mock_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        mock_get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['share'])

    @ddt.data(
        {'size': 1},
        {'size': 2, 'name': 'fake'},
        {'size': 3})
    def test_manage_snapshot_valid_snapshot(self, driver_data):
        mock_get_share_server = self.mock_object(self.share_manager,
                                                 '_get_share_server',
                                                 mock.Mock(return_value=None))
        self.mock_object(self.share_manager.db, 'share_snapshot_update')
        self.mock_object(self.share_manager, 'driver')
        self.mock_object(self.share_manager, '_update_quota_usages')
        self.share_manager.driver.driver_handles_share_servers = False
        mock_manage = self.mock_object(
            self.share_manager.driver,
            "manage_existing_snapshot",
            mock.Mock(return_value=driver_data))
        size = driver_data['size']
        share = db_utils.create_share(size=size)
        snapshot = db_utils.create_snapshot(share_id=share['id'], size=size)
        snapshot_id = snapshot['id']
        driver_options = {}
        mock_get = self.mock_object(self.share_manager.db,
                                    'share_snapshot_get',
                                    mock.Mock(return_value=snapshot))

        self.share_manager.manage_snapshot(self.context, snapshot_id,
                                           driver_options)

        mock_manage.assert_called_once_with(mock.ANY, driver_options)
        valid_snapshot_data = {
            'status': constants.STATUS_AVAILABLE}
        valid_snapshot_data.update(driver_data)
        self.share_manager.db.share_snapshot_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            snapshot_id, valid_snapshot_data)
        self.share_manager._update_quota_usages.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            snapshot['project_id'],
            {'snapshots': 1, 'snapshot_gigabytes': size})
        mock_get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['share'])
        mock_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot_id)

    def test_unmanage_snapshot_invalid_driver_mode(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = True
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        self.mock_object(self.share_manager.db, 'share_snapshot_update')

        ret = self.share_manager.unmanage_snapshot(self.context,
                                                   snapshot['id'])
        self.assertIsNone(ret)
        self.share_manager.db.share_snapshot_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            snapshot['id'],
            {'status': constants.STATUS_UNMANAGE_ERROR})

    def test_unmanage_snapshot_invalid_snapshot(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        mock_get_share_server = self.mock_object(
            self.share_manager,
            '_get_share_server',
            mock.Mock(return_value='fake_share_server'))
        self.mock_object(self.share_manager.db, 'share_snapshot_update')
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        mock_get = self.mock_object(self.share_manager.db,
                                    'share_snapshot_get',
                                    mock.Mock(return_value=snapshot))

        ret = self.share_manager.unmanage_snapshot(self.context,
                                                   snapshot['id'])

        self.assertIsNone(ret)
        self.share_manager.db.share_snapshot_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            snapshot['id'],
            {'status': constants.STATUS_UNMANAGE_ERROR})
        mock_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        mock_get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['share'])

    def test_unmanage_snapshot_invalid_share(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        mock_unmanage = mock.Mock(
            side_effect=exception.UnmanageInvalidShareSnapshot(reason="fake"))
        self.mock_object(self.share_manager.driver, "unmanage_snapshot",
                         mock_unmanage)
        mock_get_share_server = self.mock_object(
            self.share_manager,
            '_get_share_server',
            mock.Mock(return_value=None))
        self.mock_object(self.share_manager.db, 'share_snapshot_update')
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        mock_get = self.mock_object(self.share_manager.db,
                                    'share_snapshot_get',
                                    mock.Mock(return_value=snapshot))

        self.share_manager.unmanage_snapshot(self.context, snapshot['id'])

        self.share_manager.db.share_snapshot_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'],
            {'status': constants.STATUS_UNMANAGE_ERROR})
        self.share_manager.driver.unmanage_snapshot.assert_called_once_with(
            mock.ANY)
        mock_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        mock_get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['share'])

    @ddt.data(False, True)
    def test_unmanage_snapshot_valid_snapshot(self, quota_error):
        if quota_error:
            self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(
                side_effect=exception.ManilaException(message='error')))
        mock_log_warning = self.mock_object(manager.LOG, 'warning')
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(self.share_manager.driver, "unmanage_snapshot")
        mock_get_share_server = self.mock_object(
            self.share_manager,
            '_get_share_server',
            mock.Mock(return_value=None))
        mock_snapshot_instance_destroy_call = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_delete')
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        mock_get = self.mock_object(self.share_manager.db,
                                    'share_snapshot_get',
                                    mock.Mock(return_value=snapshot))

        self.share_manager.unmanage_snapshot(self.context, snapshot['id'])

        self.share_manager.driver.unmanage_snapshot.assert_called_once_with(
            mock.ANY)
        mock_snapshot_instance_destroy_call.assert_called_once_with(
            mock.ANY, snapshot['instance']['id'])
        mock_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        mock_get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['share'])
        if quota_error:
            self.assertTrue(mock_log_warning.called)

    def _setup_crud_replicated_snapshot_data(self):
        snapshot = fakes.fake_snapshot(create_instance=True)
        snapshot_instance = fakes.fake_snapshot_instance(
            base_snapshot=snapshot)
        snapshot_instances = [snapshot['instance'], snapshot_instance]
        replicas = [fake_replica(), fake_replica()]
        return snapshot, snapshot_instances, replicas

    def test_create_replicated_snapshot_driver_exception(self):
        snapshot, snapshot_instances, replicas = (
            self._setup_crud_replicated_snapshot_data()
        )
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas))
        self.mock_object(
            self.share_manager.driver, 'create_replicated_snapshot',
            mock.Mock(side_effect=exception.ManilaException))
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')

        self.assertRaises(exception.ManilaException,
                          self.share_manager.create_replicated_snapshot,
                          self.context, snapshot['id'], share_id='fake_share')
        mock_db_update_call.assert_has_calls([
            mock.call(
                self.context, snapshot['instance']['id'],
                {'status': constants.STATUS_ERROR}),
            mock.call(
                self.context, snapshot_instances[1]['id'],
                {'status': constants.STATUS_ERROR}),
        ])

    @ddt.data(None, [])
    def test_create_replicated_snapshot_driver_updates_nothing(self, retval):
        snapshot, snapshot_instances, replicas = (
            self._setup_crud_replicated_snapshot_data()
        )
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas))
        self.mock_object(
            self.share_manager.driver, 'create_replicated_snapshot',
            mock.Mock(return_value=retval))
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')

        return_value = self.share_manager.create_replicated_snapshot(
            self.context, snapshot['id'], share_id='fake_share')

        self.assertIsNone(return_value)
        self.assertFalse(mock_db_update_call.called)

    def test_create_replicated_snapshot_driver_updates_snapshot(self):
        snapshot, snapshot_instances, replicas = (
            self._setup_crud_replicated_snapshot_data()
        )
        snapshot_dict = {
            'status': constants.STATUS_AVAILABLE,
            'provider_location': 'spinners_end',
            'progress': '100%',
            'id': snapshot['instance']['id'],
        }
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas))
        self.mock_object(
            self.share_manager.driver, 'create_replicated_snapshot',
            mock.Mock(return_value=[snapshot_dict]))
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')

        return_value = self.share_manager.create_replicated_snapshot(
            self.context, snapshot['id'], share_id='fake_share')

        self.assertIsNone(return_value)
        mock_db_update_call.assert_called_once_with(
            self.context, snapshot['instance']['id'], snapshot_dict)

    def delete_replicated_snapshot_driver_exception(self):
        snapshot, snapshot_instances, replicas = (
            self._setup_crud_replicated_snapshot_data()
        )
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas))
        self.mock_object(
            self.share_manager.driver, 'delete_replicated_snapshot',
            mock.Mock(side_effect=exception.ManilaException))
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')

        self.assertRaises(exception.ManilaException,
                          self.share_manager.delete_replicated_snapshot,
                          self.context, snapshot['id'], share_id='fake_share')
        mock_db_update_call.assert_has_calls([
            mock.call(
                self.context, snapshot['instance']['id'],
                {'status': constants.STATUS_ERROR_DELETING}),
            mock.call(
                self.context, snapshot_instances[1]['id'],
                {'status': constants.STATUS_ERROR_DELETING}),
        ])
        self.assertFalse(mock_db_delete_call.called)

    def delete_replicated_snapshot_driver_exception_ignored_with_force(self):
        snapshot, snapshot_instances, replicas = (
            self._setup_crud_replicated_snapshot_data()
        )
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas))
        self.mock_object(
            self.share_manager.driver, 'delete_replicated_snapshot',
            mock.Mock(side_effect=exception.ManilaException))
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')

        retval = self.share_manager.delete_replicated_snapshot(
            self.context, snapshot['id'], share_id='fake_share')

        self.assertIsNone(retval)
        mock_db_delete_call.assert_has_calls([
            mock.call(
                self.context, snapshot['instance']['id']),
            mock.call(
                self.context, snapshot_instances[1]['id']),
        ])
        self.assertFalse(mock_db_update_call.called)

    @ddt.data(None, [])
    def delete_replicated_snapshot_driver_updates_nothing(self, retval):
        snapshot, snapshot_instances, replicas = (
            self._setup_crud_replicated_snapshot_data()
        )
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas))
        self.mock_object(
            self.share_manager.driver, 'delete_replicated_snapshot',
            mock.Mock(return_value=retval))
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')

        return_value = self.share_manager.delete_replicated_snapshot(
            self.context, snapshot['id'], share_id='fake_share')

        self.assertIsNone(return_value)
        self.assertFalse(mock_db_delete_call.called)
        self.assertFalse(mock_db_update_call.called)

    def delete_replicated_snapshot_driver_deletes_snapshots(self):
        snapshot, snapshot_instances, replicas = (
            self._setup_crud_replicated_snapshot_data()
        )
        retval = [{
            'status': constants.STATUS_DELETED,
            'id': snapshot['instance']['id'],
        }]
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas))
        self.mock_object(
            self.share_manager.driver, 'delete_replicated_snapshot',
            mock.Mock(return_value=retval))
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')

        return_value = self.share_manager.delete_replicated_snapshot(
            self.context, snapshot['id'], share_id='fake_share')

        self.assertIsNone(return_value)
        mock_db_delete_call.assert_called_once_with(
            self.context, snapshot['instance']['id'])
        self.assertFalse(mock_db_update_call.called)

    @ddt.data(True, False)
    def delete_replicated_snapshot_drv_del_and_updates_snapshots(self, force):
        snapshot, snapshot_instances, replicas = (
            self._setup_crud_replicated_snapshot_data()
        )
        updated_instance_details = {
            'status': constants.STATUS_ERROR,
            'id': snapshot_instances[1]['id'],
            'provider_location': 'azkaban',
        }
        retval = [
            {
                'status': constants.STATUS_DELETED,
                'id': snapshot['instance']['id'],
            },
        ]
        retval.append(updated_instance_details)
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager, '_get_share_server')
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas))
        self.mock_object(
            self.share_manager.driver, 'delete_replicated_snapshot',
            mock.Mock(return_value=retval))
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')

        return_value = self.share_manager.delete_replicated_snapshot(
            self.context, snapshot['id'], share_id='fake_share', force=force)

        self.assertIsNone(return_value)
        if force:
            self.assertTrue(2, mock_db_delete_call.call_count)
            self.assertFalse(mock_db_update_call.called)
        else:
            mock_db_delete_call.assert_called_once_with(
                self.context, snapshot['instance']['id'])
            mock_db_update_call.assert_called_once_with(
                self.context, snapshot_instances[1]['id'],
                updated_instance_details)

    def test_periodic_share_replica_snapshot_update(self):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        replicas = 3 * [
            fake_replica(host='malfoy@manor#_pool0',
                         replica_state=constants.REPLICA_STATE_IN_SYNC)
        ]
        replicas.append(fake_replica(replica_state=constants.STATUS_ACTIVE))
        snapshot = fakes.fake_snapshot(create_instance=True,
                                       status=constants.STATUS_DELETING)
        snapshot_instances = 3 * [
            fakes.fake_snapshot_instance(base_snapshot=snapshot)
        ]
        self.mock_object(
            db, 'share_replicas_get_all', mock.Mock(return_value=replicas))
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=snapshot_instances))
        mock_snapshot_update_call = self.mock_object(
            self.share_manager, '_update_replica_snapshot')

        retval = self.share_manager.periodic_share_replica_snapshot_update(
            self.context)

        self.assertIsNone(retval)
        self.assertEqual(1, mock_debug_log.call_count)
        self.assertEqual(0, mock_snapshot_update_call.call_count)

    @ddt.data(True, False)
    def test_periodic_share_replica_snapshot_update_nothing_to_update(
            self, has_instances):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        replicas = 3 * [
            fake_replica(host='malfoy@manor#_pool0',
                         replica_state=constants.REPLICA_STATE_IN_SYNC)
        ]
        replicas.append(fake_replica(replica_state=constants.STATUS_ACTIVE))
        snapshot = fakes.fake_snapshot(create_instance=True,
                                       status=constants.STATUS_DELETING)
        snapshot_instances = 3 * [
            fakes.fake_snapshot_instance(base_snapshot=snapshot)
        ]
        self.mock_object(db, 'share_replicas_get_all',
                         mock.Mock(side_effect=[[], replicas]))
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(side_effect=[snapshot_instances, []]))
        mock_snapshot_update_call = self.mock_object(
            self.share_manager, '_update_replica_snapshot')

        retval = self.share_manager.periodic_share_replica_snapshot_update(
            self.context)

        self.assertIsNone(retval)
        self.assertEqual(1, mock_debug_log.call_count)
        self.assertEqual(0, mock_snapshot_update_call.call_count)

    def test__update_replica_snapshot_replica_deleted_from_database(self):
        replica_not_found = exception.ShareReplicaNotFound(replica_id='xyzzy')
        self.mock_object(db, 'share_replica_get', mock.Mock(
            side_effect=replica_not_found))
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')
        mock_driver_update_call = self.mock_object(
            self.share_manager.driver, 'update_replicated_snapshot')
        snaphot_instance = fakes.fake_snapshot_instance()

        retval = self.share_manager._update_replica_snapshot(
            self.context, snaphot_instance)

        self.assertIsNone(retval)
        mock_db_delete_call.assert_called_once_with(
            self.context, snaphot_instance['id'])
        self.assertFalse(mock_driver_update_call.called)
        self.assertFalse(mock_db_update_call.called)

    def test__update_replica_snapshot_both_deleted_from_database(self):
        replica_not_found = exception.ShareReplicaNotFound(replica_id='xyzzy')
        instance_not_found = exception.ShareSnapshotInstanceNotFound(
            instance_id='spoon!')
        self.mock_object(db, 'share_replica_get', mock.Mock(
            side_effect=replica_not_found))
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete', mock.Mock(
                side_effect=instance_not_found))
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')
        mock_driver_update_call = self.mock_object(
            self.share_manager.driver, 'update_replicated_snapshot')
        snapshot_instance = fakes.fake_snapshot_instance()

        retval = self.share_manager._update_replica_snapshot(
            self.context, snapshot_instance)

        self.assertIsNone(retval)
        mock_db_delete_call.assert_called_once_with(
            self.context, snapshot_instance['id'])
        self.assertFalse(mock_driver_update_call.called)
        self.assertFalse(mock_db_update_call.called)

    def test__update_replica_snapshot_driver_raises_Not_Found_exception(self):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        replica = fake_replica()
        snapshot_instance = fakes.fake_snapshot_instance(
            status=constants.STATUS_DELETING)
        self.mock_object(
            db, 'share_replica_get', mock.Mock(return_value=replica))
        self.mock_object(db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica]))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        self.mock_object(
            self.share_manager.driver, 'update_replicated_snapshot',
            mock.Mock(
                side_effect=exception.SnapshotResourceNotFound(name='abc')))
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')

        retval = self.share_manager._update_replica_snapshot(
            self.context, snapshot_instance, replica_snapshots=None)

        self.assertIsNone(retval)
        self.assertEqual(1, mock_debug_log.call_count)
        mock_db_delete_call.assert_called_once_with(
            self.context, snapshot_instance['id'])
        self.assertFalse(mock_db_update_call.called)

    @ddt.data(exception.NotFound, exception.ManilaException)
    def test__update_replica_snapshot_driver_raises_other_exception(self, exc):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        mock_info_log = self.mock_object(manager.LOG, 'info')
        mock_exception_log = self.mock_object(manager.LOG, 'exception')
        replica = fake_replica()
        snapshot_instance = fakes.fake_snapshot_instance(
            status=constants.STATUS_CREATING)
        self.mock_object(
            db, 'share_replica_get', mock.Mock(return_value=replica))
        self.mock_object(db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica]))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        self.mock_object(self.share_manager.driver,
                         'update_replicated_snapshot',
                         mock.Mock(side_effect=exc))
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')

        retval = self.share_manager._update_replica_snapshot(
            self.context, snapshot_instance)

        self.assertIsNone(retval)
        self.assertEqual(1, mock_exception_log.call_count)
        self.assertEqual(1, mock_debug_log.call_count)
        self.assertFalse(mock_info_log.called)
        mock_db_update_call.assert_called_once_with(
            self.context, snapshot_instance['id'], {'status': 'error'})
        self.assertFalse(mock_db_delete_call.called)

    @ddt.data(True, False)
    def test__update_replica_snapshot_driver_updates_replica(self, update):
        replica = fake_replica()
        snapshot_instance = fakes.fake_snapshot_instance()
        driver_update = {}
        if update:
            driver_update = {
                'id': snapshot_instance['id'],
                'provider_location': 'knockturn_alley',
                'status': constants.STATUS_AVAILABLE,
            }
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        mock_info_log = self.mock_object(manager.LOG, 'info')
        self.mock_object(
            db, 'share_replica_get', mock.Mock(return_value=replica))
        self.mock_object(db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica]))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        self.mock_object(self.share_manager.driver,
                         'update_replicated_snapshot',
                         mock.Mock(return_value=driver_update))
        mock_db_delete_call = self.mock_object(
            db, 'share_snapshot_instance_delete')
        mock_db_update_call = self.mock_object(
            db, 'share_snapshot_instance_update')

        retval = self.share_manager._update_replica_snapshot(
            self.context, snapshot_instance, replica_snapshots=None)

        driver_update['progress'] = '100%'
        self.assertIsNone(retval)
        self.assertEqual(1, mock_debug_log.call_count)
        self.assertFalse(mock_info_log.called)
        if update:
            mock_db_update_call.assert_called_once_with(
                self.context, snapshot_instance['id'], driver_update)
        else:
            self.assertFalse(mock_db_update_call.called)
        self.assertFalse(mock_db_delete_call.called)


@ddt.ddt
class HookWrapperTestCase(test.TestCase):

    def setUp(self):
        super(HookWrapperTestCase, self).setUp()
        self.configuration = mock.Mock()
        self.configuration.safe_get.return_value = True

    @manager.add_hooks
    def _fake_wrapped_method(self, some_arg, some_kwarg):
        return "foo"

    def test_hooks_enabled(self):
        self.hooks = [mock.Mock(return_value=i) for i in range(2)]

        result = self._fake_wrapped_method(
            "some_arg", some_kwarg="some_kwarg_value")

        self.assertEqual("foo", result)
        for i, mock_hook in enumerate(self.hooks):
            mock_hook.execute_pre_hook.assert_called_once_with(
                "some_arg",
                func_name="_fake_wrapped_method",
                some_kwarg="some_kwarg_value")
            mock_hook.execute_post_hook.assert_called_once_with(
                "some_arg",
                func_name="_fake_wrapped_method",
                driver_action_results="foo",
                pre_hook_data=self.hooks[i].execute_pre_hook.return_value,
                some_kwarg="some_kwarg_value")

    def test_hooks_disabled(self):
        self.hooks = []

        result = self._fake_wrapped_method(
            "some_arg", some_kwarg="some_kwarg_value")

        self.assertEqual("foo", result)
        for mock_hook in self.hooks:
            self.assertFalse(mock_hook.execute_pre_hook.called)
            self.assertFalse(mock_hook.execute_post_hook.called)
